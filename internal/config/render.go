package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func ValidateDraft(d Draft) error {
	seen := make(map[string]bool, len(d.Schema))
	seenEnv := make(map[string]bool, len(d.Schema))
	seenYAML := make(map[string]bool, len(d.Schema))
	for _, field := range d.Schema {
		if err := field.Validate(); err != nil {
			return err
		}
		if (field.Type == "secret" || field.Sensitive) && field.Default != nil {
			return fmt.Errorf("secret field %q must not define a default", field.Path)
		}
		if !validPath(field.Path) {
			return fmt.Errorf("field path %q is invalid", field.Path)
		}
		if seen[field.Path] {
			return fmt.Errorf("duplicate field path %q", field.Path)
		}
		seen[field.Path] = true
		if field.Environment != "" && !validEnvName(field.Environment) {
			return fmt.Errorf("field %q has invalid environment variable name %q", field.Path, field.Environment)
		}
		if field.Environment != "" {
			if seenEnv[field.Environment] {
				return fmt.Errorf("duplicate environment variable mapping %q", field.Environment)
			}
			seenEnv[field.Environment] = true
		}
		yamlPath := field.YAML
		if yamlPath == "" {
			yamlPath = field.Path
		}
		if !validPath(yamlPath) {
			return fmt.Errorf("field %q has invalid YAML path %q", field.Path, yamlPath)
		}
		if seenYAML[yamlPath] {
			return fmt.Errorf("duplicate YAML mapping %q", yamlPath)
		}
		seenYAML[yamlPath] = true
		if field.Required {
			value, ok := getPath(d.Values, field.Path)
			if !ok || value == nil || value == "" {
				return fmt.Errorf("required field %q is missing", field.Path)
			}
		}
		if value, ok := getPath(d.Values, field.Path); ok {
			if err := validateValue(field, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func ApplyDefaults(d Draft) Draft {
	if d.Values == nil {
		d.Values = make(map[string]any)
	}
	for _, field := range d.Schema {
		if field.Default == nil {
			continue
		}
		if _, exists := getPath(d.Values, field.Path); !exists {
			setPath(d.Values, field.Path, field.Default)
		}
	}
	return d
}

func RenderEnvironment(schema []Field, values map[string]any) (string, error) {
	var out strings.Builder
	for _, field := range schema {
		if field.Environment == "" {
			continue
		}
		value, ok := getPath(values, field.Path)
		if !ok || value == nil {
			continue
		}
		encoded, err := scalarString(value)
		if field.Type == "json" {
			data, marshalErr := json.Marshal(value)
			err = marshalErr
			encoded = string(data)
		}
		if err != nil {
			return "", fmt.Errorf("render %s: %w", field.Path, err)
		}
		out.WriteString(field.Environment)
		out.WriteByte('=')
		out.WriteString(quoteEnv(encoded))
		out.WriteByte('\n')
	}
	return out.String(), nil
}

func RenderYAML(schema []Field, values map[string]any) ([]byte, error) {
	root := make(map[string]any)
	for _, field := range schema {
		path := field.YAML
		if path == "" {
			path = field.Path
		}
		if !validPath(path) {
			return nil, fmt.Errorf("field %q has invalid YAML path %q", field.Path, path)
		}
		value, ok := getPath(values, field.Path)
		if !ok {
			continue
		}
		setPath(root, path, value)
	}
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(root); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func CloneValues(values map[string]any) map[string]any {
	if values == nil {
		return map[string]any{}
	}
	data, _ := json.Marshal(values)
	var clone map[string]any
	_ = json.Unmarshal(data, &clone)
	if clone == nil {
		return map[string]any{}
	}
	return clone
}

func getPath(values map[string]any, path string) (any, bool) {
	var current any = values
	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func setPath(values map[string]any, path string, value any) {
	parts := strings.Split(path, ".")
	current := values
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok {
			next = make(map[string]any)
			current[part] = next
		}
		current = next
	}
	current[parts[len(parts)-1]] = value
}

func validPath(path string) bool {
	if path == "" {
		return false
	}
	for _, part := range strings.Split(path, ".") {
		if !identifierPattern.MatchString(part) {
			return false
		}
	}
	return true
}

func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		valid := r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9'
		if !valid {
			return false
		}
	}
	return true
}

func validateValue(field Field, value any) error {
	valid := false
	switch field.Type {
	case "string", "secret":
		_, valid = value.(string)
	case "integer":
		switch number := value.(type) {
		case float64:
			valid = number == float64(int64(number))
		case int, int32, int64:
			valid = true
		case json.Number:
			_, err := number.Int64()
			valid = err == nil
		}
	case "number":
		switch number := value.(type) {
		case float64, int, int32, int64:
			valid = true
		case json.Number:
			_, err := number.Float64()
			valid = err == nil
		}
	case "boolean":
		_, valid = value.(bool)
	case "enum":
		if text, ok := value.(string); ok {
			for _, option := range field.Options {
				if text == option {
					valid = true
					break
				}
			}
		}
	case "json":
		_, err := json.Marshal(value)
		valid = err == nil
	}
	if !valid {
		return fmt.Errorf("field %q has invalid value for type %s", field.Path, field.Type)
	}
	return nil
}

func scalarString(value any) (string, error) {
	switch typed := value.(type) {
	case string:
		return typed, nil
	case bool:
		return strconv.FormatBool(typed), nil
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64), nil
	case int:
		return strconv.Itoa(typed), nil
	case int64:
		return strconv.FormatInt(typed, 10), nil
	case json.Number:
		return typed.String(), nil
	case []any, map[string]any:
		encoded, err := json.Marshal(typed)
		return string(encoded), err
	default:
		return "", fmt.Errorf("expected scalar value, got %T", value)
	}
}

func quoteEnv(value string) string {
	if value == "" {
		return `""`
	}
	if strings.ContainsAny(value, " \t\n\r#\"'\\") || strings.HasPrefix(value, "=") {
		return strconv.Quote(value)
	}
	return value
}
