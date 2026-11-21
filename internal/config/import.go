package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

func Import(format, content string) (Draft, error) {
	switch strings.ToLower(strings.TrimPrefix(format, ".")) {
	case "env":
		return importEnvironment(content)
	case "yaml", "yml":
		return importYAML(content)
	case "json":
		return importJSON(content)
	default:
		return Draft{}, fmt.Errorf("unsupported import format %q; use env, yaml, yml, or json", format)
	}
}

func importEnvironment(content string) (Draft, error) {
	draft := Draft{Values: make(map[string]any)}
	seen := make(map[string]bool)
	lines := strings.Split(content, "\n")
	for index, rawLine := range lines {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		separator := strings.IndexByte(line, '=')
		if separator < 1 {
			return Draft{}, fmt.Errorf("line %d: expected KEY=VALUE", index+1)
		}
		name := strings.TrimSpace(line[:separator])
		if !validEnvName(name) {
			return Draft{}, fmt.Errorf("line %d: invalid environment variable name %q", index+1, name)
		}
		if seen[name] {
			return Draft{}, fmt.Errorf("line %d: duplicate environment variable %q", index+1, name)
		}
		seen[name] = true
		value, err := parseEnvValue(strings.TrimSpace(line[separator+1:]))
		if err != nil {
			return Draft{}, fmt.Errorf("line %d, %s: %w", index+1, name, err)
		}
		path := strings.ToLower(name)
		if !identifierPattern.MatchString(path) {
			path = "env_" + strings.TrimLeft(path, "_")
		}
		draft.Schema = append(draft.Schema, Field{
			Path: path, Label: name, Type: "string", Environment: name,
		})
		setPath(draft.Values, path, value)
	}
	if len(draft.Schema) == 0 {
		return Draft{}, fmt.Errorf("no environment variables found")
	}
	return draft, nil
}

func importYAML(content string) (Draft, error) {
	decoder := yaml.NewDecoder(strings.NewReader(content))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return Draft{}, fmt.Errorf("parse YAML: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Draft{}, fmt.Errorf("multiple YAML documents are not supported")
		}
		return Draft{}, fmt.Errorf("parse YAML: %w", err)
	}
	if len(document.Content) == 0 {
		return Draft{}, fmt.Errorf("empty YAML document")
	}
	var value any
	if err := document.Content[0].Decode(&value); err != nil {
		return Draft{}, fmt.Errorf("parse YAML: %w", err)
	}
	descriptions := make(map[string]string)
	collectYAMLComments(&document, "", descriptions)
	return importStructured(value, descriptions)
}

// collectYAMLComments walks a YAML node tree and maps field paths to their
// nearest comment text. Line comments take precedence over head and foot
// comments because they are usually attached to the value on the same line.
func collectYAMLComments(node *yaml.Node, prefix string, out map[string]string) {
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) > 0 {
			collectYAMLComments(node.Content[0], prefix, out)
		}
		return
	}
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		keyNode, valueNode := node.Content[i], node.Content[i+1]
		path := keyNode.Value
		if prefix != "" {
			path = prefix + "." + keyNode.Value
		}
		if description := yamlFieldDescription(keyNode, valueNode); description != "" {
			out[path] = description
		}
		if valueNode.Kind == yaml.MappingNode {
			collectYAMLComments(valueNode, path, out)
		}
	}
}

func yamlFieldDescription(keyNode, valueNode *yaml.Node) string {
	candidates := make([]string, 0, 6)
	if valueNode != nil {
		candidates = append(candidates, valueNode.LineComment, valueNode.HeadComment, valueNode.FootComment)
	}
	candidates = append(candidates, keyNode.LineComment, keyNode.HeadComment, keyNode.FootComment)
	for _, candidate := range candidates {
		if description := cleanYAMLComment(candidate); description != "" {
			return description
		}
	}
	return ""
}

func cleanYAMLComment(comment string) string {
	parts := make([]string, 0, 2)
	for _, line := range strings.Split(comment, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
		if line == "" {
			continue
		}
		hasText := false
		for _, r := range line {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				hasText = true
				break
			}
		}
		if hasText {
			parts = append(parts, line)
		}
	}
	return strings.Join(parts, " ")
}

func importJSON(content string) (Draft, error) {
	decoder := json.NewDecoder(bytes.NewBufferString(content))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return Draft{}, fmt.Errorf("parse JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Draft{}, fmt.Errorf("multiple JSON values are not supported")
		}
		return Draft{}, fmt.Errorf("parse JSON: %w", err)
	}
	return importStructured(value, nil)
}

func importStructured(value any, descriptions map[string]string) (Draft, error) {
	root, ok := value.(map[string]any)
	if !ok || len(root) == 0 {
		return Draft{}, fmt.Errorf("configuration root must be a non-empty object")
	}
	draft := Draft{Values: make(map[string]any)}
	if err := flattenStructured("", root, descriptions, &draft); err != nil {
		return Draft{}, err
	}
	return draft, nil
}

func flattenStructured(prefix string, value any, descriptions map[string]string, draft *Draft) error {
	if object, ok := value.(map[string]any); ok && len(object) > 0 {
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			if strings.Contains(key, ".") || !identifierPattern.MatchString(key) || !validPath(path) {
				return fmt.Errorf("key %q cannot be represented as a field path", path)
			}
			if child, nested := object[key].(map[string]any); nested && len(child) > 0 {
				if err := flattenStructured(path, child, descriptions, draft); err != nil {
					return err
				}
				continue
			}
			appendStructuredField(path, object[key], descriptions[path], draft)
		}
		return nil
	}
	if prefix == "" {
		return fmt.Errorf("configuration root must be an object")
	}
	appendStructuredField(prefix, value, descriptions[prefix], draft)
	return nil
}

func appendStructuredField(path string, value any, description string, draft *Draft) {
	fieldType := scalarType(value)
	if number, ok := value.(json.Number); ok {
		if integer, err := number.Int64(); err == nil {
			value = integer
		} else if decimal, err := number.Float64(); err == nil {
			value = decimal
		}
	}
	field := Field{Path: path, Label: path, Type: fieldType, Description: description}
	draft.Schema = append(draft.Schema, field)
	setPath(draft.Values, path, value)
}

func scalarType(value any) string {
	switch value.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case int, int32, int64:
		return "integer"
	case float64:
		return "number"
	case json.Number:
		if number, ok := value.(json.Number); ok {
			if _, err := number.Int64(); err == nil {
				return "integer"
			}
		}
		return "number"
	case nil, []any, map[string]any:
		return "json"
	default:
		return "json"
	}
}

func parseEnvValue(value string) (string, error) {
	if len(value) > 0 && (value[0] == '"' || value[0] == '\'') {
		quote := value[0]
		end := -1
		for i := 1; i < len(value); i++ {
			if quote == '"' && value[i] == '\\' {
				i++
				continue
			}
			if value[i] == quote {
				end = i
				break
			}
		}
		if end < 0 {
			return "", fmt.Errorf("unterminated quoted value")
		}
		remainder := strings.TrimSpace(value[end+1:])
		if remainder != "" && !strings.HasPrefix(remainder, "#") {
			return "", fmt.Errorf("unexpected text after quoted value")
		}
		if quote == '"' {
			decoded, err := strconv.Unquote(value[:end+1])
			if err != nil {
				return "", fmt.Errorf("invalid double-quoted value")
			}
			return decoded, nil
		}
		return value[1:end], nil
	}
	if index := strings.Index(value, " #"); index >= 0 {
		value = strings.TrimRightFunc(value[:index], unicode.IsSpace)
	}
	return value, nil
}
