package config

import (
	"fmt"
	"regexp"
	"strings"
)

var identifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type Field struct {
	Path        string   `json:"path"`
	Label       string   `json:"label"`
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Sensitive   bool     `json:"sensitive,omitempty"`
	Environment string   `json:"environment,omitempty"`
	YAML        string   `json:"yaml,omitempty"`
	Options     []string `json:"options,omitempty"`
	Default     any      `json:"default,omitempty"`
}

type Address struct {
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Service     string `json:"service"`
}

type Document struct {
	Address Address        `json:"address"`
	Schema  []Field        `json:"schema"`
	Values  map[string]any `json:"values"`
	Version int            `json:"version"`
	Updated string         `json:"updatedAt"`
}

type Draft struct {
	Schema []Field        `json:"schema"`
	Values map[string]any `json:"values"`
}

type History struct {
	Version   int            `json:"version"`
	Schema    []Field        `json:"schema"`
	Values    map[string]any `json:"values"`
	CreatedAt string         `json:"createdAt"`
}

func (a Address) Validate() error {
	for name, value := range map[string]string{
		"project": a.Project, "environment": a.Environment,
		"service": a.Service,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%s must start with a letter or digit and contain only letters, digits, '.', '_' or '-'", name)
		}
	}
	return nil
}

func (f Field) Validate() error {
	if strings.TrimSpace(f.Label) == "" {
		return fmt.Errorf("field %q must have a label", f.Path)
	}
	switch f.Type {
	case "string", "integer", "number", "boolean", "enum", "secret", "json":
	default:
		return fmt.Errorf("field %q has unsupported type %q", f.Path, f.Type)
	}
	if f.Type == "enum" && len(f.Options) == 0 {
		return fmt.Errorf("enum field %q must define options", f.Path)
	}
	return nil
}
