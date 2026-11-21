package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRenderEnvironmentAndYAML(t *testing.T) {
	schema := []Field{
		{Path: "http.port", Label: "HTTP 端口", Type: "integer", Environment: "APP_PORT"},
		{Path: "database.password", Label: "数据库密码", Type: "secret", Environment: "APP_DB_PASSWORD", YAML: "database.password"},
		{Path: "feature.enabled", Label: "功能开关", Type: "boolean"},
	}
	values := map[string]any{
		"http":     map[string]any{"port": float64(8080)},
		"database": map[string]any{"password": "space # and \"quote"},
		"feature":  map[string]any{"enabled": true},
	}
	if err := ValidateDraft(Draft{Schema: schema, Values: values}); err != nil {
		t.Fatalf("ValidateDraft() error = %v", err)
	}
	env, err := RenderEnvironment(schema, values)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(env, "APP_PORT=8080\n") || !strings.Contains(env, `APP_DB_PASSWORD="space # and \"quote"`) {
		t.Fatalf("unexpected environment output: %q", env)
	}
	renderedYAML, err := RenderYAML(schema, values)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		HTTP struct {
			Port int `yaml:"port"`
		} `yaml:"http"`
		Database struct {
			Password string `yaml:"password"`
		} `yaml:"database"`
		Feature struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"feature"`
	}
	if err := yaml.Unmarshal(renderedYAML, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.HTTP.Port != 8080 || decoded.Database.Password != `space # and "quote` || !decoded.Feature.Enabled {
		t.Fatalf("unexpected YAML output: %s", renderedYAML)
	}
}

func TestValidateDraftRejectsInvalidAndCollidingMappings(t *testing.T) {
	tests := []struct {
		name  string
		draft Draft
	}{
		{
			name: "duplicate environment variable",
			draft: Draft{Schema: []Field{
				{Path: "first", Label: "First", Type: "string", Environment: "APP_VALUE"},
				{Path: "second", Label: "Second", Type: "string", Environment: "APP_VALUE"},
			}},
		},
		{
			name: "required value missing",
			draft: Draft{Schema: []Field{
				{Path: "database.password", Label: "Password", Type: "secret", Required: true},
			}},
		},
		{
			name: "secret default",
			draft: Draft{Schema: []Field{
				{Path: "token", Label: "Token", Type: "secret", Default: "unsafe"},
			}},
		},
		{
			name: "invalid field type",
			draft: Draft{Schema: []Field{
				{Path: "value", Label: "Value", Type: "map"},
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateDraft(test.draft); err == nil {
				t.Fatal("ValidateDraft() unexpectedly succeeded")
			}
		})
	}
}

func TestApplyDefaultsPopulatesMissingNestedValues(t *testing.T) {
	draft := ApplyDefaults(Draft{
		Schema: []Field{
			{Path: "http.port", Label: "HTTP Port", Type: "integer", Default: 8080},
		},
	})
	if err := ValidateDraft(draft); err != nil {
		t.Fatal(err)
	}
	httpValues, ok := draft.Values["http"].(map[string]any)
	if !ok || httpValues["port"] != 8080 {
		t.Fatalf("default value was not applied: %#v", draft.Values)
	}
}
