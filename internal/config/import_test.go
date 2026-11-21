package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestImportEnvironmentFile(t *testing.T) {
	draft, err := Import("env", "# local settings\nexport APP_PORT=8080\nDB_PASSWORD=\"a=b # c\" # trailing comment\nMODE='staging'\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateDraft(draft); err != nil {
		t.Fatal(err)
	}
	if len(draft.Schema) != 3 {
		t.Fatalf("imported %d fields, want 3", len(draft.Schema))
	}
	if draft.Schema[1].Type != "string" || draft.Schema[1].Sensitive {
		t.Fatalf("import must not auto-detect sensitive fields: %#v", draft.Schema[1])
	}
	if draft.Values["db_password"] != "a=b # c" || draft.Values["mode"] != "staging" {
		t.Fatalf("unexpected imported values: %#v", draft.Values)
	}
	environment, err := RenderEnvironment(draft.Schema, draft.Values)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(environment, `DB_PASSWORD="a=b # c"`) {
		t.Fatalf("unexpected rendered .env: %q", environment)
	}
}

func TestImportYAMLAndJSONPreservesNestedStructures(t *testing.T) {
	tests := []struct {
		format  string
		content string
	}{
		{
			format:  "yaml",
			content: "server:\n  port: 8080\n  enabled: true\n  tags: [blue, green]\n",
		},
		{
			format:  "json",
			content: `{"server":{"port":8080,"enabled":true,"tags":["blue","green"]}}`,
		},
	}
	for _, test := range tests {
		t.Run(test.format, func(t *testing.T) {
			draft, err := Import(test.format, test.content)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateDraft(draft); err != nil {
				t.Fatal(err)
			}
			types := make(map[string]string)
			for _, field := range draft.Schema {
				types[field.Path] = field.Type
			}
			if types["server.port"] != "integer" || types["server.enabled"] != "boolean" || types["server.tags"] != "json" {
				t.Fatalf("unexpected field types: %#v", types)
			}
			rendered, err := RenderYAML(draft.Schema, draft.Values)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if err := yaml.Unmarshal(rendered, &decoded); err != nil {
				t.Fatal(err)
			}
			server := decoded["server"].(map[string]any)
			if server["port"] != 8080 || server["enabled"] != true {
				t.Fatalf("unexpected YAML structure: %#v", decoded)
			}
			if _, ok := server["tags"].([]any); !ok {
				t.Fatalf("array value was not preserved: %#v", server["tags"])
			}
		})
	}
}

func TestImportYAMLCommentsBecomeDescriptions(t *testing.T) {
	content := "# database settings\n" +
		"server:\n" +
		"  # listening port\n" +
		"  port: 8080 # inline description\n" +
		"  enabled: true\n" +
		"token: abc\n"
	draft, err := Import("yaml", content)
	if err != nil {
		t.Fatal(err)
	}
	descriptions := make(map[string]string)
	for _, field := range draft.Schema {
		descriptions[field.Path] = field.Description
	}
	if descriptions["server.port"] != "inline description" {
		t.Fatalf("inline comment was not imported: %q", descriptions["server.port"])
	}
	if descriptions["server.enabled"] != "" {
		t.Fatalf("field without a comment got a description: %q", descriptions["server.enabled"])
	}
	if descriptions["token"] != "" {
		t.Fatalf("document-level head comment was reused for a field: %q", descriptions["token"])
	}
}

func TestImportRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name, format, content string
	}{
		{name: "unknown format", format: "toml", content: "a=1"},
		{name: "duplicate env key", format: "env", content: "A=1\nA=2"},
		{name: "invalid env key", format: "env", content: "BAD-KEY=1"},
		{name: "bad JSON", format: "json", content: `{"a":`},
		{name: "non-object YAML", format: "yaml", content: "- one\n- two"},
		{name: "multiple YAML documents", format: "yaml", content: "a: 1\n---\nb: 2"},
		{name: "invalid structured key", format: "json", content: `{"not valid":1}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Import(test.format, test.content); err == nil {
				t.Fatal("Import() unexpectedly succeeded")
			}
		})
	}
}
