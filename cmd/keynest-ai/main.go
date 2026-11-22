package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/shybily/keynest/internal/aitool"
)

var version = "0.3.2"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	command := os.Args[1]
	ctx := context.Background()

	switch command {
	case "help", "-h", "--help":
		usage()
	case "version":
		fmt.Println(version)
	case "list-tools":
		printTools()
	case "mcp":
		if err := aitool.RunMCP(ctx, envOr("KEYNEST_URL", "http://127.0.0.1:8080"), os.Getenv("KEYNEST_ADMIN_PASSWORD")); err != nil {
			fmt.Fprintln(os.Stderr, "MCP server error:", err)
			os.Exit(1)
		}
	default:
		if err := runTool(ctx, command, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}
}

func runTool(ctx context.Context, name string, argv []string) error {
	var tool *aitool.Tool
	for i := range aitool.Tools() {
		candidate := aitool.Tools()[i]
		if candidate.Name == name {
			tool = &candidate
			break
		}
	}
	if tool == nil {
		return fmt.Errorf("unknown tool %q; run 'keynest-ai list-tools' to see available tools", name)
	}

	args, err := parseKV(argv)
	if err != nil {
		return err
	}
	client, err := aitool.New(envOr("KEYNEST_URL", "http://127.0.0.1:8080"), os.Getenv("KEYNEST_ADMIN_PASSWORD"))
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		return err
	}
	value, err := tool.Handler(ctx, client, encoded)
	if err != nil {
		return err
	}
	fmt.Println(aitool.FormatOutput(value))
	return nil
}

// parseKV accepts key=value pairs, where value is JSON when it starts with
// [ { " or a digit, otherwise a plain string. Also accepts key:=json for an
// explicit JSON value.
func parseKV(argv []string) (map[string]any, error) {
	args := make(map[string]any)
	for _, item := range argv {
		key, raw, found := strings.Cut(item, "=")
		if !found || key == "" {
			return nil, fmt.Errorf("invalid argument %q: expected key=value", item)
		}
		forceJSON := strings.HasSuffix(key, ":")
		if forceJSON {
			key = strings.TrimSuffix(key, ":")
		}
		var value any
		if forceJSON || strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[") || strings.HasPrefix(raw, `"`) {
			if err := json.Unmarshal([]byte(raw), &value); err != nil {
				return nil, fmt.Errorf("invalid JSON for %q: %w", key, err)
			}
		} else {
			value = raw
		}
		args[key] = value
	}
	return args, nil
}

func printTools() {
	for _, tool := range aitool.Tools() {
		fmt.Printf("%-26s %s\n", tool.Name, tool.Description)
	}
}

func usage() {
	fmt.Println(`keynest-ai — 让 LLM / 脚本通过 MCP 或命令行访问 Keynest 配置中心

用法:
  keynest-ai mcp                     以 MCP stdio 服务运行（供 LLM 客户端连接）
  keynest-ai list-tools             列出所有可用工具
  keynest-ai <tool> [key=value ...]  调用某个工具
  keynest-ai help                    显示本帮助
  keynest-ai version                 显示版本

连接:
  KEYNEST_URL              Keynest 地址，默认 http://127.0.0.1:8080
  KEYNEST_ADMIN_PASSWORD   管理员密码（必需）

参数:
  key=value      普通字符串；以 { [ " 开头的值按 JSON 解析
  key:=[...]     强制按 JSON 解析，例如 schema:=[{"path":"x","type":"string"}]

示例:
  keynest-ai list_configs
  keynest-ai get_draft project=shop environment=prod service=api
  keynest-ai publish project=shop environment=prod service=api
  keynest-ai render_draft project=shop environment=prod service=api format=env`)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
