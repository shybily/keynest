package aitool

import (
	"context"
	"encoding/json"
	"fmt"
)

// Tool is one atomic operation against the Keynest admin API. Handlers are
// shared by the MCP server and the CLI so both expose exactly the same surface.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`

	Handler func(ctx context.Context, c *Client, args json.RawMessage) (any, error) `json:"-"`
}

type addressArgs struct {
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Service     string `json:"service"`
}

func (a addressArgs) path() (string, error) {
	if a.Project == "" || a.Environment == "" || a.Service == "" {
		return "", fmt.Errorf("project, environment and service are all required")
	}
	return fmt.Sprintf("/configs/%s/%s/%s", escape(a.Project), escape(a.Environment), escape(a.Service)), nil
}

func decodeArgs(raw json.RawMessage, target any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

func schema(props map[string]any, required []string) json.RawMessage {
	document := map[string]any{
		"type":       "object",
		"properties": props,
	}
	// MCP clients validate inputSchema.required as an array; null is invalid.
	// Omit the field entirely when there are no required parameters.
	if len(required) > 0 {
		document["required"] = required
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return encoded
}

var addressProps = map[string]any{
	"project":     map[string]any{"type": "string", "description": "项目标识"},
	"environment": map[string]any{"type": "string", "description": "环境标识，如 prod"},
	"service":     map[string]any{"type": "string", "description": "服务标识"},
}

var addressRequired = []string{"project", "environment", "service"}

func mergeProps(extra map[string]any) map[string]any {
	result := make(map[string]any, len(addressProps)+len(extra))
	for key, value := range addressProps {
		result[key] = value
	}
	for key, value := range extra {
		result[key] = value
	}
	return result
}

// Tools returns the full catalog. A fresh slice is returned on each call so
// callers cannot mutate the shared definitions.
func Tools() []Tool {
	return []Tool{
		{
			Name:        "list_configs",
			Description: "列出所有服务的配置摘要（项目、环境、服务、版本、更新时间）。",
			InputSchema: schema(map[string]any{}, nil),
			Handler: func(ctx context.Context, c *Client, _ json.RawMessage) (any, error) {
				raw, err := c.Get(ctx, "/configs")
				return rawJSON(raw), err
			},
		},
		{
			Name:        "get_draft",
			Description: "读取指定服务的草稿配置，包含字段 Schema、值与敏感字段的设置状态。敏感值不会返回明文。",
			InputSchema: schema(addressProps, addressRequired),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args addressArgs
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				path, err := args.path()
				if err != nil {
					return nil, err
				}
				body, err := c.Get(ctx, path)
				return rawJSON(body), err
			},
		},
		{
			Name: "save_draft",
			Description: "保存指定服务的草稿配置。schema 与 values 为完整文档（会整体替换草稿）；" +
				"preserveSecrets 列出要沿用旧值的敏感字段路径，clearSecrets 列出要清除的敏感字段路径。" +
				"敏感字段转普通字段需先用 clearSecrets 清空，不能直接提交占位值。" +
				"草稿保存不会影响线上读取。",
			InputSchema: schema(mergeProps(map[string]any{
				"schema":          map[string]any{"type": "array", "description": "字段定义数组", "items": map[string]any{"type": "object"}},
				"values":          map[string]any{"type": "object", "description": "配置值对象，按字段路径分层"},
				"preserveSecrets": map[string]any{"type": "array", "description": "保留原值的敏感字段路径", "items": map[string]any{"type": "string"}},
				"clearSecrets":    map[string]any{"type": "array", "description": "要清除的敏感字段路径", "items": map[string]any{"type": "string"}},
			}), append(append([]string{}, addressRequired...), "schema", "values")),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					addressArgs
					Schema          []any          `json:"schema"`
					Values          map[string]any `json:"values"`
					PreserveSecrets []string       `json:"preserveSecrets"`
					ClearSecrets    []string       `json:"clearSecrets"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				path, err := args.addressArgs.path()
				if err != nil {
					return nil, err
				}
				if args.Schema == nil {
					return nil, fmt.Errorf("schema is required")
				}
				if args.Values == nil {
					args.Values = map[string]any{}
				}
				body := map[string]any{
					"schema":          args.Schema,
					"values":          args.Values,
					"preserveSecrets": args.PreserveSecrets,
					"clearSecrets":    args.ClearSecrets,
				}
				resp, err := c.Put(ctx, path, body)
				return rawJSON(resp), err
			},
		},
		{
			Name: "import_draft",
			Description: "从 .env / YAML / JSON 内容导入为草稿。format 取值：env、yaml、json。" +
				"导入不会自动识别敏感字段，所有字段默认为 string，如需保密请在导入后用 save_draft 手动标记为 secret。" +
				"YAML 的行内/上方注释会自动提取为字段说明。导入只覆盖草稿，不会自动发布。",
			InputSchema: schema(mergeProps(map[string]any{
				"format":  map[string]any{"type": "string", "description": "导入格式：env / yaml / json"},
				"content": map[string]any{"type": "string", "description": "文件原文内容"},
			}), append(append([]string{}, addressRequired...), "format", "content")),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					addressArgs
					Format  string `json:"format"`
					Content string `json:"content"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				path, err := args.addressArgs.path()
				if err != nil {
					return nil, err
				}
				resp, err := c.Post(ctx, path+"/import", map[string]string{
					"format": args.Format, "content": args.Content,
				})
				return rawJSON(resp), err
			},
		},
		{
			Name:        "publish",
			Description: "将当前草稿发布为新的不可变版本。发布会校验必填字段、类型与映射，返回新版本号。",
			InputSchema: schema(addressProps, addressRequired),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args addressArgs
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				path, err := args.path()
				if err != nil {
					return nil, err
				}
				resp, err := c.Post(ctx, path+"/publish", nil)
				return rawJSON(resp), err
			},
		},
		{
			Name:        "list_history",
			Description: "列出指定服务的已发布历史版本，敏感值不会返回明文。",
			InputSchema: schema(addressProps, addressRequired),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args addressArgs
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				path, err := args.path()
				if err != nil {
					return nil, err
				}
				resp, err := c.Get(ctx, path+"/history")
				return rawJSON(resp), err
			},
		},
		{
			Name:        "restore",
			Description: "将某个历史版本恢复为当前草稿。恢复后需再次发布才会影响线上读取。",
			InputSchema: schema(mergeProps(map[string]any{
				"version": map[string]any{"type": "integer", "description": "要恢复的版本号，至少为 1"},
			}), append(append([]string{}, addressRequired...), "version")),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					addressArgs
					Version int `json:"version"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				path, err := args.path()
				if err != nil {
					return nil, err
				}
				if args.Version < 1 {
					return nil, fmt.Errorf("version must be at least 1")
				}
				resp, err := c.Post(ctx, fmt.Sprintf("%s/history/%d/restore", path, args.Version), nil)
				return rawJSON(resp), err
			},
		},
		{
			Name:        "render_draft",
			Description: "将草稿渲染为 .env 或 YAML 文本，用于预览。format 取值：env、yaml。",
			InputSchema: schema(mergeProps(map[string]any{
				"format": map[string]any{"type": "string", "description": "渲染格式：env / yaml", "enum": []string{"env", "yaml"}},
			}), append(append([]string{}, addressRequired...), "format")),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					addressArgs
					Format string `json:"format"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				path, err := args.path()
				if err != nil {
					return nil, err
				}
				if args.Format != "env" && args.Format != "yaml" {
					return nil, fmt.Errorf("format must be env or yaml")
				}
				return c.Get(ctx, path+"/render/"+args.Format)
			},
		},
		{
			Name:        "list_resources",
			Description: "列出全部项目 → 环境 → 服务资源树，含每个服务的版本与密钥状态。",
			InputSchema: schema(map[string]any{}, nil),
			Handler: func(ctx context.Context, c *Client, _ json.RawMessage) (any, error) {
				resp, err := c.Get(ctx, "/resources")
				return rawJSON(resp), err
			},
		},
		{
			Name:        "create_project",
			Description: "创建项目。id 省略时使用 name 作为标识。",
			InputSchema: schema(map[string]any{
				"id":   map[string]any{"type": "string", "description": "项目标识，省略则用 name"},
				"name": map[string]any{"type": "string", "description": "项目名称"},
			}, []string{"name"}),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				resp, err := c.Post(ctx, "/projects", map[string]string{"id": args.ID, "name": args.Name})
				return rawJSON(resp), err
			},
		},
		{
			Name:        "delete_project",
			Description: "删除项目及其下所有环境、服务、配置与密钥。",
			InputSchema: schema(map[string]any{
				"project": map[string]any{"type": "string", "description": "项目标识"},
			}, []string{"project"}),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					Project string `json:"project"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				if args.Project == "" {
					return nil, fmt.Errorf("project is required")
				}
				return c.Delete(ctx, "/projects/"+escape(args.Project))
			},
		},
		{
			Name:        "create_environment",
			Description: "在指定项目下创建环境。",
			InputSchema: schema(map[string]any{
				"project": map[string]any{"type": "string", "description": "项目标识"},
				"name":    map[string]any{"type": "string", "description": "环境名称"},
			}, []string{"project", "name"}),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					Project string `json:"project"`
					Name    string `json:"name"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				if args.Project == "" {
					return nil, fmt.Errorf("project is required")
				}
				resp, err := c.Post(ctx, "/projects/"+escape(args.Project)+"/environments", map[string]string{"name": args.Name})
				return rawJSON(resp), err
			},
		},
		{
			Name:        "delete_environment",
			Description: "删除环境及其下所有服务、配置与密钥。",
			InputSchema: schema(map[string]any{
				"project":     map[string]any{"type": "string", "description": "项目标识"},
				"environment": map[string]any{"type": "string", "description": "环境标识"},
			}, []string{"project", "environment"}),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					Project     string `json:"project"`
					Environment string `json:"environment"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				if args.Project == "" || args.Environment == "" {
					return nil, fmt.Errorf("project and environment are required")
				}
				return c.Delete(ctx, "/projects/"+escape(args.Project)+"/environments/"+escape(args.Environment))
			},
		},
		{
			Name:        "create_service",
			Description: "创建服务并自动生成访问令牌与 RSA 密钥。令牌与密钥 ID 仅在此次响应中返回一次，请妥善保存。",
			InputSchema: schema(map[string]any{
				"project":     map[string]any{"type": "string", "description": "项目标识"},
				"environment": map[string]any{"type": "string", "description": "环境标识"},
				"name":        map[string]any{"type": "string", "description": "服务名称"},
			}, []string{"project", "environment", "name"}),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					Project     string `json:"project"`
					Environment string `json:"environment"`
					Name        string `json:"name"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				if args.Project == "" || args.Environment == "" {
					return nil, fmt.Errorf("project and environment are required")
				}
				path := "/projects/" + escape(args.Project) + "/environments/" + escape(args.Environment) + "/services"
				resp, err := c.Post(ctx, path, map[string]string{"name": args.Name})
				return rawJSON(resp), err
			},
		},
		{
			Name:        "delete_service",
			Description: "删除服务及其配置与密钥。",
			InputSchema: schema(addressProps, addressRequired),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args addressArgs
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				if _, err := args.path(); err != nil {
					return nil, err
				}
				return c.Delete(ctx, "/projects/"+escape(args.Project)+"/environments/"+escape(args.Environment)+"/services/"+escape(args.Service))
			},
		},
		{
			Name:        "delete_service_config",
			Description: "仅删除指定服务的草稿、发布版本与历史配置，保留服务与密钥。",
			InputSchema: schema(addressProps, addressRequired),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args addressArgs
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				path, err := args.path()
				if err != nil {
					return nil, err
				}
				return c.Delete(ctx, path)
			},
		},
		{
			Name:        "list_keys",
			Description: "列出全部访问凭证：所属项目/环境/服务、密钥 ID、创建时间。",
			InputSchema: schema(map[string]any{}, nil),
			Handler: func(ctx context.Context, c *Client, _ json.RawMessage) (any, error) {
				resp, err := c.Get(ctx, "/keys")
				return rawJSON(resp), err
			},
		},
		{
			Name:        "create_key",
			Description: "创建一个独立访问凭证。令牌仅在此次响应中返回一次。",
			InputSchema: schema(map[string]any{
				"name":        map[string]any{"type": "string", "description": "凭证名称"},
				"project":     map[string]any{"type": "string", "description": "授权项目"},
				"environment": map[string]any{"type": "string", "description": "授权环境"},
				"service":     map[string]any{"type": "string", "description": "授权服务"},
			}, []string{"name", "project", "environment", "service"}),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					Name        string `json:"name"`
					Project     string `json:"project"`
					Environment string `json:"environment"`
					Service     string `json:"service"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				resp, err := c.Post(ctx, "/keys", map[string]string{
					"name": args.Name, "project": args.Project,
					"environment": args.Environment, "service": args.Service,
				})
				return rawJSON(resp), err
			},
		},
		{
			Name:        "delete_key",
			Description: "吊销并删除访问凭证。",
			InputSchema: schema(map[string]any{
				"id": map[string]any{"type": "string", "description": "密钥 ID"},
			}, []string{"id"}),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					ID string `json:"id"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				if args.ID == "" {
					return nil, fmt.Errorf("id is required")
				}
				return c.Delete(ctx, "/keys/"+escape(args.ID))
			},
		},
		{
			Name:        "regenerate_key_token",
			Description: "仅重新生成指定凭证的访问令牌，密钥对保持不变。旧令牌立即失效，新令牌仅返回一次。",
			InputSchema: schema(map[string]any{
				"id": map[string]any{"type": "string", "description": "密钥 ID"},
			}, []string{"id"}),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					ID string `json:"id"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				if args.ID == "" {
					return nil, fmt.Errorf("id is required")
				}
				resp, err := c.Post(ctx, "/keys/"+escape(args.ID)+"/token/regenerate", nil)
				return rawJSON(resp), err
			},
		},
		{
			Name:        "regenerate_key_pair",
			Description: "仅重新生成指定凭证的 RSA 密钥对，令牌保持不变。旧密钥对立即失效。",
			InputSchema: schema(map[string]any{
				"id": map[string]any{"type": "string", "description": "密钥 ID"},
			}, []string{"id"}),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					ID string `json:"id"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				if args.ID == "" {
					return nil, fmt.Errorf("id is required")
				}
				resp, err := c.Post(ctx, "/keys/"+escape(args.ID)+"/pair/regenerate", nil)
				return rawJSON(resp), err
			},
		},
		{
			Name:        "download_private_key",
			Description: "下载凭证私钥 PEM 文本（application/x-pem-file）。该操作会被审计记录，请仅在必要时调用。",
			InputSchema: schema(map[string]any{
				"id": map[string]any{"type": "string", "description": "密钥 ID"},
			}, []string{"id"}),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					ID string `json:"id"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				if args.ID == "" {
					return nil, fmt.Errorf("id is required")
				}
				return c.Get(ctx, "/keys/"+escape(args.ID)+"/private-key")
			},
		},
		{
			Name:        "view_private_key",
			Description: "查看凭证私钥明文（JSON）。该操作会被审计记录，请仅在必要时调用。",
			InputSchema: schema(map[string]any{
				"id": map[string]any{"type": "string", "description": "密钥 ID"},
			}, []string{"id"}),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args struct {
					ID string `json:"id"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				if args.ID == "" {
					return nil, fmt.Errorf("id is required")
				}
				resp, err := c.Get(ctx, "/keys/"+escape(args.ID)+"/private-key/view")
				return rawJSON(resp), err
			},
		},
		{
			Name:        "regenerate_service_key",
			Description: "重新生成服务的令牌与密钥对，旧凭证立即失效。新令牌仅返回一次。",
			InputSchema: schema(addressProps, addressRequired),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args addressArgs
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				if _, err := args.path(); err != nil {
					return nil, err
				}
				path := "/projects/" + escape(args.Project) + "/environments/" + escape(args.Environment) + "/services/" + escape(args.Service) + "/key/regenerate"
				resp, err := c.Post(ctx, path, nil)
				return rawJSON(resp), err
			},
		},
		{
			Name:        "regenerate_service_token",
			Description: "仅重新生成服务的访问令牌，密钥对保持不变。新令牌仅返回一次。",
			InputSchema: schema(addressProps, addressRequired),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args addressArgs
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				if _, err := args.path(); err != nil {
					return nil, err
				}
				path := "/projects/" + escape(args.Project) + "/environments/" + escape(args.Environment) + "/services/" + escape(args.Service) + "/key/token/regenerate"
				resp, err := c.Post(ctx, path, nil)
				return rawJSON(resp), err
			},
		},
		{
			Name:        "regenerate_service_key_pair",
			Description: "仅重新生成服务的 RSA 密钥对，令牌保持不变。",
			InputSchema: schema(addressProps, addressRequired),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args addressArgs
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				if _, err := args.path(); err != nil {
					return nil, err
				}
				path := "/projects/" + escape(args.Project) + "/environments/" + escape(args.Environment) + "/services/" + escape(args.Service) + "/key/pair/regenerate"
				resp, err := c.Post(ctx, path, nil)
				return rawJSON(resp), err
			},
		},
		{
			Name:        "delete_service_key",
			Description: "删除服务的凭证，服务将无法再读取配置。",
			InputSchema: schema(addressProps, addressRequired),
			Handler: func(ctx context.Context, c *Client, raw json.RawMessage) (any, error) {
				var args addressArgs
				if err := decodeArgs(raw, &args); err != nil {
					return nil, err
				}
				if _, err := args.path(); err != nil {
					return nil, err
				}
				path := "/projects/" + escape(args.Project) + "/environments/" + escape(args.Environment) + "/services/" + escape(args.Service) + "/key"
				return c.Delete(ctx, path)
			},
		},
	}
}

// rawJSON marks a JSON response so the caller knows it is already encoded.
type rawJSON []byte
