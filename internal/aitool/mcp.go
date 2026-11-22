package aitool

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const mcpProtocolVersion = "2025-06-18"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ServeMCP runs a newline-delimited JSON-RPC 2.0 MCP server over stdio.
func ServeMCP(ctx context.Context, client *Client, in io.Reader, out io.Writer) error {
	tools := Tools()
	byName := make(map[string]Tool, len(tools))
	for _, tool := range tools {
		byName[tool.Name] = tool
	}

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	encoder := json.NewEncoder(out)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			if err := writeRPC(encoder, rpcResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error:   &rpcError{Code: -32700, Message: "parse error"},
			}); err != nil {
				return err
			}
			continue
		}
		if req.JSONRPC != "2.0" {
			if err := writeRPC(encoder, rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &rpcError{Code: -32600, Message: "invalid request: jsonrpc must be 2.0"},
			}); err != nil {
				return err
			}
			continue
		}
		// Notifications have no id and must not receive a response.
		if len(req.ID) == 0 {
			continue
		}

		var result any
		var rpcErr *rpcError
		switch req.Method {
		case "initialize":
			result = map[string]any{
				"protocolVersion": mcpProtocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
				"serverInfo":      map[string]any{"name": "keynest", "version": "0.3.2"},
			}
		case "ping":
			result = map[string]any{}
		case "tools/list":
			result = map[string]any{"tools": tools}
		case "tools/call":
			var params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			if err := json.Unmarshal(req.Params, &params); err != nil {
				rpcErr = &rpcError{Code: -32602, Message: "invalid params"}
				break
			}
			tool, ok := byName[params.Name]
			if !ok {
				result = toolResult(true, fmt.Sprintf("unknown tool: %s", params.Name))
				break
			}
			value, err := tool.Handler(ctx, client, params.Arguments)
			if err != nil {
				result = toolResult(true, err.Error())
			} else {
				result = toolResult(false, outputText(value))
			}
		default:
			rpcErr = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
		}

		response := rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rpcErr}
		if err := writeRPC(encoder, response); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func toolResult(isError bool, text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

func outputText(value any) string {
	switch typed := value.(type) {
	case nil:
		return "ok"
	case rawJSON:
		if len(typed) == 0 {
			return "ok"
		}
		return string(typed)
	case []byte:
		if len(typed) == 0 {
			return "ok"
		}
		return string(typed)
	case string:
		return typed
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Sprintf("%v", value)
		}
		return string(encoded)
	}
}

// FormatOutput renders a tool result as text for CLI or MCP transport.
func FormatOutput(value any) string {
	return outputText(value)
}

func writeRPC(encoder *json.Encoder, response rpcResponse) error {
	return encoder.Encode(response)
}

// RunMCP is the stdio entry point used by the CLI.
func RunMCP(ctx context.Context, baseURL, password string) error {
	client, err := New(baseURL, password)
	if err != nil {
		return err
	}
	return ServeMCP(ctx, client, os.Stdin, os.Stdout)
}
