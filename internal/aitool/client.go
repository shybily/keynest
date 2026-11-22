// Package aitool exposes Keynest's admin API as a thin interface for external
// LLM agents (MCP stdio server) and as a CLI. It deliberately adds no policy:
// every operation maps one-to-one to an existing admin endpoint.
package aitool

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

const (
	sessionCookie = "keynest_session"
	csrfCookie    = "keynest_csrf"
	csrfHeader    = "X-CSRF-Token"
	adminPrefix   = "/api/v1/admin"
)

// Client is a stateful admin-API client. It keeps the login session in a cookie
// jar and mirrors the CSRF cookie into a request header for unsafe methods.
type Client struct {
	baseURL  string
	origin   string
	password string
	http     *http.Client
	jar      *cookiejar.Jar
	csrf     string
	loggedIn bool
}

// New creates a client for the Keynest instance at baseURL.
func New(baseURL, password string) (*Client, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse Keynest URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("Keynest URL must use http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("Keynest URL must include a host")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	origin := &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}
	return &Client{
		baseURL:  parsed.String(),
		origin:   origin.String(),
		password: password,
		jar:      jar,
		http:     &http.Client{Jar: jar},
	}, nil
}

// Login authenticates against the admin endpoint. The Origin header is
// required by the server's same-origin check.
func (c *Client) Login(ctx context.Context) error {
	body, err := json.Marshal(map[string]string{"password": c.password})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+adminPrefix+"/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", c.origin)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, msg := readError(resp)
		return fmt.Errorf("login failed (HTTP %d): %s", resp.StatusCode, msg)
	}
	c.csrf = cookieValue(c.jar, c.baseURL, csrfCookie)
	c.loggedIn = true
	return nil
}

// Get performs a GET request and returns the raw response body.
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	return c.request(ctx, http.MethodGet, path, nil)
}

// Post performs a POST request. body may be nil.
func (c *Client) Post(ctx context.Context, path string, body any) ([]byte, error) {
	return c.request(ctx, http.MethodPost, path, body)
}

// Put performs a PUT request.
func (c *Client) Put(ctx context.Context, path string, body any) ([]byte, error) {
	return c.request(ctx, http.MethodPut, path, body)
}

// Delete performs a DELETE request.
func (c *Client) Delete(ctx context.Context, path string) ([]byte, error) {
	return c.request(ctx, http.MethodDelete, path, nil)
}

func (c *Client) request(ctx context.Context, method, path string, body any) ([]byte, error) {
	data, err := c.do(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	if !c.loggedIn {
		if err := c.Login(ctx); err != nil {
			return nil, err
		}
	}
	raw, status, err := c.send(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	// Session may have expired between calls: re-login and retry once.
	if status == http.StatusUnauthorized {
		c.loggedIn = false
		if err := c.Login(ctx); err != nil {
			return nil, err
		}
		raw, status, err = c.send(ctx, method, path, body)
		if err != nil {
			return nil, err
		}
	}
	if status < 200 || status >= 300 {
		var envelope struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			envelope.Error = strings.TrimSpace(string(raw))
		}
		message := envelope.Error
		if message == "" {
			message = http.StatusText(status)
		}
		return nil, fmt.Errorf("keynest API %s %s: HTTP %d: %s", method, path, status, message)
	}
	return raw, nil
}

func (c *Client) send(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+adminPrefix+path, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Origin", c.origin)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		req.Header.Set(csrfHeader, c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}
	return raw, resp.StatusCode, nil
}

func readError(resp *http.Response) ([]byte, string) {
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var envelope struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) == nil && envelope.Error != "" {
		return raw, envelope.Error
	}
	return raw, strings.TrimSpace(string(raw))
}

func cookieValue(jar *cookiejar.Jar, baseURL, name string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	for _, cookie := range jar.Cookies(parsed) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

func escape(value string) string {
	return url.PathEscape(value)
}
