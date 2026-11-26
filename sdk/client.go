package sdk

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shybily/keynest/internal/config"
	"github.com/shybily/keynest/internal/secure"
)

type Address struct {
	Project     string
	Environment string
	Service     string
}

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

type Document struct {
	Address Address        `json:"address"`
	Schema  []Field        `json:"schema"`
	Values  map[string]any `json:"values"`
	Version int            `json:"version"`
	Updated string         `json:"updatedAt"`
}

type Options struct {
	CacheDir     string
	OnFallback   func(Address, error)
	OnCacheError func(Address, error)
	Logger       Logger
}

var ErrCenterUnavailable = errors.New("configuration center unavailable")

type Client struct {
	baseURL          string
	token            string
	privateKey       *rsa.PrivateKey
	http             *http.Client
	cacheDir         string
	onFallback       func(Address, error)
	onCacheError     func(Address, error)
	cacheMu          sync.Mutex
	fallbackMu       sync.Mutex
	fallbackReported map[string]bool
	logger           Logger
}

func New(baseURL, token string, privateKeyPEM []byte, httpClient *http.Client) (*Client, error) {
	return NewWithOptions(baseURL, token, privateKeyPEM, httpClient, Options{})
}

func NewWithOptions(baseURL, token string, privateKeyPEM []byte, httpClient *http.Client, options Options) (*Client, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid configuration center URL")
	}
	if token == "" {
		return nil, fmt.Errorf("configuration access token is required")
	}
	if len(privateKeyPEM) == 0 {
		return nil, fmt.Errorf("configuration decryption private key is required")
	}
	privateKey, err := secure.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	logger := options.Logger
	if logger == nil {
		logger = NewSlogLogger(nil)
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"), token: token,
		privateKey: privateKey, http: httpClient, cacheDir: options.CacheDir,
		onFallback: options.OnFallback, onCacheError: options.OnCacheError,
		fallbackReported: make(map[string]bool),
		logger:           logger,
	}, nil
}

func (c *Client) Fetch(ctx context.Context, address Address) (Document, error) {
	envelope, fromCache, err := c.fetchEnvelope(ctx, address, "")
	if err != nil {
		return Document{}, err
	}
	plain, err := secure.DecryptWithKey(c.privateKey, envelope, config.Address{
		Project: address.Project, Environment: address.Environment,
		Service: address.Service,
	})
	if err != nil {
		c.logger.Log(LogLevelError, "sdk_decrypt_failed", "failed to decrypt configuration response", LogFields{
			"project": address.Project, "environment": address.Environment,
			"service": address.Service,
			"error":   err,
		})
		return Document{}, fmt.Errorf("decrypt configuration response: %w", err)
	}
	var document Document
	if err := json.Unmarshal(plain, &document); err != nil {
		c.logger.Log(LogLevelError, "sdk_decode_failed", "failed to decode configuration response", LogFields{
			"project": address.Project, "environment": address.Environment,
			"service": address.Service,
			"error":   err,
		})
		return Document{}, fmt.Errorf("decode configuration response: %w", err)
	}
	if !fromCache {
		c.markAvailable(c.cacheKey(address, ""))
		c.storeEnvelope(address, "", envelope)
	}
	c.logger.Log(LogLevelDebug, "sdk_fetch_success", "configuration fetched", LogFields{
		"project": address.Project, "environment": address.Environment,
		"service": address.Service,
		"version": document.Version, "from_cache": fromCache,
	})
	return document, nil
}

func (c *Client) FetchRendered(ctx context.Context, address Address, format string) ([]byte, int, error) {
	if format != "env" && format != "yaml" {
		return nil, 0, fmt.Errorf("format must be env or yaml")
	}
	suffix := "/render/" + format
	envelope, fromCache, err := c.fetchEnvelope(ctx, address, suffix)
	if err != nil {
		return nil, 0, err
	}
	plain, err := secure.DecryptWithKey(c.privateKey, envelope, config.Address{
		Project: address.Project, Environment: address.Environment,
		Service: address.Service,
	})
	if err != nil {
		c.logger.Log(LogLevelError, "sdk_render_decrypt_failed", "failed to decrypt rendered configuration", LogFields{
			"project": address.Project, "environment": address.Environment,
			"service": address.Service,
			"format":  format,
			"error":   err,
		})
		return nil, 0, fmt.Errorf("decrypt rendered configuration: %w", err)
	}
	if !fromCache {
		c.markAvailable(c.cacheKey(address, suffix))
		c.storeEnvelope(address, suffix, envelope)
	}
	return plain, envelope.Version, nil
}

func (c *Client) fetchEnvelope(ctx context.Context, address Address, suffix string) (secure.Envelope, bool, error) {
	path := fmt.Sprintf("/api/v1/configs/%s/%s/%s%s",
		url.PathEscape(address.Project), url.PathEscape(address.Environment),
		url.PathEscape(address.Service), suffix)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return secure.Envelope{}, false, err
	}
	var cached secure.Envelope
	if c.cacheDir != "" {
		key := c.cacheKey(address, suffix)
		if envelope, readErr := c.readEnvelope(key); readErr == nil {
			cached = envelope
			request.Header.Set("If-None-Match", fmt.Sprintf(`"%d"`, envelope.Version))
		}
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			c.logger.Log(LogLevelDebug, "sdk_request_canceled", "configuration request canceled", LogFields{
				"project": address.Project, "environment": address.Environment,
				"service": address.Service,
			})
			return secure.Envelope{}, false, err
		}
		return c.fallbackEnvelope(address, suffix, fmt.Errorf("%w: %v", ErrCenterUnavailable, err))
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		if c.cacheDir == "" || cached.Version == 0 {
			return secure.Envelope{}, false, fmt.Errorf("configuration center returned 304 without a cached response")
		}
		return cached, true, nil
	}
	if response.StatusCode != http.StatusOK {
		err := fmt.Errorf("configuration center returned %s", response.Status)
		if response.StatusCode == http.StatusRequestTimeout ||
			response.StatusCode == http.StatusTooManyRequests ||
			response.StatusCode >= http.StatusInternalServerError {
			err = fmt.Errorf("%w: %s", ErrCenterUnavailable, response.Status)
			return c.fallbackEnvelope(address, suffix, err)
		}
		c.logger.Log(LogLevelWarn, "sdk_http_error", "configuration request rejected", LogFields{
			"project": address.Project, "environment": address.Environment,
			"service": address.Service,
			"status":  response.StatusCode,
		})
		return secure.Envelope{}, false, err
	}
	var envelope secure.Envelope
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return secure.Envelope{}, false, fmt.Errorf("decode encrypted configuration response: %w", err)
	}
	return envelope, false, nil
}

func (c *Client) fallbackEnvelope(address Address, suffix string, cause error) (secure.Envelope, bool, error) {
	if !errors.Is(cause, ErrCenterUnavailable) || c.cacheDir == "" {
		return secure.Envelope{}, false, cause
	}
	key := c.cacheKey(address, suffix)
	envelope, err := c.readEnvelope(key)
	if err != nil {
		return secure.Envelope{}, false, fmt.Errorf("%w; cached fallback unavailable: %v", cause, err)
	}
	c.reportFallback(key, address, cause)
	return envelope, true, nil
}

func (c *Client) cacheKey(address Address, suffix string) string {
	identity, _ := json.Marshal(struct {
		BaseURL    string
		Address    Address
		Suffix     string
		PublicKeyN string
		PublicKeyE int
	}{
		BaseURL: c.baseURL, Address: address, Suffix: suffix,
		PublicKeyN: c.privateKey.PublicKey.N.Text(16), PublicKeyE: c.privateKey.PublicKey.E,
	})
	sum := sha256.Sum256(identity)
	return hex.EncodeToString(sum[:])
}

func (c *Client) readEnvelope(key string) (secure.Envelope, error) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	data, err := os.ReadFile(filepath.Join(c.cacheDir, key+".json"))
	if err != nil {
		return secure.Envelope{}, err
	}
	var envelope secure.Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return secure.Envelope{}, fmt.Errorf("decode cached encrypted configuration: %w", err)
	}
	return envelope, nil
}

func (c *Client) storeEnvelope(address Address, suffix string, envelope secure.Envelope) {
	if c.cacheDir == "" {
		return
	}
	key := c.cacheKey(address, suffix)
	c.cacheMu.Lock()
	err := c.writeEnvelope(key, envelope)
	c.cacheMu.Unlock()
	if err != nil {
		c.reportCacheError(address, err)
	}
}

func (c *Client) writeEnvelope(key string, envelope secure.Envelope) error {
	path := filepath.Join(c.cacheDir, key+".json")
	if data, err := os.ReadFile(path); err == nil {
		var cached secure.Envelope
		if json.Unmarshal(data, &cached) == nil && cached.Version > envelope.Version {
			return nil
		}
	}
	if err := os.MkdirAll(c.cacheDir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(c.cacheDir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(c.cacheDir, ".keynest-*.tmp")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return nil
}

func (c *Client) reportFallback(key string, address Address, cause error) {
	c.fallbackMu.Lock()
	if c.fallbackReported[key] {
		c.fallbackMu.Unlock()
		return
	}
	c.fallbackReported[key] = true
	c.fallbackMu.Unlock()

	c.logger.Log(LogLevelWarn, "sdk_cache_fallback", "configuration center unavailable; using cached configuration", LogFields{
		"project": address.Project, "environment": address.Environment,
		"service": address.Service,
		"error":   cause,
	})
	if c.onFallback != nil {
		c.onFallback(address, cause)
	}
}

func (c *Client) reportCacheError(address Address, err error) {
	c.logger.Log(LogLevelError, "sdk_cache_error", "cannot persist encrypted configuration cache", LogFields{
		"project": address.Project, "environment": address.Environment,
		"service": address.Service,
		"error":   err,
	})
	if c.onCacheError != nil {
		c.onCacheError(address, err)
	}
}

func (c *Client) markAvailable(key string) {
	c.fallbackMu.Lock()
	delete(c.fallbackReported, key)
	c.fallbackMu.Unlock()
}

func (c *Client) Get(ctx context.Context, address Address, destination any) (int, error) {
	document, err := c.Fetch(ctx, address)
	if err != nil {
		return 0, err
	}
	values, err := json.Marshal(document.Values)
	if err != nil {
		return 0, err
	}
	if err := json.Unmarshal(values, destination); err != nil {
		return 0, fmt.Errorf("decode configuration values: %w", err)
	}
	return document.Version, nil
}

func (c *Client) Watch(ctx context.Context, address Address, interval time.Duration, onChange func(Document) error) error {
	if interval <= 0 {
		return fmt.Errorf("watch interval must be positive")
	}
	if onChange == nil {
		return fmt.Errorf("watch callback is required")
	}
	var lastVersion int
	fetch := func() {
		document, err := c.Fetch(ctx, address)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logger.Log(LogLevelWarn, "sdk_watch_fetch_failed", "watch fetch failed; retrying on next tick", LogFields{
				"project": address.Project, "environment": address.Environment,
				"service": address.Service, "error": err,
			})
			return
		}
		if document.Version == lastVersion {
			return
		}
		if err := onChange(document); err != nil {
			c.logger.Log(LogLevelWarn, "sdk_watch_callback_failed", "watch callback failed; retrying on next tick", LogFields{
				"project": address.Project, "environment": address.Environment,
				"service": address.Service, "version": document.Version, "error": err,
			})
			return
		}
		lastVersion = document.Version
	}
	fetch()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			fetch()
		}
	}
}
