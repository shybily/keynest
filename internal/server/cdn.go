package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/shybily/keynest/internal/config"
	"github.com/shybily/keynest/internal/store"
)

const cloudflareAPIBaseURL = "https://api.cloudflare.com/client/v4"

type CloudflareConfig struct {
	Enabled         bool
	APIToken        string
	ZoneID          string
	PublicURL       string
	ValidationError string
}

type CDNStatus struct {
	Configured bool   `json:"configured"`
	Enabled    bool   `json:"enabled"`
	State      string `json:"state"`
	Message    string `json:"message,omitempty"`
	Pending    int    `json:"pending"`
	LastStatus string `json:"lastStatus,omitempty"`
	LastError  string `json:"lastError,omitempty"`
	LastUpdate string `json:"lastUpdatedAt,omitempty"`
}

type cdnController struct {
	config CloudflareConfig
	store  *store.Store
	logger *slog.Logger
	client *cloudflareClient

	mu      sync.RWMutex
	status  CDNStatus
	blocked bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

type cloudflareClient struct {
	token      string
	zoneID     string
	httpClient *http.Client
	apiBaseURL string
}

type cloudflareResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Result struct {
		Status string `json:"status"`
	} `json:"result"`
}

func newCDNController(cfg CloudflareConfig, repository *store.Store, logger *slog.Logger) *cdnController {
	cfg.APIToken = strings.TrimSpace(cfg.APIToken)
	cfg.ZoneID = strings.TrimSpace(cfg.ZoneID)
	cfg.PublicURL = strings.TrimSpace(cfg.PublicURL)
	c := &cdnController{
		config: cfg,
		store:  repository,
		logger: logger,
		status: CDNStatus{Configured: cfg.Enabled, State: "disabled", Message: "Cloudflare 刷新未启用"},
	}
	if !cfg.Enabled {
		return c
	}
	if cfg.ValidationError != "" {
		c.status.Message = cfg.ValidationError
		logger.Warn("Cloudflare CDN refresh disabled by invalid configuration",
			"event", "cdn_disabled", "reason", cfg.ValidationError)
		return c
	}
	if message := validateCloudflareConfig(cfg); message != "" {
		c.status.State = "disabled"
		c.status.Message = message
		logger.Warn("Cloudflare CDN refresh disabled by invalid configuration",
			"event", "cdn_disabled", "reason", message)
		return c
	}
	c.client = &cloudflareClient{
		token:      cfg.APIToken,
		zoneID:     cfg.ZoneID,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		apiBaseURL: cloudflareAPIBaseURL,
	}
	c.status.State = "verifying"
	c.status.Message = "正在验证 Cloudflare Token 和 Zone 权限"
	return c
}

func validateCloudflareConfig(cfg CloudflareConfig) string {
	if strings.TrimSpace(cfg.APIToken) == "" {
		return "缺少 KEYNEST_CLOUDFLARE_API_TOKEN"
	}
	if strings.TrimSpace(cfg.ZoneID) == "" {
		return "缺少 KEYNEST_CLOUDFLARE_ZONE_ID"
	}
	parsed, err := url.Parse(strings.TrimSpace(cfg.PublicURL))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "KEYNEST_PUBLIC_URL 必须是有效的 HTTPS URL，且不能包含用户名、查询参数或片段"
	}
	return ""
}

func (c *cdnController) start(ctx context.Context) {
	if c.client == nil {
		return
	}
	if err := c.store.ResetProcessingCDNPurgeJobs(); err != nil {
		c.logger.Error("failed to restore interrupted CDN purge jobs",
			"event", "cdn_queue_recovery_failed", "error", err)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.run(workerCtx)
	}()
}

func (c *cdnController) stop() {
	if c.cancel != nil {
		c.cancel()
		c.wg.Wait()
	}
}

func (c *cdnController) run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	nextVerification := time.Time{}
	for {
		if !c.isEnabled() && !c.isBlocked() &&
			(nextVerification.IsZero() || !time.Now().Before(nextVerification)) {
			verifyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := c.client.verify(verifyCtx)
			cancel()
			if err != nil {
				c.setUnavailable(err)
			} else {
				c.setEnabled()
			}
			nextVerification = time.Now().Add(30 * time.Second)
		}
		if c.isEnabled() {
			if err := c.processOne(ctx); err != nil {
				c.logger.Error("failed to process CDN purge job",
					"event", "cdn_purge_worker_failed", "error", err)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *cdnController) processOne(ctx context.Context) error {
	job, err := c.store.ClaimCDNPurgeJob()
	if err != nil || job == nil {
		return err
	}
	if err := c.client.purge(ctx, job.Files); err != nil {
		nextAttempt := time.Now().Add(cdnRetryDelay(job.Attempts))
		if retryErr := c.store.RetryCDNPurgeJob(job.ID, err.Error(), nextAttempt); retryErr != nil {
			return fmt.Errorf("purge failed (%v), and retry scheduling failed: %w", err, retryErr)
		}
		var apiErr *cloudflareHTTPError
		if errors.As(err, &apiErr) && (apiErr.status == http.StatusUnauthorized || apiErr.status == http.StatusForbidden) {
			c.setUnavailable(&cloudflareValidationError{message: "Cloudflare Token 已失效或缺少清理缓存权限"})
		}
		c.logger.Warn("Cloudflare cache purge failed; retry scheduled",
			"event", "cdn_purge_retry", "job_id", job.ID, "attempt", job.Attempts, "error", err)
		return nil
	}
	if err := c.store.CompleteCDNPurgeJob(job.ID); err != nil {
		return fmt.Errorf("complete CDN purge job %d: %w", job.ID, err)
	}
	c.logger.Info("Cloudflare cache purged",
		"event", "cdn_purge_succeeded", "job_id", job.ID, "files", len(job.Files))
	return nil
}

func cdnRetryDelay(attempt int) time.Duration {
	delay := 5 * time.Second
	for i := 1; i < attempt && delay < time.Hour; i++ {
		delay *= 2
	}
	if delay > time.Hour {
		return time.Hour
	}
	return delay
}

func (c *cdnController) isEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status.Enabled
}

func (c *cdnController) isBlocked() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.blocked
}

func (c *cdnController) setEnabled() {
	c.mu.Lock()
	c.status.State = "enabled"
	c.status.Enabled = true
	c.status.Message = "Cloudflare Token 有效且目标 Zone 可访问"
	c.mu.Unlock()
	c.logger.Info("Cloudflare CDN refresh enabled", "event", "cdn_enabled")
}

func (c *cdnController) setUnavailable(err error) {
	state := "unavailable"
	message := "无法连接 Cloudflare API，已暂停 CDN 刷新并将重试校验"
	var validationErr *cloudflareValidationError
	if errors.As(err, &validationErr) {
		state = "disabled"
		message = validationErr.Error()
	} else if c.client != nil && errors.Is(err, context.DeadlineExceeded) {
		message = "Cloudflare API 校验超时，已暂停 CDN 刷新并将重试校验"
	}
	c.mu.Lock()
	c.status.State = state
	c.status.Enabled = false
	c.status.Message = message
	if state == "disabled" {
		c.blocked = true
	}
	c.mu.Unlock()
	c.logger.Warn("Cloudflare CDN refresh is unavailable",
		"event", "cdn_validation_failed", "state", state, "reason", message)
}

func (c *cdnController) snapshot() (CDNStatus, error) {
	c.mu.RLock()
	status := c.status
	c.mu.RUnlock()
	queue, err := c.store.CDNPurgeStatus()
	if err != nil {
		return status, err
	}
	status.Pending = queue.Pending
	status.LastStatus = queue.LastStatus
	status.LastError = queue.LastError
	status.LastUpdate = queue.LastUpdatedAt
	return status, nil
}

type cloudflareValidationError struct {
	message string
}

func (e *cloudflareValidationError) Error() string { return e.message }

type cloudflareHTTPError struct {
	status int
}

func (e *cloudflareHTTPError) Error() string {
	return fmt.Sprintf("Cloudflare API returned HTTP %d", e.status)
}

func (c *cloudflareClient) verify(ctx context.Context) error {
	var token cloudflareResponse
	if err := c.request(ctx, http.MethodGet, "/user/tokens/verify", nil, &token); err != nil {
		var apiErr *cloudflareHTTPError
		if errors.As(err, &apiErr) && (apiErr.status == http.StatusBadRequest || apiErr.status == http.StatusUnauthorized || apiErr.status == http.StatusForbidden) {
			return &cloudflareValidationError{message: "Cloudflare Token 无效或缺少读取验证状态的权限"}
		}
		return err
	}
	if !token.Success || token.Result.Status != "active" {
		return &cloudflareValidationError{message: "Cloudflare Token 无效或未处于 active 状态"}
	}
	var zone cloudflareResponse
	if err := c.request(ctx, http.MethodGet, "/zones/"+url.PathEscape(c.zoneID), nil, &zone); err != nil {
		var apiErr *cloudflareHTTPError
		if errors.As(err, &apiErr) && (apiErr.status == http.StatusBadRequest || apiErr.status == http.StatusUnauthorized || apiErr.status == http.StatusForbidden || apiErr.status == http.StatusNotFound) {
			return &cloudflareValidationError{message: "Cloudflare Zone 不存在或 Token 无权访问该 Zone"}
		}
		return err
	}
	if !zone.Success {
		return &cloudflareValidationError{message: "Cloudflare Zone 不存在或 Token 无权访问该 Zone"}
	}
	return nil
}

func (c *cloudflareClient) purge(ctx context.Context, files []string) error {
	payload, err := json.Marshal(struct {
		Files []string `json:"files"`
	}{Files: files})
	if err != nil {
		return err
	}
	var response cloudflareResponse
	path := "/zones/" + url.PathEscape(c.zoneID) + "/purge_cache"
	if err := c.request(ctx, http.MethodPost, path, payload, &response); err != nil {
		return err
	}
	if !response.Success {
		return errors.New("Cloudflare rejected the cache purge request")
	}
	return nil
}

func (c *cloudflareClient) request(ctx context.Context, method, path string, body []byte, target *cloudflareResponse) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.apiBaseURL+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return &cloudflareHTTPError{status: response.StatusCode}
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode Cloudflare API response: %w", err)
	}
	return nil
}

func (c *cdnController) purgeFiles(address config.Address) []string {
	base := strings.TrimRight(c.config.PublicURL, "/") + "/api/v1/configs/"
	prefix := url.PathEscape(address.Project) + "/" +
		url.PathEscape(address.Environment) + "/" + url.PathEscape(address.Service)
	return []string{
		base + prefix,
		base + prefix + "/render/env",
		base + prefix + "/render/yaml",
	}
}
