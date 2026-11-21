package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kataras/iris/v12"
	"github.com/shybily/keynest/internal/config"
	"github.com/shybily/keynest/internal/secure"
	"github.com/shybily/keynest/internal/store"
	"github.com/shybily/keynest/web"
)

const (
	sessionCookie    = "keynest_session"
	csrfCookie       = "keynest_csrf"
	keepSecret       = "__KEYNEST_KEEP_SECRET__"
	sessionIdle      = 30 * time.Minute
	sessionAbsolute  = 12 * time.Hour
	sessionReissue   = 5 * time.Minute
	loginWindow      = 15 * time.Minute
	loginLockout     = 15 * time.Minute
	loginMaxFailures = 5
	csrfTokenHeader  = "X-CSRF-Token"
	sessionClockSkew = 2 * time.Minute
)

type Server struct {
	store          *store.Store
	adminPassword  []byte
	authSecret     []byte
	logger         *slog.Logger
	limiter        *loginLimiter
	trustedProxies []*net.IPNet
	now            func() time.Time
}

func New(repository *store.Store, adminPassword, authSecret string) *iris.Application {
	return NewWithLogger(repository, adminPassword, authSecret, slog.Default())
}

func NewWithLogger(repository *store.Store, adminPassword, authSecret string, logger *slog.Logger) *iris.Application {
	app, err := NewWithOptions(repository, adminPassword, authSecret, logger, nil)
	if err != nil {
		panic(err)
	}
	return app
}

func NewWithOptions(repository *store.Store, adminPassword, authSecret string, logger *slog.Logger, trustedProxies []string) (*iris.Application, error) {
	if logger == nil {
		logger = slog.Default()
	}
	proxies, err := parseTrustedProxies(trustedProxies)
	if err != nil {
		return nil, err
	}
	s := &Server{
		store:          repository,
		adminPassword:  []byte(adminPassword),
		authSecret:     []byte(authSecret),
		logger:         logger,
		limiter:        newLoginLimiter(),
		trustedProxies: proxies,
		now:            time.Now,
	}
	app := iris.New()
	app.Use(s.httpLogger)
	app.Use(func(ctx iris.Context) {
		ctx.Header("X-Content-Type-Options", "nosniff")
		ctx.Header("X-Frame-Options", "DENY")
		ctx.Header("Referrer-Policy", "same-origin")
		ctx.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		ctx.Header("Cross-Origin-Opener-Policy", "same-origin")
		ctx.Header("Cross-Origin-Resource-Policy", "same-origin")
		ctx.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		if strings.HasPrefix(ctx.Path(), "/api/v1/admin") {
			ctx.Header("Cache-Control", "no-store")
		}
		ctx.Next()
	})
	app.Get("/", func(ctx iris.Context) {
		data, err := web.IndexHTML()
		if err != nil {
			ctx.StopWithStatus(iris.StatusInternalServerError)
			return
		}
		ctx.ContentType("text/html; charset=utf-8")
		ctx.Header("Cache-Control", "no-store")
		_, _ = ctx.Write(data)
	})
	app.Get("/static/{file:path}", func(ctx iris.Context) {
		name := "static/" + ctx.Params().Get("file")
		data, err := web.Files.ReadFile(name)
		if err != nil {
			ctx.StopWithStatus(iris.StatusNotFound)
			return
		}
		switch {
		case strings.HasSuffix(name, ".js"):
			ctx.ContentType("application/javascript; charset=utf-8")
		case strings.HasSuffix(name, ".css"):
			ctx.ContentType("text/css; charset=utf-8")
		default:
			ctx.ContentType("application/octet-stream")
		}
		if ctx.Request().URL.Query().Get("v") != "" {
			ctx.Header("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			ctx.Header("Cache-Control", "no-cache")
		}
		_, _ = ctx.Write(data)
	})
	app.Get("/healthz", func(ctx iris.Context) {
		ctx.JSON(iris.Map{"status": "ok"})
	})

	app.Post("/api/v1/admin/login", s.login)
	app.Post("/api/v1/admin/logout", s.logout)
	admin := app.Party("/api/v1/admin", s.requireAdmin)
	admin.Use(s.csrfProtect)
	admin.Get("/configs", s.listConfigs)
	admin.Get("/configs/{project}/{environment}/{service}", s.getDraft)
	admin.Put("/configs/{project}/{environment}/{service}", s.saveDraft)
	admin.Post("/configs/{project}/{environment}/{service}/import", s.importDraft)
	admin.Post("/configs/{project}/{environment}/{service}/publish", s.publish)
	admin.Get("/configs/{project}/{environment}/{service}/history", s.history)
	admin.Post("/configs/{project}/{environment}/{service}/history/{version:int}/restore", s.restore)
	admin.Get("/configs/{project}/{environment}/{service}/render/{format}", s.render)
	admin.Get("/resources", s.listResources)
	admin.Post("/projects", s.createProject)
	admin.Delete("/projects/{project}", s.deleteProject)
	admin.Post("/projects/{project}/environments", s.createEnvironment)
	admin.Delete("/projects/{project}/environments/{environment}", s.deleteEnvironment)
	admin.Post("/projects/{project}/environments/{environment}/services", s.createService)
	admin.Delete("/projects/{project}/environments/{environment}/services/{service}", s.deleteService)
	admin.Post("/projects/{project}/environments/{environment}/services/{service}/key/regenerate", s.regenerateServiceKey)
	admin.Delete("/projects/{project}/environments/{environment}/services/{service}/key", s.deleteServiceKey)
	admin.Delete("/configs/{project}/{environment}/{service}", s.deleteServiceConfig)
	admin.Get("/keys", s.listKeys)
	admin.Post("/keys", s.createKey)
	admin.Get("/keys/{id}/private-key", s.downloadPrivateKey)
	admin.Delete("/keys/{id}", s.deleteKey)

	app.Get("/api/v1/configs/{project}/{environment}/{service}", s.getPublished)
	app.Get("/api/v1/configs/{project}/{environment}/{service}/render/{format}", s.renderPublished)
	return app, nil
}

func (s *Server) login(ctx iris.Context) {
	if !s.sameOrigin(ctx) {
		writeError(ctx, iris.StatusForbidden, "request origin is not allowed")
		return
	}
	ip := s.clientIP(ctx)
	now := s.now()
	if wait, locked := s.limiter.locked(ip, now); locked {
		ctx.Header("Retry-After", retryAfter(wait))
		s.logger.Warn("admin login rate limited", "event", "login_rate_limited", "remote_ip", ip)
		writeError(ctx, iris.StatusTooManyRequests, "too many login attempts; try again later")
		return
	}
	var request struct {
		Password string `json:"password"`
	}
	if err := ctx.ReadJSON(&request); err != nil {
		s.logger.Warn("admin login rejected", "event", "login_failed", "reason", "invalid_json", "remote_ip", ip)
		writeError(ctx, iris.StatusBadRequest, "invalid JSON body")
		return
	}
	if subtle.ConstantTimeCompare([]byte(request.Password), s.adminPassword) != 1 {
		wait, locked := s.limiter.fail(ip, now)
		s.logger.Warn("admin login rejected", "event", "login_failed", "reason", "invalid_credentials", "remote_ip", ip)
		if locked {
			ctx.Header("Retry-After", retryAfter(wait))
			writeError(ctx, iris.StatusTooManyRequests, "too many login attempts; try again later")
			return
		}
		writeError(ctx, iris.StatusUnauthorized, "invalid credentials")
		return
	}
	s.limiter.success(ip)
	s.setSessionCookie(ctx, s.newSession(now), sessionAbsolute)
	s.ensureCSRFCookie(ctx)
	s.logger.Info("admin login succeeded", "event", "login_success", "remote_ip", ip)
	ctx.JSON(iris.Map{"ok": true})
}

func (s *Server) logout(ctx iris.Context) {
	if !s.sameOrigin(ctx) {
		writeError(ctx, iris.StatusForbidden, "request origin is not allowed")
		return
	}
	s.clearCookie(ctx, sessionCookie)
	s.clearCookie(ctx, csrfCookie)
	s.logger.Info("admin logout succeeded", "event", "logout")
	ctx.JSON(iris.Map{"ok": true})
}

func (s *Server) requireAdmin(ctx iris.Context) {
	cookie, err := ctx.Request().Cookie(sessionCookie)
	now := s.now()
	state, ok := s.readSession(cookie, now)
	if err != nil || !ok {
		s.clearCookie(ctx, sessionCookie)
		writeError(ctx, iris.StatusUnauthorized, "authentication required")
		return
	}
	if !s.sessionValid(state, now) {
		s.clearCookie(ctx, sessionCookie)
		s.clearCookie(ctx, csrfCookie)
		writeError(ctx, iris.StatusUnauthorized, "session expired")
		return
	}
	if now.Sub(state.lastSeen) > sessionReissue {
		remaining := state.issued.Add(sessionAbsolute).Sub(now)
		s.setSessionCookie(ctx, s.sessionToken(state.issued.Unix(), now.Unix(), state.nonce), remaining)
	}
	ctx.Values().Set("actor", "admin")
	ctx.Next()
}

func (s *Server) sessionValid(state sessionState, now time.Time) bool {
	return now.Sub(state.issued) <= sessionAbsolute && now.Sub(state.lastSeen) <= sessionIdle
}

func (s *Server) csrfProtect(ctx iris.Context) {
	if isSafeMethod(ctx.Method()) {
		s.ensureCSRFCookie(ctx)
		ctx.Next()
		return
	}
	if !s.sameOrigin(ctx) {
		writeError(ctx, iris.StatusForbidden, "request origin is not allowed")
		return
	}
	cookie, err := ctx.Request().Cookie(csrfCookie)
	header := ctx.GetHeader(csrfTokenHeader)
	if err != nil || header == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
		writeError(ctx, iris.StatusForbidden, "CSRF token is missing or invalid")
		return
	}
	ctx.Next()
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func (s *Server) sameOrigin(ctx iris.Context) bool {
	request := ctx.Request()
	reference := request.Header.Get("Origin")
	if reference == "" {
		reference = request.Header.Get("Referer")
	}
	if reference == "" {
		return false
	}
	parsed, err := url.Parse(reference)
	if err != nil || parsed.Host == "" {
		return false
	}
	expected := request.Host
	if s.isTrustedProxy(remoteHost(request.RemoteAddr)) {
		if forwarded := request.Header.Get("X-Forwarded-Host"); forwarded != "" {
			expected = strings.TrimSpace(strings.Split(forwarded, ",")[0])
		}
	}
	return strings.EqualFold(parsed.Host, expected)
}

func (s *Server) ensureCSRFCookie(ctx iris.Context) {
	if cookie, err := ctx.Request().Cookie(csrfCookie); err == nil && len(cookie.Value) >= 32 {
		return
	}
	http.SetCookie(ctx.ResponseWriter(), &http.Cookie{
		Name: csrfCookie, Value: randomToken(), Path: "/", HttpOnly: false,
		SameSite: http.SameSiteStrictMode, Secure: s.isSecure(ctx),
		Expires: s.now().Add(sessionAbsolute), MaxAge: int(sessionAbsolute.Seconds()),
	})
}

func (s *Server) setSessionCookie(ctx iris.Context, token string, maxAge time.Duration) {
	http.SetCookie(ctx.ResponseWriter(), &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: s.isSecure(ctx),
		Expires: s.now().Add(maxAge), MaxAge: int(maxAge.Seconds()),
	})
}

func (s *Server) clearCookie(ctx iris.Context, name string) {
	http.SetCookie(ctx.ResponseWriter(), &http.Cookie{
		Name: name, Value: "", Path: "/", HttpOnly: name == sessionCookie,
		SameSite: http.SameSiteStrictMode, Secure: s.isSecure(ctx),
		MaxAge: -1, Expires: time.Unix(1, 0),
	})
}

func (s *Server) isSecure(ctx iris.Context) bool {
	if ctx.Request().TLS != nil {
		return true
	}
	if s.isTrustedProxy(remoteHost(ctx.Request().RemoteAddr)) {
		return strings.EqualFold(strings.TrimSpace(strings.Split(ctx.GetHeader("X-Forwarded-Proto"), ",")[0]), "https")
	}
	return false
}

func (s *Server) clientIP(ctx iris.Context) string {
	return s.clientIPFromRequest(ctx.Request())
}

func (s *Server) clientIPFromRequest(request *http.Request) string {
	remote := remoteHost(request.RemoteAddr)
	if !s.isTrustedProxy(remote) {
		return remote
	}
	forwarded := request.Header.Get("X-Forwarded-For")
	parts := strings.Split(forwarded, ",")
	for index := len(parts) - 1; index >= 0; index-- {
		candidate := strings.TrimSpace(parts[index])
		if net.ParseIP(candidate) == nil {
			continue
		}
		if s.isTrustedProxy(candidate) {
			continue
		}
		return candidate
	}
	return remote
}

func (s *Server) isTrustedProxy(value string) bool {
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	for _, network := range s.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func remoteHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

func parseTrustedProxies(values []string) ([]*net.IPNet, error) {
	var result []*net.IPNet
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if strings.Contains(item, "/") {
				_, network, err := net.ParseCIDR(item)
				if err != nil {
					return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", item, err)
				}
				result = append(result, network)
				continue
			}
			ip := net.ParseIP(item)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted proxy IP %q", item)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			result = append(result, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return result, nil
}

func (s *Server) listConfigs(ctx iris.Context) {
	items, err := s.store.List()
	if err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	ctx.JSON(items)
}

func (s *Server) getDraft(ctx iris.Context) {
	address, ok := readAddress(ctx)
	if !ok {
		return
	}
	draft, version, updated, err := s.store.GetDraft(address)
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	values, secretSet := redactSecrets(draft.Schema, draft.Values)
	ctx.JSON(iris.Map{
		"address": address, "schema": draft.Schema, "values": values,
		"secretSet": secretSet, "version": version, "updatedAt": updated,
	})
}

func (s *Server) saveDraft(ctx iris.Context) {
	address, ok := readAddress(ctx)
	if !ok {
		return
	}
	var request struct {
		config.Draft
		PreserveSecrets []string `json:"preserveSecrets"`
		ClearSecrets    []string `json:"clearSecrets"`
	}
	if err := ctx.ReadJSON(&request); err != nil {
		writeError(ctx, iris.StatusBadRequest, "invalid JSON body")
		return
	}
	if request.Values == nil {
		request.Values = map[string]any{}
	}
	sensitive := make(map[string]bool, len(request.Schema))
	for _, field := range request.Schema {
		if isSensitiveField(field) {
			sensitive[field.Path] = true
		}
	}
	preserve := make(map[string]bool, len(request.PreserveSecrets))
	for _, path := range request.PreserveSecrets {
		if !sensitive[path] {
			writeError(ctx, iris.StatusBadRequest, "preserveSecrets contains a field that is not sensitive")
			return
		}
		preserve[path] = true
	}
	clear := make(map[string]bool, len(request.ClearSecrets))
	for _, path := range request.ClearSecrets {
		if !sensitive[path] {
			writeError(ctx, iris.StatusBadRequest, "clearSecrets contains a field that is not sensitive")
			return
		}
		if preserve[path] {
			writeError(ctx, iris.StatusBadRequest, "a field cannot be both preserved and cleared")
			return
		}
		clear[path] = true
	}
	previousValues := map[string]any{}
	previousFound := false
	if previous, _, _, err := s.store.GetDraft(address); err == nil {
		previousValues = previous.Values
		previousFound = true
	} else if !errors.Is(err, sql.ErrNoRows) {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	for path := range preserve {
		if previousFound {
			if value, exists := getValue(previousValues, path); exists {
				setValue(request.Values, path, value)
				continue
			}
		}
		setValue(request.Values, path, "")
	}
	for path := range clear {
		deleteValue(request.Values, path)
	}
	for path := range sensitive {
		if value, ok := getValue(request.Values, path); ok {
			if text, ok := value.(string); ok && text == keepSecret {
				writeError(ctx, iris.StatusBadRequest, "reserved secret placeholder submitted without preserveSecrets")
				return
			}
		}
	}
	request.Draft = config.ApplyDefaults(request.Draft)
	if err := config.ValidateDraft(request.Draft); err != nil {
		writeError(ctx, iris.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.SaveDraft(address, request.Draft); err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	details := ""
	if len(preserve) > 0 || len(clear) > 0 {
		details = fmt.Sprintf("preserved=%d cleared=%d", len(preserve), len(clear))
	}
	if err := s.store.Audit("admin", "save-draft", address, details); err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	s.logBusiness("draft_saved", "draft saved", address)
	ctx.JSON(iris.Map{"ok": true})
}

func (s *Server) importDraft(ctx iris.Context) {
	address, ok := readAddress(ctx)
	if !ok {
		return
	}
	const maxImportBytes = 2 << 20
	body, err := io.ReadAll(http.MaxBytesReader(ctx.ResponseWriter(), ctx.Request().Body, maxImportBytes))
	if err != nil {
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			writeError(ctx, iris.StatusRequestEntityTooLarge, "import file exceeds 2 MiB limit")
			return
		}
		writeError(ctx, iris.StatusBadRequest, "could not read import body")
		return
	}
	var request struct {
		Format  string `json:"format"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		writeError(ctx, iris.StatusBadRequest, "invalid JSON body")
		return
	}
	draft, err := config.Import(request.Format, request.Content)
	if err != nil {
		writeError(ctx, iris.StatusBadRequest, err.Error())
		return
	}
	draft = config.ApplyDefaults(draft)
	if err := config.ValidateDraft(draft); err != nil {
		writeError(ctx, iris.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.SaveDraft(address, draft); err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.Audit("admin", "import-draft", address, strings.ToLower(request.Format)); err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	s.logBusiness("draft_imported", "draft imported", address, slog.String("format", strings.ToLower(request.Format)), slog.Int("fields", len(draft.Schema)))
	ctx.JSON(iris.Map{"ok": true, "fields": len(draft.Schema)})
}

func (s *Server) publish(ctx iris.Context) {
	address, ok := readAddress(ctx)
	if !ok {
		return
	}
	draft, _, _, err := s.store.GetDraft(address)
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	if err := config.ValidateDraft(draft); err != nil {
		writeError(ctx, iris.StatusBadRequest, err.Error())
		return
	}
	if len(draft.Schema) == 0 {
		writeError(ctx, iris.StatusBadRequest, "at least one schema field is required")
		return
	}
	version, err := s.store.Publish(address, "admin")
	if err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	s.logBusiness("config_published", "configuration published", address, slog.Int("version", version))
	ctx.JSON(iris.Map{"ok": true, "version": version})
}

func (s *Server) history(ctx iris.Context) {
	address, ok := readAddress(ctx)
	if !ok {
		return
	}
	items, err := s.store.History(address)
	if err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	for i := range items {
		items[i].Values, _ = redactSecrets(items[i].Schema, items[i].Values)
	}
	ctx.JSON(items)
}

func (s *Server) restore(ctx iris.Context) {
	address, ok := readAddress(ctx)
	if !ok {
		return
	}
	version, err := strconv.Atoi(ctx.Params().Get("version"))
	if err != nil || version < 1 {
		writeError(ctx, iris.StatusBadRequest, "invalid version")
		return
	}
	if err := s.store.Restore(address, version, "admin"); err != nil {
		writeStoreError(ctx, err)
		return
	}
	s.logBusiness("draft_restored", "draft restored", address, slog.Int("source_version", version))
	ctx.JSON(iris.Map{"ok": true})
}

func (s *Server) render(ctx iris.Context) {
	address, ok := readAddress(ctx)
	if !ok {
		return
	}
	draft, _, _, err := s.store.GetDraft(address)
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	if err := config.ValidateDraft(draft); err != nil {
		writeError(ctx, iris.StatusBadRequest, err.Error())
		return
	}
	var data []byte
	switch ctx.Params().Get("format") {
	case "env":
		text, err := config.RenderEnvironment(draft.Schema, draft.Values)
		if err != nil {
			writeError(ctx, iris.StatusBadRequest, err.Error())
			return
		}
		data = []byte(text)
		ctx.ContentType("text/plain; charset=utf-8")
	case "yaml":
		data, err = config.RenderYAML(draft.Schema, draft.Values)
		if err != nil {
			writeError(ctx, iris.StatusBadRequest, err.Error())
			return
		}
		ctx.ContentType("application/yaml; charset=utf-8")
	default:
		writeError(ctx, iris.StatusBadRequest, "format must be env or yaml")
		return
	}
	ctx.Header("Cache-Control", "no-store")
	_, _ = ctx.Write(data)
}

func (s *Server) getPublished(ctx iris.Context) {
	address, ok := readAddress(ctx)
	if !ok {
		return
	}
	credential, authorized := s.authorizeRead(ctx, address)
	if !authorized {
		return
	}
	document, err := s.store.GetPublished(address)
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	etag := fmt.Sprintf(`"%d"`, document.Version)
	ctx.Header("ETag", etag)
	ctx.Header("Cache-Control", "no-store")
	if ctx.GetHeader("If-None-Match") == etag {
		ctx.StatusCode(iris.StatusNotModified)
		return
	}
	plain, err := json.Marshal(document)
	if err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	envelope, err := secure.Encrypt(credential.PublicKey, credential.ID, address, document.Version, plain)
	if err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	ctx.JSON(envelope)
}

func (s *Server) renderPublished(ctx iris.Context) {
	address, ok := readAddress(ctx)
	if !ok {
		return
	}
	credential, authorized := s.authorizeRead(ctx, address)
	if !authorized {
		return
	}
	document, err := s.store.GetPublished(address)
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	ctx.Header("ETag", fmt.Sprintf(`"%d"`, document.Version))
	ctx.Header("Cache-Control", "no-store")
	var data []byte
	switch ctx.Params().Get("format") {
	case "env":
		text, err := config.RenderEnvironment(document.Schema, document.Values)
		if err != nil {
			writeError(ctx, iris.StatusInternalServerError, err.Error())
			return
		}
		data = []byte(text)
	case "yaml":
		data, err = config.RenderYAML(document.Schema, document.Values)
		if err != nil {
			writeError(ctx, iris.StatusInternalServerError, err.Error())
			return
		}
	default:
		writeError(ctx, iris.StatusBadRequest, "format must be env or yaml")
		return
	}
	envelope, err := secure.Encrypt(credential.PublicKey, credential.ID, address, document.Version, data)
	if err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	ctx.JSON(envelope)
}

func (s *Server) authorizeRead(ctx iris.Context, address config.Address) (store.ReadCredential, bool) {
	header := ctx.GetHeader("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		writeError(ctx, iris.StatusUnauthorized, "bearer token required")
		return store.ReadCredential{}, false
	}
	key := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if key == "" {
		writeError(ctx, iris.StatusUnauthorized, "bearer token required")
		return store.ReadCredential{}, false
	}
	hash := sha256.Sum256([]byte(key))
	credential, authorized, err := s.store.AuthenticateKey(hex.EncodeToString(hash[:]), address.Project, address.Environment, address.Service)
	if err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return store.ReadCredential{}, false
	}
	if !authorized {
		writeError(ctx, iris.StatusForbidden, "credential is not authorized for this service")
		return store.ReadCredential{}, false
	}
	if len(credential.PublicKey) == 0 {
		writeError(ctx, iris.StatusForbidden, "credential has no encryption key; create a replacement credential")
		return store.ReadCredential{}, false
	}
	return credential, true
}

func (s *Server) listResources(ctx iris.Context) {
	resources, err := s.store.ListResources()
	if err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	ctx.JSON(iris.Map{"projects": resources})
}

func (s *Server) createProject(ctx iris.Context) {
	var request struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := ctx.ReadJSON(&request); err != nil {
		writeError(ctx, iris.StatusBadRequest, "invalid JSON body")
		return
	}
	if request.ID == "" {
		request.ID = request.Name
	}
	if err := (config.Address{Project: request.ID, Environment: "env", Service: "service"}).Validate(); err != nil {
		writeError(ctx, iris.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateProject(request.ID, request.Name); err != nil {
		writeError(ctx, iris.StatusConflict, err.Error())
		return
	}
	s.logger.Info("project created", "event", "project_created", "project", request.ID)
	ctx.StatusCode(iris.StatusCreated)
	ctx.JSON(store.Project{ID: request.ID, Name: request.Name})
}

func (s *Server) deleteProject(ctx iris.Context) {
	project := ctx.Params().Get("project")
	if err := s.store.DeleteProject(project, "admin"); err != nil {
		writeStoreError(ctx, err)
		return
	}
	s.logger.Info("project deleted", "event", "project_deleted", "project", project)
	ctx.StatusCode(iris.StatusNoContent)
}

func (s *Server) createEnvironment(ctx iris.Context) {
	project := ctx.Params().Get("project")
	var request struct {
		Name string `json:"name"`
	}
	if err := ctx.ReadJSON(&request); err != nil {
		writeError(ctx, iris.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := (config.Address{Project: project, Environment: request.Name, Service: "service"}).Validate(); err != nil {
		writeError(ctx, iris.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateEnvironment(project, request.Name); err != nil {
		writeError(ctx, iris.StatusConflict, err.Error())
		return
	}
	address := config.Address{Project: project, Environment: request.Name}
	if err := s.store.Audit("admin", "create-environment", address, ""); err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	s.logger.Info("environment created", "event", "environment_created",
		"project", project, "environment", request.Name)
	ctx.StatusCode(iris.StatusCreated)
	ctx.JSON(iris.Map{"ok": true, "environment": request.Name})
}

func (s *Server) deleteEnvironment(ctx iris.Context) {
	project, environment := ctx.Params().Get("project"), ctx.Params().Get("environment")
	if err := s.store.DeleteEnvironment(project, environment, "admin"); err != nil {
		writeStoreError(ctx, err)
		return
	}
	s.logger.Info("environment deleted", "event", "environment_deleted",
		"project", project, "environment", environment)
	ctx.StatusCode(iris.StatusNoContent)
}

func (s *Server) createService(ctx iris.Context) {
	project, environment := ctx.Params().Get("project"), ctx.Params().Get("environment")
	var request struct {
		Name string `json:"name"`
	}
	if err := ctx.ReadJSON(&request); err != nil {
		writeError(ctx, iris.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := (config.Address{Project: project, Environment: environment, Service: request.Name}).Validate(); err != nil {
		writeError(ctx, iris.StatusBadRequest, err.Error())
		return
	}
	key, token, privatePEM, publicPEM, err := s.generateServiceKey(project, environment, request.Name)
	if err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	digest := sha256.Sum256([]byte(token))
	if err := s.store.CreateServiceWithKey(project, environment, request.Name, key,
		hex.EncodeToString(digest[:]), string(publicPEM), string(privatePEM)); err != nil {
		writeError(ctx, iris.StatusConflict, err.Error())
		return
	}
	if err := s.store.Audit("admin", "create-service",
		config.Address{Project: project, Environment: environment, Service: request.Name}, key.ID); err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	s.logger.Info("service created", "event", "service_created",
		"project", project, "environment", environment, "service", request.Name, "key_id", key.ID)
	ctx.StatusCode(iris.StatusCreated)
	ctx.JSON(iris.Map{"ok": true, "service": request.Name, "key": key, "token": token})
}

func (s *Server) deleteService(ctx iris.Context) {
	project, environment, service := ctx.Params().Get("project"), ctx.Params().Get("environment"), ctx.Params().Get("service")
	if err := s.store.DeleteService(project, environment, service, "admin"); err != nil {
		writeStoreError(ctx, err)
		return
	}
	s.logger.Info("service deleted", "event", "service_deleted",
		"project", project, "environment", environment, "service", service)
	ctx.StatusCode(iris.StatusNoContent)
}

func (s *Server) regenerateServiceKey(ctx iris.Context) {
	project, environment, service := ctx.Params().Get("project"), ctx.Params().Get("environment"), ctx.Params().Get("service")
	key, token, privatePEM, publicPEM, err := s.generateServiceKey(project, environment, service)
	if err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	digest := sha256.Sum256([]byte(token))
	if err := s.store.ReplaceServiceKey(project, environment, service, key,
		hex.EncodeToString(digest[:]), string(publicPEM), string(privatePEM)); err != nil {
		writeStoreError(ctx, err)
		return
	}
	if err := s.store.Audit("admin", "regenerate-key",
		config.Address{Project: project, Environment: environment, Service: service}, key.ID); err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	s.logger.Info("service key regenerated", "event", "service_key_regenerated",
		"project", project, "environment", environment, "service", service, "key_id", key.ID)
	ctx.JSON(iris.Map{"key": key, "token": token})
}

func (s *Server) deleteServiceKey(ctx iris.Context) {
	project, environment, service := ctx.Params().Get("project"), ctx.Params().Get("environment"), ctx.Params().Get("service")
	if err := s.store.DeleteServiceKey(project, environment, service); err != nil {
		writeStoreError(ctx, err)
		return
	}
	if err := s.store.Audit("admin", "delete-key",
		config.Address{Project: project, Environment: environment, Service: service}, ""); err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	s.logger.Info("service key deleted", "event", "service_key_deleted",
		"project", project, "environment", environment, "service", service)
	ctx.StatusCode(iris.StatusNoContent)
}

func (s *Server) deleteServiceConfig(ctx iris.Context) {
	address, ok := readAddress(ctx)
	if !ok {
		return
	}
	if err := s.store.DeleteEnvironmentConfig(address, "admin"); err != nil {
		writeStoreError(ctx, err)
		return
	}
	s.logger.Info("service configuration deleted", "event", "service_config_deleted",
		"project", address.Project, "environment", address.Environment,
		"service", address.Service)
	ctx.StatusCode(iris.StatusNoContent)
}

func (s *Server) generateServiceKey(project, environment, service string) (store.AccessKey, string, []byte, []byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return store.AccessKey{}, "", nil, nil, err
	}
	token := "cm_" + base64.RawURLEncoding.EncodeToString(random)
	privatePEM, publicPEM, err := secure.GenerateKeyPair(3072)
	if err != nil {
		return store.AccessKey{}, "", nil, nil, err
	}
	key := store.AccessKey{
		ID:          fmt.Sprintf("%x", random[:8]),
		Name:        service + "/" + environment,
		Project:     project,
		Environment: environment,
		Service:     service,
		CreatedAt:   s.now().UTC().Format(time.RFC3339Nano),
	}
	return key, token, privatePEM, publicPEM, nil
}

func (s *Server) listKeys(ctx iris.Context) {
	keys, err := s.store.ListKeys()
	if err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	ctx.JSON(keys)
}

func (s *Server) createKey(ctx iris.Context) {
	var key store.AccessKey
	if err := ctx.ReadJSON(&key); err != nil {
		writeError(ctx, iris.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(key.Name) == "" {
		writeError(ctx, iris.StatusBadRequest, "name is required")
		return
	}
	if err := (config.Address{
		Project: key.Project, Environment: key.Environment,
		Service: key.Service,
	}).Validate(); err != nil {
		writeError(ctx, iris.StatusBadRequest, err.Error())
		return
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	plain := "cm_" + base64.RawURLEncoding.EncodeToString(random)
	digest := sha256.Sum256([]byte(plain))
	privatePEM, publicPEM, err := secure.GenerateKeyPair(3072)
	if err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	key.ID = fmt.Sprintf("%x", random[:8])
	key.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.store.CreateKey(key, hex.EncodeToString(digest[:]), string(publicPEM), string(privatePEM)); err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.Audit("admin", "create-key", config.Address{
		Project: key.Project, Environment: key.Environment, Service: key.Service,
	}, key.ID); err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	s.logger.Info("access key created", "event", "key_created",
		"project", key.Project, "environment", key.Environment, "service", key.Service, "key_id", key.ID)
	ctx.StatusCode(iris.StatusCreated)
	ctx.JSON(iris.Map{"key": key, "token": plain})
}

func (s *Server) downloadPrivateKey(ctx iris.Context) {
	id := ctx.Params().Get("id")
	privateKey, err := s.store.PrivateKey(id)
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	if err := s.store.Audit("admin", "download-private-key", config.Address{}, id); err != nil {
		writeError(ctx, iris.StatusInternalServerError, err.Error())
		return
	}
	s.logger.Info("private key downloaded", "event", "private_key_downloaded", "key_id", id)
	ctx.ContentType("application/x-pem-file")
	ctx.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="keynest-%s-private.pem"`, id))
	ctx.Header("Cache-Control", "no-store")
	_, _ = ctx.Write([]byte(privateKey))
}

func (s *Server) deleteKey(ctx iris.Context) {
	id := ctx.Params().Get("id")
	if err := s.store.DeleteKey(id, "admin"); err != nil {
		writeStoreError(ctx, err)
		return
	}
	s.logger.Info("access key revoked", "event", "key_revoked", "key_id", id)
	ctx.JSON(iris.Map{"ok": true})
}

type sessionState struct {
	issued   time.Time
	lastSeen time.Time
	nonce    string
}

func (s *Server) newSession(now time.Time) string {
	return s.sessionToken(now.Unix(), now.Unix(), randomToken())
}

func (s *Server) sessionToken(issued, lastSeen int64, nonce string) string {
	value := fmt.Sprintf("v2.%d.%d.%s", issued, lastSeen, nonce)
	return value + "." + s.sign(value)
}

func (s *Server) readSession(cookie *http.Cookie, now time.Time) (sessionState, bool) {
	if cookie == nil {
		return sessionState{}, false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 5 || parts[0] != "v2" || len(parts[3]) < 16 {
		return sessionState{}, false
	}
	issuedUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return sessionState{}, false
	}
	lastSeenUnix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return sessionState{}, false
	}
	value := strings.Join(parts[:4], ".")
	if subtle.ConstantTimeCompare([]byte(parts[4]), []byte(s.sign(value))) != 1 {
		return sessionState{}, false
	}
	issued := time.Unix(issuedUnix, 0)
	lastSeen := time.Unix(lastSeenUnix, 0)
	if lastSeen.Before(issued) || issued.After(now.Add(sessionClockSkew)) || lastSeen.After(now.Add(sessionClockSkew)) {
		return sessionState{}, false
	}
	return sessionState{issued: issued, lastSeen: lastSeen, nonce: parts[3]}, true
}

func (s *Server) sign(value string) string {
	h := hmacSHA256(s.authSecret, []byte(value))
	return hex.EncodeToString(h)
}

func hmacSHA256(secret, value []byte) []byte {
	h := hmac.New(sha256.New, secret)
	_, _ = h.Write(value)
	return h.Sum(nil)
}

func randomToken() string {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		panic("secure random source unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(random)
}

func retryAfter(wait time.Duration) string {
	seconds := int64((wait + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.FormatInt(seconds, 10)
}

type loginEntry struct {
	failures    []time.Time
	lockedUntil time.Time
	lastSeen    time.Time
}

type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginEntry
	window  time.Duration
	lockout time.Duration
	max     int
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		entries: make(map[string]*loginEntry),
		window:  loginWindow,
		lockout: loginLockout,
		max:     loginMaxFailures,
	}
}

func (l *loginLimiter) locked(ip string, now time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanup(now)
	entry := l.entries[ip]
	if entry == nil {
		return 0, false
	}
	if now.Before(entry.lockedUntil) {
		return entry.lockedUntil.Sub(now), true
	}
	return 0, false
}

func (l *loginLimiter) fail(ip string, now time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanup(now)
	entry := l.entries[ip]
	if entry == nil {
		entry = &loginEntry{}
		l.entries[ip] = entry
	}
	entry.lastSeen = now
	if now.Before(entry.lockedUntil) {
		return entry.lockedUntil.Sub(now), true
	}
	cutoff := now.Add(-l.window)
	kept := entry.failures[:0]
	for _, failure := range entry.failures {
		if failure.After(cutoff) {
			kept = append(kept, failure)
		}
	}
	entry.failures = append(kept, now)
	if len(entry.failures) >= l.max {
		entry.failures = nil
		entry.lockedUntil = now.Add(l.lockout)
		return l.lockout, true
	}
	return 0, false
}

func (l *loginLimiter) success(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

func (l *loginLimiter) cleanup(now time.Time) {
	for ip, entry := range l.entries {
		if now.After(entry.lockedUntil) && now.Sub(entry.lastSeen) > l.window {
			delete(l.entries, ip)
		}
	}
}

func (s *Server) httpLogger(ctx iris.Context) {
	requestID := ctx.GetHeader("X-Request-ID")
	if requestID == "" {
		requestID = newRequestID()
	}
	ctx.Header("X-Request-ID", requestID)
	ctx.Values().Set("request_id", requestID)

	start := time.Now()
	ctx.Next()

	status := ctx.GetStatusCode()
	if status == 0 {
		status = http.StatusOK
	}
	level := slog.LevelInfo
	if status >= http.StatusBadRequest && status < http.StatusInternalServerError {
		level = slog.LevelWarn
	} else if status >= http.StatusInternalServerError {
		level = slog.LevelError
	}
	s.logger.Log(ctx.Request().Context(), level, "http request completed",
		"event", "http_request",
		"request_id", requestID,
		"method", ctx.Request().Method,
		"path", ctx.Request().URL.Path,
		"status", status,
		"duration_ms", time.Since(start).Milliseconds(),
		"remote_ip", ctx.Request().RemoteAddr,
	)
}

func newRequestID() string {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(random)
}

func (s *Server) logBusiness(event, message string, address config.Address, attrs ...slog.Attr) {
	args := []any{
		"event", event,
		"project", address.Project,
		"environment", address.Environment,
		"service", address.Service,
	}
	for _, attr := range attrs {
		args = append(args, attr)
	}
	s.logger.Info(message, args...)
}

func readAddress(ctx iris.Context) (config.Address, bool) {
	address := config.Address{
		Project: ctx.Params().Get("project"), Environment: ctx.Params().Get("environment"),
		Service: ctx.Params().Get("service"),
	}
	if err := address.Validate(); err != nil {
		writeError(ctx, iris.StatusBadRequest, err.Error())
		return config.Address{}, false
	}
	return address, true
}

func writeStoreError(ctx iris.Context, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeError(ctx, iris.StatusNotFound, "configuration or version not found")
	default:
		writeError(ctx, iris.StatusInternalServerError, err.Error())
	}
}

func writeError(ctx iris.Context, status int, message string) {
	ctx.StatusCode(status)
	ctx.JSON(iris.Map{"error": message})
}

func isSensitiveField(field config.Field) bool {
	return field.Sensitive || field.Type == "secret"
}

func redactSecrets(schema []config.Field, values map[string]any) (map[string]any, []string) {
	result := config.CloneValues(values)
	var paths []string
	for _, field := range schema {
		if !isSensitiveField(field) {
			continue
		}
		if value, ok := getValue(result, field.Path); ok && value != nil && value != "" {
			setValue(result, field.Path, keepSecret)
			paths = append(paths, field.Path)
		}
	}
	return result, paths
}

func getValue(values map[string]any, path string) (any, bool) {
	var current any = values
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func deleteValue(values map[string]any, path string) {
	parts := strings.Split(path, ".")
	current := values
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok {
			return
		}
		current = next
	}
	delete(current, parts[len(parts)-1])
}

func setValue(values map[string]any, path string, value any) {
	parts := strings.Split(path, ".")
	current := values
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok {
			next = make(map[string]any)
			current[part] = next
		}
		current = next
	}
	current[parts[len(parts)-1]] = value
}
