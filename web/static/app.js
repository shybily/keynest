(() => {
  "use strict";

  const KEEP_SECRET = "__KEYNEST_KEEP_SECRET__";
  const SESSION_WARN_MS = 25 * 60 * 1000;
  const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[ch]));
  const enc = (value) => encodeURIComponent(String(value ?? ""));

  const state = {
    resources: [],
    keys: [],
    summaries: new Map(),
    route: { mode: "empty", project: "", environment: "", service: "" },
    hash: "",
    tab: "config",
    history: [],
    editor: null,
    collapsedProjects: new Set(),
    collapsedEnvs: new Set(),
    collapsedGroups: new Set(),
    pendingHash: null,
    bypassHash: false,
    fieldEdit: null,
    dialogScope: null,
    diffVersion: null,
    loggedIn: false,
    cdnStatusTimer: null,
    busy: false,
    lastActivity: Date.now(),
    sessionWarned: false,
    loginLockTimer: null,
    confirmHandler: null,
    preview: { raw: "", masked: "", visible: false, reveal: true, history: false },
    paletteItems: [],
    paletteIndex: 0
  };

  class ApiError extends Error {
    constructor(message, status, retryAfter) {
      super(message);
      this.name = "ApiError";
      this.status = status;
      this.retryAfter = retryAfter;
    }
  }

  const isSensitive = (field) => Boolean(field && (field.sensitive || field.type === "secret"));
  const addressKey = (project, environment, service) => project + "|" + environment + "|" + service;

  function getPath(object, path) {
    let current = object;
    for (const part of String(path).split(".")) {
      if (!current || typeof current !== "object" || !(part in current)) return undefined;
      current = current[part];
    }
    return current;
  }

  function setPath(object, path, value) {
    const parts = String(path).split(".");
    let current = object;
    for (const part of parts.slice(0, -1)) {
      if (!current[part] || typeof current[part] !== "object") current[part] = {};
      current = current[part];
    }
    current[parts[parts.length - 1]] = value;
  }

  function readCookie(name) {
    for (const entry of document.cookie.split(";")) {
      const [key, ...rest] = entry.trim().split("=");
      if (key === name) return decodeURIComponent(rest.join("="));
    }
    return "";
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    const pad = (number) => String(number).padStart(2, "0");
    return date.getFullYear() + "-" + pad(date.getMonth() + 1) + "-" + pad(date.getDate()) +
      " " + pad(date.getHours()) + ":" + pad(date.getMinutes());
  }

  function toast(message, kind) {
    const node = $("#toast");
    node.textContent = message;
    node.classList.toggle("error", kind === "error");
    node.classList.add("show");
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => node.classList.remove("show"), 2800);
  }

  function toastError(error) {
    const message = error instanceof Error ? error.message : String(error);
    toast(message || "操作失败", "error");
  }

  function markActivity() {
    state.lastActivity = Date.now();
    state.sessionWarned = false;
  }

  async function api(path, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const headers = { Accept: "application/json" };
    let body;
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(options.body);
    }
    if (!SAFE_METHODS.has(method)) {
      const token = readCookie("keynest_csrf");
      if (token) headers["X-CSRF-Token"] = token;
    }
    let response;
    try {
      response = await fetch(path, {
        method,
        headers,
        body,
        credentials: "same-origin",
        cache: "no-store"
      });
    } catch (error) {
      throw new ApiError("无法连接服务，请检查网络后重试。", 0);
    }
    if (response.status === 401 && !options.skipAuth) {
      handleUnauthorized();
      throw new ApiError("登录已过期，请重新登录。", 401);
    }
    if (!response.ok) {
      const text = await response.text();
      let message = text;
      try {
        const data = JSON.parse(text);
        if (data && typeof data.error === "string") message = data.error;
      } catch (_) {
        // keep the raw response text
      }
      throw new ApiError(message || ("请求失败（" + response.status + "）"), response.status,
        response.headers.get("Retry-After"));
    }
    markActivity();
    if (response.status === 204) return null;
    if (options.rawText) return response.text();
    const type = response.headers.get("Content-Type") || "";
    if (type.includes("application/json")) return response.json();
    return response.text();
  }

  function handleUnauthorized() {
    if (!$("#login-screen").hidden) return;
    showLogin("登录已过期，请重新登录。");
  }

  function closeAllDialogs() {
    $$("dialog[open]").forEach((dialog) => dialog.close());
  }

  function showLogin(message) {
    state.loggedIn = false;
    clearInterval(state.cdnStatusTimer);
    state.cdnStatusTimer = null;
    state.pendingHash = null;
    state.bypassHash = false;
    clearInterval(state.loginLockTimer);
    closeAllDialogs();
    $("#app").hidden = true;
    $("#login-screen").hidden = false;
    $("#login-error").textContent = message || "";
    $("#login-password").value = "";
    $("#login-submit").disabled = false;
    $("#login-submit").textContent = "登录";
    $("#tree").innerHTML = "";
    state.resources = [];
    state.keys = [];
    state.summaries.clear();
    state.editor = null;
    state.history = [];
    document.title = "枢钥 Keynest · 登录";
    $("#login-password").focus();
  }

  function showApp() {
    $("#login-screen").hidden = true;
    $("#app").hidden = false;
    document.title = "枢钥 Keynest";
  }

  function dialogById(id) {
    return document.getElementById(id);
  }

  function openDialog(id) {
    const dialog = dialogById(id);
    if (dialog && !dialog.open) dialog.showModal();
    return dialog;
  }

  function closeDialog(dialog) {
    if (dialog && dialog.open) dialog.close();
  }

  function lockLoginForm(seconds) {
    const button = $("#login-submit");
    const error = $("#login-error");
    const total = Math.max(1, Number(seconds) || 60);
    let remainder = total;
    clearInterval(state.loginLockTimer);
    button.disabled = true;
    error.textContent = "尝试次数过多，请在 " +
      (total >= 60 ? Math.ceil(total / 60) + " 分钟后" : total + " 秒后") + "重试。";
    const tick = () => {
      button.textContent = total >= 60
        ? "请稍候 " + Math.floor(remainder / 60) + ":" + String(remainder % 60).padStart(2, "0")
        : "请稍候 " + remainder + "s";
      remainder -= 1;
      if (remainder < 0) {
        clearInterval(state.loginLockTimer);
        button.disabled = false;
        button.textContent = "登录";
        error.textContent = "";
      }
    };
    tick();
    state.loginLockTimer = setInterval(tick, 1000);
  }

  async function login(event) {
    event.preventDefault();
    const button = $("#login-submit");
    const error = $("#login-error");
    error.textContent = "";
    button.disabled = true;
    button.textContent = "登录中";
    try {
      await api("/api/v1/admin/login", {
        method: "POST",
        body: { password: $("#login-password").value },
        skipAuth: true
      });
      state.loggedIn = true;
      markActivity();
      $("#login-password").value = "";
      showApp();
      await bootstrap();
      toast("已登录");
    } catch (failure) {
      if (failure.status === 429) {
        lockLoginForm(failure.retryAfter);
        return;
      }
      if (failure.status === 401) error.textContent = "密码不正确，请重试。";
      else if (failure.status === 403) error.textContent = "请求来源不被允许，请通过正常入口访问。";
      else error.textContent = failure.message || "登录失败。";
    } finally {
      if (!state.loginLockTimer || !$("#login-submit").disabled) {
        button.disabled = false;
        button.textContent = "登录";
      }
    }
  }

  async function logout() {
    try {
      await fetch("/api/v1/admin/logout", {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRF-Token": readCookie("keynest_csrf") }
      });
    } catch (_) {
      // local sign-out still proceeds
    }
    showLogin("已退出登录。");
  }

  function safeDecode(value) {
    try {
      return decodeURIComponent(value);
    } catch (_) {
      return value;
    }
  }

  function parseHash(hash) {
    const parts = String(hash || "").replace(/^#\/?/, "").split("/").filter(Boolean).map(safeDecode);
    if (parts[0] === "keys") return { mode: "keys", project: "", environment: "", service: "" };
    if (parts[0] === "p" && parts[2] === "e") {
      if (parts[4] === "s" && parts[5]) {
        return { mode: "service", project: parts[1] || "", environment: parts[3] || "", service: parts[5] };
      }
      return { mode: "env", project: parts[1] || "", environment: parts[3] || "", service: "" };
    }
    return { mode: "empty", project: "", environment: "", service: "" };
  }

  function hashFor(route) {
    if (route.mode === "keys") return "#/keys";
    if (route.mode === "service") {
      return "#/p/" + enc(route.project) + "/e/" + enc(route.environment) + "/s/" + enc(route.service);
    }
    if (route.mode === "env") return "#/p/" + enc(route.project) + "/e/" + enc(route.environment);
    return "#/";
  }

  function findProject(id) {
    return state.resources.find((project) => project.id === id) || null;
  }

  function findEnvironment(projectId, environmentName) {
    const project = findProject(projectId);
    return project ? (project.environments || []).find((env) => env.name === environmentName) || null : null;
  }

  function findService(projectId, environmentName, serviceName) {
    const environment = findEnvironment(projectId, environmentName);
    return environment ? (environment.services || []).find((service) => service.name === serviceName) || null : null;
  }

  function serviceList() {
    const rows = [];
    for (const project of state.resources) {
      for (const environment of project.environments || []) {
        for (const service of environment.services || []) rows.push({ project, environment, service });
      }
    }
    return rows;
  }

  function findSummary(project, environment, service) {
    return state.summaries.get(addressKey(project, environment, service)) || null;
  }

  async function loadResources() {
    const payload = await api("/api/v1/admin/resources");
    state.resources = Array.isArray(payload && payload.projects) ? payload.projects : [];
    renderTree();
  }

  async function loadKeys() {
    const payload = await api("/api/v1/admin/keys");
    state.keys = Array.isArray(payload) ? payload : [];
  }

  async function loadSummaries() {
    const payload = await api("/api/v1/admin/configs");
    const map = new Map();
    for (const item of Array.isArray(payload) ? payload : []) {
      if (item && item.address) {
        map.set(addressKey(item.address.project, item.address.environment, item.address.service), item);
      }
    }
    state.summaries = map;
  }

  function renderCDNStatus(status) {
    const node = $("#cdn-status");
    const labels = {
      disabled: status.configured ? "CDN 自动关闭" : "CDN 未启用",
      verifying: "CDN 校验中",
      unavailable: "CDN 暂不可用",
      enabled: "CDN 已启用"
    };
    node.className = "cdn-status " + esc(status.state || "unavailable");
    node.textContent = labels[status.state] || "CDN 状态未知";
    const details = [];
    if (status.message) details.push(status.message);
    if (status.pending) details.push("待刷新任务：" + status.pending);
    if (status.lastError) details.push("最近错误：" + status.lastError);
    node.title = details.join("；");
    node.setAttribute("aria-label", [node.textContent, ...details].filter(Boolean).join("；"));
  }

  async function loadCDNStatus() {
    try {
      renderCDNStatus(await api("/api/v1/admin/cdn/status"));
    } catch (failure) {
      renderCDNStatus({ state: "unavailable", message: failure.message || "CDN 状态查询失败" });
      throw failure;
    }
  }

  async function bootstrap() {
    try {
      await Promise.all([loadResources(), loadKeys(), loadSummaries()]);
      try {
        await loadCDNStatus();
      } catch (failure) {
        if (failure.status !== 401) toastError(failure);
      }
      await handleRoute(location.hash || state.hash || "#/");
      clearInterval(state.cdnStatusTimer);
      state.cdnStatusTimer = setInterval(() => {
        if (state.loggedIn && document.visibilityState !== "hidden") {
          loadCDNStatus().catch(() => {});
        }
      }, 15000);
    } catch (failure) {
      if (failure.status !== 401) toastError(failure);
    }
  }

  function draftUrl(route, suffix) {
    return "/api/v1/admin/configs/" + enc(route.project) + "/" + enc(route.environment) + "/" +
      enc(route.service) + (suffix || "");
  }

  function displayValue(field, value) {
    if (value === undefined || value === null) return "";
    if (field.type === "boolean") return value === true || value === "true" ? "true" : "false";
    if (field.type === "json") {
      if (typeof value === "string") return value;
      try {
        return JSON.stringify(value, null, 2);
      } catch (_) {
        return String(value);
      }
    }
    return String(value);
  }

  function editorFromDraft(data, route) {
    const schema = data && Array.isArray(data.schema) ? data.schema : [];
    const values = {};
    const savedValues = {};
    const secrets = new Set(Array.isArray(data && data.secretSet) ? data.secretSet : []);
    const secretMode = new Map();
    const secretInput = new Map();
    const sourceValues = (data && data.values) || {};
    for (const field of schema) {
      const raw = getPath(sourceValues, field.path);
      const display = raw === KEEP_SECRET ? "" : displayValue(field, raw);
      values[field.path] = display;
      savedValues[field.path] = display;
      if (isSensitive(field)) {
        secretMode.set(field.path, "keep");
        secretInput.set(field.path, "");
      }
    }
    const summary = findSummary(route.project, route.environment, route.service);
    return {
      schema,
      savedSchema: JSON.stringify(schema),
      values,
      savedValues,
      baselineSecrets: secrets,
      secretMode,
      secretInput,
      version: data ? Number(data.version) || 0 : Number(summary && summary.version) || 0,
      updatedAt: (data && data.updatedAt) || (summary && summary.updatedAt) || "",
      exists: Boolean(data)
    };
  }

  async function loadDraftFor(route) {
    try {
      const data = await api(draftUrl(route));
      return editorFromDraft(data, route);
    } catch (failure) {
      if (failure.status === 404) return editorFromDraft(null, route);
      throw failure;
    }
  }

  function effectiveSecretSet(path) {
    if (!state.editor) return false;
    const mode = state.editor.secretMode.get(path) || "keep";
    if (mode === "clear") return false;
    if (state.editor.baselineSecrets.has(path)) return true;
    return mode === "replace" && String(state.editor.secretInput.get(path) || "").trim() !== "";
  }

  function fieldDirty(field) {
    if (!state.editor) return false;
    if (isSensitive(field)) {
      const path = field.path;
      const mode = state.editor.secretMode.get(path) || "keep";
      const base = state.editor.baselineSecrets.has(path);
      if (mode === "clear") return base;
      if (mode === "replace") return String(state.editor.secretInput.get(path) || "").trim() !== "";
      return false;
    }
    return String(state.editor.values[field.path] ?? "") !== String(state.editor.savedValues[field.path] ?? "");
  }

  function schemaDirty() {
    if (!state.editor) return false;
    return JSON.stringify(state.editor.schema) !== state.editor.savedSchema;
  }

  function dirtyCount() {
    if (!state.editor) return 0;
    let count = state.editor.schema.filter(fieldDirty).length;
    if (schemaDirty()) count += 1;
    return count;
  }

  function isDirty() {
    return Boolean(state.editor) && (schemaDirty() || state.editor.schema.some(fieldDirty));
  }

  function fieldPatternIssue(field) {
    const segments = String(field.path || "").split(".");
    if (!field.path || segments.some((segment) => !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(segment))) {
      return "字段路径只能包含字母、数字、点、下划线和连字符，且每段以字母或数字开头。";
    }
    if (field.environment && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(field.environment)) {
      return "环境变量名只能包含字母、数字和下划线，且不能以数字开头。";
    }
    const yamlPath = field.yaml || field.path;
    if (String(yamlPath).split(".").some((segment) => !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(segment))) {
      return "YAML 路径格式不正确。";
    }
    if (field.type === "enum" && (!Array.isArray(field.options) || field.options.length === 0)) {
      return "enum 字段至少需要一个可选值。";
    }
    if (isSensitive(field) && field.default !== undefined && field.default !== null) {
      return "敏感字段不能设置默认值。";
    }
    if (!String(field.label || "").trim()) return "字段需要显示名称。";
    return "";
  }

  function collectSchemaIssues() {
    const issues = new Map();
    if (!state.editor) return issues;
    const paths = new Map();
    const envs = new Map();
    const yamls = new Map();
    for (const field of state.editor.schema) {
      const pattern = fieldPatternIssue(field);
      if (pattern) issues.set(field.path, pattern);
      const yamlPath = field.yaml || field.path;
      if (paths.has(field.path)) issues.set(field.path, "字段路径与其他字段重复。");
      paths.set(field.path, true);
      if (field.environment) {
        if (envs.has(field.environment)) issues.set(field.path, "环境变量名与其他字段重复。");
        envs.set(field.environment, true);
      }
      if (yamls.has(yamlPath)) issues.set(field.path, "YAML 路径与其他字段重复。");
      yamls.set(yamlPath, true);
    }
    return issues;
  }

  function validateField(field, issues) {
    if (!state.editor) return "";
    const schemaIssue = (issues || collectSchemaIssues()).get(field.path);
    if (schemaIssue) return schemaIssue;
    if (isSensitive(field)) {
      return field.required && !effectiveSecretSet(field.path) ? "尚未设置密钥值。" : "";
    }
    const raw = state.editor.values[field.path];
    const text = String(raw ?? "");
    if (field.required && text.trim() === "") return "此字段为必填项。";
    if (text.trim() === "") return "";
    if (field.type === "integer") {
      if (!/^[+-]?\d+$/.test(text.trim()) || !Number.isSafeInteger(Number(text))) {
        return "请输入整数。";
      }
    }
    if (field.type === "number" && !Number.isFinite(Number(text))) {
      return "请输入数字。";
    }
    if (field.type === "json") {
      try {
        JSON.parse(text);
      } catch (_) {
        return "JSON 格式不正确，请检查逗号与引号。";
      }
    }
    if (field.type === "enum" && Array.isArray(field.options) && field.options.length &&
      !field.options.includes(text)) {
      return "请选择列表中的值。";
    }
    return "";
  }

  function collectErrors() {
    if (!state.editor) return [];
    const issues = collectSchemaIssues();
    const result = [];
    state.editor.schema.forEach((field, index) => {
      const message = validateField(field, issues);
      if (message) result.push({ field, index, message });
    });
    return result;
  }

  function focusField(index) {
    const row = $('#field-groups .field[data-index="' + index + '"]');
    if (!row) return;
    row.scrollIntoView({ block: "center", behavior: "smooth" });
    const input = row.querySelector(".input, input, select, textarea");
    if (input) input.focus();
  }

  function currentServiceEntry() {
    if (state.route.mode !== "service") return null;
    const project = findProject(state.route.project);
    const environment = findEnvironment(state.route.project, state.route.environment);
    const service = findService(state.route.project, state.route.environment, state.route.service);
    if (!project || !environment || !service) return null;
    return { project, environment, service };
  }

  function renderChips() {
    if (!state.editor || state.route.mode !== "service") return;
    const entry = currentServiceEntry();
    const version = state.editor.version;
    const dirty = isDirty();
    const chips = [
      '<span class="chip chip-mono">' + (version ? "v" + version : "未发布") + "</span>",
      dirty
        ? '<span class="chip chip-warn"><span class="dot warn"></span>草稿有改动</span>'
        : (state.editor.exists
          ? '<span class="chip chip-success"><svg class="icon sm"><use href="#i-check"/></svg>已保存</span>'
          : '<span class="chip">未创建草稿</span>')
    ];
    if (entry) {
      chips.push(entry.service.keyId
        ? '<span class="chip chip-success"><svg class="icon sm"><use href="#i-key"/></svg>凭证已就绪</span>'
        : '<span class="chip chip-warn"><svg class="icon sm"><use href="#i-warn"/></svg>缺少凭证</span>');
    }
    $("#svc-chips").innerHTML = chips.join("");
  }

  function renderSaveLine() {
    if (!state.editor || state.route.mode !== "service") return;
    const errors = collectErrors();
    const changed = dirtyCount();
    const savedAt = state.editor.updatedAt ? formatDate(state.editor.updatedAt) : "尚未保存";
    let statusText;
    if (isDirty()) statusText = "上次保存 " + savedAt + " · " + changed + " 处改动";
    else if (state.editor.exists) statusText = "所有改动已保存 · " + savedAt;
    else statusText = "草稿尚未创建";
    const validation = errors.length
      ? '<button class="link danger-text" type="button" data-action="jump-first">' + errors.length + " 个字段需要修正</button>"
      : '<span class="ok-text">校验通过</span>';
    $("#save-line").innerHTML =
      '<span class="dot ' + (isDirty() ? "warn" : "ok") + '"></span>' +
      "<span>" + esc(statusText) + "</span>" +
      '<span class="sep">·</span>' + validation;
    $("#msb-state").innerHTML =
      '<span class="dot ' + (isDirty() || errors.length ? "warn" : "ok") + '"></span>' +
      "<span>" + (isDirty() ? changed + " 处改动" : "已保存") +
      (errors.length ? ' · <span class="danger-text">' + errors.length + " 项待修正</span>" : ' · <span class="ok-text">校验通过</span>') +
      "</span>";
  }

  function groupLabel(field) {
    const head = String(field.path || "").split(".")[0] || "字段";
    return ({
      server: "服务",
      log: "日志",
      database: "数据库",
      db: "数据库",
      redis: "缓存",
      cache: "缓存",
      jwt: "安全",
      auth: "安全",
      feature: "功能",
      features: "功能",
      token: "安全"
    })[head] || head;
  }

  function fieldControl(field, index) {
    const value = state.editor.values[field.path] ?? "";
    if (field.type === "boolean") {
      const checked = String(value) === "true";
      return '<label class="switch"><input type="checkbox" data-field-index="' + index + '" ' +
        (checked ? "checked" : "") + '><span class="switch-track"></span>' +
        '<span class="switch-label">' + (checked ? "已开启" : "已关闭") + "</span></label>";
    }
    if (field.type === "enum") {
      const options = (field.options || []).map((option) =>
        '<option value="' + esc(option) + '"' + (String(value) === option ? " selected" : "") + ">" +
        esc(option) + "</option>").join("");
      return '<select class="input" data-field-index="' + index + '"><option value="">请选择</option>' +
        options + "</select>";
    }
    if (field.type === "json") {
      let valid = true;
      try {
        if (String(value).trim() !== "") JSON.parse(value);
      } catch (_) {
        valid = false;
      }
      return '<textarea class="input mono" data-field-index="' + index + '" rows="5" spellcheck="false">' +
        esc(value) + "</textarea>" +
        '<div class="input-foot"><span class="json-state ' + (valid ? "ok" : "bad") + '">' +
        (valid ? "JSON 有效" : "JSON 格式不正确") +
        '</span><button class="link" type="button" data-action="format-json" data-index="' + index + '">格式化</button></div>';
    }
    if (isSensitive(field)) {
      const path = field.path;
      const base = state.editor.baselineSecrets.has(path);
      const mode = state.editor.secretMode.get(path) || (base ? "keep" : "replace");
      if (mode === "clear") {
        return '<div class="secret-line"><span class="masked mono">••••••••••••</span>' +
          '<span class="chip chip-warn">保存后清除</span>' +
          '<button class="btn btn-ghost btn-sm" type="button" data-action="secret-undo" data-index="' + index + '">撤销清除</button></div>' +
          '<p class="hint">保存草稿后，渲染结果不再包含该字段。</p>';
      }
      if (base && mode === "keep") {
        return '<div class="secret-line"><span class="masked mono">••••••••••••</span>' +
          '<span class="chip chip-success">已设置</span>' +
          '<button class="btn btn-ghost btn-sm" type="button" data-action="secret-replace" data-index="' + index + '">替换</button>' +
          '<button class="btn btn-ghost btn-sm danger-text" type="button" data-action="secret-clear" data-index="' + index + '">清除</button></div>' +
          '<p class="hint">原值不会返回浏览器；服务读取时由服务端解密，再用该服务的公钥加密。</p>';
      }
      const inputValue = state.editor.secretInput.get(path) || "";
      return '<div class="secret-input"><input class="input mono" type="password" data-field-index="' + index + '" ' +
        'value="' + esc(inputValue) + '" placeholder="输入新的密钥值" autocomplete="new-password" spellcheck="false">' +
        '<button class="icon-btn" type="button" data-action="eye" aria-label="显示密钥"><svg class="icon"><use href="#i-eye"/></svg></button></div>' +
        '<div class="secret-line">' + (base ? '<span class="chip chip-success">已设置</span>' : '<span class="chip chip-warn">未设置</span>') +
        (base ? '<button class="btn btn-ghost btn-sm" type="button" data-action="secret-cancel" data-index="' + index + '">取消替换</button>' : "") +
        "</div>" +
        '<p class="hint">输入新值后保存草稿；原值不会被读取到浏览器。</p>';
    }
    const inputMode = field.type === "integer" || field.type === "number" ? ' inputmode="decimal"' : "";
    return '<input class="input mono" type="text" data-field-index="' + index + '" value="' + esc(value) + '"' +
      inputMode + ">" +
      (field.type === "integer" ? '<span class="hint">请输入整数。</span>' : "") +
      (field.type === "number" ? '<span class="hint">请输入数字。</span>' : "");
  }

  function renderField(field, index, issue) {
    const message = validateField(field, issue) || "";
    const meta = (field.environment
      ? '<span class="mono">' + esc(field.environment) + "</span>"
      : "<span>未映射到 .env</span>") +
      ' <span>·</span> YAML <span class="mono">' + esc(field.yaml || field.path) + "</span>" +
      '<span class="field-actions">' +
      '<button class="link" type="button" data-action="edit-field" data-index="' + index + '">编辑</button>' +
      ' <span>·</span>' +
      '<button class="link danger-text" type="button" data-action="delete-field" data-index="' + index + '">删除</button>' +
      "</span>";
    return '<div class="field ' + (message ? "invalid" : "") + '" data-index="' + index + '">' +
      '<div class="field-info">' +
        '<div class="field-label">' + esc(field.label) + (field.required ? ' <span class="req">必填</span>' : "") + "</div>" +
        '<code class="path">' + esc(field.path) + "</code>" +
        '<div class="field-meta">' + meta + "</div>" +
        (field.description ? '<p class="field-desc">' + esc(field.description) + "</p>" : "") +
      "</div>" +
      '<div class="field-control">' + fieldControl(field, index) +
        '<div class="field-error" role="alert">' + esc(message) + "</div>" +
      "</div>" +
    "</div>";
  }

  function renderFields() {
    if (!state.editor) return;
    const fields = state.editor.schema;
    $("#field-count").textContent = String(fields.length);
    if (!fields.length) {
      $("#field-groups").innerHTML = '<div class="empty-fields"><h3>这个服务还没有配置字段</h3>' +
        '<p>先定义字段结构，或从 .env、YAML、JSON 导入。导入结果会先保存为草稿。</p>' +
        '<div class="empty-actions"><button class="btn btn-primary btn-sm" type="button" data-action="add-field">添加字段</button>' +
        '<button class="btn btn-secondary btn-sm" type="button" data-action="import">导入配置</button></div></div>';
      return;
    }
    const groups = [];
    const map = new Map();
    for (const field of fields) {
      const name = groupLabel(field);
      if (!map.has(name)) {
        map.set(name, []);
        groups.push(name);
      }
      map.get(name).push(field);
    }
    const issues = collectSchemaIssues();
    $("#field-groups").innerHTML = groups.map((name) => {
      const closed = state.collapsedGroups.has(name);
      const items = map.get(name).map((field) => {
        const index = fields.indexOf(field);
        return renderField(field, index, issues);
      }).join("");
      return '<section class="group">' +
        '<button class="group-head" type="button" data-action="toggle-group" data-group="' + esc(name) + '" aria-expanded="' + String(!closed) + '">' +
          '<svg class="icon chev"><use href="#i-chevron"/></svg>' +
          '<span class="group-title">' + esc(name) + "</span>" +
          '<span class="group-count">' + map.get(name).length + " 个字段</span>" +
        "</button>" +
        '<div class="group-body"' + (closed ? " hidden" : "") + ">" + items + "</div>" +
      "</section>";
    }).join("");
  }

  function renderTabState() {
    $$(".tab").forEach((tab) => {
      const active = tab.dataset.tab === state.tab;
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", String(active));
    });
    $("#config-panel").hidden = state.tab !== "config";
    $("#history-panel").hidden = state.tab !== "history";
  }

  function renderServiceView() {
    if (!state.editor || state.route.mode !== "service") return;
    const entry = currentServiceEntry();
    if (!entry) return;
    $("#svc-crumbs").innerHTML =
      "<span>" + esc(entry.project.name || entry.project.id) + "</span>" +
      '<span class="crumb-sep">/</span><span class="mono">' + esc(entry.environment.name) + "</span>" +
      '<span class="crumb-sep">/</span><span class="mono">' + esc(entry.service.name) + "</span>";
    $("#svc-title").textContent = entry.service.name;
    renderChips();
    renderSaveLine();
    renderFields();
    renderTabState();
    if (state.tab === "history") renderHistory();
    document.title = entry.service.name + " · Keynest";
  }

  function renderHistory() {
    if (!state.editor || state.route.mode !== "service") return;
    const rows = state.history || [];
    $("#history-panel").innerHTML = '<div class="table history-table">' +
      '<div class="table-head"><span>版本</span><span>发布时间</span><span>字段</span><span></span></div>' +
      (rows.length
        ? rows.map((item, index) => '<div class="table-row">' +
            '<span><span class="chip chip-mono">v' + esc(item.version) + "</span>" +
            (index === 0 ? ' <span class="chip chip-success">当前</span>' : "") + "</span>" +
            '<span class="mono">' + esc(formatDate(item.createdAt)) + "</span>" +
            "<span>" + (Array.isArray(item.schema) ? item.schema.length : 0) + " 个</span>" +
            '<span class="cell-actions">' +
              '<button class="btn btn-ghost btn-sm" type="button" data-action="view-version" data-version="' + esc(item.version) + '">查看</button>' +
              '<button class="btn btn-secondary btn-sm" type="button" data-action="restore-version" data-version="' + esc(item.version) + '">恢复为草稿</button>' +
            "</span>" +
          "</div>").join("")
        : '<div class="table-row"><span class="muted">还没有发布记录</span></div>') +
    "</div>";
  }

  function handleHistoryClick(event) {
    const button = event.target.closest("[data-action]");
    if (!button) return;
    const version = Number(button.dataset.version);
    if (button.dataset.action === "view-version") {
      openHistoryPreview(version);
      return;
    }
    if (button.dataset.action === "restore-version") {
      restoreVersion(version);
    }
  }

  async function loadHistory() {
    if (state.route.mode !== "service") return;
    try {
      const payload = await api(draftUrl(state.route, "/history"));
      state.history = Array.isArray(payload) ? payload : [];
    } catch (failure) {
      state.history = [];
      if (failure.status !== 401) toastError(failure);
    }
    renderHistory();
  }

  function setTab(tab) {
    state.tab = tab;
    renderTabState();
    if (tab === "history") loadHistory();
  }

  function renderEnvView() {
    const project = findProject(state.route.project);
    const environment = findEnvironment(state.route.project, state.route.environment);
    if (!project || !environment) {
      showEmpty();
      return;
    }
    const services = environment.services || [];
    const withKeys = services.filter((service) => service.keyId).length;
    const missing = services.length - withKeys;
    $("#env-crumbs").innerHTML = "<span>" + esc(project.name || project.id) + "</span>" +
      '<span class="crumb-sep">/</span><span class="mono">' + esc(environment.name) + "</span>";
    $("#env-title").textContent = environment.name;
    $("#env-chips").innerHTML =
      '<span class="chip chip-primary">' + services.length + " 个服务</span>" +
      '<span class="chip">' + withKeys + " 份凭证</span>" +
      (missing ? '<span class="chip chip-warn"><svg class="icon sm"><use href="#i-warn"/></svg>' +
        missing + " 个服务缺少凭证</span>" : "");
    $("#env-services").innerHTML = services.length
      ? '<div class="table env-table">' +
          '<div class="table-head"><span>服务</span><span>版本</span><span>凭证</span><span></span></div>' +
          services.map((service) => {
            const summary = findSummary(project.id, environment.name, service.name);
            return '<div class="table-row" data-service="' + esc(service.name) + '">' +
              '<span class="cell-main"><strong class="mono">' + esc(service.name) + "</strong><small>" +
              esc(project.name || project.id) + " / " + esc(environment.name) + "</small></span>" +
              '<span><span class="chip chip-mono">' + (summary && summary.version ? "v" + summary.version : "未发布") + "</span></span>" +
              '<span><span class="chip ' + (service.keyId ? "chip-success" : "chip-warn") + '">' +
              (service.keyId ? "已就绪" : "缺少凭证") + "</span></span>" +
              '<span class="cell-actions">' +
                '<button class="btn btn-secondary btn-sm" type="button" data-action="open-service" data-service="' + esc(service.name) + '">打开配置</button>' +
                '<button class="icon-btn danger-text" type="button" data-action="delete-service" data-service="' + esc(service.name) + '" aria-label="删除服务 ' + esc(service.name) + '" title="删除服务"><svg class="icon sm"><use href="#i-trash"/></svg></button>' +
              "</span>" +
            "</div>";
          }).join("") +
        "</div>"
      : '<div class="empty-fields"><h3>这个环境还没有服务</h3>' +
        "<p>服务创建后会挂在当前环境之下，并获得独立的访问凭证。配置地址仍然是 项目 / 环境 / 服务。</p>" +
        '<div class="empty-actions"><button class="btn btn-primary btn-sm" type="button" data-action="new-service">新建服务</button></div></div>';
    document.title = environment.name + " · Keynest";
  }

  function keyFor(project, environment, service) {
    return state.keys.find((key) => key.project === project && key.environment === environment && key.service === service) || null;
  }

  function renderKeys() {
    const rows = serviceList();
    if (!rows.length) {
      $("#keys-table").innerHTML = '<div class="empty-fields"><h3>还没有服务</h3>' +
        "<p>在环境中创建服务后会自动生成访问令牌与 RSA 密钥。</p></div>";
      return;
    }
    $("#keys-table").innerHTML = '<div class="table keys-table">' +
      '<div class="table-head"><span>服务</span><span>密钥 ID</span><span>创建时间</span><span>状态</span><span></span></div>' +
      rows.map(({ project, environment, service }) => {
        const key = keyFor(project.id, environment.name, service.name);
        return '<div class="table-row" data-project="' + esc(project.id) + '" data-environment="' + esc(environment.name) +
          '" data-service="' + esc(service.name) + '"' + (key ? ' data-key="' + esc(key.id) + '"' : "") + ">" +
          '<span class="cell-main"><strong class="mono">' + esc(service.name) + "</strong><small>" +
          esc(project.name || project.id) + " / " + esc(environment.name) + "</small></span>" +
          (key ? '<span class="mono">' + esc(key.id) + "</span>" : '<span class="muted">未创建</span>') +
          '<span class="mono">' + (key ? esc(formatDate(key.createdAt)) : "—") + "</span>" +
          '<span><span class="chip ' + (key ? "chip-success" : "chip-warn") + '">' +
          (key ? "正常" : "缺少凭证") + "</span></span>" +
          '<span class="cell-actions">' +
            (key
              ? '<button class="btn btn-ghost btn-sm" type="button" data-action="key-view">查看私钥</button>' +
                '<button class="btn btn-ghost btn-sm" type="button" data-action="key-download">下载私钥</button>' +
                '<button class="btn btn-ghost btn-sm" type="button" data-action="key-token">换令牌</button>' +
                '<button class="btn btn-ghost btn-sm" type="button" data-action="key-pair">换密钥对</button>' +
                '<button class="btn btn-ghost btn-sm" type="button" data-action="key-regenerate">全部重生成</button>' +
                '<button class="icon-btn danger-text" type="button" data-action="key-delete" aria-label="删除 ' + esc(service.name) + ' 的凭证" title="删除凭证"><svg class="icon sm"><use href="#i-trash"/></svg></button>'
              : '<button class="btn btn-secondary btn-sm" type="button" data-action="key-generate">生成凭证</button>') +
          "</span>" +
        "</div>";
      }).join("") +
    "</div>";
  }

  function renderTree() {
    const filter = $("#tree-filter").value.trim().toLowerCase();
    const match = (...values) => values.some((value) => String(value || "").toLowerCase().includes(filter));
    const html = state.resources.map((project) => {
      const projectMatches = match(project.name, project.id);
      const environments = project.environments || [];
      const envsHtml = environments.map((environment) => {
        const envMatches = projectMatches || match(environment.name);
        const services = (environment.services || []).filter((service) => {
          if (!filter) return true;
          return envMatches || match(service.name);
        });
        if (filter && !envMatches && services.length === 0) return "";
        const envKey = project.id + "|" + environment.name;
        const collapsed = !filter && state.collapsedEnvs.has(envKey);
        const envSelected = state.route.mode === "env" && state.route.project === project.id &&
          state.route.environment === environment.name;
        const missingKey = (environment.services || []).some((service) => !service.keyId);
        const servicesHtml = services.map((service) => {
          const selected = state.route.mode === "service" && state.route.project === project.id &&
            state.route.environment === environment.name && state.route.service === service.name;
          const summary = findSummary(project.id, environment.name, service.name);
          const dirty = selected && isDirty();
          return '<button class="service-row' + (selected ? " selected" : "") + '" type="button" role="treeitem" aria-selected="' +
            String(selected) + '" data-action="open-service" data-project="' + esc(project.id) + '" data-environment="' +
            esc(environment.name) + '" data-service="' + esc(service.name) + '">' +
            '<span class="dot ' + (dirty ? "warn" : (service.keyId ? "ok" : "warn")) + '"></span>' +
            '<span class="service-name mono">' + esc(service.name) + "</span>" +
            '<span class="ver mono">' + (summary && summary.version ? "v" + summary.version : "未发布") + "</span>" +
          "</button>";
        }).join("");
        return '<div class="tree-env">' +
          '<div class="tree-row env-row">' +
            '<button class="tree-toggle" type="button" data-action="toggle-env" data-env-key="' + esc(envKey) + '" aria-expanded="' + String(!collapsed) + '" aria-label="折叠环境 ' + esc(environment.name) + '"><svg class="icon sm"><use href="#i-chevron"/></svg></button>' +
            '<button class="tree-name env-name' + (envSelected ? " selected" : "") + '" type="button" data-action="open-env" data-project="' + esc(project.id) + '" data-environment="' + esc(environment.name) + '"><span class="mono">' + esc(environment.name) + '</span><span class="count">' + (environment.services || []).length + " 服务</span>" +
            (missingKey ? '<span class="dot warn" title="有服务缺少凭证"></span>' : "") + "</button>" +
            '<span class="tree-actions"><button class="icon-btn" type="button" data-action="new-service" data-project="' + esc(project.id) + '" data-environment="' + esc(environment.name) + '" aria-label="在 ' + esc(environment.name) + ' 中新建服务" title="新建服务"><svg class="icon sm"><use href="#i-plus"/></svg></button></span>' +
          "</div>" +
          '<div class="tree-children"' + (collapsed ? " hidden" : "") + ">" + servicesHtml + "</div>" +
        "</div>";
      }).join("");
      if (filter && !projectMatches && !envsHtml) return "";
      const collapsedProject = !filter && state.collapsedProjects.has(project.id);
      return '<section class="tree-project">' +
        '<div class="tree-row">' +
          '<button class="tree-toggle" type="button" data-action="toggle-project" data-project="' + esc(project.id) + '" aria-expanded="' + String(!collapsedProject) + '" aria-label="折叠项目 ' + esc(project.name) + '"><svg class="icon sm"><use href="#i-chevron"/></svg></button>' +
          '<button class="tree-name project-name" type="button" data-action="toggle-project" data-project="' + esc(project.id) + '">' + esc(project.name || project.id) + "</button>" +
          '<span class="tree-actions">' +
            '<button class="icon-btn" type="button" data-action="new-env" data-project="' + esc(project.id) + '" aria-label="在 ' + esc(project.name) + ' 中新建环境" title="新建环境"><svg class="icon sm"><use href="#i-plus"/></svg></button>' +
            '<button class="icon-btn" type="button" data-action="delete-project" data-project="' + esc(project.id) + '" aria-label="删除项目 ' + esc(project.name) + '" title="删除项目"><svg class="icon sm"><use href="#i-trash"/></svg></button>' +
          "</span>" +
        "</div>" +
        '<div class="tree-children"' + (collapsedProject ? " hidden" : "") + ">" + envsHtml + "</div>" +
      "</section>";
    }).join("");
    $("#tree").innerHTML = html || (filter
      ? '<div class="tree-empty">没有匹配的资源<button class="link" type="button" data-action="clear-filter">清除过滤</button></div>'
      : '<div class="tree-empty">还没有项目<button class="link" type="button" data-action="new-project">新建项目</button></div>');
  }

  function showEmpty() {
    state.route = { mode: "empty", project: "", environment: "", service: "" };
    state.editor = null;
    $("#view-service").hidden = true;
    $("#view-env").hidden = true;
    $("#view-keys").hidden = true;
    $("#view-empty").hidden = false;
    $("#nav-keys").classList.remove("is-active");
    document.title = "枢钥 Keynest";
  }

  function showView(mode) {
    $("#view-empty").hidden = mode !== "empty";
    $("#view-service").hidden = mode !== "service";
    $("#view-env").hidden = mode !== "env";
    $("#view-keys").hidden = mode !== "keys";
    $("#nav-keys").classList.toggle("is-active", mode === "keys");
  }

  function expandAncestors(route) {
    if (!route.project) return;
    state.collapsedProjects.delete(route.project);
    if (route.environment) state.collapsedEnvs.delete(route.project + "|" + route.environment);
  }

  async function handleRoute(hash) {
    const target = hash || location.hash || "#/";
    const route = parseHash(target);
    if (route.mode === "service") {
      const entry = { project: findProject(route.project), environment: findEnvironment(route.project, route.environment), service: findService(route.project, route.environment, route.service) };
      if (!entry.project || !entry.environment || !entry.service) {
        state.hash = "#/";
        history.replaceState(null, "", "#/");
        showEmpty();
        renderTree();
        return;
      }
    }
    if (route.mode === "env") {
      if (!findProject(route.project) || !findEnvironment(route.project, route.environment)) {
        state.hash = "#/";
        history.replaceState(null, "", "#/");
        showEmpty();
        renderTree();
        return;
      }
    }
    const previous = state.route;
    state.route = route;
    state.hash = hashFor(route);
    if (route.mode !== "service" ||
      previous.mode !== "service" || previous.project !== route.project ||
      previous.environment !== route.environment || previous.service !== route.service) {
      state.tab = "config";
      state.history = [];
    }
    expandAncestors(route);
    closeSidebar();
    if (route.mode === "empty") {
      showEmpty();
      renderTree();
      return;
    }
    if (route.mode === "keys") {
      showView("keys");
      try {
        await loadKeys();
      } catch (failure) {
        if (failure.status !== 401) toastError(failure);
      }
      renderKeys();
      renderTree();
      document.title = "访问凭证 · Keynest";
      return;
    }
    if (route.mode === "env") {
      showView("env");
      renderEnvView();
      renderTree();
      return;
    }
    showView("service");
    const requestHash = state.hash;
    state.editor = null;
    $("#svc-crumbs").textContent = "";
    $("#svc-title").textContent = route.service;
    $("#svc-chips").innerHTML = '<span class="chip">正在载入</span>';
    $("#save-line").innerHTML = "";
    $("#field-groups").innerHTML = "";
    try {
      const editor = await loadDraftFor(route);
      if (state.hash !== requestHash) return;
      state.editor = editor;
      renderServiceView();
      renderTree();
    } catch (failure) {
      if (failure.status !== 401) {
        toastError(failure);
        showEmpty();
        renderTree();
      }
    }
  }

  function navigate(hash) {
    if (!state.loggedIn) return;
    if (hash === state.hash && hash === location.hash) return;
    if (isDirty()) {
      state.pendingHash = hash;
      openUnsaved();
      return;
    }
    if (location.hash === hash) {
      handleRoute(hash);
      return;
    }
    location.hash = hash;
  }

  function commitHash(hash) {
    state.bypassHash = true;
    state.pendingHash = null;
    if (location.hash === hash) {
      state.bypassHash = false;
      handleRoute(hash);
      return;
    }
    location.hash = hash;
  }

  function openUnsaved() {
    const entry = currentServiceEntry();
    const target = state.pendingHash ? parseHash(state.pendingHash) : null;
    let text = "当前服务的草稿有未保存的改动。离开后这些改动会丢失。";
    if (entry && target) {
      if (target.mode === "service") text = "当前服务有未保存的草稿改动。继续前往 " + target.service + " 会丢失这些改动。";
      else if (target.mode === "env") text = "当前服务有未保存的草稿改动。继续前往环境 " + target.environment + " 会丢失这些改动。";
      else if (target.mode === "keys") text = "当前服务有未保存的草稿改动。继续前往访问凭证会丢失这些改动。";
    }
    $("#unsaved-text").textContent = text;
    openDialog("dlg-unsaved");
  }

  function closeSidebar() {
    $("#sidebar").classList.remove("open");
    $("#sidebar-backdrop").hidden = true;
    $("#open-sidebar").setAttribute("aria-expanded", "false");
  }

  function openSidebar() {
    $("#sidebar").classList.add("open");
    $("#sidebar-backdrop").hidden = false;
    $("#open-sidebar").setAttribute("aria-expanded", "true");
  }

  function buildPayload() {
    const values = {};
    const preserveSecrets = [];
    const clearSecrets = [];
    for (const field of state.editor.schema) {
      if (isSensitive(field)) {
        const path = field.path;
        const base = state.editor.baselineSecrets.has(path);
        const mode = state.editor.secretMode.get(path) || (base ? "keep" : "replace");
        if (mode === "clear") {
          if (base) clearSecrets.push(path);
          continue;
        }
        if (mode === "replace") {
          const text = String(state.editor.secretInput.get(path) || "");
          if (text !== "") setPath(values, path, text);
          else if (base) preserveSecrets.push(path);
          continue;
        }
        if (base) preserveSecrets.push(path);
        continue;
      }
      const raw = state.editor.values[field.path];
      const text = String(raw ?? "");
      if (field.type === "boolean") {
        setPath(values, field.path, text === "true");
        continue;
      }
      if (field.type === "integer") {
        if (text.trim() !== "") setPath(values, field.path, Number(text));
        continue;
      }
      if (field.type === "number") {
        if (text.trim() !== "") setPath(values, field.path, Number(text));
        continue;
      }
      if (field.type === "json") {
        if (text.trim() !== "") setPath(values, field.path, JSON.parse(text));
        continue;
      }
      setPath(values, field.path, text);
    }
    return { schema: state.editor.schema, values, preserveSecrets, clearSecrets };
  }

  function setSaving(busy) {
    state.busy = busy;
    for (const id of ["save-draft", "msb-save", "publish", "msb-publish"]) {
      const button = document.getElementById(id);
      if (button) button.disabled = busy;
    }
  }

  async function reloadEditor() {
    const route = { ...state.route };
    const editor = await loadDraftFor(route);
    if (state.route.mode !== "service" || state.route.service !== route.service ||
      state.route.project !== route.project || state.route.environment !== route.environment) {
      return;
    }
    state.editor = editor;
    renderServiceView();
    renderTree();
  }

  async function refreshSummariesQuietly() {
    try {
      await loadSummaries();
      renderTree();
    } catch (_) {
      // the editor remains usable if the summary refresh fails
    }
  }

  async function saveDraft(options = {}) {
    if (!state.editor || state.busy || state.route.mode !== "service") return false;
    const errors = collectErrors();
    if (errors.length) {
      toast("有 " + errors.length + " 个字段需要修正", "error");
      focusField(errors[0].index);
      return false;
    }
    const payload = buildPayload();
    setSaving(true);
    try {
      await api(draftUrl(state.route), { method: "PUT", body: payload });
      await reloadEditor();
      if (!options.silent) toast("草稿已保存");
      refreshSummariesQuietly();
      return true;
    } catch (failure) {
      if (failure.status !== 401) toastError(failure);
      return false;
    } finally {
      setSaving(false);
    }
  }

  function openPublishDialog() {
    if (!state.editor) return;
    const entry = currentServiceEntry();
    if (!entry) return;
    const errors = collectErrors();
    if (errors.length) {
      toast("有 " + errors.length + " 个字段需要修正", "error");
      focusField(errors[0].index);
      return;
    }
    if (!state.editor.schema.length) {
      toast("至少添加一个字段后才能发布", "error");
      return;
    }
    const sensitive = state.editor.schema.filter(isSensitive).length;
    const nextVersion = (state.editor.version || 0) + 1;
    $("#publish-body").innerHTML =
      '<p class="dialog-lead">发布后，客户端通过 SDK 读取到的配置会切换到新版本。</p>' +
      '<ul class="summary">' +
        "<li><span>服务</span><strong>" + esc(entry.project.id + " / " + entry.environment.name + " / " + entry.service.name) + "</strong></li>" +
        "<li><span>字段</span><strong>" + state.editor.schema.length + " 个</strong></li>" +
        "<li><span>敏感字段</span><strong>" + sensitive + " 个</strong></li>" +
        "<li><span>新版本</span><strong>v" + nextVersion + "</strong></li>" +
      "</ul>" +
      (state.editor.version ? "" : '<p class="hint publish-first">这是首次发布。发布后该服务即可用访问令牌读取配置。</p>');
    openDialog("dlg-publish");
  }

  async function beginPublish() {
    if (!state.editor || state.busy) return;
    if (!state.editor.schema.length) {
      toast("至少添加一个字段后才能发布", "error");
      return;
    }
    if (isDirty()) {
      const saved = await saveDraft({ silent: true });
      if (!saved) return;
    }
    openPublishDialog();
  }

  async function confirmPublish() {
    if (state.busy) return;
    const button = $("#confirm-publish");
    button.disabled = true;
    setSaving(true);
    try {
      const payload = await api(draftUrl(state.route, "/publish"), { method: "POST" });
      closeDialog(dialogById("dlg-publish"));
      toast("已发布 v" + payload.version);
      loadCDNStatus().catch(() => {});
      await reloadEditor();
      refreshSummariesQuietly();
      if (state.tab === "history") loadHistory();
    } catch (failure) {
      if (failure.status !== 401) toastError(failure);
    } finally {
      button.disabled = false;
      setSaving(false);
    }
  }

  function maskPreview(text, format) {
    if (!state.editor) return text;
    const fields = state.editor.schema.filter(isSensitive);
    if (!fields.length) return text;
    if (format === "env") {
      const envs = new Set(fields.map((field) => field.environment).filter(Boolean));
      return String(text).split("\n").map((line) => {
        const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
        if (match && envs.has(match[1])) return match[1] + '="••••••"';
        return line;
      }).join("\n");
    }
    const paths = new Set(fields.map((field) => field.yaml || field.path));
    const stack = [];
    return String(text).split("\n").map((line) => {
      const match = line.match(/^(\s*)([A-Za-z0-9_.-]+):(.*)$/);
      if (!match) return line;
      const indent = match[1].length;
      while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();
      stack.push({ indent, key: match[2] });
      const path = stack.map((item) => item.key).join(".");
      if (paths.has(path)) return match[1] + match[2] + ': "••••••"';
      return line;
    }).join("\n");
  }

  async function openPreview(format) {
    if (!state.editor) return;
    if (isDirty()) {
      const saved = await saveDraft({ silent: true });
      if (!saved) return;
    }
    try {
      const raw = await api(draftUrl(state.route, "/render/" + format), { rawText: true });
      const masked = maskPreview(raw, format);
      const reveal = masked !== raw;
      state.preview = { raw, masked, visible: false, reveal, history: false };
      $("#preview-title").textContent = format === "env" ? "预览 .env" : "预览 YAML";
      $("#preview-content").textContent = masked;
      $("#preview-hint").textContent = reveal ? "密钥值已遮蔽。" : "此预览不包含敏感字段。";
      $("#preview-reveal").hidden = !reveal;
      $("#preview-reveal").textContent = "显示明文";
      openDialog("dlg-preview");
    } catch (failure) {
      if (failure.status === 404) toast("草稿尚未创建，请先添加字段并保存", "error");
      else if (failure.status !== 401) toastError(failure);
    }
  }

  function openHistoryPreview(version) {
    const item = state.history.find((entry) => Number(entry.version) === Number(version));
    if (!item) return;
    const values = {};
    for (const [key, value] of Object.entries(item.values || {})) values[key] = value;
    const redact = (schema, source) => {
      const clone = JSON.parse(JSON.stringify(source || {}));
      for (const field of schema || []) {
        if (!isSensitive(field)) continue;
        const current = getPath(clone, field.path);
        if (current !== undefined && current !== null && current !== "") setPath(clone, field.path, "••••••");
      }
      return clone;
    };
    const content = JSON.stringify({ schema: item.schema || [], values: redact(item.schema, values) }, null, 2);
    state.preview = { raw: content, masked: content, visible: true, reveal: false, history: true };
    $("#preview-title").textContent = "历史版本 v" + item.version;
    $("#preview-content").textContent = content;
    $("#preview-hint").textContent = "该版本中的敏感值已遮蔽。";
    $("#preview-reveal").hidden = true;
    openDialog("dlg-preview");
  }

  function togglePreviewReveal() {
    if (!state.preview.reveal) return;
    state.preview.visible = !state.preview.visible;
    $("#preview-content").textContent = state.preview.visible ? state.preview.raw : state.preview.masked;
    $("#preview-hint").textContent = state.preview.visible ? "明文仅显示在当前浏览器中，关闭后不再保留。" : "密钥值已遮蔽。";
    $("#preview-reveal").textContent = state.preview.visible ? "隐藏明文" : "显示明文";
  }

  function openProjectDialog() {
    const form = $("#form-project");
    form.reset();
    openDialog("dlg-project");
    form.elements.id.focus();
  }

  function openEnvDialog(project) {
    const form = $("#form-env");
    form.reset();
    form.elements.project.value = project.id;
    openDialog("dlg-env");
    form.elements.name.focus();
  }

  function openServiceDialog(project, environment) {
    const form = $("#form-service");
    form.reset();
    form.elements.scope.value = project.id + " / " + environment.name;
    state.dialogScope = { project, environment };
    openDialog("dlg-service");
    form.elements.name.focus();
  }

  function showToken(token) {
    $("#token-value").textContent = token;
    openDialog("dlg-token");
  }

  async function submitProject(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const id = form.elements.id.value.trim();
    const name = form.elements.name.value.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id)) {
      toast("项目标识格式不正确", "error");
      form.elements.id.focus();
      return;
    }
    if (!name) {
      toast("请填写项目名称", "error");
      form.elements.name.focus();
      return;
    }
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      await api("/api/v1/admin/projects", { method: "POST", body: { id, name } });
      closeDialog(dialogById("dlg-project"));
      await loadResources();
      await loadSummaries();
      renderTree();
      toast("项目已创建");
    } catch (failure) {
      if (failure.status !== 401) toastError(failure);
    } finally {
      button.disabled = false;
    }
  }

  async function submitEnvironment(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const project = form.elements.project.value.trim();
    const name = form.elements.name.value.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name)) {
      toast("环境标识格式不正确", "error");
      form.elements.name.focus();
      return;
    }
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      await api("/api/v1/admin/projects/" + enc(project) + "/environments", {
        method: "POST", body: { name }
      });
      closeDialog(dialogById("dlg-env"));
      await loadResources();
      await loadSummaries();
      renderTree();
      toast("环境已创建");
      navigate(hashFor({ mode: "env", project, environment: name }));
    } catch (failure) {
      if (failure.status !== 401) toastError(failure);
    } finally {
      button.disabled = false;
    }
  }

  async function submitService(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const scope = state.dialogScope;
    const name = form.elements.name.value.trim();
    if (!scope) return;
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name)) {
      toast("服务标识格式不正确", "error");
      form.elements.name.focus();
      return;
    }
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const payload = await api("/api/v1/admin/projects/" + enc(scope.project.id) + "/environments/" +
        enc(scope.environment.name) + "/services", { method: "POST", body: { name } });
      closeDialog(dialogById("dlg-service"));
      await loadResources();
      await loadSummaries();
      renderTree();
      navigate(hashFor({ mode: "service", project: scope.project.id, environment: scope.environment.name, service: name }));
      showToken(payload.token);
      toast("服务已创建，访问令牌只显示一次");
    } catch (failure) {
      if (failure.status !== 401) toastError(failure);
    } finally {
      button.disabled = false;
    }
  }

  function openFieldDialog(mode, index) {
    const form = $("#form-field");
    form.reset();
    $("#field-form-error").textContent = "";
    state.fieldEdit = { mode, index: index === undefined ? -1 : index };
    const field = mode === "edit" && state.editor ? state.editor.schema[index] : null;
    $("#field-dialog-title").textContent = mode === "edit" ? "编辑字段" : "添加字段";
    $("#field-submit").textContent = mode === "edit" ? "保存字段" : "添加字段";
    if (field) {
      form.elements.path.value = field.path || "";
      form.elements.label.value = field.label || "";
      form.elements.type.value = field.type || "string";
      form.elements.env.value = field.environment || "";
      form.elements.yaml.value = field.yaml || "";
      form.elements.desc.value = field.description || "";
      form.elements.options.value = (field.options || []).join(", ");
      form.elements.default.value = field.default === undefined || field.default === null
        ? "" : (typeof field.default === "object" ? JSON.stringify(field.default) : String(field.default));
      form.elements.required.checked = Boolean(field.required);
      form.elements.sensitive.checked = Boolean(field.sensitive || field.type === "secret");
    }
    syncFieldTypeUI();
    openDialog("dlg-field");
    form.elements.path.focus();
  }

  function syncFieldTypeUI() {
    const form = $("#form-field");
    const type = form.elements.type.value;
    const sensitive = type === "secret";
    $$(".enum-only", form).forEach((node) => { node.hidden = type !== "enum"; });
    $$(".default-only", form).forEach((node) => { node.hidden = sensitive; });
    if (sensitive) form.elements.sensitive.checked = true;
    form.elements.default.disabled = sensitive;
  }

  function parseDefaultValue(form, type) {
    const text = form.elements.default.value.trim();
    if (text === "" || type === "secret") return null;
    if (type === "integer") {
      if (!/^[+-]?\d+$/.test(text)) throw new Error("默认值必须是整数。");
      return Number(text);
    }
    if (type === "number") {
      if (!Number.isFinite(Number(text))) throw new Error("默认值必须是数字。");
      return Number(text);
    }
    if (type === "boolean") {
      if (text !== "true" && text !== "false") throw new Error("布尔默认值只能是 true 或 false。");
      return text === "true";
    }
    if (type === "json") {
      try {
        return JSON.parse(text);
      } catch (_) {
        throw new Error("默认值不是有效的 JSON。");
      }
    }
    return text;
  }

  function submitField(event) {
    event.preventDefault();
    if (!state.editor || !state.fieldEdit) return;
    const form = event.currentTarget;
    const type = form.elements.type.value;
    const path = form.elements.path.value.trim();
    const label = form.elements.label.value.trim();
    const environment = form.elements.env.value.trim();
    const yaml = form.elements.yaml.value.trim();
    const description = form.elements.desc.value.trim();
    const options = form.elements.options.value.split(",").map((item) => item.trim()).filter(Boolean);
    const required = form.elements.required.checked;
    const sensitive = form.elements.sensitive.checked || type === "secret";
    const segments = path.split(".");
    const error = $("#field-form-error");
    error.textContent = "";
    if (!path || segments.some((segment) => !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(segment))) {
      error.textContent = "字段路径格式不正确。";
      form.elements.path.focus();
      return;
    }
    if (!label) {
      error.textContent = "请填写显示名称。";
      form.elements.label.focus();
      return;
    }
    if (environment && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(environment)) {
      error.textContent = "环境变量名格式不正确。";
      form.elements.env.focus();
      return;
    }
    if (type === "enum" && options.length === 0) {
      error.textContent = "enum 字段至少需要一个可选值。";
      form.elements.options.focus();
      return;
    }
    if (yaml && yaml.split(".").some((segment) => !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(segment))) {
      error.textContent = "YAML 路径格式不正确。";
      form.elements.yaml.focus();
      return;
    }
    let defaultValue;
    try {
      defaultValue = parseDefaultValue(form, type);
    } catch (failure) {
      error.textContent = failure.message;
      form.elements.default.focus();
      return;
    }
    if (sensitive && defaultValue !== null) {
      error.textContent = "敏感字段不能设置默认值。";
      form.elements.default.focus();
      return;
    }
    const duplicate = state.editor.schema.some((field, index) =>
      index !== state.fieldEdit.index && field.path === path);
    if (duplicate) {
      error.textContent = "字段路径与其他字段重复。";
      form.elements.path.focus();
      return;
    }
    const duplicateEnv = environment && state.editor.schema.some((field, index) =>
      index !== state.fieldEdit.index && field.environment === environment);
    if (duplicateEnv) {
      error.textContent = "环境变量名与其他字段重复。";
      form.elements.env.focus();
      return;
    }
    const finalYaml = yaml || path;
    const duplicateYaml = state.editor.schema.some((field, index) =>
      index !== state.fieldEdit.index && (field.yaml || field.path) === finalYaml);
    if (duplicateYaml) {
      error.textContent = "YAML 路径与其他字段重复。";
      form.elements.yaml.focus();
      return;
    }
    const next = {
      path,
      label,
      type,
      description,
      required,
      sensitive,
      environment,
      yaml,
      options: type === "enum" ? options : undefined,
      default: defaultValue === null ? undefined : defaultValue
    };
    const previous = state.fieldEdit.mode === "edit" ? state.editor.schema[state.fieldEdit.index] : null;
    if (previous && isSensitive(previous) && isSensitive(next) &&
      state.editor.baselineSecrets.has(previous.path) && previous.path !== path) {
      error.textContent = "已设置的敏感字段不能修改路径，请先清除密钥或转换为普通字段。";
      form.elements.path.focus();
      return;
    }
    if (!previous) {
      state.editor.schema.push(next);
      if (defaultValue !== null) {
        state.editor.values[path] = displayValue(next, defaultValue);
      } else {
        state.editor.values[path] = "";
      }
      state.editor.savedValues[path] = state.editor.savedValues[path] ?? "";
      if (isSensitive(next)) {
        state.editor.secretMode.set(path, "replace");
        state.editor.secretInput.set(path, "");
      }
    } else {
      const oldPath = previous.path;
      if (oldPath !== path) {
        state.editor.values[path] = state.editor.values[oldPath];
        state.editor.savedValues[path] = state.editor.savedValues[oldPath];
        delete state.editor.values[oldPath];
        delete state.editor.savedValues[oldPath];
      }
      if (isSensitive(previous) && isSensitive(next)) {
        state.editor.secretMode.set(path, state.editor.secretMode.get(oldPath) || "keep");
        state.editor.secretInput.set(path, state.editor.secretInput.get(oldPath) || "");
        if (oldPath !== path) {
          state.editor.secretMode.delete(oldPath);
          state.editor.secretInput.delete(oldPath);
        }
      } else if (!isSensitive(previous) && isSensitive(next)) {
        const current = state.editor.values[path] ?? "";
        state.editor.secretMode.set(path, "replace");
        state.editor.secretInput.set(path, current);
        state.editor.values[path] = "";
      } else if (isSensitive(previous) && !isSensitive(next)) {
        state.editor.secretMode.delete(path);
        state.editor.secretInput.delete(path);
        state.editor.baselineSecrets.delete(path);
        state.editor.values[path] = "";
        state.editor.savedValues[path] = "";
      }
      state.editor.schema[state.fieldEdit.index] = next;
    }
    closeDialog(dialogById("dlg-field"));
    renderServiceView();
    renderTree();
    toast(state.fieldEdit.mode === "edit" ? "字段已更新" : "字段已添加");
  }

  function deleteField(index) {
    if (!state.editor) return;
    const field = state.editor.schema[index];
    if (!field) return;
    const secretSet = isSensitive(field) && state.editor.baselineSecrets.has(field.path);
    askConfirm({
      title: "删除字段",
      text: "将从草稿中移除字段 " + field.path + "。保存草稿后生效，发布版本不受影响。",
      extra: secretSet ? '<p class="hint">该字段已设置密钥，删除并保存后草稿中的密钥也会移除。</p>' : "",
      confirmLabel: "删除字段",
      danger: true,
      onConfirm: async () => {
        state.editor.schema.splice(index, 1);
        delete state.editor.values[field.path];
        delete state.editor.savedValues[field.path];
        state.editor.secretMode.delete(field.path);
        state.editor.secretInput.delete(field.path);
        renderServiceView();
        renderTree();
        toast("字段已从草稿移除，保存草稿后生效");
      }
    });
  }

  function askConfirm(options) {
    $("#confirm-title").textContent = options.title || "请确认操作";
    $("#confirm-text").textContent = options.text || "";
    $("#confirm-extra").innerHTML = options.extra || "";
    const button = $("#confirm-ok");
    button.textContent = options.confirmLabel || "确认";
    button.className = "btn " + (options.danger ? "btn-danger-solid" : "btn-primary");
    state.confirmHandler = options.onConfirm || null;
    openDialog("dlg-confirm");
  }

  async function runConfirm() {
    const handler = state.confirmHandler;
    state.confirmHandler = null;
    if (!handler) {
      closeDialog(dialogById("dlg-confirm"));
      return;
    }
    const button = $("#confirm-ok");
    button.disabled = true;
    try {
      closeDialog(dialogById("dlg-confirm"));
      await handler();
    } catch (failure) {
      if (failure.status !== 401) toastError(failure);
    } finally {
      button.disabled = false;
    }
  }

  async function deleteProject(project) {
    const environments = project.environments || [];
    const services = environments.reduce((sum, env) => sum + (env.services || []).length, 0);
    askConfirm({
      title: "删除项目",
      text: "删除项目 " + (project.name || project.id) + " 及其全部环境、服务、配置和访问凭证。此操作不可撤销。",
      extra: '<ul class="summary"><li><span>环境</span><strong>' + environments.length +
        " 个</strong></li><li><span>服务</span><strong>" + services + " 个</strong></li></ul>",
      confirmLabel: "删除项目",
      danger: true,
      onConfirm: async () => {
        await api("/api/v1/admin/projects/" + enc(project.id), { method: "DELETE" });
        if (state.route.project === project.id) {
          commitHash("#/");
        }
        await loadResources();
        await loadSummaries();
        await loadKeys();
        renderTree();
        toast("项目已删除");
      }
    });
  }

  async function deleteEnvironment() {
    const project = findProject(state.route.project);
    const environment = findEnvironment(state.route.project, state.route.environment);
    if (!project || !environment) return;
    const services = environment.services || [];
    askConfirm({
      title: "删除环境",
      text: "删除环境 " + project.id + " / " + environment.name +
        " 及其全部服务、配置和访问凭证。此操作不可撤销。",
      extra: '<ul class="summary"><li><span>服务</span><strong>' + services.length + " 个</strong></li></ul>",
      confirmLabel: "删除环境",
      danger: true,
      onConfirm: async () => {
        await api("/api/v1/admin/projects/" + enc(project.id) + "/environments/" + enc(environment.name),
          { method: "DELETE" });
        commitHash("#/");
        await loadResources();
        await loadSummaries();
        await loadKeys();
        renderTree();
        toast("环境已删除");
      }
    });
  }

  async function deleteService(serviceName) {
    const project = findProject(state.route.project);
    const environment = findEnvironment(state.route.project, state.route.environment);
    if (!project || !environment) return;
    askConfirm({
      title: "删除服务",
      text: "删除服务 " + environment.name + " / " + serviceName + " 及其草稿、发布历史和访问凭证。此操作不可撤销。",
      confirmLabel: "删除服务",
      danger: true,
      onConfirm: async () => {
        await api("/api/v1/admin/projects/" + enc(project.id) + "/environments/" + enc(environment.name) +
          "/services/" + enc(serviceName), { method: "DELETE" });
        if (state.route.mode === "service" && state.route.service === serviceName) {
          commitHash(hashFor({ mode: "env", project: project.id, environment: environment.name }));
        }
        await loadResources();
        await loadSummaries();
        await loadKeys();
        renderTree();
        toast("服务已删除");
      }
    });
  }

  function clearConfig() {
    if (!state.editor || state.route.mode !== "service") return;
    const entry = currentServiceEntry();
    if (!entry) return;
    askConfirm({
      title: "清除配置",
      text: "删除服务 " + entry.service.name + " 的草稿与发布历史。访问凭证和服务本身不受影响。此操作不可撤销。",
      confirmLabel: "清除配置",
      danger: true,
      onConfirm: async () => {
        await api(draftUrl(state.route), { method: "DELETE" });
        await reloadEditor();
        await refreshSummariesQuietly();
        toast("配置已清除");
      }
    });
  }

  function diffText(value) {
    const text = value === undefined || value === null ? "" : String(value);
    return text.length > 120 ? text.slice(0, 120) + "…" : text;
  }

  function buildVersionDiff(item, editor) {
    const historySchema = Array.isArray(item.schema) ? item.schema : [];
    const currentSchema = Array.isArray(editor.schema) ? editor.schema : [];
    const historyValues = item.values || {};
    const historyByPath = new Map(historySchema.map((field) => [field.path, field]));
    const currentByPath = new Map(currentSchema.map((field) => [field.path, field]));
    const result = { added: [], removed: [], changed: [] };

    for (const field of historySchema) {
      if (!currentByPath.has(field.path)) {
        result.added.push({ path: field.path, label: field.label, type: field.type });
      }
    }
    for (const field of currentSchema) {
      if (!historyByPath.has(field.path)) {
        result.removed.push({ path: field.path, label: field.label, type: field.type });
      }
    }
    for (const field of historySchema) {
      const current = historyByPath.has(field.path) ? currentByPath.get(field.path) : null;
      if (!current) continue;
      const changes = [];
      const attributes = [
        ["label", "显示名称"], ["type", "类型"], ["description", "说明"],
        ["required", "必填"], ["environment", "环境变量"], ["yaml", "YAML 路径"]
      ];
      for (const [key, label] of attributes) {
        const before = current[key];
        const after = field[key];
        if (String(before ?? "") !== String(after ?? "")) {
          changes.push({ label, before: diffText(before), after: diffText(after) });
        }
      }
      const currentOptions = (current.options || []).join(", ");
      const historyOptions = (field.options || []).join(", ");
      if (currentOptions !== historyOptions) {
        changes.push({ label: "可选项", before: diffText(currentOptions), after: diffText(historyOptions) });
      }
      if (isSensitive(field) || isSensitive(current)) {
        const beforeSet = effectiveSecretSet(field.path);
        const afterSet = getPath(historyValues, field.path) === KEEP_SECRET;
        if (beforeSet !== afterSet) {
          changes.push({
            label: "敏感值",
            before: beforeSet ? "已设置" : "未设置",
            after: afterSet ? "已设置" : "未设置"
          });
        }
      } else {
        const before = String(editor.values[field.path] ?? "");
        const after = displayValue(field, getPath(historyValues, field.path));
        if (before !== after) {
          changes.push({ label: "值", before: diffText(before), after: diffText(after) });
        }
      }
      if (changes.length) {
        result.changed.push({ path: field.path, label: field.label || field.path, changes });
      }
    }
    return result;
  }

  function renderVersionDiff(diff, version) {
    const total = diff.added.length + diff.removed.length + diff.changed.length;
    if (!total) {
      return '<p class="muted">历史版本 v' + esc(version) + " 与当前草稿一致，无差异。</p>";
    }
    const rows = [];
    if (diff.added.length) {
      rows.push('<h3>恢复后新增的字段</h3><ul class="diff-list">' +
        diff.added.map((field) => '<li class="diff-item diff-add"><span class="chip chip-success">新增</span>' +
          '<code class="mono">' + esc(field.path) + "</code>" +
          (field.label && field.label !== field.path ? " " + esc(field.label) : "") +
          ' <span class="muted">· ' + esc(field.type) + "</span></li>").join("") + "</ul>");
    }
    if (diff.removed.length) {
      rows.push('<h3>恢复后移除的字段</h3><ul class="diff-list">' +
        diff.removed.map((field) => '<li class="diff-item diff-remove"><span class="chip chip-warn">移除</span>' +
          '<code class="mono">' + esc(field.path) + "</code>" +
          (field.label && field.label !== field.path ? " " + esc(field.label) : "") +
          ' <span class="muted">· ' + esc(field.type) + "</span></li>").join("") + "</ul>");
    }
    if (diff.changed.length) {
      rows.push('<h3>字段变更（当前草稿 → 历史 v' + esc(version) + "）</h3>" +
        diff.changed.map((field) => '<div class="diff-field"><code class="mono">' + esc(field.path) + "</code>" +
          '<ul class="diff-list">' + field.changes.map((change) =>
            '<li class="diff-item"><span class="diff-label">' + esc(change.label) + "</span>" +
            '<span class="diff-before">' + esc(change.before || "（空）") + "</span>" +
            '<span class="diff-arrow">→</span>' +
            '<span class="diff-after">' + esc(change.after || "（空）") + "</span></li>").join("") +
          "</ul></div>").join(""));
    }
    return rows.join("");
  }

  function restoreVersion(version) {
    if (!state.editor) return;
    const item = state.history.find((entry) => Number(entry.version) === Number(version));
    if (!item) return;
    const diff = buildVersionDiff(item, state.editor);
    $("#version-diff-title").textContent = "恢复 v" + version + " 为草稿";
    $("#version-diff-body").innerHTML =
      '<div class="notice notice-warn"><svg class="icon"><use href="#i-warn" /></svg>' +
      "<div>恢复只替换草稿，发布的 v" + esc(version) +
      " 不会改变，仍需发布才会生效。当前未保存的修改会被覆盖。</div></div>" +
      renderVersionDiff(diff, version);
    state.diffVersion = Number(version);
    openDialog("dlg-version-diff");
  }

  async function confirmVersionRestore() {
    const version = state.diffVersion;
    if (!version || !state.editor) return;
    const button = $("#confirm-version-restore");
    button.disabled = true;
    closeDialog(dialogById("dlg-version-diff"));
    try {
      await api(draftUrl(state.route, "/history/" + enc(version) + "/restore"), { method: "POST" });
      await reloadEditor();
      await loadHistory();
      toast("已恢复为草稿 v" + version);
    } catch (failure) {
      if (failure.status !== 401) toastError(failure);
    } finally {
      button.disabled = false;
      state.diffVersion = null;
    }
  }

  function openImportDialog() {
    const form = $("#form-import");
    form.reset();
    $("#import-form-error").textContent = "";
    openDialog("dlg-import");
    form.elements.content.focus();
  }

  async function submitImport(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const format = form.elements.format.value;
    const content = form.elements.content.value;
    const error = $("#import-form-error");
    error.textContent = "";
    if (!content.trim()) {
      error.textContent = "请粘贴内容或选择文件。";
      form.elements.content.focus();
      return;
    }
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const payload = await api(draftUrl(state.route, "/import"), {
        method: "POST", body: { format, content }
      });
      closeDialog(dialogById("dlg-import"));
      await reloadEditor();
      await refreshSummariesQuietly();
      state.tab = "config";
      renderTabState();
      toast("已导入 " + payload.fields + " 个字段到草稿");
    } catch (failure) {
      if (failure.status !== 401) error.textContent = failure.message || "导入失败。";
    } finally {
      button.disabled = false;
    }
  }

  async function readImportFile(file) {
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      toast("导入文件不能超过 2 MiB", "error");
      return;
    }
    try {
      const text = await file.text();
      const form = $("#form-import");
      form.elements.content.value = text;
      if (/\.ya?ml$/i.test(file.name)) form.elements.format.value = "yaml";
      else if (/\.json$/i.test(file.name)) form.elements.format.value = "json";
      else form.elements.format.value = "env";
    } catch (_) {
      toast("无法读取该文件", "error");
    }
  }

  async function downloadKey(id, serviceName) {
    try {
      const response = await fetch("/api/v1/admin/keys/" + enc(id) + "/private-key", {
        credentials: "same-origin",
        cache: "no-store"
      });
      if (response.status === 401) {
        handleUnauthorized();
        return;
      }
      if (!response.ok) {
        const text = await response.text();
        let message = text;
        try {
          message = JSON.parse(text).error || text;
        } catch (_) {
          // keep text
        }
        throw new ApiError(message || "下载私钥失败。", response.status);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "keynest-" + id + "-private.pem";
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 4000);
      markActivity();
      toast("私钥已开始下载" + (serviceName ? "：" + serviceName : ""));
    } catch (failure) {
      if (failure.status !== 401) toastError(failure);
    }
  }

  function rowScope(row) {
    return {
      project: row.dataset.project || "",
      environment: row.dataset.environment || "",
      service: row.dataset.service || "",
      key: row.dataset.key || ""
    };
  }

  async function regenerateKeyToken(scope) {
    askConfirm({
      title: "重新生成访问令牌",
      text: "只重新生成访问令牌，RSA 密钥对保持不变。旧令牌会立即失效，新令牌只显示一次。",
      confirmLabel: "换令牌",
      danger: true,
      onConfirm: async () => {
        const payload = await api("/api/v1/admin/projects/" + enc(scope.project) + "/environments/" +
          enc(scope.environment) + "/services/" + enc(scope.service) + "/key/token/regenerate", { method: "POST" });
        await loadKeys();
        renderKeys();
        showToken(payload.token);
        toast("访问令牌已重新生成");
      }
    });
  }

  async function regenerateKeyPair(scope) {
    askConfirm({
      title: "重新生成 RSA 密钥对",
      text: "只重新生成 RSA 密钥对，访问令牌保持不变。已签发的信封将无法用旧私钥解开，请同步更新客户端私钥。",
      confirmLabel: "换密钥对",
      danger: true,
      onConfirm: async () => {
        await api("/api/v1/admin/projects/" + enc(scope.project) + "/environments/" +
          enc(scope.environment) + "/services/" + enc(scope.service) + "/key/pair/regenerate", { method: "POST" });
        await loadKeys();
        renderKeys();
        toast("RSA 密钥对已重新生成");
      }
    });
  }

  async function viewKey(id, serviceName) {
    try {
      const payload = await api("/api/v1/admin/keys/" + enc(id) + "/private-key/view", { cache: "no-store" });
      $("#private-key-content").textContent = payload.privateKey || "";
      $("#private-key-title").textContent = "查看私钥" + (serviceName ? " · " + serviceName : "");
      openDialog("dlg-private-key");
    } catch (failure) {
      if (failure.status !== 401) toastError(failure);
    }
  }

  async function regenerateKey(scope) {
    askConfirm({
      title: "重新生成访问凭证",
      text: "现有访问令牌会立即失效，使用旧令牌的服务将无法读取配置。新令牌只显示一次。",
      confirmLabel: "重新生成",
      danger: true,
      onConfirm: async () => {
        const payload = await api("/api/v1/admin/projects/" + enc(scope.project) + "/environments/" +
          enc(scope.environment) + "/services/" + enc(scope.service) + "/key/regenerate", { method: "POST" });
        await loadResources();
        await loadKeys();
        await loadSummaries();
        renderKeys();
        renderTree();
        if (state.route.mode === "service") {
          await reloadEditor();
        }
        showToken(payload.token);
        toast("访问凭证已重新生成");
      }
    });
  }

  async function createMissingKey(scope) {
    askConfirm({
      title: "生成访问凭证",
      text: "为服务 " + scope.service + " 生成访问令牌与 RSA 密钥。令牌只显示一次。",
      confirmLabel: "生成凭证",
      danger: false,
      onConfirm: async () => {
        const payload = await api("/api/v1/admin/keys", {
          method: "POST",
          body: {
            name: scope.service + "/" + scope.environment,
            project: scope.project,
            environment: scope.environment,
            service: scope.service
          }
        });
        await loadResources();
        await loadKeys();
        renderKeys();
        renderTree();
        showToken(payload.token);
        toast("访问凭证已生成");
      }
    });
  }

  function deleteKey(scope) {
    askConfirm({
      title: "删除访问凭证",
      text: "删除服务 " + scope.service + " 的访问凭证后，使用该令牌的服务将立即无法读取配置。此操作不可撤销。",
      confirmLabel: "删除凭证",
      danger: true,
      onConfirm: async () => {
        await api("/api/v1/admin/keys/" + enc(scope.key), { method: "DELETE" });
        await loadResources();
        await loadKeys();
        await loadSummaries();
        renderKeys();
        renderTree();
        if (state.route.mode === "service") await reloadEditor();
        toast("访问凭证已删除");
      }
    });
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      // fall back to a selection copy
    }
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.left = "-1000px";
    document.body.appendChild(area);
    area.select();
    let copied = false;
    try {
      copied = document.execCommand("copy");
    } catch (_) {
      copied = false;
    }
    area.remove();
    return copied;
  }

  /* Palette */
  function buildPalette() {
    const items = [];
    items.push({ kind: "操作", title: "新建项目", subtitle: "添加一个项目", icon: "i-plus", run: () => openProjectDialog() });
    items.push({ kind: "页面", title: "访问凭证", subtitle: "查看所有服务的凭证", icon: "i-key", run: () => navigate("#/keys") });
    for (const project of state.resources) {
      items.push({
        kind: "项目", title: project.name || project.id, subtitle: project.id,
        icon: "i-chevron", run: () => { state.collapsedProjects.delete(project.id); renderTree(); }
      });
      for (const environment of project.environments || []) {
        items.push({
          kind: "环境", title: environment.name,
          subtitle: (project.name || project.id) + " / " + environment.name,
          icon: "i-chevron",
          run: () => navigate(hashFor({ mode: "env", project: project.id, environment: environment.name }))
        });
        for (const service of environment.services || []) {
          const summary = findSummary(project.id, environment.name, service.name);
          items.push({
            kind: "服务", title: service.name,
            subtitle: (project.name || project.id) + " / " + environment.name +
              (summary && summary.version ? " · v" + summary.version : ""),
            icon: "i-enter",
            run: () => navigate(hashFor({
              mode: "service", project: project.id,
              environment: environment.name, service: service.name
            }))
          });
        }
      }
    }
    return items;
  }

  function openPalette() {
    state.paletteItems = [];
    state.paletteIndex = 0;
    $("#palette-input").value = "";
    renderPalette("");
    openDialog("dlg-palette");
    $("#palette-input").focus();
  }

  function renderPalette(query) {
    const needle = String(query || "").trim().toLowerCase();
    const all = buildPalette();
    const matches = needle
      ? all.filter((item) => (item.title + " " + item.subtitle + " " + item.kind).toLowerCase().includes(needle))
      : all;
    state.paletteItems = matches;
    if (state.paletteIndex >= matches.length) state.paletteIndex = Math.max(0, matches.length - 1);
    $("#palette-list").innerHTML = matches.length
      ? matches.map((item, index) => '<button class="palette-item' + (index === state.paletteIndex ? " is-active" : "") +
          '" type="button" role="option" aria-selected="' + String(index === state.paletteIndex) +
          '" data-index="' + index + '"><svg class="icon"><use href="#' + item.icon + '"/></svg>' +
          '<span class="palette-item-text"><strong>' + esc(item.title) + "</strong><small>" +
          esc(item.subtitle) + "</small></span><span class=\"palette-kind\">" + esc(item.kind) + "</span></button>").join("")
      : '<div class="palette-empty">没有匹配的资源</div>';
  }

  function paletteMove(delta) {
    if (!state.paletteItems.length) return;
    state.paletteIndex = (state.paletteIndex + delta + state.paletteItems.length) % state.paletteItems.length;
    renderPalette($("#palette-input").value);
    const active = $('#palette-list .palette-item[data-index="' + state.paletteIndex + '"]');
    if (active) active.scrollIntoView({ block: "nearest" });
  }

  function paletteRun(index) {
    const item = state.paletteItems[index];
    if (!item) return;
    closeDialog(dialogById("dlg-palette"));
    item.run();
  }

  /* Session timer */
  function startSessionWatch() {
    setInterval(() => {
      if (!state.loggedIn || state.sessionWarned) return;
      if (document.visibilityState === "hidden") return;
      if (Date.now() - state.lastActivity >= SESSION_WARN_MS) {
        state.sessionWarned = true;
        openDialog("dlg-session");
      }
    }, 30000);
  }

  /* Events */
  function bindEvents() {
    $("#login-form").addEventListener("submit", login);
    $("#toggle-password").addEventListener("click", () => {
      const input = $("#login-password");
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      $("#toggle-password").setAttribute("aria-label", show ? "隐藏密码" : "显示密码");
      $("#toggle-password").querySelector("use").setAttribute("href", show ? "#i-eye-off" : "#i-eye");
    });
    $("#logout").addEventListener("click", logout);
    $("#nav-keys").addEventListener("click", () => navigate("#/keys"));
    $("#open-sidebar").addEventListener("click", openSidebar);
    $("#sidebar-backdrop").addEventListener("click", closeSidebar);
    $("#search-trigger").addEventListener("click", openPalette);
    $("#empty-palette").addEventListener("click", openPalette);
    $("#new-project").addEventListener("click", openProjectDialog);
    $("#empty-new-project").addEventListener("click", openProjectDialog);
    $("#tree-filter").addEventListener("input", renderTree);
    $("#tree").addEventListener("click", handleTreeClick);
    $("#save-draft").addEventListener("click", () => saveDraft());
    $("#msb-save").addEventListener("click", () => saveDraft());
    $("#publish").addEventListener("click", beginPublish);
    $("#msb-publish").addEventListener("click", beginPublish);
    $("#confirm-publish").addEventListener("click", confirmPublish);
    $("#add-field").addEventListener("click", () => openFieldDialog("add"));
    $("#history-panel").addEventListener("click", handleHistoryClick);
    $("#confirm-version-restore").addEventListener("click", confirmVersionRestore);
    $("#field-groups").addEventListener("click", handleFieldClick);
    $("#field-groups").addEventListener("input", handleFieldInput);
    $("#field-groups").addEventListener("change", handleFieldInput);
    $$(".tab").forEach((tab) => {
      tab.addEventListener("click", () => setTab(tab.dataset.tab));
      tab.addEventListener("keydown", (event) => {
        if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
        event.preventDefault();
        setTab(state.tab === "config" ? "history" : "config");
        const active = $('.tab[data-tab="' + state.tab + '"]');
        if (active) active.focus();
      });
    });
    $("#more-menu").addEventListener("click", (event) => {
      const button = event.target.closest("[data-more]");
      if (!button) return;
      const action = button.dataset.more;
      closeMenu();
      if (action === "preview-env") openPreview("env");
      if (action === "preview-yaml") openPreview("yaml");
      if (action === "import") openImportDialog();
      if (action === "clear-config") clearConfig();
    });
    $("#new-service").addEventListener("click", () => {
      const project = findProject(state.route.project);
      const environment = findEnvironment(state.route.project, state.route.environment);
      if (project && environment) openServiceDialog(project, environment);
    });
    $("#delete-env").addEventListener("click", deleteEnvironment);
    $("#env-services").addEventListener("click", handleEnvTableClick);
    $("#keys-table").addEventListener("click", handleKeysClick);
    $("#refresh-keys").addEventListener("click", async () => {
      try {
        await loadKeys();
        renderKeys();
        toast("凭证列表已刷新");
      } catch (failure) {
        if (failure.status !== 401) toastError(failure);
      }
    });
    $("#form-project").addEventListener("submit", submitProject);
    $("#form-env").addEventListener("submit", submitEnvironment);
    $("#form-service").addEventListener("submit", submitService);
    $("#form-field").addEventListener("submit", submitField);
    $("#form-import").addEventListener("submit", submitImport);
    $("#form-field").elements.type.addEventListener("change", syncFieldTypeUI);
    $("#import-file").addEventListener("change", (event) => readImportFile(event.target.files[0]));
    $("#confirm-ok").addEventListener("click", runConfirm);
    $("#preview-reveal").addEventListener("click", togglePreviewReveal);
    $("#copy-token").addEventListener("click", async () => {
      const token = $("#token-value").textContent;
      const copied = await copyText(token);
      toast(copied ? "访问令牌已复制" : "无法自动复制，请手动选择令牌", copied ? undefined : "error");
    });
    $("#session-keep").addEventListener("click", async () => {
      try {
        await api("/api/v1/admin/resources");
        closeDialog(dialogById("dlg-session"));
        markActivity();
        toast("会话已续期");
      } catch (failure) {
        if (failure.status !== 401) toastError(failure);
      }
    });
    $("#session-logout").addEventListener("click", () => {
      closeDialog(dialogById("dlg-session"));
      logout();
    });
    $$("[data-close-dialog]").forEach((button) => {
      button.addEventListener("click", () => closeDialog(button.closest("dialog")));
    });
    $("#dlg-unsaved").addEventListener("close", () => {
      if (!state.bypassHash) state.pendingHash = null;
    });
    $("#discard-changes").addEventListener("click", () => {
      const target = state.pendingHash;
      state.editor = null;
      state.pendingHash = null;
      closeDialog(dialogById("dlg-unsaved"));
      if (target) commitHash(target);
    });
    $("#save-and-leave").addEventListener("click", async () => {
      const target = state.pendingHash;
      const button = $("#save-and-leave");
      button.disabled = true;
      button.textContent = "保存中";
      const saved = await saveDraft({ silent: true });
      button.disabled = false;
      button.textContent = "保存草稿并继续";
      if (!saved) {
        state.pendingHash = null;
        closeDialog(dialogById("dlg-unsaved"));
        return;
      }
      state.pendingHash = target;
      closeDialog(dialogById("dlg-unsaved"));
      if (target) commitHash(target);
    });
    $("#palette-input").addEventListener("input", (event) => {
      state.paletteIndex = 0;
      renderPalette(event.target.value);
    });
    $("#palette-input").addEventListener("keydown", (event) => {
      if (event.key === "ArrowDown") {
        event.preventDefault();
        paletteMove(1);
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        paletteMove(-1);
      } else if (event.key === "Enter") {
        event.preventDefault();
        paletteRun(state.paletteIndex);
      }
    });
    $("#palette-list").addEventListener("click", (event) => {
      const button = event.target.closest(".palette-item");
      if (button) paletteRun(Number(button.dataset.index));
    });
    document.addEventListener("keydown", (event) => {
      const commandKey = event.ctrlKey || event.metaKey;
      if (commandKey && event.key.toLowerCase() === "k") {
        event.preventDefault();
        openPalette();
        return;
      }
      if (event.key === "Escape") {
        closeMenu();
        if ($("#sidebar").classList.contains("open")) closeSidebar();
      }
    });
    document.addEventListener("click", (event) => {
      const menu = $("#more-menu");
      if (menu && menu.open && !menu.contains(event.target)) closeMenu();
    });
    window.addEventListener("hashchange", () => {
      if (state.bypassHash) {
        state.bypassHash = false;
        const target = location.hash || "#/";
        state.pendingHash = null;
        handleRoute(target);
        return;
      }
      const target = location.hash || "#/";
      if (isDirty() && hashFor(state.route) !== target) {
        const revert = state.hash || hashFor(state.route);
        history.replaceState(null, "", revert);
        state.pendingHash = target;
        openUnsaved();
        return;
      }
      handleRoute(target);
    });
    window.addEventListener("beforeunload", (event) => {
      if (!isDirty()) return;
      event.preventDefault();
      event.returnValue = "";
    });
    $$("dialog").forEach((dialog) => {
      dialog.addEventListener("click", (event) => {
        if (event.target === dialog) closeDialog(dialog);
      });
    });
    $("#dlg-private-key").addEventListener("close", () => {
      $("#private-key-content").textContent = "";
    });
  }

  function closeMenu() {
    const menu = $("#more-menu");
    if (menu) menu.open = false;
  }

  function handleTreeClick(event) {
    const button = event.target.closest("[data-action]");
    if (!button) return;
    const action = button.dataset.action;
    if (action === "toggle-project") {
      const id = button.dataset.project;
      if (state.collapsedProjects.has(id)) state.collapsedProjects.delete(id);
      else state.collapsedProjects.add(id);
      renderTree();
      return;
    }
    if (action === "toggle-env") {
      const key = button.dataset.envKey;
      if (state.collapsedEnvs.has(key)) state.collapsedEnvs.delete(key);
      else state.collapsedEnvs.add(key);
      renderTree();
      return;
    }
    if (action === "open-service") {
      navigate(hashFor({
        mode: "service",
        project: button.dataset.project,
        environment: button.dataset.environment,
        service: button.dataset.service
      }));
      closeSidebar();
      return;
    }
    if (action === "open-env") {
      navigate(hashFor({
        mode: "env", project: button.dataset.project, environment: button.dataset.environment
      }));
      closeSidebar();
      return;
    }
    if (action === "new-project") {
      openProjectDialog();
      return;
    }
    if (action === "new-env") {
      const project = findProject(button.dataset.project);
      if (project) openEnvDialog(project);
      return;
    }
    if (action === "new-service") {
      const project = findProject(button.dataset.project);
      const environment = findEnvironment(button.dataset.project, button.dataset.environment);
      if (project && environment) openServiceDialog(project, environment);
      return;
    }
    if (action === "delete-project") {
      const project = findProject(button.dataset.project);
      if (project) deleteProject(project);
      return;
    }
    if (action === "clear-filter") {
      $("#tree-filter").value = "";
      renderTree();
    }
  }

  function handleEnvTableClick(event) {
    const button = event.target.closest("[data-action]");
    if (!button) return;
    const action = button.dataset.action;
    if (action === "open-service") {
      navigate(hashFor({
        mode: "service", project: state.route.project,
        environment: state.route.environment, service: button.dataset.service
      }));
      return;
    }
    if (action === "delete-service") {
      deleteService(button.dataset.service);
      return;
    }
    if (action === "new-service") {
      const project = findProject(state.route.project);
      const environment = findEnvironment(state.route.project, state.route.environment);
      if (project && environment) openServiceDialog(project, environment);
    }
  }

  function handleKeysClick(event) {
    const button = event.target.closest("[data-action]");
    if (!button) return;
    const row = button.closest(".table-row");
    if (!row) return;
    const scope = rowScope(row);
    const action = button.dataset.action;
    if (action === "key-view") viewKey(scope.key, scope.service);
    if (action === "key-download") downloadKey(scope.key, scope.service);
    if (action === "key-token") regenerateKeyToken(scope);
    if (action === "key-pair") regenerateKeyPair(scope);
    if (action === "key-regenerate") regenerateKey(scope);
    if (action === "key-delete") deleteKey(scope);
    if (action === "key-generate") createMissingKey(scope);
  }

  function handleFieldClick(event) {
    const target = event.target.closest("[data-action]");
    if (!target) return;
    const action = target.dataset.action;
    const index = Number(target.dataset.index);
    if (action === "toggle-group") {
      const group = target.dataset.group;
      if (state.collapsedGroups.has(group)) state.collapsedGroups.delete(group);
      else state.collapsedGroups.add(group);
      renderFields();
      return;
    }
    if (action === "add-field") {
      openFieldDialog("add");
      return;
    }
    if (action === "import") {
      openImportDialog();
      return;
    }
    if (action === "jump-first") {
      const errors = collectErrors();
      if (errors.length) focusField(errors[0].index);
      return;
    }
    if (action === "edit-field") {
      openFieldDialog("edit", index);
      return;
    }
    if (action === "delete-field") {
      deleteField(index);
      return;
    }
    if (action === "secret-replace") {
      state.editor.secretMode.set(state.editor.schema[index].path, "replace");
      state.editor.secretInput.set(state.editor.schema[index].path, "");
      renderFields();
      renderChips();
      renderSaveLine();
      const input = $('#field-groups .field[data-index="' + index + '"] .secret-input .input');
      if (input) input.focus();
      return;
    }
    if (action === "secret-cancel") {
      const path = state.editor.schema[index].path;
      state.editor.secretMode.set(path, "keep");
      state.editor.secretInput.set(path, "");
      renderFields();
      renderChips();
      renderSaveLine();
      return;
    }
    if (action === "secret-clear") {
      const path = state.editor.schema[index].path;
      state.editor.secretMode.set(path, "clear");
      state.editor.secretInput.set(path, "");
      renderFields();
      renderChips();
      renderSaveLine();
      return;
    }
    if (action === "secret-undo") {
      const path = state.editor.schema[index].path;
      state.editor.secretMode.set(path, "keep");
      renderFields();
      renderChips();
      renderSaveLine();
      return;
    }
    if (action === "eye") {
      const input = $('#field-groups .field[data-index="' + index + '"] .secret-input .input');
      if (!input) return;
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      target.setAttribute("aria-label", show ? "隐藏密钥" : "显示密钥");
      target.querySelector("use").setAttribute("href", show ? "#i-eye-off" : "#i-eye");
      input.focus();
      return;
    }
    if (action === "format-json") {
      const field = state.editor.schema[index];
      const area = $('#field-groups .field[data-index="' + index + '"] textarea');
      if (!field || !area) return;
      try {
        state.editor.values[field.path] = JSON.stringify(JSON.parse(area.value), null, 2);
        area.value = state.editor.values[field.path];
        updateFieldRow(index);
        renderChips();
        renderSaveLine();
        renderTree();
        toast("JSON 已格式化");
      } catch (_) {
        toast("JSON 格式不正确，无法格式化", "error");
      }
    }
  }

  function updateFieldRow(index) {
    if (!state.editor) return;
    const field = state.editor.schema[index];
    const row = $('#field-groups .field[data-index="' + index + '"]');
    if (!field || !row) return;
    const message = validateField(field);
    row.classList.toggle("invalid", Boolean(message));
    const error = row.querySelector(".field-error");
    if (error) error.textContent = message;
    const jsonState = row.querySelector(".json-state");
    if (jsonState && field.type === "json") {
      let valid = true;
      try {
        if (String(state.editor.values[field.path] || "").trim() !== "") JSON.parse(state.editor.values[field.path]);
      } catch (_) {
        valid = false;
      }
      jsonState.textContent = valid ? "JSON 有效" : "JSON 格式不正确";
      jsonState.className = "json-state " + (valid ? "ok" : "bad");
    }
  }

  function handleFieldInput(event) {
    if (!state.editor) return;
    const target = event.target.closest("[data-field-index]");
    if (!target) return;
    const index = Number(target.dataset.fieldIndex);
    const field = state.editor.schema[index];
    if (!field) return;
    if (isSensitive(field)) {
      state.editor.secretInput.set(field.path, target.value);
    } else if (field.type === "boolean") {
      state.editor.values[field.path] = target.checked ? "true" : "false";
      const label = target.closest(".switch").querySelector(".switch-label");
      if (label) label.textContent = target.checked ? "已开启" : "已关闭";
    } else {
      state.editor.values[field.path] = target.value;
    }
    updateFieldRow(index);
    renderChips();
    renderSaveLine();
    renderTree();
  }

  function init() {
    bindEvents();
    startSessionWatch();
    document.title = "枢钥 Keynest";
    api("/api/v1/admin/resources")
      .then(() => {
        state.loggedIn = true;
        showApp();
        bootstrap();
      })
      .catch((failure) => {
        if (failure.status === 401 || failure.status === 0) {
          showLogin(failure.status === 0 ? "无法连接服务，请稍后重试。" : "");
        } else {
          showLogin("");
          toastError(failure);
        }
      });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
