/* =========================================================================
 * WFH Access Portal — single-page frontend.
 *
 * Auth model: after login we hold an opaque token in localStorage and send it
 * as the `X-AUTH-TOKEN` header on every API call. No cookies are used. SAML
 * hands the token back via the URL fragment (#saml_token=...).
 * ========================================================================= */

const TOKEN_KEY = "wfh_token";
const TOKEN_HEADER = "X-AUTH-TOKEN";
let ME = null; // identity payload from /api/auth/me
let REGIONS_TAB = "config"; // active tab on the Regions & EC2 page ("config" | "ec2")

const root = () => document.getElementById("root");

/* ---------- token storage ---------- */
const getToken = () => localStorage.getItem(TOKEN_KEY);
const setToken = (t) => localStorage.setItem(TOKEN_KEY, t);
const clearToken = () => localStorage.removeItem(TOKEN_KEY);

/* ---------- tiny utils ---------- */
function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
}

function toast(msg, type = "info") {
    const wrap = document.getElementById("toast");
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    el.textContent = msg;
    wrap.appendChild(el);
    setTimeout(() => el.remove(), 4200);
}

function copyText(text) {
    navigator.clipboard?.writeText(text).then(
        () => toast("Copied to clipboard.", "success"),
        () => toast("Could not copy.", "error"),
    );
}

// A small copy button. The raw text lives in data-copy; a single delegated
// listener (startCopyDelegation) handles clicks, so it survives re-renders.
function copyBtn(text, label = "Copy") {
    return `<button type="button" class="btn small secondary" data-copy="${esc(text)}">${label}</button>`;
}
// Short masked preview of a secret for tables (full value is still copyable).
function maskSecret(s) {
    if (!s) return "—";
    return s.length <= 8 ? s : `${s.slice(0, 4)}…${s.slice(-2)}`;
}
let copyDelegationStarted = false;
function startCopyDelegation() {
    if (copyDelegationStarted) return;
    copyDelegationStarted = true;
    document.addEventListener("click", (e) => {
        const b = e.target.closest("[data-copy]");
        if (b) copyText(b.getAttribute("data-copy")); // getAttribute returns decoded original
    });
}

/* ---------- icons (inline SVG, currentColor) ---------- */
const ICONS = {
    dashboard: '<rect x="3" y="3" width="8" height="8" rx="1"/><rect x="13" y="3" width="8" height="5" rx="1"/><rect x="13" y="10" width="8" height="11" rx="1"/><rect x="3" y="13" width="8" height="8" rx="1"/>',
    users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    add: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/>',
    regions: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    audit: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/>',
    admins: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>',
    metrics: '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>',
    logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
    sun: '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>',
    moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
    trash: '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
    back: '<line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/>',
    menu: '<line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
    key: '<path d="M21 2l-2 2"/><path d="M14.5 6.5l3 3"/><path d="M12.5 8.5L19 2"/><circle cx="7" cy="15" r="4"/><path d="M9.8 12.2L14.5 7.5"/>',
    bug: '<rect x="8" y="6" width="8" height="14" rx="4"/><path d="M12 6V3"/><path d="M9 3h6"/><path d="M8 10L4 8"/><path d="M8 14H3"/><path d="M8 18l-4 2"/><path d="M16 10l4-2"/><path d="M16 14h5"/><path d="M16 18l4 2"/>',
};
function icon(name) {
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ""}</svg>`;
}

/* ---------- AWS region friendly names (mirrors ec2_helper.AWS_REGION_NAMES) ---------- */
const REGION_NAMES = {
    "us-east-1": "US East (N. Virginia)", "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)", "us-west-2": "US West (Oregon)",
    "af-south-1": "Africa (Cape Town)", "ap-east-1": "Asia Pacific (Hong Kong)",
    "ap-south-1": "Asia Pacific (Mumbai)", "ap-northeast-3": "Asia Pacific (Osaka)",
    "ap-northeast-2": "Asia Pacific (Seoul)", "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)", "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ca-central-1": "Canada (Central)", "eu-central-1": "Europe (Frankfurt)",
    "eu-west-1": "Europe (Ireland)", "eu-west-2": "Europe (London)",
    "eu-south-1": "Europe (Milan)", "eu-west-3": "Europe (Paris)",
    "eu-north-1": "Europe (Stockholm)", "me-south-1": "Middle East (Bahrain)",
    "sa-east-1": "South America (São Paulo)",
};
// "ap-southeast-1 (Asia Pacific (Singapore))" when known, else the raw id.
function regionLabel(id) {
    const name = REGION_NAMES[id];
    return name ? `${id} (${name})` : id;
}

/* ---------- page header ---------- */
// `subtitle` and `actionsHtml` may contain trusted HTML; `title` is escaped.
function pageHeader(title, subtitle = "", actionsHtml = "") {
    return `<div class="page-head">
      <div>
        <h1 class="page-title">${esc(title)}</h1>
        ${subtitle ? `<p class="page-sub">${subtitle}</p>` : ""}
      </div>
      ${actionsHtml ? `<div class="page-head-actions">${actionsHtml}</div>` : ""}
    </div>`;
}

/* ---------- pagination ---------- */
function pagerHtml(page, pages) {
    if (pages <= 1) return "";
    return `<div class="pagination">
      <button type="button" class="btn small secondary" data-page="${page - 1}" ${page <= 1 ? "disabled" : ""}>‹ Prev</button>
      <span class="muted">Page ${page} of ${pages}</span>
      <button type="button" class="btn small secondary" data-page="${page + 1}" ${page >= pages ? "disabled" : ""}>Next ›</button>
    </div>`;
}
function wirePager(scope, cb) {
    scope.querySelectorAll(".pagination [data-page]").forEach((b) => {
        if (!b.disabled) b.onclick = () => cb(parseInt(b.dataset.page, 10));
    });
}

/* ---------- theme ---------- */
function currentTheme() { return document.documentElement.dataset.theme || "light"; }
function applyTheme(t) {
    document.documentElement.dataset.theme = t;
    try { localStorage.setItem("wfh_theme", t); } catch (e) { /* ignore */ }
}
function themeToggleInner() {
    const dark = currentTheme() === "dark";
    return `${icon(dark ? "sun" : "moon")}<span>${dark ? "Light" : "Dark"}</span>`;
}
function refreshThemeToggles() {
    document.querySelectorAll(".theme-toggle").forEach((b) => { b.innerHTML = themeToggleInner(); });
}
function toggleTheme() {
    applyTheme(currentTheme() === "dark" ? "light" : "dark");
    refreshThemeToggles();
}

/* ---------- API client ---------- */
function handleUnauthorized() {
    clearToken();
    ME = null;
    if (location.hash !== "#/login") {
        toast("Session expired — please log in again.", "error");
        location.hash = "#/login";
    }
}

async function api(method, path, body) {
    const headers = {};
    const token = getToken();
    if (token) headers[TOKEN_HEADER] = token;
    const opts = { method, headers };
    if (body !== undefined) {
        headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    if (res.status === 401) {
        handleUnauthorized();
        throw new Error("Unauthorized");
    }
    let data = null;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("application/json")) data = await res.json();
    if (!res.ok) {
        throw new Error((data && data.error) || `Request failed (${res.status})`);
    }
    return data;
}

/* ---------- permissions ---------- */
function hasPerm(name) {
    return !!(ME && ME.permissions && ME.permissions[name]);
}
function homeHash() {
    return ME && ME.actor_type === "admin" ? "#/dashboard" : "#/employee";
}

/* ---------- layout / nav ---------- */
function navItems() {
    const items = [];
    if (!ME) return items;
    if (ME.actor_type === "admin") items.push({ key: "dashboard", label: "Dashboard", hash: "#/dashboard", icon: "dashboard" });
    if (ME.actor_type === "employee") items.push({ key: "employee", label: "My Dashboard", hash: "#/employee", icon: "dashboard" });
    if (hasPerm("can_view_users_and_logs") || hasPerm("can_manage_users"))
        items.push({ key: "users", label: "Users", hash: "#/users", icon: "users" });
    if (hasPerm("can_add_user") || hasPerm("can_manage_users"))
        items.push({ key: "add-user", label: "Add User", hash: "#/add-user", icon: "add" });
    if (hasPerm("can_manage_users") || hasPerm("can_manage_aws"))
        items.push({ key: "regions", label: "Regions & EC2", hash: "#/regions", icon: "regions" });
    if (hasPerm("can_view_users_and_logs"))
        items.push({ key: "audit-log", label: "Audit Log", hash: "#/audit-log", icon: "audit" });
    if (hasPerm("can_view_users_and_logs"))
        items.push({ key: "debug-logs", label: "Diagnostics", hash: "#/debug-logs", icon: "bug" });
    if (hasPerm("can_manage_users") || hasPerm("can_view_users_and_logs"))
        items.push({ key: "admins", label: "Subadmins", hash: "#/admins", icon: "admins" });
    if (hasPerm("can_fetch_credentials"))
        items.push({ key: "credentials", label: "Fetch Credentials", hash: "#/credentials", icon: "key" });
    return items;
}

function mount(activeKey) {
    const nav = navItems().map((i) =>
        `<a href="${i.hash}" class="${i.key === activeKey ? "active" : ""}">${icon(i.icon)}<span>${esc(i.label)}</span></a>`
    ).join("");
    const role = ME.role || (ME.actor_type === "admin" ? "admin" : "user");
    const initial = (ME.username || "?").charAt(0);
    root().innerHTML = `
        <div class="app-shell" id="appShell">
          <div class="scrim" id="scrim"></div>
          <aside class="sidebar">
            <div class="sidebar-brand">${icon("shield")}<span>WFH Access</span></div>
            <nav class="sidebar-nav">${nav}
              <a href="#" class="nav-action" id="svrMetricsNav">${icon("metrics")}<span>Server Metrics</span></a>
            </nav>
            <div class="sidebar-footer">
              <button class="icon-btn grow theme-toggle" id="themeBtn">${themeToggleInner()}</button>
              <div class="user-chip">
                <div class="avatar">${esc(initial)}</div>
                <div class="meta">
                  <div class="name">${esc(ME.username)}</div>
                  <div class="role">${esc(role)}</div>
                </div>
              </div>
              <button class="icon-btn grow" id="logoutBtn">${icon("logout")}<span>Logout</span></button>
            </div>
          </aside>
          <main class="main">
            <div class="topbar-mobile">
              <button class="hamburger" id="hamburger">${icon("menu")}</button>
              <div class="brand">${icon("shield")}<span>WFH Access</span></div>
            </div>
            <div class="container" id="view"><div class="spinner">Loading…</div></div>
          </main>
        </div>`;
    const shell = document.getElementById("appShell");
    const closeNav = () => shell.classList.remove("nav-open");
    document.getElementById("logoutBtn").onclick = doLogout;
    document.getElementById("themeBtn").onclick = toggleTheme;
    document.getElementById("svrMetricsNav").onclick = (e) => { e.preventDefault(); launchSvrmetrics(); };
    document.getElementById("hamburger").onclick = () => shell.classList.toggle("nav-open");
    document.getElementById("scrim").onclick = closeNav;
    shell.querySelectorAll(".sidebar-nav a").forEach((a) => a.addEventListener("click", closeNav));
    return document.getElementById("view");
}

async function doLogout() {
    try { await api("POST", "/api/auth/logout"); } catch (e) { /* ignore */ }
    clearToken();
    ME = null;
    location.hash = "#/login";
}

function errorCard(view, e) {
    view.innerHTML = `<div class="card"><h2 class="card-title">Something went wrong</h2><p class="muted">${esc(e.message)}</p></div>`;
}

/* =========================================================================
 * Login
 * ========================================================================= */
function renderLogin() {
    root().innerHTML = `
    <div class="login-wrap">
      <button class="btn secondary small theme-toggle login-theme-toggle" id="loginTheme">${themeToggleInner()}</button>
      <div class="login-card">
        <svg class="shield" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <h1>WFH Access Portal</h1>
        <p class="sub">Secure employee access management</p>
        <form id="loginForm">
          <div class="form-group">
            <label class="form-label" for="username">Username</label>
            <input type="text" id="username" autofocus required>
          </div>
          <div class="form-group">
            <label class="form-label" for="password">Password</label>
            <input type="password" id="password" required>
          </div>
          <div class="form-group">
            <label class="form-label" for="otp">OTP (Authenticator Code)</label>
            <input type="text" id="otp" maxlength="6" pattern="\\d{6}" required>
          </div>
          <button type="submit" class="btn full">Login</button>
        </form>
        <div class="divider"><span>OR</span></div>
        <a href="/saml/login" class="btn full secondary">Login with SSO</a>
      </div>
    </div>`;

    document.getElementById("loginTheme").onclick = toggleTheme;
    document.getElementById("loginForm").onsubmit = async (ev) => {
        ev.preventDefault();
        const btn = ev.target.querySelector("button[type=submit]");
        btn.disabled = true; btn.textContent = "Signing in…";
        try {
            const data = await api("POST", "/api/auth/login", {
                username: document.getElementById("username").value,
                password: document.getElementById("password").value,
                otp: document.getElementById("otp").value,
            });
            setToken(data.token);
            ME = await api("GET", "/api/auth/me");
            if (data.access_message) toast(data.access_message, "success");
            else toast("Logged in successfully.", "success");
            location.hash = homeHash();
        } catch (e) {
            toast(e.message, "error");
            btn.disabled = false; btn.textContent = "Login";
        }
    };
}

/* =========================================================================
 * Admin dashboard
 * ========================================================================= */
function dashboardTiles() {
    const tiles = [];
    if (hasPerm("can_view_users_and_logs") || hasPerm("can_manage_users"))
        tiles.push({ href: "#/users", icon: "users", title: "View Users", desc: "Browse WFH users, access flags and SSH keys." });
    if (hasPerm("can_add_user") || hasPerm("can_manage_users"))
        tiles.push({ href: "#/add-user", icon: "add", title: "Add User", desc: "Provision a new WFH user with access and OTP." });
    if (hasPerm("can_manage_users") || hasPerm("can_manage_aws"))
        tiles.push({ href: "#/regions", icon: "regions", title: "Regions & EC2", desc: "Manage regions, provision and revoke EC2 access." });
    if (hasPerm("can_view_users_and_logs"))
        tiles.push({ href: "#/audit-log", icon: "audit", title: "Audit Log", desc: "Review recent actions across the portal." });
    if (hasPerm("can_manage_users") || hasPerm("can_view_users_and_logs"))
        tiles.push({ href: "#/admins", icon: "admins", title: "Subadmins", desc: "Grant or revoke elevated privileges." });
    return tiles;
}

function renderAdminDashboard() {
    const view = mount("dashboard");
    const tiles = dashboardTiles().map((t) =>
        `<a class="tile" href="${t.href}">
           <div class="tile-icon">${icon(t.icon)}</div>
           <div class="tile-title">${esc(t.title)}</div>
           <div class="tile-desc">${esc(t.desc)}</div>
         </a>`
    ).join("");
    view.innerHTML = `
      ${pageHeader(`Welcome, ${ME.username}`, "You are signed in as an administrator.")}
      <div class="tile-grid">
        ${tiles}
      </div>`;
}

async function launchSvrmetrics() {
    try {
        const data = await api("GET", "/api/launch/svrmetrics");
        window.open(data.url, "_blank");
    } catch (e) { toast(e.message, "error"); }
}

/* =========================================================================
 * Users list
 * ========================================================================= */
function boolBadge(v) {
    return v ? `<span class="badge yes">Yes</span>` : `<span class="badge no">No</span>`;
}

const USERS_PER_PAGE = 15;

async function renderUsers() {
    const view = mount("users");
    try {
        const data = await api("GET", "/api/admin/users");
        const canManage = hasPerm("can_manage_users");
        const entries = Object.entries(data.users);
        let filter = "";
        let page = 1;

        const addBtn = (hasPerm("can_add_user") || canManage)
            ? `<a class="btn small" href="#/add-user">${icon("plus")}<span>Add user</span></a>` : "";
        view.innerHTML = `
          ${pageHeader("WFH Users", `<span id="userCount">${entries.length}</span> user(s)`, addBtn)}
          <input type="text" id="userSearch" class="search-input" placeholder="Search users by name…" autocomplete="off">
          <div id="usersTable"></div>
          <div id="sshPanel" class="mt-3"></div>`;

        const box = document.getElementById("usersTable");
        const search = document.getElementById("userSearch");

        function filteredEntries() {
            const q = filter.trim().toLowerCase();
            return q ? entries.filter(([u]) => u.toLowerCase().includes(q)) : entries;
        }

        function renderPage() {
            const list = filteredEntries();
            const pages = Math.max(1, Math.ceil(list.length / USERS_PER_PAGE));
            if (page > pages) page = pages;
            const cnt = document.getElementById("userCount");
            if (cnt) cnt.textContent = list.length;
            const start = (page - 1) * USERS_PER_PAGE;
            const slice = list.slice(start, start + USERS_PER_PAGE);
            const rows = slice.map(([u, info]) => {
                const ks = data.ssh_key_status[u] || {};
                const keys = (data.ssh_keys && data.ssh_keys[u]) || [];
                const newestKey = keys[0] ? keys[0].public_key : "";
                const seed = info.otpSeed || "";
                const ports = (info.portsToOpen || []).join(", ") || "—";
                const ov = info.overRiddenRegionAndCfg || {};
                const ovEntries = Object.entries(ov);
                const ovCell = ovEntries.length
                    ? ovEntries.map(([r, c]) => {
                        const sgs = (c.securityGrpIds || []).join(", ") || "no SG";
                        const prts = (c.portsToOpen || []).join(", ");
                        const portTag = prts
                            ? `<span class="muted">[${esc(prts)}]</span>`
                            : `<span class="badge warn">no ports</span>`;
                        return `<div><strong>${esc(r)}</strong>: ${esc(sgs)} ${portTag}</div>`;
                    }).join("")
                    : `<span class="muted">—</span>`;
                const isSub = info.adminPermissions && Object.values(info.adminPermissions).some(Boolean);
                const sshCell = ks.has_key
                    ? `<span class="badge yes">${ks.key_count} key(s)</span>${newestKey ? " " + copyBtn(newestKey, "Copy") : ""}`
                    : `<span class="badge no">none</span>`;
                const otpCell = seed
                    ? `<span class="mono">${esc(maskSecret(seed))}</span> ${copyBtn(seed, "Copy")}`
                    : `<span class="badge no">none</span>`;
                return `<tr>
                  <td><strong>${esc(u)}</strong>${isSub ? ' <span class="badge neutral">subadmin</span>' : ""}</td>
                  <td>${boolBadge(info.allowLogAccess)}</td>
                  <td>${boolBadge(info.allowServerMetricsAccess)}</td>
                  <td>${boolBadge(info.allowHpAgentAccess)}</td>
                  <td>${esc(ports)}</td>
                  <td>${ovCell}</td>
                  <td>${sshCell}</td>
                  <td>${otpCell}</td>
                  <td><div class="actions">
                    <a class="btn small secondary" href="#/edit-user/${encodeURIComponent(u)}">${canManage ? "Edit" : "View"}</a>
                    <button class="btn small secondary" data-ssh="${esc(u)}">SSH keys</button>
                    ${canManage ? `<button class="btn small danger" data-del="${esc(u)}">Delete</button>` : ""}
                  </div></td>
                </tr>`;
            }).join("");
            box.innerHTML = `
              <div class="table-wrap"><table>
                <thead><tr><th>Username</th><th>Logs</th><th>Metrics</th><th>HP Agent</th><th>Ports</th><th>Regions / SGs</th><th>SSH key</th><th>OTP seed</th><th>Actions</th></tr></thead>
                <tbody>${rows || `<tr><td colspan="9" class="muted">${filter.trim() ? "No users match your search." : "No users."}</td></tr>`}</tbody>
              </table></div>
              ${pagerHtml(page, pages)}`;

            box.querySelectorAll("[data-del]").forEach((b) => b.onclick = async () => {
                if (!confirm(`Delete user '${b.dataset.del}'? This cannot be undone.`)) return;
                try {
                    await api("DELETE", `/api/admin/users/${encodeURIComponent(b.dataset.del)}`);
                    toast("User deleted.", "success");
                    renderUsers();
                } catch (e) { toast(e.message, "error"); }
            });
            box.querySelectorAll("[data-ssh]").forEach((b) => b.onclick = () => showSshKeys(b.dataset.ssh));
            wirePager(box, (p) => { page = p; renderPage(); window.scrollTo({ top: 0, behavior: "smooth" }); });
        }

        search.oninput = () => { filter = search.value; page = 1; renderPage(); };
        renderPage();
    } catch (e) { errorCard(view, e); }
}

async function showSshKeys(username) {
    const panel = document.getElementById("sshPanel");
    panel.innerHTML = `<div class="card"><div class="spinner">Loading keys…</div></div>`;
    try {
        const data = await api("GET", `/api/admin/users/${encodeURIComponent(username)}/ssh-key`);
        const otp = data.otp_seed
            ? `<div class="credbox"><div class="muted">OTP seed</div><div class="mono">${esc(data.otp_seed)}</div><div class="mt-1">${copyBtn(data.otp_seed, "Copy seed")}</div></div>`
            : "";
        const keys = data.ssh_keys.map((k) =>
            `<div class="credbox"><div class="muted">${esc(k.key_name)} · ${esc(k.created_at)}</div><div class="mono">${esc(k.ssh_public_key)}</div><div class="mt-1">${copyBtn(k.ssh_public_key, "Copy key")}</div></div>`
        ).join("") || `<p class="muted">No SSH keys on file.</p>`;
        panel.innerHTML = `<div class="card"><h2 class="card-title">Credentials — ${esc(username)}</h2>${otp}<h2 class="card-title mt-2">SSH keys</h2>${keys}</div>`;
        panel.scrollIntoView({ behavior: "smooth" });
    } catch (e) { toast(e.message, "error"); }
}

/* =========================================================================
 * Region-override editor (shared by add/edit user)
 * ========================================================================= */
function overrideRowHtml(region = "", sgs = "", ports = "") {
    return `<div class="overrides-row">
      <input type="text" placeholder="region (e.g. ap-south-1)" value="${esc(region)}" data-f="region">
      <input type="text" placeholder="security groups (comma sep)" value="${esc(sgs)}" data-f="sgs">
      <input type="text" placeholder="ports (comma sep)" value="${esc(ports)}" data-f="ports">
      <button type="button" class="btn small danger" data-remove>✕</button>
    </div>`;
}
function wireOverrides(container, addBtn) {
    addBtn.onclick = () => {
        const d = document.createElement("div");
        d.innerHTML = overrideRowHtml();
        container.appendChild(d.firstElementChild);
        wireRemoveButtons(container);
    };
    wireRemoveButtons(container);
}
function wireRemoveButtons(container) {
    container.querySelectorAll("[data-remove]").forEach((b) =>
        b.onclick = () => b.closest(".overrides-row").remove());
}
function collectOverrides(container) {
    const out = [];
    container.querySelectorAll(".overrides-row").forEach((row) => {
        const get = (f) => row.querySelector(`[data-f="${f}"]`).value.trim();
        const region = get("region");
        if (!region) return;
        out.push({
            region,
            securityGrpIds: get("sgs").split(",").map((s) => s.trim()).filter(Boolean),
            portsToOpen: get("ports").split(",").map((s) => s.trim()).filter(Boolean),
        });
    });
    return out;
}

/* =========================================================================
 * Add user
 * ========================================================================= */
async function renderAddUser() {
    const view = mount("add-user");
    try {
        const ctx = await api("GET", "/api/admin/add-user");
        const tplOptions = ctx.role_templates.map((t) =>
            `<option value="${t.id}" data-log="${t.allow_log_access}" data-metrics="${t.allow_metrics_access}" data-hp="${t.allow_hp_agent_access}" data-ports="${(t.ports_to_open || []).join(",")}">${esc(t.name)}</option>`
        ).join("");
        view.innerHTML = `
          ${pageHeader("Add WFH User", "Create a new employee account with access and OTP.")}
          <div class="card">
            <form id="addForm">
              <div class="form-group">
                <label class="form-label">Username</label>
                <input type="text" id="username" required>
              </div>
              <div class="form-group">
                <label class="form-label">Apply role template (optional)</label>
                <select id="tpl"><option value="">— none —</option>${tplOptions}</select>
              </div>
              <div class="checkbox-row"><input type="checkbox" id="allow_log"><label for="allow_log">Allow log access</label></div>
              <div class="checkbox-row"><input type="checkbox" id="allow_metrics"><label for="allow_metrics">Allow server metrics access</label></div>
              <div class="checkbox-row"><input type="checkbox" id="allow_hp"><label for="allow_hp">Allow HP agent access</label></div>
              <div class="form-group">
                <label class="form-label">Ports to open (comma separated)</label>
                <input type="text" id="ports" placeholder="22, 3306">
              </div>
              <div class="checkbox-row"><input type="checkbox" id="is_subadmin"><label for="is_subadmin">Grant subadmin (can fetch credentials)</label></div>
              <hr class="sep">
              <h2 class="card-title">Region overrides</h2>
              <div id="overrides"></div>
              <button type="button" class="btn small secondary mt-1" id="addOverride">${icon("plus")}<span>Add region override</span></button>
              <hr class="sep">
              <button type="submit" class="btn">Create user</button>
            </form>
          </div>
          <div id="result"></div>`;

        // Template auto-fill
        document.getElementById("tpl").onchange = (e) => {
            const o = e.target.selectedOptions[0];
            if (!o || !o.value) return;
            document.getElementById("allow_log").checked = o.dataset.log === "1";
            document.getElementById("allow_metrics").checked = o.dataset.metrics === "1";
            document.getElementById("allow_hp").checked = o.dataset.hp === "1";
            document.getElementById("ports").value = o.dataset.ports || "";
        };

        wireOverrides(document.getElementById("overrides"), document.getElementById("addOverride"));

        document.getElementById("addForm").onsubmit = async (ev) => {
            ev.preventDefault();
            const ports = document.getElementById("ports").value.split(",").map((s) => s.trim()).filter(Boolean);
            try {
                const res = await api("POST", "/api/admin/add-user", {
                    username: document.getElementById("username").value,
                    allow_log_access: document.getElementById("allow_log").checked,
                    allow_metrics_access: document.getElementById("allow_metrics").checked,
                    allow_hp_agent_access: document.getElementById("allow_hp").checked,
                    ports_to_open: ports,
                    is_subadmin: document.getElementById("is_subadmin").checked,
                    region_overrides: collectOverrides(document.getElementById("overrides")),
                });
                toast("User created.", "success");
                showCreatedUser(res);
            } catch (e) { toast(e.message, "error"); }
        };
    } catch (e) { errorCard(view, e); }
}

function showCreatedUser(res) {
    const qr = res.qr_code_b64
        ? `<img class="qr" src="data:image/png;base64,${res.qr_code_b64}" alt="OTP QR">`
        : "";
    document.getElementById("result").innerHTML = `
      <div class="card mt-3">
        <h2 class="card-title">User "${esc(res.username)}" created</h2>
        <p class="muted">Share these credentials securely — the password is shown only once.</p>
        <div class="credbox"><div class="muted">Password</div><div class="mono">${esc(res.password)}</div></div>
        <div class="credbox"><div class="muted">OTP seed</div><div class="mono">${esc(res.otp_seed)}</div></div>
        ${qr}
      </div>`;
    document.getElementById("result").scrollIntoView({ behavior: "smooth" });
}

/* =========================================================================
 * Edit user
 * ========================================================================= */
/* EC2 provisioning summary on the edit-user page: the instances this user is
 * currently provisioned onto. Provision/revoke actions live on the Regions page. */
function ec2ProvisioningCard(provisions) {
    if (!provisions.length) {
        return `<div class="card"><h2 class="card-title">EC2 provisioning</h2>
          <p class="muted">This user is not provisioned on any instance. Provision them from the <a href="#/regions">Regions &amp; EC2</a> page.</p></div>`;
    }
    const rows = provisions.map((p) => {
        const groups = (p.linux_groups || []).map((g) => `<span class="badge neutral">${esc(g)}</span>`).join(" ") || `<span class="muted">—</span>`;
        return `<tr>
          <td><strong>${esc(p.instance_name || p.instance_id || "—")}</strong></td>
          <td class="mono">${esc(p.instance_ip || "—")}</td>
          <td><span class="badge neutral" title="${esc(REGION_NAMES[p.region] || "")}">${esc(p.region || "—")}</span></td>
          <td>${groups}</td>
        </tr>`;
    }).join("");
    return `<div class="card">
      <div class="card-header">
        <h2 class="card-title">EC2 provisioning</h2>
        <span class="muted">${provisions.length} instance${provisions.length === 1 ? "" : "s"}</span>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>Instance</th><th>Instance IP</th><th>Region</th><th>Groups</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
      <p class="muted mt-2">Manage provisioning (provision, revoke, edit groups) from the <a href="#/regions">Regions &amp; EC2</a> page.</p>
    </div>`;
}

async function renderEditUser(username) {
    const view = mount("users");
    const canManage = hasPerm("can_manage_users");
    try {
        const ctx = await api("GET", `/api/admin/users/${encodeURIComponent(username)}`);
        const u = ctx.user;
        const overrides = u.overRiddenRegionAndCfg || {};
        const overrideRows = Object.entries(overrides).map(([r, c]) =>
            overrideRowHtml(r, (c.securityGrpIds || []).join(", "), (c.portsToOpen || []).join(", "))
        ).join("");
        view.innerHTML = `
          ${pageHeader(`Edit User — ${username}`, `<a href="#/users">← Back to users</a>`)}
          <div class="card">
            <form id="editForm">
              <div class="checkbox-row"><input type="checkbox" id="allow_log" ${u.allowLogAccess ? "checked" : ""}><label for="allow_log">Allow log access</label></div>
              <div class="checkbox-row"><input type="checkbox" id="allow_metrics" ${u.allowServerMetricsAccess ? "checked" : ""}><label for="allow_metrics">Allow server metrics access</label></div>
              <div class="checkbox-row"><input type="checkbox" id="allow_hp" ${u.allowHpAgentAccess ? "checked" : ""}><label for="allow_hp">Allow HP agent access</label></div>
              <div class="form-group">
                <label class="form-label">Ports to open (comma separated)</label>
                <input type="text" id="ports" value="${esc((u.portsToOpen || []).join(", "))}">
              </div>
              <div class="form-group">
                <label class="form-label">CIDR preference</label>
                <input type="text" id="cidr" value="${esc(ctx.cidr_preference || "/32")}">
              </div>
              <div class="checkbox-row"><input type="checkbox" id="is_subadmin" ${ctx.is_subadmin ? "checked" : ""}><label for="is_subadmin">Subadmin privileges</label></div>
              <hr class="sep">
              <h2 class="card-title">Region overrides</h2>
              <div id="overrides">${overrideRows}</div>
              <button type="button" class="btn small secondary mt-1" id="addOverride">${icon("plus")}<span>Add region override</span></button>
              <hr class="sep">
              <button type="submit" class="btn" ${canManage ? "" : "disabled"}>Save changes</button>
              ${canManage ? "" : '<p class="muted">You have read-only access.</p>'}
            </form>
          </div>
          ${ec2ProvisioningCard(ctx.active_provisions || [])}`;

        wireOverrides(document.getElementById("overrides"), document.getElementById("addOverride"));

        document.getElementById("editForm").onsubmit = async (ev) => {
            ev.preventDefault();
            const ports = document.getElementById("ports").value.split(",").map((s) => s.trim()).filter(Boolean);
            try {
                await api("PUT", `/api/admin/users/${encodeURIComponent(username)}`, {
                    allow_log_access: document.getElementById("allow_log").checked,
                    allow_metrics_access: document.getElementById("allow_metrics").checked,
                    allow_hp_agent_access: document.getElementById("allow_hp").checked,
                    ports_to_open: ports,
                    cidr_preference: document.getElementById("cidr").value.trim() || "/32",
                    is_subadmin: document.getElementById("is_subadmin").checked,
                    region_overrides: collectOverrides(document.getElementById("overrides")),
                });
                toast("User updated.", "success");
                location.hash = "#/users";
            } catch (e) { toast(e.message, "error"); }
        };
    } catch (e) { errorCard(view, e); }
}

/* =========================================================================
 * Regions & EC2
 * ========================================================================= */
async function renderRegions() {
    const view = mount("regions");
    try {
        const data = await api("GET", "/api/admin/regions");
        const allowedGroups = data.allowed_linux_groups || [];
        // Adding/deleting regions requires can_manage_users. Holders of can_manage_aws
        // only get edit + EC2 provisioning, so hide the add/delete controls for them.
        const canConfigure = data.can_configure_regions !== false;

        // EC2 provisioning targets are the regions that currently have active/stopped
        // instances (discovered live from AWS), not the manually-configured region list.
        let ec2Regions = [];
        try {
            const rr = await api("GET", "/api/ec2-regions");
            ec2Regions = rr.regions || [];
        } catch (_) { /* fall back to configured regions below */ }

        /* ----- Region Configuration tab ----- */
        const regionRows = Object.entries(data.regions).map(([r, c]) =>
            `<tr>
              <td>
                <div class="region-cell">
                  <strong>${esc(r)}</strong>
                  ${REGION_NAMES[r] ? `<span class="muted region-name">${esc(REGION_NAMES[r])}</span>` : ""}
                </div>
              </td>
              <td><input type="text" class="mono" data-region-sgs="${esc(r)}" value="${esc((c.securityGrpIds || []).join(", "))}"></td>
              <td><div class="actions">
                <button class="btn small secondary" data-region-save="${esc(r)}">Save</button>
                ${canConfigure ? `<button class="btn small danger" data-region-del="${esc(r)}">Delete</button>` : ""}
              </div></td>
            </tr>`
        ).join("");

        /* ----- EC2 Access Management tab ----- */
        const userOptions = Object.keys(data.users).map((u) => `<option value="${esc(u)}">${esc(u)}</option>`).join("");
        // Prefer the live list of regions that actually have instances; if that lookup
        // failed, fall back to the manually-configured regions so the form still works.
        const provRegionIds = ec2Regions.length
            ? ec2Regions.map((r) => r.id)
            : Object.keys(data.regions);
        const regionOptions = provRegionIds.map((r) =>
            `<option value="${esc(r)}">${esc(regionLabel(r))}</option>`).join("");
        const groupChecks = allowedGroups.map((g) =>
            `<label class="checkbox-row"><input type="checkbox" class="grp" value="${esc(g)}"> ${groupLabel(g)}</label>`
        ).join("");

        // Group active provisions by user (screenshot-style per-user cards).
        const byUser = {};
        (data.active_provisions || []).forEach((p) => { (byUser[p.username] = byUser[p.username] || []).push(p); });
        const byUserEntries = Object.entries(byUser);
        const provGroupHtml = ([user, list]) => `
              <div class="prov-group">
                <div class="prov-group-head">
                  <span class="prov-user">${icon("users")}<strong>${esc(user)}</strong></span>
                  <span class="badge neutral">${list.length} Instance${list.length === 1 ? "" : "s"}</span>
                </div>
                <div class="table-wrap"><table>
                  <thead><tr>
                    <th>Instance Name</th><th>Instance IP</th><th>Region</th>
                    <th>Groups</th><th>Provisioned At</th><th>Actions</th>
                  </tr></thead>
                  <tbody>${list.map((p) => provisionRowHtml(p, allowedGroups)).join("")}</tbody>
                </table></div>
              </div>`;

        const addRegionBtn = canConfigure
            ? `<button class="btn" id="addRegionBtn">${icon("plus")}<span>Add New Region</span></button>`
            : "";

        view.innerHTML = `
          ${pageHeader("AWS Management", "Manage global AWS regions, default security groups, and EC2 access.", addRegionBtn)}

          <div class="tabs" role="tablist">
            <button class="tab" data-tab="config" role="tab">Region Configuration</button>
            <button class="tab" data-tab="ec2" role="tab">EC2 Access Management</button>
          </div>

          <div class="tab-panel" data-panel="config">
            <div class="card">
              <div class="card-header">
                <h2 class="card-title">Managed regions</h2>
                <span class="muted">Region id, friendly name and the default security groups applied on provisioning.</span>
              </div>
              <div class="table-wrap"><table>
                <thead><tr><th>Region</th><th>Security group IDs</th><th>Actions</th></tr></thead>
                <tbody>${regionRows || `<tr><td colspan="3" class="muted">No regions.</td></tr>`}</tbody>
              </table></div>
              ${canConfigure ? `
              <hr class="sep">
              <div class="inline">
                <div><label class="form-label">New region</label><input type="text" id="newRegion" placeholder="ap-south-1"></div>
                <div><label class="form-label">Security groups (comma sep)</label><input type="text" id="newSgs" placeholder="sg-123, sg-456"></div>
                <div class="grow-0"><button class="btn" id="addRegionBtn2">${icon("plus")}<span>Add region</span></button></div>
              </div>` : ""}
            </div>
          </div>

          <div class="tab-panel" data-panel="ec2">
            <div class="card">
              <h2 class="card-title">Provision EC2 Access</h2>
              <div class="inline prov-form">
                <div><label class="form-label">Select User</label><select id="provUser">${userOptions}</select></div>
                <div><label class="form-label">AWS Region</label><select id="provRegion"><option value="">— select —</option>${regionOptions}</select></div>
                <div><label class="form-label">Target Instance</label><select id="provInstance"><option value="">— pick region first —</option></select></div>
              </div>
              <div class="prov-status-row"><span id="provInstanceStatus"></span></div>
              <label class="form-label mt-2">Linux Groups</label>
              <div class="grp-inline">${groupChecks || '<span class="muted">No groups configured.</span>'}</div>
              <button class="btn mt-3" id="provBtn">Provision Access</button>
            </div>

            <div class="card">
              <div class="card-header">
                <h2 class="card-title">Active EC2 Provisions</h2>
                <span class="muted"><span id="provCount">${byUserEntries.length}</span> user(s)</span>
              </div>
              ${byUserEntries.length ? `<input type="text" id="provSearch" class="search-input" placeholder="Search by user or instance name…" autocomplete="off">` : ""}
              <div id="provList">${byUserEntries.map(provGroupHtml).join("") || `<p class="muted">No active provisions.</p>`}</div>
            </div>
          </div>`;

        /* ----- tab switching (client-side; state persists across re-renders) ----- */
        const activateTab = (name) => {
            REGIONS_TAB = name;
            view.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
            view.querySelectorAll(".tab-panel").forEach((p) => {
                const on = p.dataset.panel === name;
                p.classList.toggle("active", on); // matches .tab-panel.active { display:block }
                p.hidden = !on;                    // keep in sync for accessibility
            });
        };
        view.querySelectorAll(".tab").forEach((t) => t.onclick = () => activateTab(t.dataset.tab));
        activateTab(REGIONS_TAB);

        // Add-region controls only exist for users who can configure the region catalog.
        if (canConfigure) {
            // "Add New Region" in the header jumps to the config tab and focuses the input.
            document.getElementById("addRegionBtn").onclick = () => {
                activateTab("config");
                const el = document.getElementById("newRegion");
                el.focus(); el.scrollIntoView({ behavior: "smooth", block: "center" });
            };

            // Region CRUD
            const addRegion = async () => {
                try {
                    await api("POST", "/api/admin/regions", {
                        region: document.getElementById("newRegion").value.trim(),
                        securityGrpIds: document.getElementById("newSgs").value.split(",").map((s) => s.trim()).filter(Boolean),
                    });
                    toast("Region added.", "success");
                    renderRegions();
                } catch (e) { toast(e.message, "error"); }
            };
            document.getElementById("addRegionBtn2").onclick = addRegion;
        }
        view.querySelectorAll("[data-region-save]").forEach((b) => b.onclick = async () => {
            const r = b.dataset.regionSave;
            const sgs = view.querySelector(`[data-region-sgs="${CSS.escape(r)}"]`).value.split(",").map((s) => s.trim()).filter(Boolean);
            try {
                await api("PUT", `/api/admin/regions/${encodeURIComponent(r)}`, { securityGrpIds: sgs });
                toast("Region updated.", "success");
            } catch (e) { toast(e.message, "error"); }
        });
        view.querySelectorAll("[data-region-del]").forEach((b) => b.onclick = async () => {
            if (!confirm(`Delete region ${b.dataset.regionDel}?`)) return;
            try {
                await api("DELETE", `/api/admin/regions/${encodeURIComponent(b.dataset.regionDel)}`);
                toast("Region deleted.", "success");
                renderRegions();
            } catch (e) { toast(e.message, "error"); }
        });

        // Instance loading — running=green, stopped=red.
        const instSel = document.getElementById("provInstance");
        const instStatus = document.getElementById("provInstanceStatus");
        const showInstStatus = () => {
            const opt = instSel.selectedOptions[0];
            const state = opt && opt.dataset ? opt.dataset.state : "";
            if (!state) { instStatus.innerHTML = ""; return; }
            const cls = state === "running" ? "yes" : "no";
            instStatus.innerHTML = `<span class="badge ${cls}"><span class="status-dot"></span>${esc(state)}</span>`;
        };
        instSel.onchange = showInstStatus;
        document.getElementById("provRegion").onchange = async (e) => {
            const region = e.target.value;
            instStatus.innerHTML = "";
            if (!region) { instSel.innerHTML = `<option value="">— pick region first —</option>`; return; }
            instSel.innerHTML = `<option>Loading…</option>`;
            try {
                const res = await api("GET", `/api/ec2-instances/${encodeURIComponent(region)}`);
                instSel.innerHTML = `<option value="">— Select Instance —</option>` + res.instances.map((i) => {
                    const running = i.state === "running";
                    const color = running ? "var(--success)" : "var(--danger)";
                    // Emoji dot: <option> text color (the inline style) is ignored by many
                    // browsers/OSes, so the dot is what reliably conveys running vs stopped.
                    const dot = running ? "🟢" : "🔴";
                    return `<option value="${esc(i.id)}" data-ip="${esc(i.public_ip || "")}" data-name="${esc(i.name || i.id)}" data-state="${esc(i.state)}" style="color:${color}">${dot} ${esc(i.name || i.id)} · ${esc(i.state)} · ${esc(i.public_ip || "no ip")}</option>`;
                }).join("");
                showInstStatus();
            } catch (err) { instSel.innerHTML = `<option value="">error</option>`; toast(err.message, "error"); }
        };

        document.getElementById("provBtn").onclick = async () => {
            const opt = instSel.selectedOptions[0];
            if (!opt || !opt.value) { toast("Select an instance.", "error"); return; }
            const groups = Array.from(view.querySelectorAll(".grp:checked")).map((c) => c.value);
            try {
                const res = await api("POST", "/api/admin/provision-ec2-global", {
                    username: document.getElementById("provUser").value,
                    instance_id: opt.value,
                    instance_ip: opt.dataset.ip,
                    instance_name: opt.dataset.name,
                    region: document.getElementById("provRegion").value,
                    linux_groups: groups,
                });
                toast(res.message || "Provisioned.", "success");
                renderRegions();
            } catch (e) { toast(e.message, "error"); }
        };

        // Active EC2 Provisions: searchable list. Action buttons must be re-wired after
        // each re-render, so keep the wiring in a function scoped to the provisions list.
        const provList = document.getElementById("provList");
        const provSearch = document.getElementById("provSearch");

        function wireProvisions(scope) {
            // Revoke
            scope.querySelectorAll("[data-revoke]").forEach((b) => b.onclick = async () => {
                const p = JSON.parse(b.dataset.revoke);
                if (!confirm(`Revoke ${p.username}'s access on ${p.instance_name || p.instance_id}?`)) return;
                try {
                    const res = await api("POST", "/api/admin/regions/revoke-ec2", {
                        username: p.username, instance_id: p.instance_id,
                        instance_ip: p.instance_ip, instance_name: p.instance_name, region: p.region,
                    });
                    toast(res.message || "Revocation started.", "success");
                } catch (e) { toast(e.message, "error"); }
            });

            // Edit Groups — toggle inline editor row.
            scope.querySelectorAll("[data-editgroups]").forEach((b) => b.onclick = () => {
                const editor = scope.querySelector(`[data-editor="${CSS.escape(b.dataset.editgroups)}"]`);
                if (editor) editor.hidden = !editor.hidden;
            });
            scope.querySelectorAll("[data-canceleditor]").forEach((b) => b.onclick = () => {
                const editor = scope.querySelector(`[data-editor="${CSS.escape(b.dataset.canceleditor)}"]`);
                if (editor) editor.hidden = true;
            });
            scope.querySelectorAll("[data-savegroups]").forEach((b) => b.onclick = async () => {
                const p = JSON.parse(b.dataset.prov);
                const editor = scope.querySelector(`[data-editor="${CSS.escape(b.dataset.savegroups)}"]`);
                const groups = Array.from(editor.querySelectorAll(".grp-edit:checked")).map((c) => c.value);
                try {
                    const res = await api("POST", "/api/admin/regions/update-groups", {
                        username: p.username, instance_id: p.instance_id,
                        instance_ip: p.instance_ip, instance_name: p.instance_name,
                        region: p.region, linux_groups: groups,
                    });
                    toast(res.message || "Groups update started.", "success");
                    renderRegions();
                } catch (e) { toast(e.message, "error"); }
            });
        }

        function renderProvList() {
            const q = (provSearch ? provSearch.value : "").trim().toLowerCase();
            const groups = byUserEntries.filter(([user, list]) =>
                !q || user.toLowerCase().includes(q) ||
                list.some((p) => (p.instance_name || p.instance_id || "").toLowerCase().includes(q))
            );
            const cnt = document.getElementById("provCount");
            if (cnt) cnt.textContent = groups.length;
            provList.innerHTML = groups.map(provGroupHtml).join("") ||
                `<p class="muted">${q ? "No provisions match your search." : "No active provisions."}</p>`;
            wireProvisions(provList);
        }

        if (provSearch) provSearch.oninput = renderProvList;
        wireProvisions(provList);
    } catch (e) { errorCard(view, e); }
}

/* Human label for a linux group; flags `sudo` with a warning marker (matches screenshot). */
function groupLabel(g) {
    return g === "sudo" ? `<span class="grp-warn">⚠ ${esc(g)}</span>` : esc(g);
}

/* One row in a user's Active EC2 Provisions table, plus its hidden Edit-Groups editor row. */
function provisionRowHtml(p, allowedGroups) {
    const key = `${p.username}__${p.instance_id}`;
    const current = p.linux_groups || [];
    const groupBadges = current.length
        ? current.map((g) => `<span class="badge neutral">${esc(g)}</span>`).join(" ")
        : `<span class="muted">—</span>`;
    const editChecks = (allowedGroups || []).map((g) =>
        `<label class="checkbox-row"><input type="checkbox" class="grp-edit" value="${esc(g)}" ${current.includes(g) ? "checked" : ""}> ${groupLabel(g)}</label>`
    ).join("");
    const provJson = esc(JSON.stringify(p));
    return `
      <tr>
        <td><strong>${esc(p.instance_name || p.instance_id)}</strong></td>
        <td class="mono">${esc(p.instance_ip || "—")}</td>
        <td><span class="badge neutral" title="${esc(REGION_NAMES[p.region] || "")}">${esc(p.region || "—")}</span></td>
        <td>${groupBadges}</td>
        <td class="muted">${esc(p.provisioned_at || "—")}</td>
        <td><div class="actions">
          <button class="btn small secondary" data-editgroups="${esc(key)}">Edit Groups</button>
          <button class="btn small danger" data-revoke='${provJson}'>Revoke</button>
        </div></td>
      </tr>
      <tr class="grp-editor-row" data-editor="${esc(key)}" hidden>
        <td colspan="6">
          <div class="grp-editor">
            <span class="form-label">Linux groups for ${esc(p.instance_name || p.instance_id)}</span>
            <div class="grp-inline">${editChecks || '<span class="muted">No groups configured.</span>'}</div>
            <div class="actions">
              <button class="btn small" data-savegroups="${esc(key)}" data-prov='${provJson}'>Save</button>
              <button class="btn small secondary" data-canceleditor="${esc(key)}">Cancel</button>
            </div>
          </div>
        </td>
      </tr>`;
}

/* =========================================================================
 * Audit log
 * ========================================================================= */
const AUDIT_PER_PAGE = 15;

async function renderAuditLog() {
    const view = mount("audit-log");
    view.innerHTML = `
      ${pageHeader("Audit Log", "Login activity and actions across the portal")}
      <div class="card">
        <div class="inline">
          <div><label class="form-label">Delete entries older than (days)</label><input type="number" id="days" min="1" placeholder="30"></div>
          <div class="grow-0"><button class="btn danger" id="delBtn">${icon("trash")}<span>Delete old logs</span></button></div>
        </div>
      </div>
      <div class="tabs" id="auditTabs">
        <button type="button" class="tab active" data-cat="login">Login activity</button>
        <button type="button" class="tab" data-cat="actions">Actions</button>
      </div>
      <div id="auditTable"><div class="spinner">Loading…</div></div>`;

    document.getElementById("delBtn").onclick = async () => {
        const days = parseInt(document.getElementById("days").value, 10);
        if (!days || days < 1) { toast("Enter a positive number of days.", "error"); return; }
        if (!confirm(`Delete audit logs older than ${days} days?`)) return;
        try {
            const res = await api("POST", "/api/admin/audit-log/delete", { days });
            toast(res.message, "success");
            renderAuditLog();
        } catch (e) { toast(e.message, "error"); }
    };

    const tabs = document.getElementById("auditTabs");
    tabs.querySelectorAll(".tab").forEach((b) => b.onclick = () => {
        tabs.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === b));
        loadAuditPage(b.dataset.cat, 1);
    });
    loadAuditPage("login", 1);
}

async function loadAuditPage(category, page) {
    const box = document.getElementById("auditTable");
    if (!box) return;
    box.innerHTML = `<div class="spinner">Loading…</div>`;
    try {
        const d = await api("GET", `/api/admin/audit-log?category=${category}&page=${page}&per_page=${AUDIT_PER_PAGE}`);
        let head, rows;
        if (category === "login") {
            head = `<tr><th>Time</th><th>User</th><th>IP address</th></tr>`;
            rows = d.entries.map((e) =>
                `<tr>
                  <td class="muted">${esc(e.timestamp)}</td>
                  <td><strong>${esc(e.target_user)}</strong></td>
                  <td class="mono">${esc(e.ip_address || "—")}</td>
                </tr>`
            ).join("");
        } else {
            head = `<tr><th>Time</th><th>Actor</th><th>Target</th><th>Action</th><th>Details</th><th>IP</th></tr>`;
            rows = d.entries.map((e) =>
                `<tr>
                  <td class="muted">${esc(e.timestamp)}</td>
                  <td>${esc(e.admin_username)}</td>
                  <td>${esc(e.target_user)}</td>
                  <td><span class="badge neutral">${esc(e.action)}</span></td>
                  <td class="mono">${esc(JSON.stringify(e.details))}</td>
                  <td>${esc(e.ip_address || "—")}</td>
                </tr>`
            ).join("");
        }
        const cols = category === "login" ? 3 : 6;
        box.innerHTML = `
          <div class="table-wrap"><table>
            <thead>${head}</thead>
            <tbody>${rows || `<tr><td colspan="${cols}" class="muted">No entries.</td></tr>`}</tbody>
          </table></div>
          ${pagerHtml(d.page, d.pages)}`;
        wirePager(box, (p) => loadAuditPage(category, p));
    } catch (e) { box.innerHTML = ""; toast(e.message, "error"); }
}

/* =========================================================================
 * Diagnostics (backend event log)
 * ========================================================================= */
const DEBUG_PER_PAGE = 40;
let DEBUG_FILTER = { category: "all", level: "all", page: 1 };
let DEBUG_AUTO = null; // setInterval handle for auto-refresh

const LEVEL_BADGE = { INFO: "neutral", WARN: "warn", ERROR: "danger" };

async function renderDebugLogs() {
    const view = mount("debug-logs");
    // Stop any auto-refresh from a previous visit.
    if (DEBUG_AUTO) { clearInterval(DEBUG_AUTO); DEBUG_AUTO = null; }

    const cats = ["all", "auth", "user", "aws", "provision", "system", "error"];
    const levels = ["all", "INFO", "WARN", "ERROR"];
    view.innerHTML = `
      ${pageHeader("Diagnostics", "Live backend event log — logins, AWS security-group changes, requests, and errors")}
      <div class="card">
        <div class="inline" style="flex-wrap:wrap; gap:12px; align-items:flex-end;">
          <div>
            <label class="form-label">Category</label>
            <select id="dbgCat">${cats.map((c) => `<option value="${c}" ${c === DEBUG_FILTER.category ? "selected" : ""}>${c}</option>`).join("")}</select>
          </div>
          <div>
            <label class="form-label">Level</label>
            <select id="dbgLevel">${levels.map((l) => `<option value="${l}" ${l === DEBUG_FILTER.level ? "selected" : ""}>${l}</option>`).join("")}</select>
          </div>
          <div class="grow-0"><button class="btn secondary" id="dbgRefresh">Refresh</button></div>
          <div class="grow-0"><label class="checkbox-row" style="margin:0;"><input type="checkbox" id="dbgAuto"> Auto-refresh (5s)</label></div>
          <div class="grow"></div>
          <div class="grow-0"><button class="btn danger" id="dbgClear">${icon("trash")}<span>Clear all</span></button></div>
        </div>
      </div>
      <div id="dbgTable"><div class="spinner">Loading…</div></div>`;

    const applyFilters = () => {
        DEBUG_FILTER.category = document.getElementById("dbgCat").value;
        DEBUG_FILTER.level = document.getElementById("dbgLevel").value;
        loadDebugPage(1);
    };
    document.getElementById("dbgCat").onchange = applyFilters;
    document.getElementById("dbgLevel").onchange = applyFilters;
    document.getElementById("dbgRefresh").onclick = () => loadDebugPage(DEBUG_FILTER.page);
    document.getElementById("dbgAuto").onchange = (e) => {
        if (DEBUG_AUTO) { clearInterval(DEBUG_AUTO); DEBUG_AUTO = null; }
        if (e.target.checked) {
            DEBUG_AUTO = setInterval(() => {
                // Only refresh while still on this view.
                if (location.hash === "#/debug-logs") loadDebugPage(DEBUG_FILTER.page, true);
                else { clearInterval(DEBUG_AUTO); DEBUG_AUTO = null; }
            }, 5000);
        }
    };
    document.getElementById("dbgClear").onclick = async () => {
        if (!confirm("Clear ALL diagnostic log entries? This cannot be undone.")) return;
        try {
            const res = await api("POST", "/api/admin/debug-logs/delete", { clear_all: true });
            toast(res.message, "success");
            loadDebugPage(1);
        } catch (e) { toast(e.message, "error"); }
    };

    loadDebugPage(1);
}

async function loadDebugPage(page, quiet = false) {
    DEBUG_FILTER.page = page;
    const box = document.getElementById("dbgTable");
    if (!box) return;
    if (!quiet) box.innerHTML = `<div class="spinner">Loading…</div>`;
    try {
        const q = `category=${encodeURIComponent(DEBUG_FILTER.category)}&level=${encodeURIComponent(DEBUG_FILTER.level)}&page=${page}&per_page=${DEBUG_PER_PAGE}`;
        const d = await api("GET", `/api/admin/debug-logs?${q}`);
        const rows = d.entries.map((e, i) => {
            const badge = LEVEL_BADGE[e.level] || "neutral";
            const hasDetails = e.details && Object.keys(e.details).length > 0;
            const toggle = hasDetails
                ? `<button type="button" class="btn small secondary dbg-toggle" data-idx="${i}">Details</button>`
                : `<span class="muted">—</span>`;
            const detailsRow = hasDetails
                ? `<tr class="dbg-details" data-idx="${i}" hidden><td colspan="6">
                     <pre class="mono" style="margin:0; white-space:pre-wrap; word-break:break-word;">${esc(JSON.stringify(e.details, null, 2))}</pre>
                   </td></tr>`
                : "";
            return `<tr>
                  <td class="muted" style="white-space:nowrap;">${esc(e.timestamp)}</td>
                  <td><span class="badge ${badge}">${esc(e.level)}</span></td>
                  <td><span class="badge neutral">${esc(e.category)}</span></td>
                  <td>${esc(e.actor || "—")}</td>
                  <td>${esc(e.message)}</td>
                  <td>${toggle}</td>
                </tr>${detailsRow}`;
        }).join("");
        box.innerHTML = `
          <div class="table-wrap"><table>
            <thead><tr><th>Time</th><th>Level</th><th>Category</th><th>Actor</th><th>Message</th><th></th></tr></thead>
            <tbody>${rows || `<tr><td colspan="6" class="muted">No diagnostic entries.</td></tr>`}</tbody>
          </table></div>
          ${pagerHtml(d.page, d.pages)}`;
        box.querySelectorAll(".dbg-toggle").forEach((b) => b.onclick = () => {
            const dr = box.querySelector(`.dbg-details[data-idx="${b.dataset.idx}"]`);
            if (dr) { dr.hidden = !dr.hidden; b.textContent = dr.hidden ? "Details" : "Hide"; }
        });
        wirePager(box, (p) => loadDebugPage(p));
    } catch (e) { if (!quiet) { box.innerHTML = ""; toast(e.message, "error"); } }
}

/* =========================================================================
 * Subadmins
 * ========================================================================= */
async function renderAdmins() {
    const view = mount("admins");
    const canManage = hasPerm("can_manage_users");
    try {
        const data = await api("GET", "/api/admin/admins");
        const defs = data.permission_definitions;
        const entries = Object.entries(data.subadmins);

        // Compact list: just the names + a summary of granted privileges. Clicking a
        // name (or "Edit privileges") reveals the editable checkboxes for that subadmin.
        const rows = entries.map(([u, info]) => {
            const perms = info.admin_permissions || {};
            const grantedBadges = defs.filter((d) => perms[d.key])
                .map((d) => `<span class="badge neutral">${esc(d.label)}</span>`).join(" ")
                || `<span class="muted">No privileges</span>`;
            const checks = defs.map((d) =>
                `<label class="checkbox-row"><input type="checkbox" data-perm="${d.key}" ${perms[d.key] ? "checked" : ""} ${canManage ? "" : "disabled"}> ${esc(d.label)}</label>`
            ).join("");
            return `
              <tr class="subadmin-row" data-toggle="${esc(u)}">
                <td><strong>${esc(u)}</strong></td>
                <td>${grantedBadges}</td>
                <td><div class="actions"><button class="btn small secondary" data-edit="${esc(u)}">${canManage ? "Edit privileges" : "View privileges"}</button></div></td>
              </tr>
              <tr class="subadmin-editor" data-editor="${esc(u)}" hidden>
                <td colspan="3">
                  <div class="grp-editor">
                    <span class="form-label">Privileges for ${esc(u)}</span>
                    ${checks}
                    ${canManage ? `<div class="actions"><button class="btn small" data-save="${esc(u)}">Save privileges</button></div>` : `<p class="muted">You have read-only access.</p>`}
                  </div>
                </td>
              </tr>`;
        }).join("");

        view.innerHTML = `
          ${pageHeader("Subadmins", "Employees with elevated privileges — click a name to edit privileges")}
          <div class="card">
            <div class="table-wrap"><table>
              <thead><tr><th>Subadmin</th><th>Privileges</th><th>Actions</th></tr></thead>
              <tbody>${rows || `<tr><td colspan="3" class="muted">No subadmins.</td></tr>`}</tbody>
            </table></div>
          </div>`;

        const toggle = (u) => {
            const editor = view.querySelector(`[data-editor="${CSS.escape(u)}"]`);
            if (editor) editor.hidden = !editor.hidden;
        };
        // Row click toggles the editor; the button's own handler also toggles, so skip
        // the row handler when the click originated on the button (avoids a double toggle).
        view.querySelectorAll(".subadmin-row").forEach((tr) => tr.onclick = (e) => {
            if (e.target.closest("[data-edit]")) return;
            toggle(tr.dataset.toggle);
        });
        view.querySelectorAll("[data-edit]").forEach((b) => b.onclick = () => toggle(b.dataset.edit));

        view.querySelectorAll("[data-save]").forEach((b) => b.onclick = async () => {
            const editor = view.querySelector(`[data-editor="${CSS.escape(b.dataset.save)}"]`);
            const permissions = {};
            editor.querySelectorAll("[data-perm]").forEach((c) => permissions[c.dataset.perm] = c.checked);
            try {
                const res = await api("POST", `/api/admin/admins/${encodeURIComponent(b.dataset.save)}/permissions`, { permissions });
                toast(res.message, "success");
                renderAdmins();
            } catch (e) { toast(e.message, "error"); }
        });
    } catch (e) { errorCard(view, e); }
}

/* =========================================================================
 * Fetch credentials (shared by the dedicated page and the employee dashboard)
 * Anyone with can_fetch_credentials (admins + subadmins) can look up any
 * user's OTP seed + SSH public keys.
 * ========================================================================= */
function credentialLookupCard() {
    return `<div class="card">
      <h2 class="card-title">Fetch user credentials</h2>
      <p class="muted">Look up any user's OTP seed and SSH public keys.</p>
      <div class="inline">
        <div><label class="form-label">Username</label><input type="text" id="credUser" placeholder="e.g. john_doe"></div>
        <div class="grow-0"><button class="btn" id="credBtn">${icon("key")}<span>Fetch</span></button></div>
      </div>
      <div id="credResult" class="mt-3"></div>
    </div>`;
}

function wireCredentialLookup() {
    const btn = document.getElementById("credBtn");
    if (!btn) return;
    const input = document.getElementById("credUser");
    const run = async () => {
        const u = input.value.trim();
        if (!u) { toast("Enter a username.", "error"); return; }
        const box = document.getElementById("credResult");
        box.innerHTML = `<div class="spinner">Fetching…</div>`;
        try {
            const d = await api("GET", `/api/credentials/${encodeURIComponent(u)}`);
            const keys = d.ssh_keys.map((k) =>
                `<div class="credbox">
                   <div class="muted">${esc(k.name)} · ${esc(k.created_at)}</div>
                   <div class="mono">${esc(k.public_key)}</div>
                   <div class="mt-1">${copyBtn(k.public_key, "Copy key")}</div>
                 </div>`
            ).join("") || `<p class="muted">No SSH keys on file.</p>`;
            box.innerHTML = `
              <div class="credbox">
                <div class="muted">OTP seed — ${esc(d.username)}</div>
                <div class="mono">${esc(d.otp_seed || "—")}</div>
                ${d.otp_seed ? `<div class="mt-1">${copyBtn(d.otp_seed, "Copy seed")}</div>` : ""}
              </div>
              <h2 class="card-title mt-2">SSH keys</h2>
              ${keys}`;
        } catch (e) { box.innerHTML = ""; toast(e.message, "error"); }
    };
    btn.onclick = run;
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
}

function renderCredentials() {
    const view = mount("credentials");
    view.innerHTML = `${pageHeader("Fetch Credentials", "Retrieve a user's OTP seed and SSH public keys.")}${credentialLookupCard()}`;
    wireCredentialLookup();
}

/* =========================================================================
 * SSH usage help (tabbed: Linux/macOS, Windows, PuTTY)
 * ========================================================================= */
function codeBlock(text) {
    return `<div class="codeblock">${copyBtn(text, "Copy")}<pre>${esc(text)}</pre></div>`;
}

function sshStep(n, desc, code) {
    return `<div class="ssh-step">
      <div class="num">${n}</div>
      <div class="body">
        <p>${desc}</p>
        ${code ? codeBlock(code) : ""}
      </div>
    </div>`;
}

function sshUsageCard(username) {
    const u = username || "<username>";
    const key = `<span class="mono">id_ed25519</span>`;

    const linux = `<div class="ssh-steps">
      ${sshStep(1, `Move into the folder where your private key ${key} is saved, then restrict its permissions so SSH will trust it:`, `chmod 600 id_ed25519`)}
      ${sshStep(2, `Connect to the server. You will be prompted for the one-time code from your authenticator app:`, `ssh -i id_ed25519 ${u}@<server-ip>`)}
    </div>`;

    const windows = `<div class="ssh-steps">
      ${sshStep(1, `Open <strong>PowerShell</strong> in the folder containing ${key} and lock down the file so SSH will accept it:`, `icacls id_ed25519 /inheritance:r /grant:r "%USERNAME%:R"`)}
      ${sshStep(2, `Connect to the server, entering your authenticator one-time code when asked:`, `ssh -i id_ed25519 ${u}@<server-ip>`)}
    </div>`;

    const putty = `<div class="ssh-steps">
      ${sshStep(1, `Open <strong>PuTTYgen</strong>, click <em>Load</em> and select your ${key} file, then click <em>Save private key</em> to export it as <span class="mono">id_ed25519.ppk</span>.`)}
      ${sshStep(2, `In <strong>PuTTY</strong>, set this as the Host Name, then under <em>Connection → SSH → Auth</em> choose your <span class="mono">.ppk</span> file and click <em>Open</em>:`, `${u}@<server-ip>`)}
    </div>`;

    return `<div class="card">
      <h2 class="card-title">How to use your SSH key</h2>
      <p class="muted">Use the private key you downloaded to connect to your server over SSH. Choose your operating system below.</p>
      <div class="tabs mt-2" data-tabs>
        <button type="button" class="tab active" data-tab="linux">Linux / macOS</button>
        <button type="button" class="tab" data-tab="windows">Windows</button>
        <button type="button" class="tab" data-tab="putty">PuTTY</button>
      </div>
      <div class="tab-panel active" data-panel="linux">${linux}</div>
      <div class="tab-panel" data-panel="windows">${windows}</div>
      <div class="tab-panel" data-panel="putty">${putty}</div>
      <p class="muted mt-2">Replace <span class="mono">&lt;server-ip&gt;</span> with the address of the server you were granted access to.</p>
    </div>`;
}

function wireTabs(scope) {
    scope.querySelectorAll("[data-tabs]").forEach((tabs) => {
        const card = tabs.closest(".card");
        tabs.querySelectorAll(".tab").forEach((btn) => {
            btn.onclick = () => {
                tabs.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === btn));
                card.querySelectorAll(".tab-panel").forEach((p) =>
                    p.classList.toggle("active", p.dataset.panel === btn.dataset.tab));
            };
        });
    });
}

/* =========================================================================
 * Employee dashboard
 * ========================================================================= */
async function renderEmployee() {
    const view = mount("employee");
    try {
        const d = await api("GET", "/api/employee/dashboard");
        const info = d.user_info;
        const keyRows = d.ssh_keys.map((k) =>
            `<div class="credbox">
               <div class="muted">${esc(k.key_name)} · ${esc(k.created_at)}</div>
               <div class="mono">${esc(k.ssh_public_key)}</div>
               <div class="actions mt-1">
                 ${copyBtn(k.ssh_public_key, "Copy key")}
                 <button class="btn small danger" data-delkey="${k.id}">${icon("trash")}<span>Delete</span></button>
               </div>
             </div>`
        ).join("") || `<p class="muted">No SSH keys yet.</p>`;

        const provRows = d.provisioned_instances.map((p) =>
            `<tr><td>${esc(p.instance_name || p.instance_id)}</td><td>${esc(p.region || "—")}</td><td>${esc((p.linux_groups || []).join(", ") || "—")}</td></tr>`
        ).join("") || `<tr><td colspan="3" class="muted">None.</td></tr>`;

        const apiTokenBlock = d.has_subadmin_access
            ? `<div class="card">
                 <h2 class="card-title">API token</h2>
                 ${d.api_token
                     ? `<div class="credbox mono">${esc(d.api_token)}</div>
                        <div class="actions mt-1">${copyBtn(d.api_token, "Copy token")}
                          <button class="btn secondary" id="genApiTok">Regenerate API token</button></div>`
                     : `<p class="muted">No API token generated yet.</p>
                        <button class="btn secondary mt-1" id="genApiTok">Generate API token</button>`}
               </div>`
            : "";

        view.innerHTML = `
          ${pageHeader(`Welcome, ${d.username}`, d.access_result ? esc(d.access_result) : "Your remote-access dashboard.")}

          <div class="card">
            <h2 class="card-title">Your access</h2>
            <p>Logs: ${boolBadge(info.allowLogAccess)} &nbsp; Metrics: ${boolBadge(info.allowServerMetricsAccess)} &nbsp; HP Agent: ${boolBadge(info.allowHpAgentAccess)}</p>
            <p class="muted">Ports: ${esc((info.portsToOpen || []).join(", ") || "—")}</p>
          </div>

          <div class="card">
            <h2 class="card-title">SSH keys</h2>
            ${keyRows}
            <hr class="sep">
            <div class="form-group">
              <label class="form-label">Add a public key</label>
              <textarea id="pubkey" placeholder="ssh-ed25519 AAAA..."></textarea>
            </div>
            <div class="form-group"><input type="text" id="keyname" placeholder="Key name (optional)"></div>
            <div class="actions">
              <button class="btn" id="addKeyBtn">Add key</button>
              <button class="btn secondary" id="genKeyBtn">Generate new key pair (download)</button>
            </div>
          </div>

          ${sshUsageCard(d.username)}

          <div class="card">
            <h2 class="card-title">Provisioned instances</h2>
            <div class="table-wrap"><table>
              <thead><tr><th>Instance</th><th>Region</th><th>Groups</th></tr></thead>
              <tbody>${provRows}</tbody>
            </table></div>
          </div>

          ${apiTokenBlock}`;

        wireTabs(view);
        document.getElementById("addKeyBtn").onclick = async () => {
            try {
                await api("POST", "/api/employee/ssh-keys", {
                    ssh_public_key: document.getElementById("pubkey").value,
                    key_name: document.getElementById("keyname").value,
                });
                toast("SSH key saved.", "success");
                renderEmployee();
            } catch (e) { toast(e.message, "error"); }
        };
        document.getElementById("genKeyBtn").onclick = generateKeyPair;
        view.querySelectorAll("[data-delkey]").forEach((b) => b.onclick = async () => {
            if (!confirm("Delete this SSH key?")) return;
            try {
                await api("DELETE", `/api/employee/ssh-keys/${b.dataset.delkey}`);
                toast("Key deleted.", "success");
                renderEmployee();
            } catch (e) { toast(e.message, "error"); }
        });
        const genTok = document.getElementById("genApiTok");
        if (genTok) genTok.onclick = async () => {
            try {
                await api("POST", "/api/employee/api-token");
                toast("API token generated.", "success");
                renderEmployee();
            } catch (e) { toast(e.message, "error"); }
        };
    } catch (e) { errorCard(view, e); }
}

async function generateKeyPair() {
    try {
        const res = await fetch("/api/employee/ssh-keys/generate", {
            method: "POST", headers: { [TOKEN_HEADER]: getToken() },
        });
        if (res.status === 401) { handleUnauthorized(); return; }
        if (!res.ok) { toast("Failed to generate key.", "error"); return; }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = "id_ed25519"; a.click();
        URL.revokeObjectURL(url);
        toast("Key pair generated and private key downloaded.", "success");
        renderEmployee();
    } catch (e) { toast(e.message, "error"); }
}

/* =========================================================================
 * Router
 * ========================================================================= */
function route() {
    const hash = location.hash || "";
    const path = hash.startsWith("#/") ? hash.slice(2) : "";
    const parts = path.split("/").filter(Boolean);

    if (!ME) { renderLogin(); return; }

    if (parts.length === 0) { location.hash = homeHash(); return; }

    switch (parts[0]) {
        case "login": location.hash = homeHash(); return;
        case "dashboard": return renderAdminDashboard();
        case "users": return renderUsers();
        case "add-user": return renderAddUser();
        case "edit-user": return renderEditUser(decodeURIComponent(parts[1] || ""));
        case "regions": return renderRegions();
        case "audit-log": return renderAuditLog();
        case "debug-logs": return renderDebugLogs();
        case "admins": return renderAdmins();
        case "credentials": return renderCredentials();
        case "employee": return renderEmployee();
        default: location.hash = homeHash(); return;
    }
}

/* =========================================================================
 * Periodic identity refresh
 * Keeps nav/permissions in sync when an admin changes them, without a manual
 * refresh. Re-renders only when the identity actually changed (to avoid
 * disrupting form input), and refreshes immediately when the tab regains focus.
 * ========================================================================= */
const IDENTITY_POLL_MS = 60000;
let identityPollStarted = false;

function identitySignature(me) {
    if (!me) return "";
    return JSON.stringify({ a: me.actor_type, r: me.role, p: me.permissions });
}

async function refreshIdentity() {
    if (!getToken() || !ME) return; // not logged in — nothing to sync
    let me;
    try {
        me = await api("GET", "/api/auth/me");
    } catch (e) {
        // A 401 is already handled by api() (logout on genuine session loss);
        // transient errors are ignored so we don't disturb the session.
        return;
    }
    if (!me) return;
    const changed = identitySignature(me) !== identitySignature(ME);
    ME = me;
    if (changed) {
        toast("Your permissions were updated.", "info");
        route(); // re-render nav + current view against the new privileges
    }
}

function startIdentityPolling() {
    if (identityPollStarted) return;
    identityPollStarted = true;
    setInterval(() => { if (!document.hidden) refreshIdentity(); }, IDENTITY_POLL_MS);
    document.addEventListener("visibilitychange", () => {
        if (!document.hidden) refreshIdentity();
    });
}

async function boot() {
    // 1) Capture a token/error handed back by the SAML flow via the fragment.
    const frag = location.hash || "";
    if (frag.startsWith("#saml_token=")) {
        setToken(decodeURIComponent(frag.slice("#saml_token=".length)));
        history.replaceState(null, "", "/");
    } else if (frag.startsWith("#saml_error=")) {
        toast(decodeURIComponent(frag.slice("#saml_error=".length)), "error");
        history.replaceState(null, "", "/");
    }

    // 2) Resolve identity from any stored token.
    if (getToken()) {
        try { ME = await api("GET", "/api/auth/me"); }
        catch (e) { ME = null; }
    }

    window.addEventListener("hashchange", route);
    startIdentityPolling();
    startCopyDelegation();
    route();
}

boot();
