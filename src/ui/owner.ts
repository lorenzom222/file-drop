export {};

function ownerElement<T extends HTMLElement>(id: string, type: { new(): T }): T {
  const value = document.getElementById(id);
  if (!(value instanceof type)) throw new Error(`Missing owner UI element: ${id}`);
  return value;
}

const status = ownerElement("owner-status", HTMLParagraphElement);
const panel = ownerElement("owner-panel", HTMLElement);
const permission = ownerElement("permission", HTMLSelectElement);
const description = ownerElement("access-description", HTMLParagraphElement);
const create = ownerElement("link-device", HTMLButtonElement);
const invitationPanel = ownerElement("invitation-panel", HTMLElement);
const invitationURL = ownerElement("invitation-url", HTMLInputElement);
const expiry = ownerElement("invitation-status", HTMLParagraphElement);
const copy = ownerElement("copy-link", HTMLButtonElement);
const showQR = ownerElement("show-qr", HTMLButtonElement);
const image = ownerElement("invitation-qr", HTMLImageElement);
const feedback = ownerElement("owner-feedback", HTMLParagraphElement);
const mode = ownerElement("link-mode", HTMLSelectElement);
const namePanel = ownerElement("pair-name-panel", HTMLElement);
const pairName = ownerElement("pair-name", HTMLInputElement);
const linkPolicy = ownerElement("link-policy", HTMLParagraphElement);
const management = ownerElement("paired-management", HTMLElement);
const clientsStatus = ownerElement("clients-status", HTMLParagraphElement);
const pendingApprovals = ownerElement("pending-approvals", HTMLDivElement);
const pairedClients = ownerElement("paired-clients", HTMLDivElement);
let stateDir = "";
let canPair = false;
let clientsLoading = false;
const storageKey = "filedrop-owner-session";
let credential = "";
let storageAvailable = true;
let expiresAt = 0;
let linkedPermission = "";
let linkedMode = "temporary";
let qrObjectURL = "";
let busy = false;

function report(text: string, error = false): void {
  feedback.textContent = text;
  feedback.dataset.error = String(error);
}

function clearQR(): void {
  image.hidden = true;
  image.removeAttribute("src");
  if (qrObjectURL) URL.revokeObjectURL(qrObjectURL);
  qrObjectURL = "";
  showQR.textContent = "Show QR code";
}

function clearInvitation(): void {
  clearQR();
  expiresAt = 0;
  invitationURL.value = "";
  invitationPanel.hidden = true;
}

function forgetCredential(): void {
  credential = "";
  panel.hidden = true;
  management.hidden = true;
  pendingApprovals.replaceChildren();
  pairedClients.replaceChildren();
  clearInvitation();
  if (storageAvailable) {
    try { sessionStorage.removeItem(storageKey); }
    catch { storageAvailable = false; report("Browser storage is blocked; close this owner tab.", true); }
  }
}

function errorMessage(value: unknown): string {
  return typeof value === "object" && value !== null && "message" in value && typeof value.message === "string"
    ? value.message : "Owner request failed.";
}

async function request(path: string, body?: object): Promise<Response> {
  const headers: Record<string, string> = { "X-Filedrop-Request": "1" };
  if (credential) headers.Authorization = `Bearer ${credential}`;
  if (body) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {
    method: body ? "POST" : "GET", headers, body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(8000),
  });
  if (!response.ok) {
    const result: unknown = await response.json();
    if (response.status === 401) {
      forgetCredential();
      status.textContent = "Owner session ended. Open a new owner link from the receiver.";
    }
    throw new Error(errorMessage(result));
  }
  return response;
}

function updateExpiry(): void {
  if (!expiresAt) return;
  const remaining = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
  expiry.textContent = remaining > 0
    ? `Expires in ${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, "0")}`
    : "Link expired. Create a new link.";
  copy.disabled = showQR.disabled = remaining === 0 || busy;
  if (!remaining) clearQR();
}

async function initialize(): Promise<void> {
  const bootstrap = location.hash.slice(1);
  history.replaceState(null, "", location.pathname);
  try {
    if (bootstrap) {
      credential = "";
      const response = await request("/api/owner/session", { bootstrap });
      const data: unknown = await response.json();
      if (typeof data !== "object" || data === null || !("credential" in data) || typeof data.credential !== "string") {
        throw new Error("Invalid owner session response.");
      }
      credential = data.credential;
      try { sessionStorage.setItem(storageKey, credential); }
      catch {
        storageAvailable = false;
        report("Browser storage is blocked. Keep this tab open; reload will require restarting the receiver.", true);
      }
    } else {
      try { credential = sessionStorage.getItem(storageKey) ?? ""; }
      catch {
        storageAvailable = false;
        report("Browser storage is blocked. Open the owner invitation from the receiver.", true);
      }
    }
    if (!credential) return;
    const response = await request("/api/owner/status");
    const data: unknown = await response.json();
    if (typeof data !== "object" || data === null || !("can_view_inbox" in data) || typeof data.can_view_inbox !== "boolean" || !("can_download" in data) || typeof data.can_download !== "boolean") {
      throw new Error("Invalid owner capabilities.");
    }
    for (const option of Array.from(permission.options)) {
      if (option.value === "view") option.disabled = !data.can_view_inbox;
      if (option.value === "download") option.disabled = !data.can_download;
    }
    canPair = "can_pair" in data && data.can_pair === true;
    stateDir = "state_dir" in data && typeof data.state_dir === "string" ? data.state_dir : "";
    for (const option of Array.from(mode.options)) if (option.value === "remember") option.disabled = !canPair;
    management.hidden = !canPair;
    if (canPair) void refreshClients();
    panel.hidden = false;
    status.textContent = "Owner access · local receiver";
  } catch (error) {
    report(error instanceof Error ? error.message : "Could not connect to the owner service.", true);
  }
}

permission.addEventListener("change", () => {
  clearInvitation();
  report("");
  description.textContent = permission.value === "upload" ? "This link only permits uploads."
    : permission.value === "view" ? "This link reveals names and metadata for the whole visible inbox."
    : "This link allows reading all visible files in the inbox.";
});
mode.addEventListener("change", () => {
  clearInvitation();
  namePanel.hidden = mode.value !== "remember";
  linkPolicy.textContent = mode.value === "remember"
    ? "Enrollment link: 10 minutes, single use. Approved browser access lasts until revoked; login sessions last 30 minutes."
    : "Temporary link: 10 minutes. Guest session: 30 minutes.";
  report(mode.value === "remember" ? "The receiver must confirm the browser key in its terminal." : "");
});

create.addEventListener("click", async () => {
  if (busy) return;
  busy = true;
  create.disabled = permission.disabled = mode.disabled = true;
  clearInvitation();
  report("");
  try {
    const response = await request("/api/owner/invitations", { permission: permission.value, mode: mode.value, name: mode.value === "remember" ? pairName.value.trim() : "" });
    const data: unknown = await response.json();
    if (typeof data !== "object" || data === null || !("url" in data) || typeof data.url !== "string" || !("expires_at" in data) || typeof data.expires_at !== "string" || !("permission" in data) || data.permission !== permission.value || !Number.isFinite(Date.parse(data.expires_at))) {
      throw new Error("Invalid invitation response.");
    }
    const url = new URL(data.url);
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("Invalid invitation URL.");
    invitationURL.value = data.url;
    linkedPermission = permission.value;
    linkedMode = mode.value;
    expiresAt = Date.parse(data.expires_at);
    invitationPanel.hidden = false;
    report("New link created. The previous link for this access level no longer accepts new guests.");
  } catch (error) {
    report(error instanceof Error ? error.message : "Could not create the link.", true);
  } finally {
    busy = false;
    create.disabled = permission.disabled = mode.disabled = false;
    updateExpiry();
  }
});

copy.addEventListener("click", async () => {
  if (Date.now() >= expiresAt) { updateExpiry(); return; }
  try {
    await navigator.clipboard.writeText(invitationURL.value);
    report("Link copied.");
  } catch {
    invitationURL.focus();
    invitationURL.select();
    report("Clipboard is unavailable. Copy the selected link manually.", true);
  }
});

showQR.addEventListener("click", async () => {
  if (Date.now() >= expiresAt) { updateExpiry(); return; }
  if (!image.hidden) { clearQR(); return; }
  busy = true;
  create.disabled = permission.disabled = mode.disabled = true;
  updateExpiry();
  try {
    const response = await request("/api/owner/qr", {
      permission: linkedPermission, mode: linkedMode, invitation: new URL(invitationURL.value).hash.slice(1).replace(/^pair=/, ""),
    });
    if (!response.headers.get("Content-Type")?.startsWith("image/png")) throw new Error("Invalid QR response.");
    const blob = await response.blob();
    if (Date.now() >= expiresAt) { updateExpiry(); return; }
    qrObjectURL = URL.createObjectURL(blob);
    image.src = qrObjectURL;
    image.hidden = false;
    showQR.textContent = "Hide QR code";
  } catch (error) {
    report(error instanceof Error ? error.message : "Could not load the QR code.", true);
  } finally {
    busy = false;
    create.disabled = permission.disabled = mode.disabled = false;
    updateExpiry();
  }
});

image.addEventListener("error", () => { clearQR(); report("Could not display the QR code.", true); });
window.addEventListener("pagehide", clearQR);
type Client = { id: string; name: string; fingerprint: string; permission: string; status: string; last_seen: number };
type Pending = { id: string; name: string; fingerprint: string; permission: string; operation: string };

function clientRecord(value: unknown): value is Client {
  return typeof value === "object" && value !== null
    && "id" in value && typeof value.id === "string" && /^[a-f0-9]{64}$/.test(value.id)
    && "name" in value && typeof value.name === "string"
    && "fingerprint" in value && typeof value.fingerprint === "string"
    && "permission" in value && typeof value.permission === "string"
    && "status" in value && typeof value.status === "string"
    && "last_seen" in value && typeof value.last_seen === "number";
}
function pendingRecord(value: unknown): value is Pending {
  return typeof value === "object" && value !== null
    && "id" in value && typeof value.id === "string" && /^[a-f0-9]{64}$/.test(value.id)
    && "name" in value && typeof value.name === "string"
    && "fingerprint" in value && typeof value.fingerprint === "string"
    && "permission" in value && typeof value.permission === "string"
    && "operation" in value && typeof value.operation === "string";
}
function text(tag: string, value: string): HTMLElement {
  const el = document.createElement(tag); el.textContent = value; return el;
}
function groupFingerprint(value: string): string { return value.match(/.{1,4}/g)?.join(" ") ?? value; }
async function changeClient(body: object): Promise<void> {
  try { await request("/api/owner/clients", body); report("Access updated. Increases need terminal confirmation."); void refreshClients(true); }
  catch (error) { report(error instanceof Error ? error.message : "Could not change access.", true); }
}
async function refreshClients(force = false): Promise<void> {
  if (!credential || !canPair || clientsLoading || (!force && (document.visibilityState !== "visible" || management.contains(document.activeElement)))) return;
  clientsLoading = true;
  try {
    const response = await request("/api/owner/clients");
    const data: unknown = await response.json();
    if (typeof data !== "object" || data === null || !("clients" in data) || !Array.isArray(data.clients) || !data.clients.every(clientRecord) || !("pending" in data) || !Array.isArray(data.pending) || !data.pending.every(pendingRecord)) throw new Error("Invalid paired-browser list.");
    const pending = data.pending.map(p => {
      const row = document.createElement("div"); row.className = "paired-entry";
      row.append(text("strong", `${p.name} · ${p.operation}`), text("p", `Key: ${groupFingerprint(p.fingerprint)}`), text("p", `Permission: ${p.permission}`));
      const quote = (value: string) => "'" + value.replace(/'/g, "'\\''") + "'";
      row.append(text("code", `./bin/filedrop confirm -state-dir ${quote(stateDir)} ${p.id}`));
      const decline = document.createElement("button"); decline.textContent = "Decline";
      decline.addEventListener("click", () => { void changeClient({ id: p.id, action: "decline" }); });
      row.append(decline); return row;
    });
    const clients = data.clients.map(c => {
      const row = document.createElement("div"); row.className = "paired-entry";
      row.append(text("strong", `${c.name} · ${c.status}`), text("p", `Key: ${groupFingerprint(c.fingerprint)}`), text("p", `Last authenticated: ${new Date(c.last_seen).toLocaleString()}`));
      if (c.status === "active") {
        const label = document.createElement("input"); label.value = c.name; label.maxLength = 80; label.setAttribute("aria-label", `Name for ${c.name}`);
        const grant = document.createElement("select"); grant.setAttribute("aria-label", `Permission for ${c.name}`);
        for (const option of Array.from(permission.options)) grant.append(option.cloneNode(true));
        grant.value = c.permission;
        const save = document.createElement("button"); save.textContent = "Save access";
        save.addEventListener("click", () => { void changeClient({ id: c.id, action: "edit", name: label.value.trim(), permission: grant.value }); });
        const revoke = document.createElement("button"); revoke.textContent = "Revoke";
        revoke.addEventListener("click", () => { void changeClient({ id: c.id, action: "revoke" }); });
        row.append(label, grant, save, revoke);
      }
      return row;
    });
    pendingApprovals.replaceChildren(...pending);
    pairedClients.replaceChildren(...clients);
    clientsStatus.textContent = `${clients.length} saved browsers · ${pending.length} pending approvals`;
    clientsStatus.dataset.error = "false";
  } catch (error) {
    clientsStatus.textContent = error instanceof Error ? error.message : "Could not load paired browsers.";
    clientsStatus.dataset.error = "true";
  } finally { clientsLoading = false; }
}
setInterval(() => { void refreshClients(); }, 2000);
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") void refreshClients(); });
setInterval(updateExpiry, 1000);
void initialize();
