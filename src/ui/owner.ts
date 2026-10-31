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
const storageKey = "filedrop-owner-session";
let credential = "";
let storageAvailable = true;
let expiresAt = 0;
let linkedPermission = "";
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

create.addEventListener("click", async () => {
  if (busy) return;
  busy = true;
  create.disabled = permission.disabled = true;
  clearInvitation();
  report("");
  try {
    const response = await request("/api/owner/invitations", { permission: permission.value });
    const data: unknown = await response.json();
    if (typeof data !== "object" || data === null || !("url" in data) || typeof data.url !== "string" || !("expires_at" in data) || typeof data.expires_at !== "string" || !("permission" in data) || data.permission !== permission.value || !Number.isFinite(Date.parse(data.expires_at))) {
      throw new Error("Invalid invitation response.");
    }
    const url = new URL(data.url);
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("Invalid invitation URL.");
    invitationURL.value = data.url;
    linkedPermission = permission.value;
    expiresAt = Date.parse(data.expires_at);
    invitationPanel.hidden = false;
    report("New link created. The previous link for this access level no longer accepts new guests.");
  } catch (error) {
    report(error instanceof Error ? error.message : "Could not create the link.", true);
  } finally {
    busy = false;
    create.disabled = permission.disabled = false;
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
  create.disabled = permission.disabled = true;
  updateExpiry();
  try {
    const response = await request("/api/owner/qr", {
      permission: linkedPermission, invitation: new URL(invitationURL.value).hash.slice(1),
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
    create.disabled = permission.disabled = false;
    updateExpiry();
  }
});

image.addEventListener("error", () => { clearQR(); report("Could not display the QR code.", true); });
window.addEventListener("pagehide", clearQR);
setInterval(updateExpiry, 1000);
void initialize();
