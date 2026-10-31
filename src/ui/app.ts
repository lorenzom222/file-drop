function element<T extends HTMLElement>(id: string, type: { new(): T }): T {
  const value = document.getElementById(id);
  if (!(value instanceof type)) throw new Error(`Missing UI element: ${id}`);
  return value;
}

const picker = element("files", HTMLInputElement);
const chooseButton = element("choose-files", HTMLButtonElement);
const selection = element("selection", HTMLParagraphElement);
const uploadButton = element("upload", HTMLButtonElement);
const queue = element("queue", HTMLUListElement);
const connection = element("connection", HTMLParagraphElement);
const limits = element("limits", HTMLParagraphElement);
const inbox = element("inbox", HTMLElement);
const inboxStatus = element("inbox-status", HTMLParagraphElement);
const inboxFiles = element("inbox-files", HTMLTableSectionElement);
const downloadHeading = element("download-heading", HTMLTableCellElement);
const uploadPanel = element("upload-panel", HTMLElement);
const connectHelp = element("connect-help", HTMLElement);
const pairPanel = element("pair-panel", HTMLElement);
const pairButton = element("pair-browser", HTMLButtonElement);
const pairStatus = element("pair-status", HTMLParagraphElement);
const pairFingerprint = element("pair-fingerprint", HTMLParagraphElement);
let pairingInvitation = "";
let authGeneration = 0;

type State = "ready" | "uploading" | "saved" | "failed" | "canceled";
type Item = {
  file: File;
  state: State;
  status: HTMLSpanElement;
  progress: HTMLProgressElement;
  cancel: HTMLButtonElement;
  xhr?: XMLHttpRequest;
};

let items: Item[] = [];
let authorized = false;
let running = false;
let maxFile = 0;
let canViewInbox = false;
let canDownload = false;
let inboxLoading = false;
let inboxRefreshPending = false;
const headers = { "X-Filedrop-Request": "1" };

type InboxFile = { name: string; bytes: number; modified_at: string; id?: string };

type InboxRow = {
  row: HTMLTableRowElement;
  name: HTMLTableCellElement;
  size: HTMLTableCellElement;
  time: HTMLTimeElement;
  action: HTMLTableCellElement;
  link: HTMLAnchorElement;
};

const inboxRows = new Map<string, InboxRow>();

function clearInbox(): void {
  const hadFocus = inboxFiles.contains(document.activeElement);
  inboxFiles.replaceChildren();
  inboxRows.clear();
  if (hadFocus) inboxStatus.focus({ preventScroll: true });
}

function renderInbox(files: InboxFile[]): void {
  const focused = document.activeElement instanceof HTMLAnchorElement && inboxFiles.contains(document.activeElement)
    ? document.activeElement : null;
  const names = new Set(files.map(file => file.name));
  for (const [name, entry] of inboxRows) {
    if (!names.has(name)) {
      entry.row.remove();
      inboxRows.delete(name);
    }
  }
  for (const [index, file] of files.entries()) {
    let entry = inboxRows.get(file.name);
    if (!entry) {
      const row = document.createElement("tr");
      row.setAttribute("role", "row");
      const cells = ["file-name", "file-size", "file-time", "file-action"].map(className => {
        const cell = document.createElement("td");
        cell.className = className;
        cell.setAttribute("role", "cell");
        return cell;
      });
      const [name, size, date, action] = cells;
      if (!name || !size || !date || !action) throw new Error("Missing inbox cells.");
      const time = document.createElement("time");
      date.append(time);
      const link = document.createElement("a");
      link.textContent = "Download";
      action.append(link);
      row.append(...cells);
      entry = { row, name, size, time, action, link };
      inboxRows.set(file.name, entry);
    }
    entry.name.textContent = file.name;
    entry.size.textContent = bytes(file.bytes);
    const date = new Date(file.modified_at);
    entry.time.dateTime = file.modified_at;
    entry.time.title = date.toLocaleString();
    entry.time.textContent = date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
    entry.action.hidden = !canDownload;
    if (canDownload && file.id) {
      entry.link.href = `/api/downloads/${encodeURIComponent(file.id)}`;
      entry.link.download = file.name;
      entry.link.setAttribute("aria-label", `Download ${file.name}`);
    }
    const current = inboxFiles.children.item(index);
    if (current !== entry.row) inboxFiles.insertBefore(entry.row, current);
  }
  if (focused && document.activeElement !== focused) {
    if (inboxFiles.contains(focused)) focused.focus({ preventScroll: true });
    else inboxStatus.focus({ preventScroll: true });
  }
}

function isInboxFile(value: unknown): value is InboxFile {
  return typeof value === "object" && value !== null
    && "name" in value && typeof value.name === "string"
    && "bytes" in value && typeof value.bytes === "number" && Number.isSafeInteger(value.bytes) && value.bytes >= 0
    && "modified_at" in value && typeof value.modified_at === "string" && Number.isFinite(Date.parse(value.modified_at))
    && (!("id" in value) || (typeof value.id === "string" && value.id.length > 0 && value.id.length <= 1024));
}

function expireSession(): void {
  authorized = false;
  canViewInbox = false;
  canDownload = false;
  clearInbox();
  connection.textContent = "Session expired. Open a new invitation.";
  connection.dataset.error = "true";
  inboxStatus.textContent = "Session expired. Inbox access has ended.";
  inboxStatus.dataset.error = "true";
  refresh();
}

async function refreshInbox(force = false): Promise<void> {
  if (!authorized || !canViewInbox || document.visibilityState !== "visible") return;
  if (inboxLoading) {
    inboxRefreshPending ||= force;
    return;
  }
  inboxLoading = true;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch("/api/inbox", { headers, signal: controller.signal });
    const result: unknown = await response.json();
    if (!authorized || !canViewInbox) return;
    if (response.status === 401) {
      expireSession();
      return;
    }
    if (response.status === 403) canViewInbox = false;
    if (!response.ok) throw new Error(message(result, "Could not refresh the inbox."));
    if (typeof result !== "object" || result === null || !("files" in result) || !Array.isArray(result.files) || !result.files.every(isInboxFile) || (canDownload && result.files.some(file => !file.id))) {
      throw new Error("Server returned an invalid inbox listing.");
    }
    renderInbox(result.files);
    inboxStatus.textContent = result.files.length === 0
      ? "No files."
      : `${result.files.length} file${result.files.length === 1 ? "" : "s"}`;
    inboxStatus.dataset.error = "false";
  } catch (error) {
    if (!authorized) return;
    clearInbox();
    inboxStatus.textContent = controller.signal.aborted
      ? "Inbox refresh timed out. It will retry while this page is visible."
      : error instanceof Error ? error.message : "Could not refresh the inbox.";
    inboxStatus.dataset.error = "true";
  } finally {
    clearTimeout(timeout);
    inboxLoading = false;
    if (inboxRefreshPending) {
      inboxRefreshPending = false;
      void refreshInbox();
    }
  }
}

function bytes(value: number): string {
  const units = ["B", "KiB", "MiB", "GiB"];
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index++;
  }
  return `${index === 0 ? value : value.toFixed(1)} ${units[index]}`;
}

function message(value: unknown, fallback: string): string {
  if (typeof value === "object" && value !== null && "message" in value && typeof value.message === "string") {
    return value.message;
  }
  return fallback;
}

function refresh(): void {
  uploadPanel.hidden = !authorized && !running;
  connectHelp.hidden = authorized || !pairPanel.hidden;
  inbox.hidden = !authorized || !canViewInbox;
  picker.disabled = !authorized || running;
  chooseButton.disabled = picker.disabled;
  uploadButton.disabled = !authorized || running || !items.some(item => item.state === "ready");
  const ready = items.filter(item => item.state === "ready").length;
  uploadButton.textContent = running ? "Uploading..." : ready > 0 ? `Upload ${ready} file${ready === 1 ? "" : "s"}` : "Upload";
}

async function authenticate(): Promise<void> {
  const generation = ++authGeneration;
  const invitation = location.hash.slice(1);
  history.replaceState(null, "", location.pathname);
  authorized = false;
  canViewInbox = false;
  canDownload = false;
  inbox.hidden = true;
  clearInbox();
  pairPanel.hidden = true;
  pairStatus.textContent = pairFingerprint.textContent = "";
  if (invitation.startsWith("pair=")) {
    pairingInvitation = invitation.slice(5);
    pairPanel.hidden = false;
    pairButton.disabled = false;
    connection.textContent = "Pairing invitation";
    refresh();
    return;
  }
  refresh();
  try {
    let result: unknown;
    if (!invitation) {
      result = await reconnectBrowser((message, fingerprint) => {
        if (generation !== authGeneration) return;
        connection.textContent = message;
        if (fingerprint) pairFingerprint.textContent = fingerprint;
      });
      if (generation !== authGeneration) return;
      if (result === null) { connection.textContent = "Not connected"; connection.dataset.error = "false"; return; }
    } else {
    const response = await fetch("/api/session", {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ invitation }),
    });
    result = await response.json();
    if (!response.ok) throw new Error(message(result, "Could not authorize this browser."));
    }
    if (generation !== authGeneration) return;
    acceptSession(result);
  } catch (error) {
    if (generation !== authGeneration) return;
    connection.textContent = error instanceof Error ? error.message : "Connection failed.";
    connection.dataset.error = "true";
  }
  refresh();
}

function acceptSession(result: unknown): void {
    if (typeof result !== "object" || result === null || !("max_file_bytes" in result) || typeof result.max_file_bytes !== "number" || !("can_view_inbox" in result) || typeof result.can_view_inbox !== "boolean" || !("can_download" in result) || typeof result.can_download !== "boolean") {
      throw new Error("Server returned an invalid session.");
    }
    maxFile = result.max_file_bytes;
    canViewInbox = result.can_view_inbox;
    canDownload = result.can_download;
    authorized = true;
    connection.dataset.error = "false";
    connection.textContent = location.protocol === "https:"
      ? "Connected"
      : "Local test mode. Not encrypted.";
    connection.title = "Session lasts 30 minutes.";
    limits.textContent = `Up to ${bytes(maxFile)} per file.`;
    inbox.hidden = !canViewInbox;
    downloadHeading.hidden = !canDownload;
    void refreshInbox();
    pairPanel.hidden = true;
  refresh();
}

pairButton.addEventListener("click", async () => {
  const generation = ++authGeneration;
  pairButton.disabled = true;
  try {
    const result = await rememberBrowser(pairingInvitation, (message, fingerprint) => {
      if (generation !== authGeneration) return;
      pairStatus.textContent = message;
      if (fingerprint) pairFingerprint.textContent = `Key: ${fingerprint.match(/.{1,4}/g)?.join(" ")}`;
    });
    if (generation === authGeneration) acceptSession(result);
  } catch (error) {
    if (generation === authGeneration) {
      pairStatus.textContent = error instanceof Error ? error.message : "Pairing failed.";
      pairStatus.dataset.error = "true";
    }
  }
});
chooseButton.addEventListener("click", () => picker.click());

picker.addEventListener("change", () => {
  items = [];
  queue.replaceChildren();
  for (const file of Array.from(picker.files ?? [])) {
    const row = document.createElement("li");
    const name = document.createElement("strong");
    name.textContent = `${file.name} (${bytes(file.size)})`;
    const status = document.createElement("span");
    status.setAttribute("role", "status");
    const progress = document.createElement("progress");
    progress.max = 100;
    progress.value = 0;
    progress.hidden = true;
    progress.setAttribute("aria-label", `Upload progress for ${file.name}`);
    const cancel = document.createElement("button");
    cancel.textContent = "Cancel";
    cancel.hidden = true;
    const item: Item = { file, state: file.size > maxFile ? "failed" : "ready", status, progress, cancel };
    status.textContent = item.state === "ready" ? "Ready" : "File exceeds the receiver's size limit.";
    status.dataset.error = String(item.state === "failed");
    cancel.addEventListener("click", () => item.xhr?.abort());
    row.append(name, status, progress, cancel);
    queue.append(row);
    items.push(item);
  }
  selection.textContent = items.length === 0 ? "No files selected."
    : `${items.length} file${items.length === 1 ? "" : "s"} selected · ${bytes(items.reduce((total, item) => total + item.file.size, 0))}`;
  refresh();
});

function send(item: Item): Promise<void> {
  return new Promise(resolve => {
    const xhr = new XMLHttpRequest();
    item.xhr = xhr;
    item.state = "uploading";
    item.progress.hidden = false;
    item.cancel.hidden = false;
    item.status.textContent = "Uploading...";
    xhr.open("POST", "/api/uploads");
    xhr.setRequestHeader("X-Filedrop-Request", "1");
    xhr.timeout = 15 * 60 * 1000 + 10_000;
    xhr.responseType = "json";
    xhr.upload.addEventListener("progress", event => {
      if (event.lengthComputable) item.progress.value = event.loaded / event.total * 100;
      item.status.textContent = event.lengthComputable && event.loaded === event.total
        ? "Upload sent. Waiting for storage confirmation..."
        : "Uploading...";
    });
    function finish(state: State, text: string): void {
      item.state = state;
      item.progress.hidden = state !== "saved";
      item.status.textContent = text;
      item.status.dataset.error = String(state === "failed");
      item.cancel.hidden = true;
      item.xhr = undefined;
      resolve();
    }
    xhr.addEventListener("load", () => {
      const result: unknown = xhr.response;
      if (xhr.status === 201 && typeof result === "object" && result !== null && "name" in result && typeof result.name === "string" && "bytes" in result && result.bytes === item.file.size) {
        item.progress.value = 100;
        finish("saved", `Saved: ${result.name}`);
        void refreshInbox(true);
      } else {
        if (xhr.status === 401) {
          expireSession();
        }
        finish("failed", message(result, "Storage was not confirmed. Check the receiver before retrying."));
      }
    });
    xhr.addEventListener("error", () => finish("failed", "Connection lost. Check the receiver before retrying; the file may have been saved."));
    xhr.addEventListener("timeout", () => finish("failed", "Timed out. Check the receiver before retrying."));
    xhr.addEventListener("abort", () => finish("canceled", "Canceled. If completion raced cancellation, check the receiver."));
    const data = new FormData();
    data.append("file", item.file);
    xhr.send(data);
  });
}

uploadButton.addEventListener("click", async () => {
  if (running || !authorized) return;
  running = true;
  refresh();
  let next = 0;
  async function worker(): Promise<void> {
    while (authorized && next < items.length) {
      const item = items[next++];
      if (item?.state === "ready") await send(item);
    }
  }
  await Promise.all([worker(), worker()]);
  running = false;
  refresh();
});

setInterval(() => { void refreshInbox(); }, 3000);
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") void refreshInbox(true);
});
window.addEventListener("hashchange", () => { void authenticate(); });

void authenticate();
import { reconnectBrowser, rememberBrowser } from "./pairing.js";
