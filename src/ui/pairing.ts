type Receiver = { enabled: boolean; receiver: string; epoch: string; origin: string };
type SavedBrowser = {
  privateKey: CryptoKey;
  publicKey: string;
  receiver: string;
  epoch: string;
  clientID: string;
  pending?: { id: string; token: string; expires: number };
};
type Notify = (message: string, fingerprint?: string) => void;
const headers = { "X-Filedrop-Request": "1", "Content-Type": "application/json" };

async function api(path: string, body?: object): Promise<unknown> {
  const res = await fetch(path, { method: body ? "POST" : "GET", headers, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(8000) });
  const data: unknown = await res.json();
  if (!res.ok) {
    const message = typeof data === "object" && data !== null && "message" in data && typeof data.message === "string" ? data.message : "Pairing request failed.";
    throw new Error(message);
  }
  return data;
}

async function receiver(): Promise<Receiver | null> {
  const info = await api("/api/pairing/info");
  if (typeof info !== "object" || info === null || !("enabled" in info)) throw new Error("Invalid receiver response.");
  if (info.enabled === false) return null;
  if (!("receiver" in info) || typeof info.receiver !== "string" || !("epoch" in info) || typeof info.epoch !== "string" || !("origin" in info) || info.origin !== location.origin) throw new Error("Invalid receiver identity.");
  return { enabled: true, receiver: info.receiver, epoch: info.epoch, origin: location.origin };
}

async function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("filedrop-paired-browser", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("identity");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error("Browser key storage is unavailable."));
    request.onblocked = () => reject(new Error("Close other File Drop tabs to open browser key storage."));
  });
}

async function load(slot = "browser"): Promise<SavedBrowser | undefined> {
  const db = await database();
  try {
    return await new Promise((resolve, reject) => {
      const request = db.transaction("identity").objectStore("identity").get(slot);
      request.onsuccess = async () => {
        try {
        const value: unknown = request.result;
        if (value === undefined) { resolve(undefined); return; }
        if (typeof value !== "object" || value === null || !("privateKey" in value) || !(value.privateKey instanceof CryptoKey) || value.privateKey.extractable || value.privateKey.type !== "private" || value.privateKey.algorithm.name !== "ECDSA"
          || !("namedCurve" in value.privateKey.algorithm) || value.privateKey.algorithm.namedCurve !== "P-256"
          || value.privateKey.usages.length !== 1 || value.privateKey.usages[0] !== "sign"
          || !("publicKey" in value) || typeof value.publicKey !== "string" || value.publicKey.length > 512
          || !("receiver" in value) || typeof value.receiver !== "string" || !/^[a-f0-9]{64}$/.test(value.receiver)
          || !("epoch" in value) || typeof value.epoch !== "string" || !/^[a-f0-9]{64}$/.test(value.epoch)
          || !("clientID" in value) || typeof value.clientID !== "string" || (value.clientID !== "" && !/^[a-f0-9]{64}$/.test(value.clientID))) {
          reject(new Error("Saved browser key is invalid. Clear this site's storage and pair again."));
          return;
        }
        let pending: SavedBrowser["pending"];
        if ("pending" in value && value.pending !== undefined) {
          const p = value.pending;
          if (typeof p !== "object" || p === null
            || !("id" in p) || typeof p.id !== "string" || !/^[a-f0-9]{64}$/.test(p.id)
            || !("token" in p) || typeof p.token !== "string" || !/^[a-f0-9]{64}$/.test(p.token)
            || !("expires" in p) || typeof p.expires !== "number" || !Number.isSafeInteger(p.expires)) throw new Error("Saved approval request is invalid.");
          pending = { id: p.id, token: p.token, expires: p.expires };
        }
        const publicKey = await crypto.subtle.importKey("spki", decode(value.publicKey), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
        const probe = crypto.getRandomValues(new Uint8Array(32));
        const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, value.privateKey, probe);
        if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signature, probe)) throw new Error("Saved private/public keys do not match.");
        resolve({ privateKey: value.privateKey, publicKey: value.publicKey, receiver: value.receiver, epoch: value.epoch, clientID: value.clientID, pending });
        } catch (error) { reject(error instanceof Error ? error : new Error("Could not validate the saved browser key.")); }
      };
      request.onerror = () => reject(new Error("Could not read the saved browser key."));
    });
  } finally { db.close(); }
}

async function save(value: SavedBrowser, slot = "browser", activate = false): Promise<void> {
  const db = await database();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction("identity", "readwrite");
      tx.objectStore("identity").put(value, slot);
      if (activate) tx.objectStore("identity").delete("candidate");
      tx.oncomplete = () => resolve();
      tx.onerror = tx.onabort = () => reject(new Error("Could not persist the private browser key. Pairing stopped."));
    });
  } finally { db.close(); }
}

function encode(bytes: ArrayBuffer): string {
  return btoa(Array.from(new Uint8Array(bytes), byte => String.fromCharCode(byte)).join(""));
}
function decode(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}
async function hash(bytes: Uint8Array<ArrayBuffer>, count = 32): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)).slice(0, count), byte => byte.toString(16).padStart(2, "0")).join("");
}

async function prove(saved: SavedBrowser, info: Receiver, purpose: "enroll" | "login", invitation?: string, slot = "browser"): Promise<unknown> {
  const input = purpose === "enroll" ? { purpose, invitation, public_key: saved.publicKey } : { purpose, client_id: saved.clientID };
  const data = await api("/api/pairing/challenge", input);
  if (typeof data !== "object" || data === null || !("id" in data) || typeof data.id !== "string" || !("payload" in data) || typeof data.payload !== "string") throw new Error("Invalid proof challenge.");
  const bytes = decode(data.payload);
  const payload: unknown = JSON.parse(new TextDecoder().decode(bytes));
  const fingerprint = await hash(decode(saved.publicKey), 16);
  const context = purpose === "enroll" ? await hash(new TextEncoder().encode(invitation ?? "")) : saved.clientID;
  if (typeof payload !== "object" || payload === null
    || !("version" in payload) || payload.version !== 1
    || !("receiver" in payload) || payload.receiver !== info.receiver
    || !("epoch" in payload) || payload.epoch !== info.epoch
    || !("origin" in payload) || payload.origin !== location.origin
    || !("purpose" in payload) || payload.purpose !== purpose
    || !("context" in payload) || payload.context !== context
    || !("fingerprint" in payload) || payload.fingerprint !== fingerprint
    || !("client_id" in payload) || typeof payload.client_id !== "string" || !/^[a-f0-9]{64}$/.test(payload.client_id)
    || (purpose === "login" && payload.client_id !== saved.clientID)
    || !("nonce" in payload) || typeof payload.nonce !== "string" || !/^[a-f0-9]{64}$/.test(payload.nonce)
    || !("expires" in payload) || typeof payload.expires !== "number" || payload.expires <= Date.now() || payload.expires > Date.now() + 65000) {
    throw new Error("Challenge identity, purpose or expiration does not match. Check device clocks.");
  }
  saved.clientID = payload.client_id;
  await save(saved, slot);
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, saved.privateKey, bytes);
  if (signature.byteLength !== 64) throw new Error("This browser uses an unsupported signature encoding.");
  return api("/api/pairing/proof", { id: data.id, signature: encode(signature) });
}

async function waitApproval(saved: SavedBrowser, info: Receiver, notify: Notify): Promise<unknown> {
  const pending = saved.pending;
  if (!pending) throw new Error("Missing approval request.");
  notify("Waiting for terminal approval on the receiver.", await hash(decode(saved.publicKey), 16));
  while (Date.now() < pending.expires) {
    const state = await api("/api/pairing/status", { id: pending.id, token: pending.token });
    if (typeof state !== "object" || state === null || !("status" in state)) throw new Error("Invalid approval status.");
    if (state.status === "approved") {
      saved.pending = undefined;
      await save(saved, "candidate");
      const result = await prove(saved, info, "login", undefined, "candidate");
      await save(saved, "browser", true);
      return result;
    }
    if (state.status !== "pending") throw new Error("Pairing was declined or superseded. Ask for a new pairing link.");
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  throw new Error("Pairing approval expired. Ask for a new pairing link.");
}

export async function rememberBrowser(invitation: string, notify: Notify): Promise<unknown> {
  const info = await receiver();
  if (!info) throw new Error("Pairing is disabled on this receiver.");
  if (!crypto.subtle) throw new Error("Pairing requires a secure browser context.");
  const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const saved: SavedBrowser = { privateKey: keys.privateKey, publicKey: encode(await crypto.subtle.exportKey("spki", keys.publicKey)), receiver: info.receiver, epoch: info.epoch, clientID: "" };
  await save(saved, "candidate");
  const result = await prove(saved, info, "enroll", invitation, "candidate");
  if (typeof result !== "object" || result === null
    || !("pending_id" in result) || typeof result.pending_id !== "string"
    || !("pending_token" in result) || typeof result.pending_token !== "string"
    || !("client_id" in result) || result.client_id !== saved.clientID
    || !("expires" in result) || typeof result.expires !== "number") throw new Error("Invalid enrollment result.");
  saved.pending = { id: result.pending_id, token: result.pending_token, expires: result.expires };
  await save(saved, "candidate");
  return waitApproval(saved, info, notify);
}

export async function reconnectBrowser(notify: Notify): Promise<unknown | null> {
  const info = await receiver();
  if (!info) return null;
  const saved = await load() ?? await load("candidate");
  if (!saved) return null;
  if (saved.receiver !== info.receiver || saved.epoch !== info.epoch) throw new Error("Receiver trust changed. Request a new pairing link.");
  if (saved.pending) return waitApproval(saved, info, notify);
  if (!saved.clientID) throw new Error("Pairing was interrupted. Request a new pairing link.");
  notify("Reconnecting paired browser...");
  return prove(saved, info, "login");
}
