// Background service worker.
//
// Owns the unlocked vault for the extension's lifetime. The popup asks it to
// unlock, list, and reveal; content scripts only ever receive the single
// credential they are filling. The serialized vault lives in
// `chrome.storage.local` and is always ciphertext.

import init, {
  generate_password,
  password_entropy_bits,
  totp_now,
  WasmVault,
} from "../../../packages/core-wasm/pkg/pm_core_wasm.js";
import type {
  GenerateOptions,
  GenerateResponse,
  ListResponse,
  Message,
  ResultResponse,
  RevealResponse,
  StatusResponse,
  TotpResponse,
} from "./protocol";

const STORAGE_KEY = "pm_vault_blob";
const IDLE_LOCK_MINUTES = 15;

let vault: WasmVault | null = null;
let lastActivity = Date.now();

async function ensureWasm(): Promise<void> {
  // `init` is idempotent; it fetches and instantiates the wasm module once.
  await init();
}

async function readBlob(): Promise<string | null> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  const value = stored[STORAGE_KEY];
  return typeof value === "string" ? value : null;
}

async function writeBlob(blob: string, password: string): Promise<void> {
  // `export` re-wraps the vault key for the given password, so the persisted
  // blob is always unlockable with the user's master password.
  const serialized = vault!.export(password);
  await chrome.storage.local.set({ [STORAGE_KEY]: serialized });
  void blob;
}

function touch(): void {
  lastActivity = Date.now();
}

function lockIfIdle(): void {
  const idleMs = Date.now() - lastActivity;
  if (vault && idleMs > IDLE_LOCK_MINUTES * 60_000) {
    vault.free();
    vault = null;
  }
}

async function status(): Promise<StatusResponse> {
  lockIfIdle();
  const blob = await readBlob();
  return { initialized: blob !== null, unlocked: vault !== null };
}

async function unlock(password: string): Promise<ResultResponse> {
  await ensureWasm();
  const blob = await readBlob();
  if (blob === null) {
    // First run: create a fresh vault.
    vault = WasmVault.create(password);
    await writeBlob(blob ?? "", password);
    await chrome.storage.local.set({ [STORAGE_KEY]: vault.export(password) });
    touch();
    return { ok: true };
  }
  try {
    vault = WasmVault.unlock(blob, password);
    touch();
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

function lock(): ResultResponse {
  if (vault) {
    vault.free();
    vault = null;
  }
  return { ok: true };
}

interface ItemJson {
  id: string;
  item_type: string;
  body: {
    title: string;
    username?: string;
    password?: string;
    url?: string;
    totp_secret?: string;
  };
}

function requireVault(): WasmVault {
  lockIfIdle();
  if (!vault) throw new Error("vault is locked");
  touch();
  return vault;
}

function list(): ListResponse {
  const parsed: ItemJson[] = JSON.parse(requireVault().list_items());
  return {
    items: parsed.map((item) => ({
      id: item.id,
      title: item.body.title,
      item_type: item.item_type,
      username: item.body.username ?? "",
      url: item.body.url ?? "",
      hasTotp: Boolean(item.body.totp_secret),
    })),
  };
}

function reveal(id: string): RevealResponse {
  const item: ItemJson = JSON.parse(requireVault().get_item(id));
  return { username: item.body.username ?? "", password: item.body.password ?? "" };
}

function generate(options?: GenerateOptions): GenerateResponse {
  // Generation does not require an unlocked vault and does not touch storage.
  const json = options ? JSON.stringify(options) : "";
  const password = generate_password(json);
  return { password, entropyBits: password_entropy_bits(json) };
}

function totp(id: string): TotpResponse {
  const item: ItemJson = JSON.parse(requireVault().get_item(id));
  const secret = item.body.totp_secret;
  if (!secret) throw new Error("this item has no TOTP secret");
  return JSON.parse(totp_now(secret)) as TotpResponse;
}

// Match stored logins against the active tab's host.
function match(rawUrl: string): ListResponse {
  let host: string;
  try {
    host = new URL(rawUrl).hostname.replace(/^www\./, "");
  } catch {
    return { items: [] };
  }
  const all = list().items;
  return {
    items: all.filter((item) => {
      if (item.item_type !== "login" || !item.url) return false;
      try {
        const itemHost = new URL(item.url).hostname.replace(/^www\./, "");
        return itemHost === host;
      } catch {
        return item.url.includes(host);
      }
    }),
  };
}

chrome.runtime.onMessage.addListener(
  (message: Message, sender, sendResponse: (response: unknown) => void) => {
    void (async () => {
      // Anything that reaches into the Rust core needs the wasm module ready.
      if (
        message.type === "unlock" ||
        message.type === "generate" ||
        message.type === "totp"
      ) {
        await ensureWasm();
      }
      switch (message.type) {
        case "status":
          sendResponse(await status());
          break;
        case "unlock":
          sendResponse(await unlock(message.password));
          break;
        case "lock":
          sendResponse(lock());
          break;
        case "list":
          sendResponse(safely(list));
          break;
        case "match":
          sendResponse(safely(() => match(message.url)));
          break;
        case "reveal":
          sendResponse(safely(() => reveal(message.id)));
          break;
        case "fill":
          await fillInTab(sender, message.id);
          sendResponse({ ok: true });
          break;
        case "generate":
          sendResponse(safely(() => generate(message.options)));
          break;
        case "totp":
          sendResponse(safely(() => totp(message.id)));
          break;
      }
    })();
    return true; // keep the message channel open for async responses
  },
);

function safely<T>(fn: () => T): T | ResultResponse {
  try {
    return fn();
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

async function fillInTab(
  sender: chrome.runtime.MessageSender,
  id: string,
): Promise<void> {
  const credentials = reveal(id);
  const tabId = sender.tab?.id ?? (await activeTabId());
  if (tabId === null) return;
  await chrome.tabs.sendMessage(tabId, { type: "fill", credentials });
}

async function activeTabId(): Promise<number | null> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id ?? null;
}

// Lock on browser restart and when the last window closes.
chrome.runtime.onStartup.addListener(lock);
chrome.windows?.onRemoved.addListener(() => lock());
