// Backend bridge.
//
// In the packaged app every call goes through Tauri to the Rust core. When the
// frontend is served in a plain browser (the dev/test harness), a mock backend
// keeps the exact same interface so the UI can be developed and tested without
// the native shell. The mock is clearly marked and must never ship as a real
// vault: it stores plaintext in `localStorage`.

export interface ItemSummary {
  id: string;
  item_type: string;
  title: string;
  username: string | null;
  url: string | null;
  favorite: boolean;
  tags: string[];
  updated_at: number;
  has_totp: boolean;
}

export interface ItemBody {
  title: string;
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
  totp_secret?: string;
  fields: { name: string; value: string; hidden: boolean }[];
  tags: string[];
  favorite: boolean;
}

export interface Item {
  id: string;
  item_type: string;
  created_at: number;
  updated_at: number;
  deleted: boolean;
  body: ItemBody;
}

export interface ItemInput {
  item_type: string;
  title: string;
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
  totp_secret?: string;
  fields?: { name: string; value: string; hidden: boolean }[];
  tags?: string[];
  favorite?: boolean;
}

export interface UnlockResult {
  vault_id: string;
  item_count: number;
}

export interface VaultInfo {
  vault_id: string;
  format_version: number;
  kdf_algorithm: string;
  created_at: number;
  updated_at: number;
}

export interface SyncPullResult {
  fetched: number;
  applied: number;
  revision: number;
}

export interface GenerateRequest {
  length: number;
  lowercase?: boolean;
  uppercase?: boolean;
  digits?: boolean;
  symbols?: boolean;
  exclude_ambiguous?: boolean;
}

export interface GeneratedPassword {
  password: string;
  entropy_bits: number;
}

export interface TotpCode {
  code: string;
  seconds_remaining: number;
  period: number;
}

export interface Backend {
  vaultExists(): Promise<boolean>;
  isLocked(): Promise<boolean>;
  createVault(password: string): Promise<UnlockResult>;
  unlockVault(password: string, path?: string): Promise<UnlockResult>;
  lockVault(): Promise<void>;
  vaultInfo(): Promise<VaultInfo>;
  listItems(query?: string): Promise<ItemSummary[]>;
  getItem(id: string): Promise<Item>;
  createItem(item: ItemInput): Promise<string>;
  updateItem(id: string, item: ItemInput): Promise<void>;
  deleteItem(id: string): Promise<void>;
  changePassword(current: string, next: string): Promise<void>;
  syncPush(serverUrl: string, token: string, deviceId: string): Promise<number>;
  syncPull(serverUrl: string, token: string, since: number): Promise<SyncPullResult>;
  generatePassword(request: GenerateRequest): Promise<GeneratedPassword>;
  totpCode(id: string): Promise<TotpCode>;
}

function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

class TauriBackend implements Backend {
  private async invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
    const mod = await import("@tauri-apps/api/core");
    return mod.invoke<T>(cmd, args);
  }

  vaultExists() {
    return this.invoke<boolean>("vault_exists");
  }
  isLocked() {
    return this.invoke<boolean>("is_locked");
  }
  createVault(password: string) {
    return this.invoke<UnlockResult>("create_vault", { password });
  }
  unlockVault(password: string, path?: string) {
    return this.invoke<UnlockResult>("unlock_vault", { password, path: path ?? null });
  }
  lockVault() {
    return this.invoke<void>("lock_vault");
  }
  vaultInfo() {
    return this.invoke<VaultInfo>("vault_info");
  }
  listItems(query?: string) {
    return this.invoke<ItemSummary[]>("list_items", { query: query ?? null });
  }
  getItem(id: string) {
    return this.invoke<Item>("get_item", { id });
  }
  createItem(item: ItemInput) {
    return this.invoke<string>("create_item", { item });
  }
  updateItem(id: string, item: ItemInput) {
    return this.invoke<void>("update_item", { id, item });
  }
  deleteItem(id: string) {
    return this.invoke<void>("delete_item", { id });
  }
  changePassword(current: string, next: string) {
    return this.invoke<void>("change_password", { currentPassword: current, newPassword: next });
  }
  syncPush(serverUrl: string, token: string, deviceId: string) {
    return this.invoke<number>("sync_push", { serverUrl, token, deviceId });
  }
  syncPull(serverUrl: string, token: string, since: number) {
    return this.invoke<SyncPullResult>("sync_pull", { serverUrl, token, since });
  }
  generatePassword(request: GenerateRequest) {
    return this.invoke<GeneratedPassword>("generate_password", { request });
  }
  totpCode(id: string) {
    return this.invoke<TotpCode>("totp_code", { id });
  }
}

export const api: Backend = isTauri() ? new TauriBackend() : createMockBackend();

/// Build the UI.
export function backendName(): string {
  return isTauri() ? "tauri" : "browser-mock";
}

// ---------------------------------------------------------------------------
// Dev/test mock. This exists only so the UI can run in a browser. It is not a
// security boundary and stores everything in cleartext.
// ---------------------------------------------------------------------------

function createMockBackend(): Backend {
  const STORAGE_KEY = "pm-mock-v1";
  interface MockState {
    initialized: boolean;
    locked: boolean;
    password: string;
    vaultId: string;
    items: Item[];
  }

  const load = (): MockState => {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      try {
        return JSON.parse(raw) as MockState;
      } catch {
        /* fall through to a fresh state */
      }
    }
    return { initialized: false, locked: true, password: "", vaultId: crypto.randomUUID(), items: [] };
  };
  const save = (state: MockState): void => localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  let state = load();

  const summarize = (item: Item): ItemSummary => ({
    id: item.id,
    item_type: item.item_type,
    title: item.body.title,
    username: item.body.username ?? null,
    url: item.body.url ?? null,
    favorite: item.body.favorite,
    tags: item.body.tags,
    updated_at: item.updated_at,
    has_totp: Boolean(item.body.totp_secret),
  });

  const matches = (item: Item, query: string): boolean => {
    const q = query.toLowerCase();
    const b = item.body;
    return (
      b.title.toLowerCase().includes(q) ||
      (b.username ?? "").toLowerCase().includes(q) ||
      (b.url ?? "").toLowerCase().includes(q) ||
      b.tags.some((t) => t.toLowerCase().includes(q))
    );
  };

  const requireUnlocked = (): void => {
    if (state.locked) throw new Error("vault is locked");
  };

  return {
    async vaultExists() {
      return state.initialized;
    },
    async isLocked() {
      return state.locked;
    },
    async createVault(password) {
      state = {
        initialized: true,
        locked: false,
        password,
        vaultId: crypto.randomUUID(),
        items: [],
      };
      save(state);
      return { vault_id: state.vaultId, item_count: 0 };
    },
    async unlockVault(password) {
      if (!state.initialized) throw new Error("no vault");
      if (password !== state.password) throw new Error("incorrect master password or corrupted vault");
      state.locked = false;
      save(state);
      return { vault_id: state.vaultId, item_count: state.items.length };
    },
    async lockVault() {
      state.locked = true;
      save(state);
    },
    async vaultInfo() {
      requireUnlocked();
      return {
        vault_id: state.vaultId,
        format_version: 1,
        kdf_algorithm: "argon2id-v1",
        created_at: 0,
        updated_at: 0,
      };
    },
    async listItems(query) {
      requireUnlocked();
      const all = state.items.filter((i) => !i.deleted);
      const filtered = query ? all.filter((i) => matches(i, query)) : all;
      return filtered.map(summarize);
    },
    async getItem(id) {
      requireUnlocked();
      const item = state.items.find((i) => i.id === id && !i.deleted);
      if (!item) throw new Error(`item ${id} not found`);
      return item;
    },
    async createItem(input) {
      requireUnlocked();
      const now = Math.floor(Date.now() / 1000);
      const item: Item = {
        id: crypto.randomUUID(),
        item_type: input.item_type,
        created_at: now,
        updated_at: now,
        deleted: false,
        body: {
          title: input.title,
          username: input.username,
          password: input.password,
          url: input.url,
          notes: input.notes,
          totp_secret: input.totp_secret,
          fields: input.fields ?? [],
          tags: input.tags ?? [],
          favorite: input.favorite ?? false,
        },
      };
      state.items.push(item);
      save(state);
      return item.id;
    },
    async updateItem(id, input) {
      requireUnlocked();
      const item = state.items.find((i) => i.id === id);
      if (!item) throw new Error(`item ${id} not found`);
      item.item_type = input.item_type;
      item.updated_at = Math.floor(Date.now() / 1000);
      item.body = {
        title: input.title,
        username: input.username,
        password: input.password,
        url: input.url,
        notes: input.notes,
        totp_secret: input.totp_secret,
        fields: input.fields ?? [],
        tags: input.tags ?? [],
        favorite: input.favorite ?? false,
      };
      save(state);
    },
    async deleteItem(id) {
      requireUnlocked();
      const item = state.items.find((i) => i.id === id);
      if (item) {
        item.deleted = true;
        item.updated_at = Math.floor(Date.now() / 1000);
      }
      save(state);
    },
    async changePassword(current, next) {
      requireUnlocked();
      if (current !== state.password) throw new Error("incorrect master password or corrupted vault");
      state.password = next;
      save(state);
    },
    async syncPush() {
      requireUnlocked();
      return state.items.filter((i) => !i.deleted).length;
    },
    async syncPull() {
      requireUnlocked();
      return { fetched: 0, applied: 0, revision: 0 };
    },
    async generatePassword(request) {
      return mockGenerate(request);
    },
    async totpCode(id) {
      requireUnlocked();
      const item = state.items.find((i) => i.id === id);
      const secret = item?.body.totp_secret;
      if (!secret) throw new Error("this item has no TOTP secret");
      return mockTotp(secret);
    },
  };
}

const AMBIGUOUS = new Set("lI1O0o|`'\"".split(""));
const CLASSES = {
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.?/",
};

function mockGenerate(request: GenerateRequest): GeneratedPassword {
  const opts = {
    lowercase: request.lowercase ?? true,
    uppercase: request.uppercase ?? true,
    digits: request.digits ?? true,
    symbols: request.symbols ?? true,
    exclude_ambiguous: request.exclude_ambiguous ?? false,
  };
  let alphabet = "";
  if (opts.lowercase) alphabet += CLASSES.lowercase;
  if (opts.uppercase) alphabet += CLASSES.uppercase;
  if (opts.digits) alphabet += CLASSES.digits;
  if (opts.symbols) alphabet += CLASSES.symbols;
  if (opts.exclude_ambiguous) alphabet = [...alphabet].filter((c) => !AMBIGUOUS.has(c)).join("");
  if (!alphabet) throw new Error("at least one character class is required");

  const length = Math.min(1024, Math.max(1, request.length));
  const bytes = new Uint32Array(length);
  crypto.getRandomValues(bytes);
  let password = "";
  for (let i = 0; i < length; i++) password += alphabet[bytes[i]! % alphabet.length];
  return { password, entropy_bits: length * Math.log2(alphabet.length) };
}

function base32Decode(secret: string): Uint8Array {
  const cleaned = secret.replace(/[\s=-]/g, "").toUpperCase();
  let bits = 0;
  let count = 0;
  const out: number[] = [];
  for (const ch of cleaned) {
    const code = ch.charCodeAt(0);
    let value: number;
    if (code >= 65 && code <= 90) value = code - 65;
    else if (code >= 50 && code <= 55) value = code - 50 + 26;
    else throw new Error(`invalid base32 character \`${ch}\``);
    bits = (bits << 5) | value;
    count += 5;
    if (count >= 8) {
      count -= 8;
      out.push((bits >> count) & 0xff);
    }
  }
  return new Uint8Array(out);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

async function mockTotp(secret: string): Promise<TotpCode> {
  const keyBytes = base32Decode(secret);
  const period = 30;
  const counter = Math.floor(Date.now() / 1000 / period);
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const key = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(keyBytes),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, toArrayBuffer(msg)));
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary =
    ((mac[offset]! & 0x7f) << 24) |
    ((mac[offset + 1]! & 0xff) << 16) |
    ((mac[offset + 2]! & 0xff) << 8) |
    (mac[offset + 3]! & 0xff);
  const code = String(binary % 1_000_000).padStart(6, "0");
  const secondsRemaining = period - (Math.floor(Date.now() / 1000) % period);
  return { code, seconds_remaining: secondsRemaining, period };
}
