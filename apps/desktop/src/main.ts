// pass-man desktop UI.
//
// Render-on-change: each view is a pure function of app state, and events call
// `update()` to re-render. The Rust backend owns all vault logic; this file only
// presents it. A browser mock (see api.ts) keeps the same interface for testing.

import {
  api,
  backendName,
  type GeneratedPassword,
  type Item,
  type ItemInput,
  type ItemSummary,
} from "./api";
import { h, icon, replace, type IconName } from "./dom";

const root = document.getElementById("app")!;

interface State {
  items: ItemSummary[];
  selected: Item | null;
  query: string;
  locked: boolean;
  error: string;
  busy: boolean;
  authMode: "create" | "unlock";
  modal: "generator" | "settings" | null;
}

const state: State = {
  items: [],
  selected: null,
  query: "",
  locked: true,
  error: "",
  busy: false,
  authMode: "unlock",
  modal: null,
};

function reset(): void {
  state.items = [];
  state.selected = null;
  state.error = "";
}

function toast(message: string, tone: "info" | "error" = "info"): void {
  const el = h("div", { class: `toast ${tone}` }, [message]);
  document.body.appendChild(el);
  requestAnimationFrame(() => el.classList.add("show"));
  setTimeout(() => {
    el.classList.remove("show");
    setTimeout(() => el.remove(), 200);
  }, 2400);
}

function errorOf(err: unknown): string {
  if (typeof err === "string") return err;
  if (err instanceof Error) return err.message;
  return String(err);
}

function update(): void {
  render();
}

// ---------------------------------------------------------------------------
// Boot / auth screens
// ---------------------------------------------------------------------------

async function boot(): Promise<void> {
  replace(root, [h("div", { class: "centered" }, [h("div", { class: "spinner" })])]);
  try {
    const locked = await api.isLocked();
    if (!locked) {
      state.locked = false;
      await refresh();
      update();
      return;
    }
    state.locked = true;
    state.authMode = (await api.vaultExists()) ? "unlock" : "create";
    state.modal = null;
    update();
    requestAnimationFrame(() => document.querySelector<HTMLInputElement>(".auth-input")?.focus());
  } catch (err) {
    state.error = errorOf(err);
    update();
  }
}

function authScreen(mode: "create" | "unlock"): HTMLElement {
  const password = h("input", {
    class: "auth-input",
    type: "password",
    placeholder: mode === "create" ? "Choose a strong master password" : "Master password",
    autocomplete: "off",
  }) as HTMLInputElement;
  const confirm =
    mode === "create"
      ? (h("input", {
          type: "password",
          placeholder: "Confirm master password",
          autocomplete: "off",
        }) as HTMLInputElement)
      : null;

  const submit = async (): Promise<void> => {
    if (state.busy) return;
    if (mode === "create" && password.value.length < 8) {
      toast("Master password must be at least 8 characters.", "error");
      return;
    }
    if (mode === "create" && password.value !== confirm?.value) {
      toast("Passwords do not match.", "error");
      return;
    }
    state.busy = true;
    update();
    try {
      if (mode === "create") await api.createVault(password.value);
      else await api.unlockVault(password.value);
      state.locked = false;
      state.error = "";
      await refresh();
    } catch (err) {
      toast(errorOf(err), "error");
    } finally {
      state.busy = false;
      update();
    }
  };

  for (const field of [password, confirm]) {
    field?.addEventListener("keydown", (e) => {
      if ((e as KeyboardEvent).key === "Enter") void submit();
    });
  }

  const card = h("div", { class: "auth-card" }, [
    h("div", { class: "brand" }, [icon("shield", 28), h("span", {}, ["pass-man"])]),
    h("h1", {}, [mode === "create" ? "Create your vault" : "Welcome back"]),
    h("p", { class: "muted" }, [
      mode === "create"
        ? "Your master password encrypts everything. It is never stored and cannot be recovered."
        : "Enter your master password to unlock the vault.",
    ]),
    h("label", { class: "field" }, [h("span", {}, ["Master password"]), password]),
    confirm && h("label", { class: "field" }, [h("span", {}, ["Confirm password"]), confirm]),
    h(
      "button",
      { class: "btn primary block", disabled: state.busy, onClick: () => void submit() },
      [mode === "create" ? "Create vault" : "Unlock"],
    ),
    h("div", { class: "footnote" }, [
      backendName() === "browser-mock"
        ? "Browser preview mode — data is stored unencrypted for UI testing only."
        : "Argon2id + XChaCha20-Poly1305",
    ]),
  ]);

  return h("div", { class: "centered" }, [card]);
}

// ---------------------------------------------------------------------------
// Vault shell
// ---------------------------------------------------------------------------

async function refresh(): Promise<void> {
  state.items = await api.listItems(state.query || undefined);
  if (state.selected) {
    const stillExists = state.items.some((i) => i.id === state.selected?.id);
    if (!stillExists) state.selected = null;
    else state.selected = await api.getItem(state.selected.id);
  }
}

function itemIcon(type: string): IconName {
  switch (type) {
    case "note":
      return "note";
    case "card":
      return "card";
    case "identity":
      return "user";
    default:
      return "key";
  }
}

function shell(): HTMLElement {
  const search = h("input", {
    class: "search-input",
    placeholder: "Search vault",
    value: state.query,
  }) as HTMLInputElement;
  search.addEventListener("input", () => {
    state.query = search.value;
    void refresh().then(update);
  });

  const list = state.items.length
    ? h(
        "div",
        { class: "item-list" },
        state.items.map((item) => itemRow(item)),
      )
    : h("div", { class: "empty-list" }, [
        icon("search", 22),
        h("span", {}, [state.query ? "No matches" : "No items yet"]),
      ]);

  const sidebar = h("aside", { class: "sidebar" }, [
    h("div", { class: "sidebar-top" }, [
      search,
      h(
        "button",
        { class: "btn icon primary", title: "New item (Cmd/Ctrl+N)", onClick: () => void newItem() },
        [icon("plus", 18)],
      ),
    ]),
    list,
  ]);

  const main = state.selected
    ? detail(state.selected)
    : h("div", { class: "centered muted" }, [
        h("div", { class: "placeholder" }, [icon("shield", 36), h("p", {}, ["Select an item or create one"])]),
      ]);

  return h("div", { class: "app" }, [
    sidebar,
    h("section", { class: "content" }, [toolbar(), main]),
  ]);
}

function itemRow(item: ItemSummary): HTMLElement {
  const active = state.selected?.id === item.id;
  const subtitle = item.username || item.url || item.tags[0] || item.item_type;
  return h(
    "button",
    {
      class: `item-row${active ? " active" : ""}`,
      onClick: () => void selectItem(item.id),
    },
    [
      h("span", { class: "item-icon" }, [icon(itemIcon(item.item_type), 17)]),
      h("span", { class: "item-main" }, [
        h("span", { class: "item-title" }, [item.title || "(untitled)"]),
        h("span", { class: "item-sub" }, [subtitle]),
      ]),
      h("span", { class: "item-badges" }, [
        item.has_totp ? h("span", { class: "badge dot", title: "Has one-time code" }, ["2FA"]) : null,
        item.favorite ? h("span", { class: "badge star", title: "Favorite" }, [icon("starFilled", 12)]) : null,
      ]),
    ],
  );
}

function toolbar(): HTMLElement {
  return h("header", { class: "toolbar" }, [
    h("div", { class: "toolbar-title" }, [
      icon("shield", 16),
      h("span", {}, ["pass-man"]),
      h("span", { class: `mode-pill ${backendName()}` }, [backendName() === "tauri" ? "native" : "preview"]),
    ]),
    h("div", { class: "toolbar-actions" }, [
      h(
        "button",
        { class: "btn ghost", title: "Sync (S)", onClick: () => void runSync() },
        [icon("refresh", 16), "Sync"],
      ),
      h(
        "button",
        { class: "btn ghost", title: "Settings", onClick: () => { state.modal = "settings"; update(); } },
        [icon("settings", 16), "Settings"],
      ),
      h(
        "button",
        {
          class: "btn ghost",
          title: "Lock vault (Cmd/Ctrl+L)",
          onClick: async () => {
            await api.lockVault();
            reset();
            state.locked = true;
            update();
          },
        },
        [icon("lock", 16), "Lock"],
      ),
    ]),
  ]);
}

async function selectItem(id: string): Promise<void> {
  try {
    state.selected = await api.getItem(id);
    update();
    requestAnimationFrame(() => document.querySelector<HTMLInputElement>(".detail input")?.focus());
  } catch (err) {
    toast(errorOf(err), "error");
  }
}

async function newItem(): Promise<void> {
  const now = Date.now();
  const draft: Item = {
    id: "",
    item_type: "login",
    created_at: Math.floor(now / 1000),
    updated_at: Math.floor(now / 1000),
    deleted: false,
    body: {
      title: "",
      username: "",
      password: "",
      url: "",
      notes: "",
      totp_secret: "",
      fields: [],
      tags: [],
      favorite: false,
    },
  };
  state.selected = draft;
  update();
  requestAnimationFrame(() => {
    const input = document.querySelector<HTMLInputElement>(".detail .field input");
    input?.focus();
  });
}

// ---------------------------------------------------------------------------
// Detail pane
// ---------------------------------------------------------------------------

function detail(item: Item): HTMLElement {
  const b = item.body;
  const isNew = item.id === "";

  const titleInput = textField("Title", b.title, "Untitled");
  const usernameInput = textField("Username", b.username ?? "");
  const urlInput = textField("URL", b.url ?? "");
  const notesInput = h("textarea", { rows: "3", placeholder: "Notes" }) as HTMLTextAreaElement;
  notesInput.value = b.notes ?? "";
  const totpInput = textField("TOTP secret or otpauth:// URI", b.totp_secret ?? "");
  const passwordInput = h("input", { type: "password", placeholder: "Password", autocomplete: "off" }) as HTMLInputElement;
  passwordInput.value = b.password ?? "";

  const passwordRow = secretRow(passwordInput, {
    onGenerate: () => openGenerator((password) => {
      passwordInput.value = password;
      passwordInput.type = "text";
    }),
  });

  const fields: HTMLElement[] = [
    selectField("Type", item.item_type, ["login", "note", "card", "identity"], (value) => {
      item.item_type = value;
      update();
    }),
    titleInput.row,
    usernameInput.row,
    h("div", { class: "field" }, [h("span", {}, ["Password"]), passwordRow]),
    urlInput.row,
    h("div", { class: "field" }, [
      h("span", {}, ["One-time code"]),
      b.totp_secret ? totpPanel(item) : h("div", { class: "muted small" }, ["Add a TOTP secret below"]),
    ]),
    totpInput.row,
    h("div", { class: "field" }, [h("span", {}, ["Notes"]), notesInput]),
    h(
      "label",
      { class: "checkbox" },
      [
        (() => {
          const cb = h("input", { type: "checkbox" }) as HTMLInputElement;
          cb.checked = b.favorite;
          cb.addEventListener("change", () => {
            b.favorite = cb.checked;
          });
          return cb;
        })(),
        "Favorite",
      ],
    ),
  ];

  const save = async (): Promise<void> => {
    const input: ItemInput = {
      item_type: item.item_type,
      title: titleInput.input.value,
      username: usernameInput.input.value || undefined,
      password: passwordInput.value || undefined,
      url: urlInput.input.value || undefined,
      notes: notesInput.value || undefined,
      totp_secret: totpInput.input.value || undefined,
      favorite: b.favorite,
      fields: b.fields,
      tags: b.tags,
    };
    try {
      state.busy = true;
      if (isNew) {
        const id = await api.createItem(input);
        await refresh();
        state.selected = await api.getItem(id);
      } else {
        await api.updateItem(item.id, input);
        await refresh();
        state.selected = await api.getItem(item.id);
      }
      toast("Saved");
    } catch (err) {
      toast(errorOf(err), "error");
    } finally {
      state.busy = false;
      update();
    }
  };

  const remove = async (): Promise<void> => {
    if (isNew) {
      state.selected = null;
      update();
      return;
    }
    if (!confirm(`Delete "${b.title || "this item"}"?`)) return;
    try {
      await api.deleteItem(item.id);
      state.selected = null;
      await refresh();
      toast("Deleted");
    } catch (err) {
      toast(errorOf(err), "error");
    } finally {
      update();
    }
  };

  const actions = h("div", { class: "detail-actions" }, [
    h("button", { class: "btn primary", disabled: state.busy, onClick: () => void save() }, [
      icon("check", 16),
      isNew ? "Create" : "Save",
    ]),
    h("button", { class: "btn danger", onClick: () => void remove() }, [
      icon("trash", 16),
      isNew ? "Cancel" : "Delete",
    ]),
  ]);

  return h("div", { class: "detail" }, [
    h("div", { class: "detail-head" }, [
      h("span", { class: "detail-icon" }, [icon(itemIcon(item.item_type), 20)]),
      h("div", {}, [
        h("h2", {}, [b.title || (isNew ? "New item" : "(untitled)")]),
        h("div", { class: "muted small" }, [
          isNew ? "Not saved yet" : `Updated ${formatTime(item.updated_at)}`,
        ]),
      ]),
      h(
        "button",
        {
          class: "btn icon ghost",
          title: "Toggle favorite",
          onClick: () => {
            b.favorite = !b.favorite;
            update();
          },
        },
        [icon(b.favorite ? "starFilled" : "star", 18)],
      ),
    ]),
    h("div", { class: "fields" }, fields.filter(Boolean)),
    actions,
  ]);
}

function textField(
  label: string,
  value: string,
  placeholder = "",
): { row: HTMLElement; input: HTMLInputElement } {
  const input = h("input", { type: "text", placeholder }) as HTMLInputElement;
  input.value = value;
  return { row: h("label", { class: "field" }, [h("span", {}, [label]), input]), input };
}

function selectField(
  label: string,
  value: string,
  options: string[],
  onchange: (value: string) => void,
): HTMLElement {
  const select = h("select", {}) as HTMLSelectElement;
  for (const option of options) {
    const el = h("option", { value: option }, [option]) as HTMLOptionElement;
    if (option === value) el.selected = true;
    select.appendChild(el);
  }
  select.addEventListener("change", () => onchange(select.value));
  return h("label", { class: "field" }, [h("span", {}, [label]), select]);
}

function secretRow(
  input: HTMLInputElement,
  opts: { onGenerate?: () => void } = {},
): HTMLElement {
  const reveal = h("button", { class: "btn icon ghost", type: "button", title: "Reveal" }, [icon("eye", 16)]);
  reveal.addEventListener("click", () => {
    const hidden = input.type === "password";
    input.type = hidden ? "text" : "password";
    replace(reveal, [icon(hidden ? "eyeOff" : "eye", 16)]);
  });
  const copy = h("button", { class: "btn icon ghost", type: "button", title: "Copy" }, [icon("copy", 16)]);
  copy.addEventListener("click", () => void copyText(input.value));

  const buttons = [reveal, copy];
  if (opts.onGenerate) {
    const gen = h("button", { class: "btn icon ghost", type: "button", title: "Generate password" }, [icon("refresh", 16)]);
    gen.addEventListener("click", () => opts.onGenerate?.());
    buttons.unshift(gen);
  }
  return h("div", { class: "input-row" }, [input, h("div", { class: "input-actions" }, buttons)]);
}

function totpPanel(item: Item): HTMLElement {
  const code = h("div", { class: "totp-code" }, ["······"]);
  const ring = h("div", { class: "totp-bar" }, [h("span", {})]);
  const copy = h("button", { class: "btn icon ghost", title: "Copy code" }, [icon("copy", 16)]);
  let current = "";
  copy.addEventListener("click", () => void copyText(current));

  const element = h("div", { class: "totp-panel" }, [code, ring, copy]);

  const tick = async (): Promise<void> => {
    if (!element.isConnected) return;
    try {
      const result = await api.totpCode(item.id);
      current = result.code;
      code.textContent =
        result.code.length === 6 ? `${result.code.slice(0, 3)} ${result.code.slice(3)}` : result.code;
      const bar = ring.firstElementChild as HTMLElement;
      bar.style.width = `${(result.seconds_remaining / result.period) * 100}%`;
    } catch {
      code.textContent = "error";
    }
    setTimeout(() => void tick(), 1000);
  };
  requestAnimationFrame(() => void tick());
  return element;
}

async function copyText(text: string): Promise<void> {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied");
  } catch {
    toast("Could not copy", "error");
  }
}

// ---------------------------------------------------------------------------
// Sync + modals
// ---------------------------------------------------------------------------

async function runSync(): Promise<void> {
  const serverUrl = localStorage.getItem("server_url") ?? "";
  const token = localStorage.getItem("sync_token") ?? "";
  if (!serverUrl || !token) {
    const url = prompt("Sync server URL", serverUrl || "http://127.0.0.1:8080");
    if (!url) return;
    const tok = prompt("Session token");
    if (!tok) return;
    localStorage.setItem("server_url", url);
    localStorage.setItem("sync_token", tok);
  }
  try {
    const deviceId = localStorage.getItem("device_id") ?? crypto.randomUUID();
    localStorage.setItem("device_id", deviceId);
    const pushed = await api.syncPush(
      localStorage.getItem("server_url")!,
      localStorage.getItem("sync_token")!,
      deviceId,
    );
    const pulled = await api.syncPull(
      localStorage.getItem("server_url")!,
      localStorage.getItem("sync_token")!,
      0,
    );
    await refresh();
    toast(`Pushed ${pushed}, applied ${pulled.applied} of ${pulled.fetched}`);
  } catch (err) {
    toast(errorOf(err), "error");
  } finally {
    update();
  }
}

function openGenerator(apply: (password: string) => void): void {
  const result = h("input", { type: "text", readOnly: true, class: "mono" }) as HTMLInputElement;
  const entropy = h("div", { class: "muted small" }, [""]);
  const length = h("input", {
    type: "range",
    min: "8",
    max: "64",
    value: "20",
  }) as HTMLInputElement;
  const lengthLabel = h("span", { class: "muted small" }, ["20 characters"]);

  const toggles = new Map<string, HTMLInputElement>();
  const toggle = (key: string, label: string, initial: boolean): HTMLElement => {
    const cb = h("input", { type: "checkbox" }) as HTMLInputElement;
    cb.checked = initial;
    toggles.set(key, cb);
    return h("label", { class: "checkbox" }, [cb, label]);
  };

  const regenerate = async (): Promise<void> => {
    const generated: GeneratedPassword = await api.generatePassword({
      length: Number(length.value),
      lowercase: toggles.get("lower")!.checked,
      uppercase: toggles.get("upper")!.checked,
      digits: toggles.get("digits")!.checked,
      symbols: toggles.get("symbols")!.checked,
      exclude_ambiguous: toggles.get("ambiguous")!.checked,
    });
    result.value = generated.password;
    entropy.textContent = `~${generated.entropy_bits.toFixed(0)} bits of entropy`;
  };

  length.addEventListener("input", () => {
    lengthLabel.textContent = `${length.value} characters`;
    void regenerate();
  });
  for (const cb of toggles.values()) cb.addEventListener("change", () => void regenerate());

  const use = h("button", { class: "btn primary" }, ["Use this password"]);
  use.addEventListener("click", () => {
    apply(result.value);
    state.modal = null;
    update();
  });
  const cancel = h("button", { class: "btn ghost" }, ["Cancel"]);
  cancel.addEventListener("click", () => {
    state.modal = null;
    update();
  });

  state.modal = "generator";
  modalBuilder = {
    title: "Password generator",
    body: [
      h("div", { class: "field" }, [h("span", {}, ["Generated password"]), result]),
      entropy,
      h("div", { class: "field" }, [h("span", {}, ["Length"]), length, lengthLabel]),
      h("div", { class: "toggles" }, [
        toggle("lower", "a-z", true),
        toggle("upper", "A-Z", true),
        toggle("digits", "0-9", true),
        toggle("symbols", "!@#", true),
        toggle("ambiguous", "No l/1/O/0", false),
      ]),
      h("div", { class: "modal-actions" }, [cancel, use]),
    ],
  };
  update();
  void regenerate();
}

/// Content for the modal described by `state.modal`. Built fresh on each render,
/// which keeps re-renders idempotent and avoids stacking overlays.
let modalBuilder: { title: string; body: HTMLElement[] } | null = null;

function renderModal(): void {
  document.querySelectorAll(".modal-overlay").forEach((node) => node.remove());
  if (!state.modal) {
    modalBuilder = null;
    return;
  }
  if (state.modal === "settings") {
    modalBuilder = { title: "Settings", body: settingsBody() };
  }
  if (!modalBuilder) return;
  const { title, body } = modalBuilder;
  const overlay = h(
    "div",
    {
      class: "modal-overlay",
      onClick: (e: Event) => {
        if (e.target === overlay) {
          state.modal = null;
          update();
        }
      },
    },
    [h("div", { class: "modal" }, [h("h3", {}, [title]), ...body])],
  );
  document.body.appendChild(overlay);
  requestAnimationFrame(() => overlay.classList.add("show"));
}

function settingsBody(): HTMLElement[] {
  const info = h("div", { class: "muted small" }, ["Loading…"]);
  void api.vaultInfo().then((v) => {
    replace(info, [`Vault ${v.vault_id.slice(0, 8)} · format v${v.format_version} · ${v.kdf_algorithm}`]);
  });
  const serverUrl = h("input", {
    type: "text",
    placeholder: "http://127.0.0.1:8080",
    value: localStorage.getItem("server_url") ?? "",
  }) as HTMLInputElement;
  const token = h("input", {
    type: "password",
    placeholder: "Session token",
    value: localStorage.getItem("sync_token") ?? "",
  }) as HTMLInputElement;
  serverUrl.addEventListener("change", () => localStorage.setItem("server_url", serverUrl.value));
  token.addEventListener("change", () => localStorage.setItem("sync_token", token.value));

  const close = h("button", { class: "btn primary" }, ["Close"]);
  close.addEventListener("click", () => {
    state.modal = null;
    update();
  });
  return [
    h("div", { class: "field" }, [h("span", {}, ["Vault"]), info]),
    h("div", { class: "field" }, [h("span", {}, ["Backend"]), h("div", { class: "muted small" }, [backendName()])]),
    h("div", { class: "field" }, [h("span", {}, ["Sync server"]), serverUrl]),
    h("div", { class: "field" }, [h("span", {}, ["Sync token"]), token]),
    h("div", { class: "modal-actions" }, [close]),
  ];
}

function formatTime(unix: number): string {
  if (!unix) return "just now";
  const date = new Date(unix * 1000);
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ---------------------------------------------------------------------------
// Render + global shortcuts
// ---------------------------------------------------------------------------

function render(): void {
  if (state.error) {
    replace(root, [
      h("div", { class: "centered" }, [h("div", { class: "auth-card" }, [state.error])]),
    ]);
    return;
  }
  if (state.locked) {
    replace(root, [authScreen(state.authMode)]);
    return;
  }
  replace(root, [shell()]);
  renderModal();
}

document.addEventListener("keydown", (e) => {
  const mod = e.metaKey || e.ctrlKey;
  if (e.key === "Escape" && state.modal) {
    state.modal = null;
    update();
    return;
  }
  if (!mod) return;
  if (e.key === "n") {
    e.preventDefault();
    void newItem();
  } else if (e.key === "l") {
    e.preventDefault();
    void api.lockVault().then(() => {
      reset();
      state.locked = true;
      update();
    });
  } else if (e.key === "f" || e.key === "k") {
    e.preventDefault();
    document.querySelector<HTMLInputElement>(".search-input")?.focus();
  }
});

void boot();
