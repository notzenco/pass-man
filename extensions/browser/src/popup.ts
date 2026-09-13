// Popup UI. Talks to the background worker over the message protocol.

import {
  sendMessage,
  type ListResponse,
  type StatusResponse,
  type TotpResponse,
} from "./protocol";

const root = document.getElementById("root")!;

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> & { class?: string } = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  Object.assign(node, props);
  for (const child of children) node.append(child);
  return node;
}

async function activeTabUrl(): Promise<string> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url ?? "";
}

async function render(): Promise<void> {
  const status: StatusResponse = await sendMessage({ type: "status" });

  if (!status.unlocked) {
    root.replaceChildren(lockScreen(status.initialized));
    return;
  }

  const url = await activeTabUrl();
  const matches: ListResponse = await sendMessage({ type: "match", url });

  if (matches.items.length === 0) {
    const all: ListResponse = await sendMessage({ type: "list" });
    root.replaceChildren(
      header(),
      el("div", { class: "row" }, [
        el("div", { class: "meta" }, [
          el("div", { class: "sub" }, ["No saved logins for this site."]),
        ]),
      ]),
      listSection("All items", all),
    );
    return;
  }
  root.replaceChildren(header(), listSection("Matching this site", matches));
}

function header(): HTMLElement {
  const lock = el("button", {}, ["Lock"]);
  lock.addEventListener("click", async () => {
    await sendMessage({ type: "lock" });
    void render();
  });
  const gen = el("button", {}, ["Generate"]);
  gen.addEventListener("click", () => void showGenerator());
  return el("div", { class: "row" }, [
    el("div", { class: "meta" }, [el("div", { class: "title" }, ["pass-man"])]),
    gen,
    lock,
  ]);
}

function listSection(title: string, list: ListResponse): HTMLElement {
  const rows: HTMLElement[] = [el("div", { class: "row" }, [el("div", { class: "sub" }, [title])])];
  for (const item of list.items) {
    const buttons = el("div", {});
    const fill = el("button", { class: "primary" }, ["Fill"]);
    fill.addEventListener("click", async () => {
      await sendMessage({ type: "fill", id: item.id });
      window.close();
    });
    buttons.append(fill);

    if (item.hasTotp) {
      const totpButton = el("button", {}, ["2FA"]);
      totpButton.addEventListener("click", () => void showTotp(item.id, item.title));
      buttons.append(totpButton);
    }

    rows.push(
      el("div", { class: "row" }, [
        el("div", { class: "meta" }, [
          el("div", { class: "title" }, [item.title || "(untitled)"]),
          el("div", { class: "sub" }, [item.username || item.url || item.item_type]),
        ]),
        buttons,
      ]),
    );
  }
  return el("div", {}, rows);
}

function showTotp(id: string, title: string): void {
  const code = el("div", { class: "totp" }, ["······"]);
  const status = el("div", { class: "sub" }, ["One-time code"]);
  const back = el("button", {}, ["Back"]);
  back.addEventListener("click", () => void render());

  const tick = async (): Promise<void> => {
    if (!code.isConnected) return;
    const result = await sendMessage<TotpResponse | { ok: false; error?: string }>({
      type: "totp",
      id,
    });
    if (!("code" in result)) {
      code.textContent = "error";
      return;
    }
    code.textContent =
      result.code.length === 6 ? `${result.code.slice(0, 3)} ${result.code.slice(3)}` : result.code;
    status.textContent = `Expires in ${result.secondsRemaining}s`;
    setTimeout(() => void tick(), 1000);
  };

  root.replaceChildren(
    el("div", { class: "row" }, [
      el("div", { class: "meta" }, [el("div", { class: "title" }, [title])]),
      back,
    ]),
    el("div", { class: "pad" }, [status, code]),
  );
  // Start after the element is in the DOM, or the first tick bails and stops.
  void tick();
}

async function showGenerator(): Promise<void> {
  const lengthInput = el("input", { type: "number", value: "20", min: "8", max: "128" }) as HTMLInputElement;
  const output = el("input", { type: "text", readOnly: true }) as HTMLInputElement;
  const entropy = el("div", { class: "sub" }, [""]);
  const regen = el("button", {}, ["Regenerate"]);
  const copy = el("button", { class: "primary" }, ["Copy"]);
  const back = el("button", {}, ["Back"]);
  back.addEventListener("click", () => void render());

  const make = async (): Promise<void> => {
    const length = Math.min(128, Math.max(8, Number(lengthInput.value) || 20));
    const result = await sendMessage<
      { password: string; entropyBits: number } | { ok: false; error?: string }
    >({ type: "generate", options: { length } });
    if (!("password" in result)) {
      entropy.textContent = result.error ?? "could not generate";
      return;
    }
    output.value = result.password;
    entropy.textContent = `~${result.entropyBits.toFixed(0)} bits of entropy`;
  };
  regen.addEventListener("click", () => void make());
  copy.addEventListener("click", async () => {
    await navigator.clipboard.writeText(output.value);
    entropy.textContent = "Copied";
  });
  lengthInput.addEventListener("change", () => void make());

  root.replaceChildren(
    el("div", { class: "row" }, [
      el("div", { class: "meta" }, [el("div", { class: "title" }, ["Password generator"])]),
      back,
    ]),
    el("div", { class: "pad" }, [
      el("div", {}, ["Length"]),
      lengthInput,
      output,
      entropy,
      el("div", { class: "actions" }, [regen, copy]),
    ]),
  );
  await make();
}

function lockScreen(initialized: boolean): HTMLElement {
  const password = el("input", { type: "password", placeholder: "Master password" }) as HTMLInputElement;
  const submit = el("button", { class: "primary" }, [initialized ? "Unlock" : "Create vault"]);
  const error = el("div", { class: "error" }, [""]);

  const go = async (): Promise<void> => {
    if (!password.value) {
      error.textContent = "Enter your master password.";
      return;
    }
    const result = await sendMessage<{ ok: boolean; error?: string }>({
      type: "unlock",
      password: password.value,
    });
    if (!result.ok) {
      error.textContent = result.error ?? "Could not unlock.";
      return;
    }
    void render();
  };
  submit.addEventListener("click", () => void go());
  password.addEventListener("keydown", (e) => {
    if (e.key === "Enter") void go();
  });

  return el("div", { class: "pad" }, [
    el("div", {}, [initialized ? "Unlock your vault" : "Create your vault"]),
    el("div", {}, [password]),
    submit,
    error,
    el("div", { class: "muted" }, ["The vault stays in this browser and is always encrypted."]),
  ]);
}

void render();
