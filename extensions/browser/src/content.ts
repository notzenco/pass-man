// Content script.
//
// Runs in the page and only performs DOM work: it finds login fields and fills
// them when the background worker sends credentials. It never unlocks the vault
// and never receives more than the one credential being filled.

interface Credentials {
  username: string;
  password: string;
}

type FillMessage = { type: "fill"; credentials: Credentials };

function isVisible(el: HTMLElement): boolean {
  const style = window.getComputedStyle(el);
  return style.display !== "none" && style.visibility !== "hidden" && el.offsetParent !== null;
}

function fillField(field: HTMLInputElement, value: string): void {
  if (!value) return;
  // Use the native setter so React and similar frameworks observe the change.
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  setter?.call(field, value);
  field.dispatchEvent(new Event("input", { bubbles: true }));
  field.dispatchEvent(new Event("change", { bubbles: true }));
}

function findUsernameField(): HTMLInputElement | null {
  const explicit = document.querySelector<HTMLInputElement>(
    'input[autocomplete="username"], input[type="email"], input[name*="user" i], input[id*="user" i], input[name*="email" i]',
  );
  if (explicit && isVisible(explicit)) return explicit;
  const text = [...document.querySelectorAll<HTMLInputElement>('input[type="text"]')].find(isVisible);
  return text ?? null;
}

function findPasswordField(): HTMLInputElement | null {
  const password = document.querySelector<HTMLInputElement>('input[type="password"]');
  return password && isVisible(password) ? password : null;
}

function doFill(credentials: Credentials): boolean {
  const passwordField = findPasswordField();
  if (!passwordField) return false;
  const usernameField = findUsernameField();
  if (usernameField) fillField(usernameField, credentials.username);
  fillField(passwordField, credentials.password);
  return true;
}

chrome.runtime.onMessage.addListener((message: FillMessage, _sender, sendResponse) => {
  if (message.type === "fill") {
    sendResponse({ ok: doFill(message.credentials) });
  }
  return false;
});
