// Message protocol between the popup, content scripts, and the background
// service worker. The background worker is the only context that ever unlocks
// the vault, so key material never enters a page's content script.

export interface LoginMatch {
  id: string;
  title: string;
  username: string;
  password: string;
}

export type Message =
  | { type: "status" }
  | { type: "unlock"; password: string }
  | { type: "lock" }
  | { type: "list" }
  | { type: "match"; url: string }
  | { type: "reveal"; id: string }
  | { type: "fill"; id: string }
  | { type: "generate"; options?: GenerateOptions }
  | { type: "totp"; id: string };

export interface GenerateOptions {
  length?: number;
  lowercase?: boolean;
  uppercase?: boolean;
  digits?: boolean;
  symbols?: boolean;
  exclude_ambiguous?: boolean;
}

export interface StatusResponse {
  initialized: boolean;
  unlocked: boolean;
}

export interface ListResponse {
  items: {
    id: string;
    title: string;
    item_type: string;
    username: string;
    url: string;
    hasTotp: boolean;
  }[];
}

export interface RevealResponse {
  username: string;
  password: string;
}

export interface GenerateResponse {
  password: string;
  entropyBits: number;
}

export interface TotpResponse {
  code: string;
  secondsRemaining: number;
  period: number;
}

export interface ResultResponse {
  ok: boolean;
  error?: string;
}

export function sendMessage<T>(message: Message): Promise<T> {
  return chrome.runtime.sendMessage(message) as Promise<T>;
}
