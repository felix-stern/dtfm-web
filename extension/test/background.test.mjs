// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto || !globalThis.crypto.subtle) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}

class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  static instances = [];

  constructor(url) {
    this.url = url;
    this.binaryType = "blob";
    this.readyState = MockWebSocket.CONNECTING;
    this.sent = [];
    this.onopen = null;
    this.onmessage = null;
    this.onerror = null;
    this.onclose = null;
    MockWebSocket.instances.push(this);
  }

  send(data) {
    this.sent.push(data);
  }

  close(code = 1000, reason = "") {
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) {
      this.onclose({ code, reason });
    }
  }

  simulateOpen() {
    this.readyState = MockWebSocket.OPEN;
    if (this.onopen) {
      this.onopen();
    }
  }

  simulateClose(code, reason = "") {
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) {
      this.onclose({ code, reason });
    }
  }
}

function createMockChrome() {
  const localStore = {};
  const sessionStore = {};
  const alarms = new Map();
  const permissions = new Set(["https://example.com/*"]);
  const tabs = new Map([[42, { id: 42, windowId: 1, title: "Example", url: "https://example.com/app", active: true }]]);
  const badgeHistory = [];

  const listeners = {
    tabRemoved: [],
    alarm: [],
    message: [],
  };

  return {
    _sessionStore: sessionStore,
    _localStore: localStore,
    _alarms: alarms,
    _permissions: permissions,
    _tabs: tabs,
    _badgeHistory: badgeHistory,
    _listeners: listeners,
    runtime: {
      id: "test-ext-id",
      onMessage: {
        addListener(fn) {
          listeners.message.push(fn);
        },
      },
    },
    tabs: {
      async get(tabId) {
        if (!tabs.has(tabId)) {
          throw new Error(`No tab with id: ${tabId}`);
        }
        return tabs.get(tabId);
      },
      onRemoved: {
        addListener(fn) {
          listeners.tabRemoved.push(fn);
        },
      },
    },
    permissions: {
      async contains({ origins }) {
        return origins.every((o) => permissions.has(o));
      },
      async remove({ origins }) {
        for (const o of origins) permissions.delete(o);
        return true;
      },
    },
    action: {
      async setBadgeText({ text, tabId }) {
        badgeHistory.push({ type: "text", text, tabId });
      },
      async setBadgeBackgroundColor({ color, tabId }) {
        badgeHistory.push({ type: "color", color, tabId });
      },
    },
    storage: {
      local: {
        async get(key) {
          return { [key]: localStore[key] };
        },
        async set(obj) {
          Object.assign(localStore, obj);
        },
      },
      session: {
        async get(key) {
          return { [key]: sessionStore[key] };
        },
        async set(obj) {
          Object.assign(sessionStore, obj);
        },
        async remove(key) {
          delete sessionStore[key];
        },
      },
    },
    alarms: {
      async create(name, info) {
        alarms.set(name, info);
      },
      async clear(name) {
        return alarms.delete(name);
      },
      onAlarm: {
        addListener(fn) {
          listeners.alarm.push(fn);
        },
      },
    },
  };
}

const mockChrome = createMockChrome();
globalThis.chrome = mockChrome;
globalThis.WebSocket = MockWebSocket;

const bg = await import("../background.js");

async function waitFor(predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("Timed out waiting for condition");
}

test("isPermanentCloseCode classifies permanent vs transient WebSocket close codes", () => {
  assert.equal(bg.isPermanentCloseCode(1000), true);
  assert.equal(bg.isPermanentCloseCode(4000), true);
  assert.equal(bg.isPermanentCloseCode(4003), true);

  for (const transient of [1001, 1006, 1011, 1012, 1013]) {
    assert.equal(bg.isPermanentCloseCode(transient), false, `code ${transient} should be transient`);
  }
});

test("computeReconnectDelay applies exponential backoff 1s->2s->4s->5s cap with +/-20% jitter", () => {
  assert.equal(bg.computeReconnectDelay(0, () => 0.5), 1000);
  assert.equal(bg.computeReconnectDelay(1, () => 0.5), 2000);
  assert.equal(bg.computeReconnectDelay(2, () => 0.5), 4000);
  assert.equal(bg.computeReconnectDelay(3, () => 0.5), 5000);
  assert.equal(bg.computeReconnectDelay(10, () => 0.5), 5000);

  // +/-20% jitter bounds
  assert.equal(bg.computeReconnectDelay(0, () => 0), 800);
  assert.equal(bg.computeReconnectDelay(0, () => 1), 1200);
  assert.equal(bg.computeReconnectDelay(5, () => 0), 4000);
  assert.equal(bg.computeReconnectDelay(5, () => 1), 6000);
});

test("transient disconnect triggers auto-reconnect preserving token, and permanent close/stopSharing wipes session", async () => {
  MockWebSocket.instances = [];
  mockChrome._tabs.set(42, { id: 42, windowId: 1, title: "Example", url: "https://example.com/app", active: true });
  mockChrome._permissions.add("https://example.com/*");

  const startPromise = bg.startSharing({
    tabId: 42,
    windowId: 1,
    tabTitle: "Example",
    tabUrl: "https://example.com/app",
    origin: "https://example.com",
    relayUrl: "wss://relay.dtfm.dev/ws",
  });

  // Wait for WebSocket creation after async crypto.
  await waitFor(() => MockWebSocket.instances.length >= 1);
  assert.equal(MockWebSocket.instances.length, 1);
  const ws1 = MockWebSocket.instances[0];
  ws1.simulateOpen();

  const initialState = await startPromise;
  assert.equal(initialState.active, true);
  assert.equal(initialState.connected, true);
  assert.equal(initialState.reconnecting, false);
  const token = initialState.pairingToken;
  assert.ok(token);
  assert.ok(mockChrome._sessionStore.dtfm_web_active_session);
  assert.ok(mockChrome._alarms.has("dtfm-web-keepalive-watchdog"));

  // Simulate transient close (1006)
  ws1.simulateClose(1006, "abnormal closure");
  const reconnectingState = bg.getPublicState();
  assert.equal(reconnectingState.active, true);
  assert.equal(reconnectingState.connected, false);
  assert.equal(reconnectingState.reconnecting, true);
  assert.equal(reconnectingState.pairingToken, token);

  // Stale close on ws1 must be ignored
  ws1.simulateClose(4003, "stale close");
  assert.equal(bg.getPublicState().active, true);

  // Wait for reconnect timer (<= 1.2s)
  await waitFor(() => MockWebSocket.instances.length >= 2);
  assert.equal(MockWebSocket.instances.length, 2);
  const ws2 = MockWebSocket.instances[1];
  ws2.simulateOpen();

  const recoveredState = bg.getPublicState();
  assert.equal(recoveredState.active, true);
  assert.equal(recoveredState.connected, true);
  assert.equal(recoveredState.reconnecting, false);
  assert.equal(recoveredState.pairingToken, token);

  // Permanent close (4003) must stop sharing and wipe session storage + alarm + permission
  ws2.simulateClose(4003, "forbidden");
  await waitFor(() => !bg.getPublicState().active && !mockChrome._permissions.has("https://example.com/*"));
  const stoppedState = bg.getPublicState();
  assert.equal(stoppedState.active, false);
  assert.equal(stoppedState.connected, false);
  assert.equal(stoppedState.pairingToken, null);
  assert.equal(mockChrome._sessionStore.dtfm_web_active_session, undefined);
  assert.equal(mockChrome._alarms.has("dtfm-web-keepalive-watchdog"), false);
  assert.equal(mockChrome._permissions.has("https://example.com/*"), false);
});

test("ensureRestored recovers session from chrome.storage.session and cleans up if tab is gone", async () => {
  await bg.stopSharing(null);
  MockWebSocket.instances = [];
  mockChrome._tabs.set(99, { id: 99, windowId: 2, title: "Bank", url: "https://bank.example/form", active: true });
  mockChrome._permissions.add("https://bank.example/*");

  const sessionID = "0123456789abcdef0123456789abcdef";
  const keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  mockChrome._sessionStore.dtfm_web_active_session = {
    tabId: 99,
    windowId: 2,
    tabTitle: "Bank",
    tabUrl: "https://bank.example/form",
    origin: "https://bank.example",
    originPattern: "https://bank.example/*",
    relayUrl: "wss://relay.dtfm.dev/ws",
    sessionID,
    keyHex,
  };

  const restored = await bg.ensureRestored();
  assert.equal(restored.active, true);
  assert.equal(restored.reconnecting, true);
  assert.equal(restored.pairingToken, `${sessionID}#${keyHex}`);
  assert.equal(MockWebSocket.instances.length, 1);

  MockWebSocket.instances[0].simulateOpen();
  assert.equal(bg.getPublicState().connected, true);

  // Now simulate SW restart where tab 99 no longer exists
  await bg.stopSharing(null);
  mockChrome._tabs.delete(99);
  mockChrome._permissions.add("https://bank.example/*");
  mockChrome._sessionStore.dtfm_web_active_session = {
    tabId: 99,
    windowId: 2,
    tabTitle: "Bank",
    tabUrl: "https://bank.example/form",
    origin: "https://bank.example",
    originPattern: "https://bank.example/*",
    relayUrl: "wss://relay.dtfm.dev/ws",
    sessionID,
    keyHex,
  };

  const afterMissingTab = await bg.ensureRestored();
  assert.equal(afterMissingTab.active, false);
  assert.equal(mockChrome._sessionStore.dtfm_web_active_session, undefined);
  assert.equal(mockChrome._permissions.has("https://bank.example/*"), false);
});
