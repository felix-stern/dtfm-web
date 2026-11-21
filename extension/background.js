// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

import {
  DEFAULT_RELAY_WS_URL,
  FRAME_AGENT_CONNECTED,
  FRAME_AGENT_DISCONNECTED,
  FRAME_DATA,
  FRAME_KEEPALIVE,
  FRAME_KICK_AGENT,
  RECORD_TYPE_DATA,
  RECORD_TYPE_EOF,
  ROLE_OPERATOR,
  buildOperatorAuthFrame,
  buildOperatorHandshake,
  decodeRelayFrame,
  deriveAuthTokens,
  deriveConnCipher,
  encodeRelayFrame,
  generateSessionID,
  generateSessionKey,
  handshakeKey,
  utf8Decode,
  utf8Encode,
  verifyAgentHandshake,
} from "./e2ee.js";

const KEEPALIVE_INTERVAL_MS = 20_000;
const WS_CONNECT_TIMEOUT_MS = 10_000;
const STORAGE_RELAY_URL_KEY = "dtfm_web_relay_url";

const state = {
  active: false,
  connected: false,
  tabId: null,
  windowId: null,
  tabTitle: "",
  tabUrl: "",
  origin: null,
  originPattern: null,
  relayUrl: DEFAULT_RELAY_WS_URL,
  sessionID: null,
  keyHex: null,
  secretKey: null,
  hk: null,
  ws: null,
  keepaliveTimer: null,
  connectTimer: null,
  pendingFinish: null,
  activeAgent: null, // { connID: bigint, opNonce: Uint8Array|null, cipher: ConnCipher|null, chain: Promise }
  lastError: null,
};

function isLoopbackHostname(hostname) {
  const host = (hostname || "").toLowerCase();
  return host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";
}

function validateRelayUrl(rawUrl) {
  const normalized = (rawUrl || DEFAULT_RELAY_WS_URL).trim();
  const parsed = new URL(normalized);
  if (parsed.protocol === "wss:") {
    return normalized;
  }
  if (parsed.protocol === "ws:") {
    if (isLoopbackHostname(parsed.hostname)) {
      return normalized;
    }
    throw new Error("Unencrypted ws:// relay is only allowed for loopback hosts (localhost, 127.0.0.1, ::1); use wss://");
  }
  throw new Error("Relay URL must use wss:// (or ws:// for localhost)");
}

function isPinnedOrigin(tab) {
  if (!tab || typeof tab.url !== "string" || !state.origin) {
    return false;
  }
  try {
    return new URL(tab.url).origin === state.origin;
  } catch (_) {
    return false;
  }
}

async function revokeOriginPermission(originPattern) {
  if (!originPattern) return;
  try {
    await chrome.permissions.remove({ origins: [originPattern] });
  } catch (_) {
    // Permission may have already been revoked.
  }
}

async function loadSavedRelayUrl() {
  try {
    const data = await chrome.storage.local.get(STORAGE_RELAY_URL_KEY);
    if (typeof data[STORAGE_RELAY_URL_KEY] === "string" && data[STORAGE_RELAY_URL_KEY].trim()) {
      state.relayUrl = data[STORAGE_RELAY_URL_KEY].trim();
    }
  } catch (_) {
    // Ignore storage read errors.
  }
  return state.relayUrl;
}

async function saveRelayUrl(url) {
  state.relayUrl = url;
  try {
    await chrome.storage.local.set({ [STORAGE_RELAY_URL_KEY]: url });
  } catch (_) {
    // Ignore storage write errors.
  }
}

function getPublicState() {
  return {
    active: state.active,
    connected: state.connected,
    tabId: state.tabId,
    tabTitle: state.tabTitle,
    tabUrl: state.tabUrl,
    origin: state.origin,
    relayUrl: state.relayUrl,
    pairingToken: state.active && state.sessionID && state.keyHex ? `${state.sessionID}#${state.keyHex}` : null,
    lastError: state.lastError,
  };
}

async function setLiveBadge(tabId) {
  try {
    await chrome.action.setBadgeText({ text: "LIVE", tabId });
    await chrome.action.setBadgeBackgroundColor({ color: "#16a34a", tabId });
  } catch (_) {
    // Tab may have closed.
  }
}

async function clearLiveBadge(tabId) {
  try {
    if (typeof tabId === "number") {
      await chrome.action.setBadgeText({ text: "", tabId });
    }
    await chrome.action.setBadgeText({ text: "" });
  } catch (_) {
    // Ignore if tab no longer exists.
  }
}

async function stopSharing(reason = null) {
  const prevTabId = state.tabId;
  const prevOriginPattern = state.originPattern;
  const prevWs = state.ws;
  const prevFinish = state.pendingFinish;

  if (state.keepaliveTimer !== null) {
    clearInterval(state.keepaliveTimer);
    state.keepaliveTimer = null;
  }
  if (state.connectTimer !== null) {
    clearTimeout(state.connectTimer);
    state.connectTimer = null;
  }

  state.ws = null;
  state.pendingFinish = null;
  state.active = false;
  state.connected = false;
  state.tabId = null;
  state.windowId = null;
  state.tabTitle = "";
  state.tabUrl = "";
  state.origin = null;
  state.originPattern = null;
  state.sessionID = null;
  state.keyHex = null;
  state.activeAgent = null;
  state.lastError = reason;

  if (state.secretKey) {
    state.secretKey.fill(0);
    state.secretKey = null;
  }
  if (state.hk) {
    state.hk.fill(0);
    state.hk = null;
  }

  if (prevWs) {
    try {
      prevWs.close(1000, "operator stopped sharing");
    } catch (_) {
      // Ignore close errors.
    }
  }

  await clearLiveBadge(prevTabId);
  await revokeOriginPermission(prevOriginPattern);

  if (prevFinish) {
    prevFinish();
  }
}

function sendKickAgent(ws, connID) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(encodeRelayFrame(FRAME_KICK_AGENT, connID));
}

async function handleAgentRequest(req) {
  const id = typeof req?.id === "string" ? req.id : "";
  const cmd = typeof req?.cmd === "string" ? req.cmd : "";

  if (!state.active || typeof state.tabId !== "number") {
    return {
      id,
      ok: false,
      error_code: "ERR_TAB_CLOSED",
      error: "No tab is currently shared",
    };
  }

  let tab;
  try {
    tab = await chrome.tabs.get(state.tabId);
  } catch (_) {
    await stopSharing("Shared tab was closed");
    return {
      id,
      ok: false,
      error_code: "ERR_TAB_CLOSED",
      error: "Shared tab is no longer open",
    };
  }

  // Enforce strict single-origin pinning across all commands (status, dom, shot).
  if (!isPinnedOrigin(tab)) {
    return {
      id,
      ok: false,
      error_code: "ERR_PERMISSION_DENIED",
      error: `Shared tab navigated away from pinned origin (${state.origin})`,
    };
  }

  state.tabTitle = tab.title || "";
  state.tabUrl = tab.url || "";

  if (cmd === "status") {
    return {
      id,
      ok: true,
      tab: {
        id: tab.id,
        title: tab.title || "",
        url: tab.url || "",
        active: Boolean(tab.active),
        status: tab.status || "",
        origin: state.origin || "",
      },
    };
  }

  if (cmd === "shot") {
    // Fail-closed screenshot guard: verify shared tab is still the active tab in its window.
    if (tab.active !== true) {
      return {
        id,
        ok: false,
        error_code: "ERR_TAB_NOT_ACTIVE",
        error: "Shared tab is not active in its window; refusing to capture a non-shared tab",
      };
    }

    try {
      const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });

      // Post-capture TOCTOU check: ensure tab is still active and on the pinned origin.
      let postTab;
      try {
        postTab = await chrome.tabs.get(state.tabId);
      } catch (_) {
        await stopSharing("Shared tab was closed");
        return {
          id,
          ok: false,
          error_code: "ERR_TAB_CLOSED",
          error: "Shared tab closed during screenshot capture",
        };
      }
      if (!isPinnedOrigin(postTab)) {
        return {
          id,
          ok: false,
          error_code: "ERR_PERMISSION_DENIED",
          error: `Shared tab navigated away from pinned origin (${state.origin}) during capture`,
        };
      }
      if (postTab.active !== true) {
        return {
          id,
          ok: false,
          error_code: "ERR_TAB_NOT_ACTIVE",
          error: "Shared tab became inactive during capture; discarding screenshot",
        };
      }

      const prefix = "data:image/png;base64,";
      if (!dataUrl || !dataUrl.startsWith(prefix)) {
        return {
          id,
          ok: false,
          error_code: "ERR_INTERNAL",
          error: "Unexpected screenshot format from browser",
        };
      }
      return {
        id,
        ok: true,
        mime_type: "image/png",
        image_base64: dataUrl.slice(prefix.length),
      };
    } catch (err) {
      return {
        id,
        ok: false,
        error_code: "ERR_PERMISSION_DENIED",
        error: `Failed to capture screenshot: ${err.message}`,
      };
    }
  }

  if (cmd === "dom") {
    const format = req.format === "json" ? "json" : "md";

    try {
      await chrome.scripting.executeScript({
        target: { tabId: state.tabId },
        files: ["content.js"],
      });
      const results = await chrome.scripting.executeScript({
        target: { tabId: state.tabId },
        func: (fmt) => {
          if (typeof globalThis.__dtfmWebExtract !== "function") {
            throw new Error("extractor not initialized");
          }
          return globalThis.__dtfmWebExtract(fmt);
        },
        args: [format],
      });
      const extracted = results && results[0] ? results[0].result : null;
      if (!extracted) {
        return {
          id,
          ok: false,
          error_code: "ERR_INTERNAL",
          error: "DOM extractor returned empty result",
        };
      }
      if (extracted.format === "json") {
        return {
          id,
          ok: true,
          format: "json",
          dom: extracted.dom,
        };
      }
      return {
        id,
        ok: true,
        format: "md",
        markdown: extracted.markdown || "",
      };
    } catch (err) {
      return {
        id,
        ok: false,
        error_code: "ERR_PERMISSION_DENIED",
        error: `Failed to extract DOM: ${err.message}`,
      };
    }
  }

  return {
    id,
    ok: false,
    error_code: "ERR_INVALID_REQUEST",
    error: `Unsupported read-only command: ${cmd}`,
  };
}

async function processAgentFrame(ws, agent, payload) {
  if (ws !== state.ws || state.activeAgent !== agent) {
    return;
  }

  if (!agent.cipher) {
    if (!agent.opNonce) {
      if (state.activeAgent === agent) state.activeAgent = null;
      sendKickAgent(ws, agent.connID);
      return;
    }

    // First frame from agent must be the 69-byte authenticated handshake packet.
    let agentNonce;
    try {
      agentNonce = await verifyAgentHandshake(state.hk, state.sessionID, payload);
    } catch (_) {
      if (state.activeAgent === agent) state.activeAgent = null;
      sendKickAgent(ws, agent.connID);
      return;
    }

    if (ws !== state.ws || state.activeAgent !== agent) {
      return;
    }

    try {
      agent.cipher = await deriveConnCipher(
        ROLE_OPERATOR,
        state.sessionID,
        state.secretKey,
        agent.opNonce,
        agentNonce
      );
    } catch (_) {
      if (state.activeAgent === agent) state.activeAgent = null;
      sendKickAgent(ws, agent.connID);
      return;
    }
    return;
  }

  let record;
  try {
    record = await agent.cipher.decryptRecord(payload);
  } catch (_) {
    if (state.activeAgent === agent) state.activeAgent = null;
    sendKickAgent(ws, agent.connID);
    return;
  }

  if (record.recordType === RECORD_TYPE_EOF) {
    if (state.activeAgent === agent) state.activeAgent = null;
    return;
  }

  if (record.recordType !== RECORD_TYPE_DATA) {
    if (state.activeAgent === agent) state.activeAgent = null;
    sendKickAgent(ws, agent.connID);
    return;
  }

  let req;
  try {
    req = JSON.parse(utf8Decode(record.plaintext));
  } catch (err) {
    const respBytes = utf8Encode(
      JSON.stringify({
        ok: false,
        error_code: "ERR_INVALID_REQUEST",
        error: `Malformed JSON request: ${err.message}`,
      }) + "\n"
    );
    await sendEncryptedResponse(ws, agent, respBytes);
    return;
  }

  const resp = await handleAgentRequest(req);
  const respBytes = utf8Encode(JSON.stringify(resp) + "\n");
  await sendEncryptedResponse(ws, agent, respBytes);
}

async function sendEncryptedResponse(ws, agent, respBytes) {
  if (ws !== state.ws || state.activeAgent !== agent || ws.readyState !== WebSocket.OPEN || !agent.cipher) {
    return;
  }
  const encryptedData = await agent.cipher.encryptRecord(RECORD_TYPE_DATA, respBytes);
  ws.send(encodeRelayFrame(FRAME_DATA, agent.connID, encryptedData));

  const encryptedEOF = await agent.cipher.encryptRecord(RECORD_TYPE_EOF, new Uint8Array(0));
  ws.send(encodeRelayFrame(FRAME_DATA, agent.connID, encryptedEOF));
}

function handleAgentChainError(ws, agent, err) {
  console.error("[dtfm-web] agent frame error:", err);
  if (state.activeAgent === agent) {
    state.activeAgent = null;
  }
  sendKickAgent(ws, agent.connID);
}

function handleRelayMessage(ws, data) {
  if (ws !== state.ws || !(data instanceof ArrayBuffer)) {
    return;
  }
  const bytes = new Uint8Array(data);
  if (bytes.length < 9) {
    return;
  }

  const { ctrlByte, connID, payload } = decodeRelayFrame(bytes);

  if (ctrlByte === FRAME_AGENT_CONNECTED) {
    // Synchronously register activeAgent before any await so immediately-arriving
    // FRAME_DATA(agentHandshake) or FRAME_AGENT_DISCONNECTED frames are never dropped.
    const agent = {
      connID,
      opNonce: null,
      cipher: null,
      chain: Promise.resolve(),
    };
    state.activeAgent = agent;
    agent.chain = agent.chain
      .then(async () => {
        if (ws !== state.ws || state.activeAgent !== agent) {
          return;
        }
        const { opNonce, packet } = await buildOperatorHandshake(state.hk, state.sessionID);
        if (ws !== state.ws || state.activeAgent !== agent || ws.readyState !== WebSocket.OPEN) {
          return;
        }
        agent.opNonce = opNonce;
        ws.send(encodeRelayFrame(FRAME_DATA, connID, packet));
      })
      .catch((err) => handleAgentChainError(ws, agent, err));
    return;
  }

  if (ctrlByte === FRAME_AGENT_DISCONNECTED) {
    if (state.activeAgent && state.activeAgent.connID === connID) {
      state.activeAgent = null;
    }
    return;
  }

  if (ctrlByte === FRAME_DATA) {
    const agent = state.activeAgent;
    if (!agent || agent.connID !== connID) {
      return;
    }
    // Serialize async crypto & handler operations per agent connection.
    const payloadCopy = new Uint8Array(payload);
    agent.chain = agent.chain
      .then(() => processAgentFrame(ws, agent, payloadCopy))
      .catch((err) => handleAgentChainError(ws, agent, err));
  }
}

async function startSharing({ tabId, windowId, tabTitle, tabUrl, origin, relayUrl }) {
  await stopSharing(null);

  const originPattern = origin ? `${origin}/*` : null;

  let normalizedRelay;
  try {
    normalizedRelay = validateRelayUrl(relayUrl);
  } catch (err) {
    await revokeOriginPermission(originPattern);
    state.lastError = `Invalid relay URL: ${err.message}`;
    return getPublicState();
  }

  await saveRelayUrl(normalizedRelay);

  let sessionID;
  let secretKey;
  let keyHex;
  let authFrame;
  let hk;
  try {
    sessionID = generateSessionID();
    const generated = generateSessionKey();
    secretKey = generated.key;
    keyHex = generated.keyHex;
    const { opAuth, agentVerifier } = await deriveAuthTokens(secretKey, sessionID);
    hk = await handshakeKey(secretKey, sessionID);
    authFrame = buildOperatorAuthFrame(opAuth, agentVerifier);
  } catch (err) {
    if (secretKey) secretKey.fill(0);
    if (hk) hk.fill(0);
    await revokeOriginPermission(originPattern);
    state.lastError = `Failed to initialize E2EE session: ${err.message}`;
    return getPublicState();
  }

  const wsUrl = new URL(normalizedRelay);
  wsUrl.searchParams.set("session", sessionID);
  wsUrl.searchParams.set("role", ROLE_OPERATOR);

  state.active = true;
  state.connected = false;
  state.tabId = tabId;
  state.windowId = windowId;
  state.tabTitle = tabTitle || "";
  state.tabUrl = tabUrl || "";
  state.origin = origin;
  state.originPattern = originPattern;
  state.sessionID = sessionID;
  state.keyHex = keyHex;
  state.secretKey = secretKey;
  state.hk = hk;
  state.activeAgent = null;
  state.lastError = null;

  let ws;
  try {
    ws = new WebSocket(wsUrl.toString());
    ws.binaryType = "arraybuffer";
  } catch (err) {
    await stopSharing(`Failed to open relay WebSocket: ${err.message}`);
    return getPublicState();
  }
  state.ws = ws;

  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (!settled) {
        settled = true;
        if (state.pendingFinish === finish) {
          state.pendingFinish = null;
        }
        resolve(getPublicState());
      }
    };
    state.pendingFinish = finish;

    let hadError = false;
    let timedOut = false;

    state.connectTimer = setTimeout(() => {
      if (state.ws === ws && ws.readyState !== WebSocket.OPEN) {
        timedOut = true;
        try {
          ws.close();
        } catch (_) {
          // Ignore close errors.
        }
        stopSharing("Relay WebSocket connection timed out").finally(finish);
      }
    }, WS_CONNECT_TIMEOUT_MS);

    ws.onopen = () => {
      if (ws !== state.ws) {
        ws.close();
        finish();
        return;
      }
      if (state.connectTimer !== null) {
        clearTimeout(state.connectTimer);
        state.connectTimer = null;
      }
      ws.send(authFrame);
      state.connected = true;
      state.lastError = null;

      // Set LIVE badge only once relay connection is established.
      setLiveBadge(tabId);

      // 1-byte keepalive every 20s keeps MV3 service worker awake and refreshes relay idle timer.
      state.keepaliveTimer = setInterval(() => {
        if (state.ws === ws && ws.readyState === WebSocket.OPEN) {
          ws.send(new Uint8Array([FRAME_KEEPALIVE]));
        }
      }, KEEPALIVE_INTERVAL_MS);

      finish();
    };

    ws.onmessage = (event) => {
      handleRelayMessage(ws, event.data);
    };

    ws.onerror = () => {
      if (ws !== state.ws) return;
      hadError = true;
    };

    ws.onclose = (event) => {
      if (ws !== state.ws) {
        finish();
        return;
      }
      let reason = null;
      if (timedOut) {
        reason = "Relay WebSocket connection timed out";
      } else if (event.code !== 1000) {
        reason = hadError
          ? `Relay WebSocket connection failed (code ${event.code})`
          : `Relay disconnected (code ${event.code}${event.reason ? `: ${event.reason}` : ""})`;
      }
      stopSharing(reason).finally(finish);
    };
  });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  if (state.active && state.tabId === tabId) {
    stopSharing("Shared tab was closed");
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Restrict messages strictly to this extension's own UI pages (popup), never content scripts or external senders.
  if (!sender || sender.id !== chrome.runtime.id || sender.tab) {
    return;
  }

  (async () => {
    if (!msg || typeof msg.type !== "string") {
      sendResponse({ error: "invalid message" });
      return;
    }

    if (msg.type === "GET_STATE") {
      await loadSavedRelayUrl();
      sendResponse(getPublicState());
      return;
    }

    if (msg.type === "START_SHARING") {
      const result = await startSharing(msg);
      sendResponse(result);
      return;
    }

    if (msg.type === "STOP_SHARING") {
      await stopSharing(null);
      sendResponse(getPublicState());
      return;
    }

    sendResponse({ error: `unknown message type: ${msg.type}` });
  })().catch((err) => {
    sendResponse({ error: err.message });
  });
  return true;
});
