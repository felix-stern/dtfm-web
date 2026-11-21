// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

// Web Crypto E2EE implementation with exact wire parity to
// github.com/iinozemtsev-lab/dtfm/pkg/e2ee.

export const ROLE_OPERATOR = "operator";
export const ROLE_AGENT = "agent";

export const KEY_SIZE = 32;
export const HEX_KEY_LEN = 64;
export const NONCE_SIZE = 12;

export const HANDSHAKE_MAGIC = "DTFM1";
export const HANDSHAKE_PACKET_SIZE = 5 + 32 + 32; // 69 bytes

export const DEFAULT_RELAY_WS_URL = "wss://relay.dtfm.dev/ws";

const KDF_SALT = "dtfm-e2ee-salt-v1";

// Relay framing control bytes between Relay and Operator.
export const FRAME_KEEPALIVE = 0x00;
export const FRAME_DATA = 0x01;
export const FRAME_AGENT_CONNECTED = 0x02;
export const FRAME_AGENT_DISCONNECTED = 0x03;
export const FRAME_AUTH = 0x04;
export const FRAME_KICK_AGENT = 0x06;

// Encrypted E2EE record types.
export const RECORD_TYPE_DATA = 0x01;
export const RECORD_TYPE_EOF = 0x02;

const AES_GCM_TAG_BYTES = 16;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const HANDSHAKE_MAGIC_BYTES = textEncoder.encode(HANDSHAKE_MAGIC);

function getCrypto() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error("Web Crypto API (crypto.subtle) is unavailable");
  }
  return c;
}

export function utf8Encode(str) {
  return textEncoder.encode(str);
}

export function utf8Decode(bytes) {
  return textDecoder.decode(bytes);
}

export function bytesToHex(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = "";
  for (let i = 0; i < u8.length; i++) {
    out += u8[i].toString(16).padStart(2, "0");
  }
  return out;
}

export function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0) {
    throw new Error("invalid hex string length");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = parseHexNibble(hex.charCodeAt(i * 2));
    const lo = parseHexNibble(hex.charCodeAt(i * 2 + 1));
    if (hi < 0 || lo < 0) {
      throw new Error("invalid hex character");
    }
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function parseHexNibble(code) {
  if (code >= 48 && code <= 57) return code - 48; // 0-9
  if (code >= 97 && code <= 102) return code - 87; // a-f
  if (code >= 65 && code <= 70) return code - 55; // A-F
  return -1;
}

export function concatBytes(...parts) {
  let total = 0;
  for (const p of parts) {
    total += p.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
    return false;
  }
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function validateSessionID(id) {
  if (typeof id !== "string" || id.length === 0) {
    throw new Error("session ID cannot be empty");
  }
  if (id.length > 64) {
    throw new Error(`session ID exceeds maximum allowed length of 64 characters`);
  }
  for (let i = 0; i < id.length; i++) {
    const c = id.charCodeAt(i);
    const ok =
      (c >= 97 && c <= 122) || // a-z
      (c >= 65 && c <= 90) ||  // A-Z
      (c >= 48 && c <= 57) ||  // 0-9
      c === 45 ||              // -
      c === 95;                // _
    if (!ok) {
      throw new Error(`invalid character in session ID: only [a-zA-Z0-9_-] allowed`);
    }
  }
}

export function generateSessionID() {
  const buf = new Uint8Array(16);
  getCrypto().getRandomValues(buf);
  return bytesToHex(buf);
}

export function generateSessionKey() {
  const key = new Uint8Array(KEY_SIZE);
  getCrypto().getRandomValues(key);
  return { key, keyHex: bytesToHex(key) };
}

async function hkdfDeriveBytes(ikm, salt, info, byteLength) {
  const subtle = getCrypto().subtle;
  const baseKey = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info,
    },
    baseKey,
    byteLength * 8
  );
  return new Uint8Array(bits);
}

async function hmacSha256(keyBytes, data) {
  const subtle = getCrypto().subtle;
  const key = await subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await subtle.sign("HMAC", key, data);
  return new Uint8Array(sig);
}

async function sha256(data) {
  const digest = await getCrypto().subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

// DeriveSubkey derives a 32-byte subkey using HKDF-SHA256 with salt "dtfm-e2ee-salt-v1:<sessionID>".
export async function deriveSubkey(secretKey, sessionID, info) {
  const salt = utf8Encode(`${KDF_SALT}:${sessionID}`);
  return hkdfDeriveBytes(secretKey, salt, utf8Encode(info), KEY_SIZE);
}

// DeriveAuthTokens generates zero-knowledge relay auth tokens and verifier.
export async function deriveAuthTokens(secretKey, sessionID) {
  validateSessionID(sessionID);
  if (!(secretKey instanceof Uint8Array) || secretKey.length !== KEY_SIZE) {
    throw new Error(`invalid secret key length: expected ${KEY_SIZE} bytes`);
  }

  const opAuth = await deriveSubkey(secretKey, sessionID, "dtfm-relay-operator-auth-v1");
  const agentAuth = await deriveSubkey(secretKey, sessionID, "dtfm-relay-agent-auth-v1");
  const agentVerifier = await sha256(agentAuth);

  return {
    opAuth,
    opAuthHex: bytesToHex(opAuth),
    agentAuth,
    agentAuthHex: bytesToHex(agentAuth),
    agentVerifier,
    agentVerifierHex: bytesToHex(agentVerifier),
  };
}

// HandshakeKey derives the HMAC authentication key for per-connection handshakes.
export async function handshakeKey(secretKey, sessionID) {
  return deriveSubkey(secretKey, sessionID, "dtfm-handshake-v1");
}

async function buildHandshake(roleLabel, hk, sessionID, fixedNonce) {
  let nonce;
  if (fixedNonce !== undefined) {
    if (!(fixedNonce instanceof Uint8Array) || fixedNonce.length !== 32) {
      throw new Error("fixedNonce must be a 32-byte Uint8Array");
    }
    nonce = new Uint8Array(fixedNonce);
  } else {
    nonce = new Uint8Array(32);
    getCrypto().getRandomValues(nonce);
  }

  const macInput = concatBytes(utf8Encode(roleLabel), utf8Encode(sessionID), nonce);
  const tag = await hmacSha256(hk, macInput);
  const packet = concatBytes(HANDSHAKE_MAGIC_BYTES, nonce, tag);
  return { nonce, packet };
}

async function verifyHandshake(roleLabel, hk, sessionID, packet) {
  const bytes = packet instanceof Uint8Array ? packet : new Uint8Array(packet);
  if (bytes.length !== HANDSHAKE_PACKET_SIZE) {
    throw new Error(
      `invalid ${roleLabel} handshake size: expected ${HANDSHAKE_PACKET_SIZE} bytes, got ${bytes.length}`
    );
  }
  const magic = bytes.subarray(0, 5);
  if (!constantTimeEqual(magic, HANDSHAKE_MAGIC_BYTES)) {
    throw new Error(`invalid ${roleLabel} handshake magic header`);
  }

  const nonce = bytes.subarray(5, 37);
  const tag = bytes.subarray(37, 69);

  const macInput = concatBytes(utf8Encode(roleLabel), utf8Encode(sessionID), nonce);
  const expectedTag = await hmacSha256(hk, macInput);
  if (!constantTimeEqual(tag, expectedTag)) {
    throw new Error(`${roleLabel} handshake authentication failed: HMAC mismatch`);
  }

  return new Uint8Array(nonce);
}

export async function buildAgentHandshake(hk, sessionID, fixedNonce) {
  const { nonce, packet } = await buildHandshake("agent", hk, sessionID, fixedNonce);
  return { agentNonce: nonce, packet };
}

export async function verifyAgentHandshake(hk, sessionID, packet) {
  return verifyHandshake("agent", hk, sessionID, packet);
}

export async function buildOperatorHandshake(hk, sessionID, fixedNonce) {
  const { nonce, packet } = await buildHandshake("operator", hk, sessionID, fixedNonce);
  return { opNonce: nonce, packet };
}

export async function verifyOperatorHandshake(hk, sessionID, packet) {
  return verifyHandshake("operator", hk, sessionID, packet);
}

// Build 65-byte operator FrameAuth: [0x04 | opAuth(32B) | agentVerifier(32B)].
export function buildOperatorAuthFrame(opAuth, agentVerifier) {
  if (!(opAuth instanceof Uint8Array) || opAuth.length !== 32) {
    throw new Error("opAuth must be 32 bytes");
  }
  if (!(agentVerifier instanceof Uint8Array) || agentVerifier.length !== 32) {
    throw new Error("agentVerifier must be 32 bytes");
  }
  const frame = new Uint8Array(65);
  frame[0] = FRAME_AUTH;
  frame.set(opAuth, 1);
  frame.set(agentVerifier, 33);
  return frame;
}

// Build 33-byte agent FrameAuth: [0x04 | agentAuth(32B)].
export function buildAgentAuthFrame(agentAuth) {
  if (!(agentAuth instanceof Uint8Array) || agentAuth.length !== 32) {
    throw new Error("agentAuth must be 32 bytes");
  }
  const frame = new Uint8Array(33);
  frame[0] = FRAME_AUTH;
  frame.set(agentAuth, 1);
  return frame;
}

// Encode 9-byte operator relay frame: [ctrlByte(1B) | connID(8B BE) | payload].
export function encodeRelayFrame(ctrlByte, connID, payload) {
  const body = payload ? (payload instanceof Uint8Array ? payload : new Uint8Array(payload)) : new Uint8Array(0);
  const frame = new Uint8Array(9 + body.length);
  frame[0] = ctrlByte & 0xff;
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  view.setBigUint64(1, BigInt(connID), false);
  if (body.length > 0) {
    frame.set(body, 9);
  }
  return frame;
}

// Decode 9-byte operator relay frame into { ctrlByte, connID: BigInt, payload: Uint8Array }.
export function decodeRelayFrame(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (bytes.length < 9) {
    throw new Error(`relay frame too short: ${bytes.length} bytes`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const ctrlByte = bytes[0];
  const connID = view.getBigUint64(1, false);
  const payload = bytes.subarray(9);
  return { ctrlByte, connID, payload };
}

function buildIV(seq) {
  const iv = new Uint8Array(NONCE_SIZE);
  const view = new DataView(iv.buffer);
  view.setBigUint64(4, seq, false);
  return iv;
}

function buildAAD(sessionIDBytes, roleByte, seq) {
  const aad = new Uint8Array(sessionIDBytes.length + 1 + 8);
  aad.set(sessionIDBytes, 0);
  aad[sessionIDBytes.length] = roleByte;
  const view = new DataView(aad.buffer);
  view.setBigUint64(sessionIDBytes.length + 1, seq, false);
  return aad;
}

export class ConnCipher {
  constructor(sessionID, role, sendKey, recvKey) {
    this.sessionID = sessionID;
    this.sessionIDBytes = utf8Encode(sessionID);
    this.role = role;
    this.sendKey = sendKey;
    this.recvKey = recvKey;
    this.sendSeq = 0n;
    this.recvSeq = 0n;
  }

  async encryptRecord(recordType, plaintext) {
    const pt = plaintext instanceof Uint8Array ? plaintext : new Uint8Array(plaintext);
    const seq = this.sendSeq;
    this.sendSeq += 1n;

    const iv = buildIV(seq);
    const roleByte = this.role === ROLE_AGENT ? 0x02 : 0x01;
    const aad = buildAAD(this.sessionIDBytes, roleByte, seq);

    const payload = new Uint8Array(1 + pt.length);
    payload[0] = recordType & 0xff;
    payload.set(pt, 1);

    const sealed = await getCrypto().subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: aad,
        tagLength: AES_GCM_TAG_BYTES * 8,
      },
      this.sendKey,
      payload
    );

    const sealedBytes = new Uint8Array(sealed);
    const frame = new Uint8Array(8 + sealedBytes.length);
    const view = new DataView(frame.buffer);
    view.setBigUint64(0, seq, false);
    frame.set(sealedBytes, 8);
    return frame;
  }

  async decryptRecord(frame) {
    const bytes = frame instanceof Uint8Array ? frame : new Uint8Array(frame);
    if (bytes.length < 8 + 1 + AES_GCM_TAG_BYTES) {
      throw new Error("frame is too short to be a valid authenticated record");
    }

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const seq = view.getBigUint64(0, false);
    if (seq !== this.recvSeq) {
      throw new Error(`out-of-order or replayed frame: expected seq ${this.recvSeq}, got ${seq}`);
    }

    const iv = buildIV(seq);
    const peerRoleByte = this.role === ROLE_AGENT ? 0x01 : 0x02;
    const aad = buildAAD(this.sessionIDBytes, peerRoleByte, seq);

    let decryptedBuf;
    try {
      decryptedBuf = await getCrypto().subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: aad,
          tagLength: AES_GCM_TAG_BYTES * 8,
        },
        this.recvKey,
        bytes.subarray(8)
      );
    } catch (err) {
      throw new Error(`e2ee record authentication failed: ${err.message}`);
    }

    this.recvSeq += 1n;
    const decrypted = new Uint8Array(decryptedBuf);
    return {
      recordType: decrypted[0],
      plaintext: decrypted.subarray(1),
    };
  }
}

export async function deriveConnCipher(role, sessionID, secretKey, opNonce, agentNonce) {
  if (role !== ROLE_OPERATOR && role !== ROLE_AGENT) {
    throw new Error(`invalid e2ee role: ${role}`);
  }
  validateSessionID(sessionID);
  if (!(secretKey instanceof Uint8Array) || secretKey.length !== KEY_SIZE) {
    throw new Error(`invalid secret key length: expected ${KEY_SIZE} bytes`);
  }
  if (!(opNonce instanceof Uint8Array) || opNonce.length !== 32) {
    throw new Error("invalid opNonce length: expected 32 bytes");
  }
  if (!(agentNonce instanceof Uint8Array) || agentNonce.length !== 32) {
    throw new Error("invalid agentNonce length: expected 32 bytes");
  }

  const saltStr = `dtfm-e2ee-v1:${sessionID}:${bytesToHex(opNonce)}:${bytesToHex(agentNonce)}`;
  const salt = utf8Encode(saltStr);

  const opKeyRaw = await hkdfDeriveBytes(secretKey, salt, utf8Encode("operator-to-agent"), KEY_SIZE);
  const agentKeyRaw = await hkdfDeriveBytes(secretKey, salt, utf8Encode("agent-to-operator"), KEY_SIZE);

  const subtle = getCrypto().subtle;
  const opKey = await subtle.importKey("raw", opKeyRaw, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
  const agentKey = await subtle.importKey("raw", agentKeyRaw, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);

  if (role === ROLE_OPERATOR) {
    return new ConnCipher(sessionID, role, opKey, agentKey);
  }
  return new ConnCipher(sessionID, role, agentKey, opKey);
}
