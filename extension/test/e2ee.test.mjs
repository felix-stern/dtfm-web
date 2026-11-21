// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto || !globalThis.crypto.subtle) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}

import {
  FRAME_AUTH,
  FRAME_DATA,
  HANDSHAKE_PACKET_SIZE,
  RECORD_TYPE_DATA,
  RECORD_TYPE_EOF,
  ROLE_AGENT,
  ROLE_OPERATOR,
  buildAgentHandshake,
  buildOperatorAuthFrame,
  buildOperatorHandshake,
  bytesToHex,
  decodeRelayFrame,
  deriveAuthTokens,
  deriveConnCipher,
  encodeRelayFrame,
  generateSessionID,
  generateSessionKey,
  handshakeKey,
  hexToBytes,
  utf8Decode,
  utf8Encode,
  validateSessionID,
  verifyAgentHandshake,
  verifyOperatorHandshake,
} from "../e2ee.js";

test("session ID and key generation + validation", () => {
  const sid = generateSessionID();
  assert.equal(sid.length, 32);
  assert.match(sid, /^[0-9a-f]{32}$/);
  validateSessionID(sid);

  const { key, keyHex } = generateSessionKey();
  assert.equal(key.length, 32);
  assert.equal(keyHex.length, 64);
  assert.deepEqual(hexToBytes(keyHex), key);

  assert.throws(() => validateSessionID(""));
  assert.throws(() => validateSessionID("a".repeat(65)));
  assert.throws(() => validateSessionID("bad/id"));
});

test("operator FrameAuth and 9-byte BigInt relay framing", () => {
  const opAuth = new Uint8Array(32).fill(0xaa);
  const agentVerifier = new Uint8Array(32).fill(0xbb);
  const authFrame = buildOperatorAuthFrame(opAuth, agentVerifier);
  assert.equal(authFrame.length, 65);
  assert.equal(authFrame[0], FRAME_AUTH);
  assert.deepEqual(authFrame.subarray(1, 33), opAuth);
  assert.deepEqual(authFrame.subarray(33, 65), agentVerifier);

  const connID = 0x0102030405060708n;
  const payload = utf8Encode("hello");
  const encoded = encodeRelayFrame(FRAME_DATA, connID, payload);
  assert.equal(encoded.length, 9 + 5);
  const decoded = decodeRelayFrame(encoded);
  assert.equal(decoded.ctrlByte, FRAME_DATA);
  assert.equal(decoded.connID, connID);
  assert.deepEqual(decoded.payload, payload);
});

test("E2EE handshake, bidirectional encryption, anti-replay, and AAD validation", async () => {
  const sessionID = "test-session_42";
  const secretKey = hexToBytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  );

  const tokens = await deriveAuthTokens(secretKey, sessionID);
  assert.equal(tokens.opAuthHex.length, 64);
  assert.equal(tokens.agentAuthHex.length, 64);
  assert.equal(tokens.agentVerifierHex.length, 64);
  assert.notEqual(tokens.opAuthHex, tokens.agentAuthHex);

  const hk = await handshakeKey(secretKey, sessionID);
  const { opNonce, packet: opPacket } = await buildOperatorHandshake(hk, sessionID);
  const { agentNonce, packet: agentPacket } = await buildAgentHandshake(hk, sessionID);

  assert.equal(opPacket.length, HANDSHAKE_PACKET_SIZE);
  assert.equal(agentPacket.length, HANDSHAKE_PACKET_SIZE);

  // Verify valid handshakes
  assert.deepEqual(await verifyOperatorHandshake(hk, sessionID, opPacket), opNonce);
  assert.deepEqual(await verifyAgentHandshake(hk, sessionID, agentPacket), agentNonce);

  // Cross-role handshake must fail
  await assert.rejects(() => verifyAgentHandshake(hk, sessionID, opPacket));
  await assert.rejects(() => verifyOperatorHandshake(hk, sessionID, agentPacket));

  // Tampered handshake must fail
  const tampered = new Uint8Array(agentPacket);
  tampered[68] ^= 0x01;
  await assert.rejects(() => verifyAgentHandshake(hk, sessionID, tampered));

  const opCipher = await deriveConnCipher(ROLE_OPERATOR, sessionID, secretKey, opNonce, agentNonce);
  const agentCipher = await deriveConnCipher(ROLE_AGENT, sessionID, secretKey, opNonce, agentNonce);

  // Agent -> Operator
  const reqFrame = await agentCipher.encryptRecord(RECORD_TYPE_DATA, utf8Encode('{"cmd":"status"}\n'));
  const decReq = await opCipher.decryptRecord(reqFrame);
  assert.equal(decReq.recordType, RECORD_TYPE_DATA);
  assert.equal(utf8Decode(decReq.plaintext), '{"cmd":"status"}\n');

  // Replay of seq=0 must fail
  await assert.rejects(() => opCipher.decryptRecord(reqFrame), /out-of-order or replayed/);

  // Operator -> Agent (seq=0 data, seq=1 EOF)
  const respFrame = await opCipher.encryptRecord(RECORD_TYPE_DATA, utf8Encode('{"ok":true}\n'));
  const eofFrame = await opCipher.encryptRecord(RECORD_TYPE_EOF, new Uint8Array(0));

  // Out-of-order (seq=1 before seq=0) must fail without advancing recvSeq
  await assert.rejects(() => agentCipher.decryptRecord(eofFrame), /out-of-order or replayed/);

  const decResp = await agentCipher.decryptRecord(respFrame);
  assert.equal(decResp.recordType, RECORD_TYPE_DATA);
  assert.equal(utf8Decode(decResp.plaintext), '{"ok":true}\n');

  const decEOF = await agentCipher.decryptRecord(eofFrame);
  assert.equal(decEOF.recordType, RECORD_TYPE_EOF);
  assert.equal(decEOF.plaintext.length, 0);

  // Wrong sessionID AAD mismatch must fail
  const wrongSessionCipher = await deriveConnCipher(
    ROLE_OPERATOR,
    "different-session",
    secretKey,
    opNonce,
    agentNonce
  );
  const frame2 = await agentCipher.encryptRecord(RECORD_TYPE_DATA, utf8Encode("ping"));
  await assert.rejects(() => wrongSessionCipher.decryptRecord(frame2));

  // Tampered ciphertext byte must fail authentication
  const badFrame = new Uint8Array(frame2);
  badFrame[badFrame.length - 1] ^= 0xff;
  await assert.rejects(() => opCipher.decryptRecord(badFrame), /authentication failed/);
  // Verify bytesToHex roundtrip
  assert.equal(bytesToHex(new Uint8Array([0x00, 0x0f, 0xff])), "000fff");
});
