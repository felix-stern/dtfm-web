// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

// Cross-language golden-vector helper invoked by Go's e2ee_vectors_test.go.
// Reads JSON input from stdin, executes JS WebCrypto E2EE primitives, and prints JSON output to stdout.

import { webcrypto } from "node:crypto";

if (!globalThis.crypto || !globalThis.crypto.subtle) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}

import {
  RECORD_TYPE_DATA,
  RECORD_TYPE_EOF,
  ROLE_AGENT,
  ROLE_OPERATOR,
  buildAgentHandshake,
  buildOperatorHandshake,
  bytesToHex,
  deriveAuthTokens,
  deriveConnCipher,
  handshakeKey,
  hexToBytes,
  verifyAgentHandshake,
  verifyOperatorHandshake,
} from "../e2ee.js";

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function main() {
  const input = JSON.parse(await readStdin());
  const sessionID = input.session_id;
  const secretKey = hexToBytes(input.secret_key_hex);
  const opNonce = hexToBytes(input.op_nonce_hex);
  const agentNonce = hexToBytes(input.agent_nonce_hex);

  const tokens = await deriveAuthTokens(secretKey, sessionID);
  const hk = await handshakeKey(secretKey, sessionID);

  const opHs = await buildOperatorHandshake(hk, sessionID, opNonce);
  const agentHs = await buildAgentHandshake(hk, sessionID, agentNonce);

  // Verify Go-generated handshake packets if supplied
  if (input.go_op_handshake_hex) {
    const verifiedOpNonce = await verifyOperatorHandshake(
      hk,
      sessionID,
      hexToBytes(input.go_op_handshake_hex)
    );
    if (bytesToHex(verifiedOpNonce) !== input.op_nonce_hex) {
      throw new Error("verified Go operator handshake nonce mismatch");
    }
  }
  if (input.go_agent_handshake_hex) {
    const verifiedAgentNonce = await verifyAgentHandshake(
      hk,
      sessionID,
      hexToBytes(input.go_agent_handshake_hex)
    );
    if (bytesToHex(verifiedAgentNonce) !== input.agent_nonce_hex) {
      throw new Error("verified Go agent handshake nonce mismatch");
    }
  }

  // Derive ciphers and verify Go-encrypted ciphertexts + produce JS-encrypted ciphertexts
  const opCipher = await deriveConnCipher(ROLE_OPERATOR, sessionID, secretKey, opNonce, agentNonce);
  const agentCipher = await deriveConnCipher(ROLE_AGENT, sessionID, secretKey, opNonce, agentNonce);

  const decryptedByOp = [];
  for (const frameHex of input.go_agent_frames_hex || []) {
    const rec = await opCipher.decryptRecord(hexToBytes(frameHex));
    decryptedByOp.push({
      record_type: rec.recordType,
      plaintext_hex: bytesToHex(rec.plaintext),
    });
  }

  const decryptedByAgent = [];
  for (const frameHex of input.go_op_frames_hex || []) {
    const rec = await agentCipher.decryptRecord(hexToBytes(frameHex));
    decryptedByAgent.push({
      record_type: rec.recordType,
      plaintext_hex: bytesToHex(rec.plaintext),
    });
  }

  // Produce deterministic JS frames (seq 0 and seq 1) for Go to decrypt and compare byte-for-byte
  const opCipherFresh = await deriveConnCipher(ROLE_OPERATOR, sessionID, secretKey, opNonce, agentNonce);
  const agentCipherFresh = await deriveConnCipher(ROLE_AGENT, sessionID, secretKey, opNonce, agentNonce);

  const jsOpData = await opCipherFresh.encryptRecord(
    RECORD_TYPE_DATA,
    hexToBytes(input.op_plaintext_hex)
  );
  const jsOpEOF = await opCipherFresh.encryptRecord(RECORD_TYPE_EOF, new Uint8Array(0));

  const jsAgentData = await agentCipherFresh.encryptRecord(
    RECORD_TYPE_DATA,
    hexToBytes(input.agent_plaintext_hex)
  );
  const jsAgentEOF = await agentCipherFresh.encryptRecord(RECORD_TYPE_EOF, new Uint8Array(0));

  const out = {
    op_auth_hex: tokens.opAuthHex,
    agent_auth_hex: tokens.agentAuthHex,
    agent_verifier_hex: tokens.agentVerifierHex,
    handshake_key_hex: bytesToHex(hk),
    op_handshake_hex: bytesToHex(opHs.packet),
    agent_handshake_hex: bytesToHex(agentHs.packet),
    decrypted_by_op: decryptedByOp,
    decrypted_by_agent: decryptedByAgent,
    js_op_frames_hex: [bytesToHex(jsOpData), bytesToHex(jsOpEOF)],
    js_agent_frames_hex: [bytesToHex(jsAgentData), bytesToHex(jsAgentEOF)],
  };

  process.stdout.write(JSON.stringify(out));
}

main().catch((err) => {
  process.stderr.write(`${err.stack || err.message}\n`);
  process.exit(1);
});
