// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/iinozemtsev-lab/dtfm/pkg/e2ee"
)

type crossLangInput struct {
	SessionID          string   `json:"session_id"`
	SecretKeyHex       string   `json:"secret_key_hex"`
	OpNonceHex         string   `json:"op_nonce_hex"`
	AgentNonceHex      string   `json:"agent_nonce_hex"`
	GoOpHandshakeHex   string   `json:"go_op_handshake_hex"`
	GoAgentHandshakeHx string   `json:"go_agent_handshake_hex"`
	GoOpFramesHex      []string `json:"go_op_frames_hex"`
	GoAgentFramesHex   []string `json:"go_agent_frames_hex"`
	OpPlaintextHex     string   `json:"op_plaintext_hex"`
	AgentPlaintextHex  string   `json:"agent_plaintext_hex"`
}

type crossLangDecrypted struct {
	RecordType   byte   `json:"record_type"`
	PlaintextHex string `json:"plaintext_hex"`
}

type crossLangOutput struct {
	OpAuthHex        string               `json:"op_auth_hex"`
	AgentAuthHex     string               `json:"agent_auth_hex"`
	AgentVerifierHex string               `json:"agent_verifier_hex"`
	HandshakeKeyHex  string               `json:"handshake_key_hex"`
	OpHandshakeHex   string               `json:"op_handshake_hex"`
	AgentHandshakeHx string               `json:"agent_handshake_hex"`
	DecryptedByOp    []crossLangDecrypted `json:"decrypted_by_op"`
	DecryptedByAgent []crossLangDecrypted `json:"decrypted_by_agent"`
	JSOpFramesHex    []string             `json:"js_op_frames_hex"`
	JSAgentFramesHex []string             `json:"js_agent_frames_hex"`
}

// TestCrossLanguageE2EEGoldenVectors verifies byte-for-byte interoperability between
// Go github.com/iinozemtsev-lab/dtfm/pkg/e2ee and JS extension/e2ee.js (Web Crypto).
func TestCrossLanguageE2EEGoldenVectors(t *testing.T) {
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node binary is required for cross-language E2EE golden-vector test: %v", err)
	}

	sessionID := "golden-vector-session_01"
	secretKey, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatalf("decode secretKey: %v", err)
	}

	goOpAuthHex, goAgentAuthHex, goAgentVerifierHex, err := e2ee.DeriveAuthTokens(secretKey, sessionID)
	if err != nil {
		t.Fatalf("DeriveAuthTokens: %v", err)
	}
	goHK, err := e2ee.HandshakeKey(secretKey, sessionID)
	if err != nil {
		t.Fatalf("HandshakeKey: %v", err)
	}

	opNonce, goOpHandshake, err := e2ee.BuildOperatorHandshake(goHK, sessionID)
	if err != nil {
		t.Fatalf("BuildOperatorHandshake: %v", err)
	}
	agentNonce, goAgentHandshake, err := e2ee.BuildAgentHandshake(goHK, sessionID)
	if err != nil {
		t.Fatalf("BuildAgentHandshake: %v", err)
	}

	goOpCipher, err := e2ee.DeriveConnCipher(e2ee.RoleOperator, sessionID, secretKey, opNonce, agentNonce)
	if err != nil {
		t.Fatalf("DeriveConnCipher(operator): %v", err)
	}
	goAgentCipher, err := e2ee.DeriveConnCipher(e2ee.RoleAgent, sessionID, secretKey, opNonce, agentNonce)
	if err != nil {
		t.Fatalf("DeriveConnCipher(agent): %v", err)
	}

	opPlaintext := []byte(`{"id":"1","ok":true,"tab":{"title":"ZHprivateTax"}}` + "\n")
	agentPlaintext := []byte(`{"id":"1","cmd":"dom","format":"md"}` + "\n")

	goOpData, err := goOpCipher.EncryptRecord(e2ee.RecordTypeData, opPlaintext)
	if err != nil {
		t.Fatalf("goOpCipher.EncryptRecord(data): %v", err)
	}
	goOpEOF, err := goOpCipher.EncryptRecord(e2ee.RecordTypeEOF, nil)
	if err != nil {
		t.Fatalf("goOpCipher.EncryptRecord(eof): %v", err)
	}

	goAgentData, err := goAgentCipher.EncryptRecord(e2ee.RecordTypeData, agentPlaintext)
	if err != nil {
		t.Fatalf("goAgentCipher.EncryptRecord(data): %v", err)
	}
	goAgentEOF, err := goAgentCipher.EncryptRecord(e2ee.RecordTypeEOF, nil)
	if err != nil {
		t.Fatalf("goAgentCipher.EncryptRecord(eof): %v", err)
	}

	in := crossLangInput{
		SessionID:          sessionID,
		SecretKeyHex:       hex.EncodeToString(secretKey),
		OpNonceHex:         hex.EncodeToString(opNonce),
		AgentNonceHex:      hex.EncodeToString(agentNonce),
		GoOpHandshakeHex:   hex.EncodeToString(goOpHandshake),
		GoAgentHandshakeHx: hex.EncodeToString(goAgentHandshake),
		GoOpFramesHex:      []string{hex.EncodeToString(goOpData), hex.EncodeToString(goOpEOF)},
		GoAgentFramesHex:   []string{hex.EncodeToString(goAgentData), hex.EncodeToString(goAgentEOF)},
		OpPlaintextHex:     hex.EncodeToString(opPlaintext),
		AgentPlaintextHex:  hex.EncodeToString(agentPlaintext),
	}
	inBytes, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}

	helperPath := filepath.Join("..", "..", "extension", "test", "cross_lang_helper.mjs")
	cmd := exec.Command(nodeBin, helperPath)
	cmd.Stdin = bytes.NewReader(inBytes)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("node helper failed: %v\nstderr: %s", err, stderr.String())
	}

	var out crossLangOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal node helper output: %v\nraw: %s", err, stdout.String())
	}

	// 1. Auth tokens & handshake key must match byte-for-byte.
	if out.OpAuthHex != goOpAuthHex {
		t.Fatalf("opAuth mismatch:\n  go: %s\n  js: %s", goOpAuthHex, out.OpAuthHex)
	}
	if out.AgentAuthHex != goAgentAuthHex {
		t.Fatalf("agentAuth mismatch:\n  go: %s\n  js: %s", goAgentAuthHex, out.AgentAuthHex)
	}
	if out.AgentVerifierHex != goAgentVerifierHex {
		t.Fatalf("agentVerifier mismatch:\n  go: %s\n  js: %s", goAgentVerifierHex, out.AgentVerifierHex)
	}
	if out.HandshakeKeyHex != hex.EncodeToString(goHK) {
		t.Fatalf("handshakeKey mismatch:\n  go: %x\n  js: %s", goHK, out.HandshakeKeyHex)
	}

	// 2. Deterministic handshake packets with identical nonces must match byte-for-byte.
	if out.OpHandshakeHex != hex.EncodeToString(goOpHandshake) {
		t.Fatalf("operator handshake packet mismatch:\n  go: %x\n  js: %s", goOpHandshake, out.OpHandshakeHex)
	}
	if out.AgentHandshakeHx != hex.EncodeToString(goAgentHandshake) {
		t.Fatalf("agent handshake packet mismatch:\n  go: %x\n  js: %s", goAgentHandshake, out.AgentHandshakeHx)
	}

	// 3. Go verifies JS handshake packets.
	jsOpHsBytes, _ := hex.DecodeString(out.OpHandshakeHex)
	if gotOpNonce, err := e2ee.VerifyOperatorHandshake(goHK, sessionID, jsOpHsBytes); err != nil || !bytes.Equal(gotOpNonce, opNonce) {
		t.Fatalf("Go VerifyOperatorHandshake failed on JS packet: err=%v", err)
	}
	jsAgentHsBytes, _ := hex.DecodeString(out.AgentHandshakeHx)
	if gotAgentNonce, err := e2ee.VerifyAgentHandshake(goHK, sessionID, jsAgentHsBytes); err != nil || !bytes.Equal(gotAgentNonce, agentNonce) {
		t.Fatalf("Go VerifyAgentHandshake failed on JS packet: err=%v", err)
	}

	// 4. Verify JS decrypted Go's records accurately.
	if len(out.DecryptedByOp) != 2 ||
		out.DecryptedByOp[0].RecordType != e2ee.RecordTypeData ||
		out.DecryptedByOp[0].PlaintextHex != hex.EncodeToString(agentPlaintext) ||
		out.DecryptedByOp[1].RecordType != e2ee.RecordTypeEOF ||
		out.DecryptedByOp[1].PlaintextHex != "" {
		t.Fatalf("JS operator decryption mismatch: %+v", out.DecryptedByOp)
	}
	if len(out.DecryptedByAgent) != 2 ||
		out.DecryptedByAgent[0].RecordType != e2ee.RecordTypeData ||
		out.DecryptedByAgent[0].PlaintextHex != hex.EncodeToString(opPlaintext) ||
		out.DecryptedByAgent[1].RecordType != e2ee.RecordTypeEOF ||
		out.DecryptedByAgent[1].PlaintextHex != "" {
		t.Fatalf("JS agent decryption mismatch: %+v", out.DecryptedByAgent)
	}

	// 5. Because AES-GCM uses deterministic counter IVs [0x00*4 | seq(8B BE)],
	// JS-encrypted ciphertexts MUST match Go-encrypted ciphertexts byte-for-byte!
	if out.JSOpFramesHex[0] != hex.EncodeToString(goOpData) {
		t.Fatalf("operator Data ciphertext mismatch:\n  go: %x\n  js: %s", goOpData, out.JSOpFramesHex[0])
	}
	if out.JSOpFramesHex[1] != hex.EncodeToString(goOpEOF) {
		t.Fatalf("operator EOF ciphertext mismatch:\n  go: %x\n  js: %s", goOpEOF, out.JSOpFramesHex[1])
	}
	if out.JSAgentFramesHex[0] != hex.EncodeToString(goAgentData) {
		t.Fatalf("agent Data ciphertext mismatch:\n  go: %x\n  js: %s", goAgentData, out.JSAgentFramesHex[0])
	}
	if out.JSAgentFramesHex[1] != hex.EncodeToString(goAgentEOF) {
		t.Fatalf("agent EOF ciphertext mismatch:\n  go: %x\n  js: %s", goAgentEOF, out.JSAgentFramesHex[1])
	}

	// 6. Go decrypts JS-generated frames and rejects replay/out-of-order.
	goVerifyAgent, _ := e2ee.DeriveConnCipher(e2ee.RoleAgent, sessionID, secretKey, opNonce, agentNonce)
	jsOpFrame0, _ := hex.DecodeString(out.JSOpFramesHex[0])
	jsOpFrame1, _ := hex.DecodeString(out.JSOpFramesHex[1])

	recType, pt, err := goVerifyAgent.DecryptRecord(jsOpFrame0)
	if err != nil || recType != e2ee.RecordTypeData || !bytes.Equal(pt, opPlaintext) {
		t.Fatalf("Go DecryptRecord failed on JS operator frame 0: err=%v type=%d pt=%q", err, recType, pt)
	}
	if _, _, err := goVerifyAgent.DecryptRecord(jsOpFrame0); err == nil {
		t.Fatal("Go DecryptRecord accepted replayed frame 0")
	}
	recType, pt, err = goVerifyAgent.DecryptRecord(jsOpFrame1)
	if err != nil || recType != e2ee.RecordTypeEOF || len(pt) != 0 {
		t.Fatalf("Go DecryptRecord failed on JS operator EOF frame 1: err=%v type=%d", err, recType)
	}
}
