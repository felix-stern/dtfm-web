// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/iinozemtsev-lab/dtfm-web/pkg/webproto"
	"github.com/iinozemtsev-lab/dtfm/pkg/e2ee"
)

func startMockRelayAndOperator(t *testing.T, sessionID string, secretKey []byte, handler func(webproto.Request) webproto.Response, conflictCount int32) string {
	t.Helper()

	_, expectedAgentAuth, _, err := e2ee.DeriveAuthTokens(secretKey, sessionID)
	if err != nil {
		t.Fatalf("DeriveAuthTokens: %v", err)
	}
	hk, err := e2ee.HandshakeKey(secretKey, sessionID)
	if err != nil {
		t.Fatalf("HandshakeKey: %v", err)
	}

	var remainingConflicts atomic.Int32
	remainingConflicts.Store(conflictCount)

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("session") != sessionID {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("role") != e2ee.RoleAgent {
			http.Error(w, "bad role", http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-DTFM-Auth") != expectedAgentAuth {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		if remainingConflicts.Add(-1) >= 0 {
			http.Error(w, "session busy", http.StatusConflict)
			return
		}

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()

		// Operator side: build & send operator handshake, read & verify agent handshake.
		opNonce, opPacket, err := e2ee.BuildOperatorHandshake(hk, sessionID)
		if err != nil {
			return
		}
		if err := ws.WriteMessage(websocket.BinaryMessage, opPacket); err != nil {
			return
		}

		mt, agentPacket, err := ws.ReadMessage()
		if err != nil || mt != websocket.BinaryMessage {
			return
		}
		agentNonce, err := e2ee.VerifyAgentHandshake(hk, sessionID, agentPacket)
		if err != nil {
			return
		}

		opCipher, err := e2ee.DeriveConnCipher(e2ee.RoleOperator, sessionID, secretKey, opNonce, agentNonce)
		if err != nil {
			return
		}

		mt, encReq, err := ws.ReadMessage()
		if err != nil || mt != websocket.BinaryMessage {
			return
		}
		recType, plainReq, err := opCipher.DecryptRecord(encReq)
		if err != nil || recType != e2ee.RecordTypeData {
			return
		}

		var req webproto.Request
		if err := json.Unmarshal(plainReq, &req); err != nil {
			return
		}

		resp := handler(req)
		respBytes, _ := json.Marshal(resp)
		respBytes = append(respBytes, '\n')

		encResp, err := opCipher.EncryptRecord(e2ee.RecordTypeData, respBytes)
		if err != nil {
			return
		}
		_ = ws.WriteMessage(websocket.BinaryMessage, encResp)

		encEOF, err := opCipher.EncryptRecord(e2ee.RecordTypeEOF, nil)
		if err != nil {
			return
		}
		_ = ws.WriteMessage(websocket.BinaryMessage, encEOF)
	}))
	t.Cleanup(srv.Close)

	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
}

func TestDoRequestRoundTripAnd409Retry(t *testing.T) {
	sessionID, err := e2ee.GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	secretKey, _, err := e2ee.GenerateSessionKey()
	if err != nil {
		t.Fatalf("GenerateSessionKey: %v", err)
	}

	wsURL := startMockRelayAndOperator(t, sessionID, secretKey, func(req webproto.Request) webproto.Response {
		return webproto.Response{
			ID: req.ID,
			OK: true,
			Tab: &webproto.TabInfo{
				ID:     7,
				Title:  "Portal",
				URL:    "https://example.ch/form",
				Active: true,
				Origin: "https://example.ch",
			},
		}
	}, 1) // First attempt gets 409 Conflict, retry succeeds.

	var retries atomic.Int32
	resp, err := DoRequest(wsURL, sessionID, secretKey, webproto.Request{
		ID:  "req-1",
		Cmd: webproto.CmdStatus,
	}, &RelayOptions{
		RetryDelayFn: func() time.Duration {
			retries.Add(1)
			return 5 * time.Millisecond
		},
	})
	if err != nil {
		t.Fatalf("DoRequest failed after 409 retry: %v", err)
	}
	if retries.Load() != 1 {
		t.Fatalf("expected exactly 1 retry on 409 Conflict, got %d", retries.Load())
	}
	if !resp.OK || resp.Tab == nil || resp.Tab.Title != "Portal" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestDoRequest409FailsAfterSingleRetry(t *testing.T) {
	sessionID, _ := e2ee.GenerateSessionID()
	secretKey, _, _ := e2ee.GenerateSessionKey()

	wsURL := startMockRelayAndOperator(t, sessionID, secretKey, func(req webproto.Request) webproto.Response {
		return webproto.Response{ID: req.ID, OK: true}
	}, 2) // Both initial and retry get 409 Conflict.

	_, err := DoRequest(wsURL, sessionID, secretKey, webproto.Request{
		ID:  "req-2",
		Cmd: webproto.CmdStatus,
	}, &RelayOptions{
		RetryDelayFn: func() time.Duration { return 2 * time.Millisecond },
	})
	if err == nil {
		t.Fatal("expected 409 error when conflict persists past single retry")
	}
	if !strings.Contains(err.Error(), "409 Conflict") {
		t.Fatalf("expected 409 Conflict in error, got: %v", err)
	}
}

func TestDoRequestAuthAndInactiveErrors(t *testing.T) {
	sessionID, _ := e2ee.GenerateSessionID()
	secretKey, _, _ := e2ee.GenerateSessionKey()
	wrongKey, _, _ := e2ee.GenerateSessionKey()

	wsURL := startMockRelayAndOperator(t, sessionID, secretKey, func(req webproto.Request) webproto.Response {
		return webproto.Response{ID: req.ID, OK: true}
	}, 0)

	// Wrong key -> HTTP 403 -> exit code 1
	_, err := DoRequest(wsURL, sessionID, wrongKey, webproto.Request{ID: "r1", Cmd: webproto.CmdStatus}, nil)
	if err == nil {
		t.Fatal("expected 403 auth failure")
	}
	rErr, ok := err.(*RelayError)
	if !ok || rErr.Code != 1 {
		t.Fatalf("expected RelayError with code 1, got %T %v", err, err)
	}

	// Unknown session -> HTTP 404 -> exit code 2
	_, err = DoRequest(wsURL, "nonexistent-session", secretKey, webproto.Request{ID: "r2", Cmd: webproto.CmdStatus}, nil)
	if err == nil {
		t.Fatal("expected 404 session inactive failure")
	}
	rErr, ok = err.(*RelayError)
	if !ok || rErr.Code != 2 {
		t.Fatalf("expected RelayError with code 2, got %T %v", err, err)
	}
}
