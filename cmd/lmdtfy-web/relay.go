// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	"github.com/iinozemtsev-lab/dtfm-web/pkg/webproto"
	"github.com/iinozemtsev-lab/dtfm/pkg/e2ee"
)

const (
	defaultHandshakeTimeout = 10 * time.Second
	defaultRequestTimeout   = 30 * time.Second
	defaultWriteTimeout     = 10 * time.Second
	maxWSReadBytes          = 16*1024*1024 + 256*1024 // 16.25 MB for PNG screenshots
	conflictRetryBase       = 200 * time.Millisecond
	conflictRetryJitterMax  = 100 * time.Millisecond
)

// RelayError represents a classified transport or protocol failure with a POSIX exit code.
type RelayError struct {
	Code    int // 1 = auth/bad request/busy, 2 = inactive/unreachable
	Message string
	Err     error
}

func (e *RelayError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *RelayError) Unwrap() error {
	return e.Err
}

// RelayOptions customizes relay dialing and timeouts (primarily for tests).
type RelayOptions struct {
	Dialer           *websocket.Dialer
	HandshakeTimeout time.Duration
	RequestTimeout   time.Duration
	RetryDelayFn     func() time.Duration
}

// jitteredConflictDelay returns a duration in [200ms, 300ms] (~250ms jitter).
func jitteredConflictDelay() time.Duration {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 250 * time.Millisecond
	}
	n := binary.BigEndian.Uint64(b[:]) % uint64(conflictRetryJitterMax+1)
	return conflictRetryBase + time.Duration(n)
}

// DoRequest opens a stateless E2EE connection to the relay, sends req, and returns the decrypted Response.
// On HTTP 409 Conflict, it retries once after ~250ms jitter so accidental parallel agent calls succeed cleanly.
func DoRequest(relayWsURL, sessionID string, secretKey []byte, req webproto.Request, opts *RelayOptions) (*webproto.Response, error) {
	if err := e2ee.ValidateSessionID(sessionID); err != nil {
		return nil, &RelayError{Code: 1, Message: fmt.Sprintf("invalid session ID: %v", err)}
	}
	if len(secretKey) != e2ee.KeySize {
		return nil, &RelayError{Code: 1, Message: fmt.Sprintf("invalid secret key length: expected %d bytes, got %d", e2ee.KeySize, len(secretKey))}
	}

	_, agentAuthHex, _, err := e2ee.DeriveAuthTokens(secretKey, sessionID)
	if err != nil {
		return nil, &RelayError{Code: 1, Message: "failed to derive agent auth tokens", Err: err}
	}

	hk, err := e2ee.HandshakeKey(secretKey, sessionID)
	if err != nil {
		return nil, &RelayError{Code: 1, Message: "failed to derive handshake key", Err: err}
	}

	u, err := url.Parse(relayWsURL)
	if err != nil {
		return nil, &RelayError{Code: 1, Message: fmt.Sprintf("invalid relay websocket url: %v", err)}
	}
	if (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" {
		return nil, &RelayError{Code: 1, Message: fmt.Sprintf("invalid relay websocket url (must be ws:// or wss:// with host): %q", relayWsURL)}
	}

	q := u.Query()
	q.Set("session", sessionID)
	q.Set("role", e2ee.RoleAgent)
	u.RawQuery = q.Encode()

	headers := make(http.Header)
	headers.Set("X-DTFM-Auth", agentAuthHex)

	dialer := *websocket.DefaultDialer
	handshakeTimeout := defaultHandshakeTimeout
	requestTimeout := defaultRequestTimeout
	retryDelayFn := jitteredConflictDelay

	if opts != nil {
		if opts.Dialer != nil {
			dialer = *opts.Dialer
		}
		if opts.HandshakeTimeout > 0 {
			handshakeTimeout = opts.HandshakeTimeout
		}
		if opts.RequestTimeout > 0 {
			requestTimeout = opts.RequestTimeout
		}
		if opts.RetryDelayFn != nil {
			retryDelayFn = opts.RetryDelayFn
		}
	}
	if dialer.HandshakeTimeout <= 0 {
		dialer.HandshakeTimeout = handshakeTimeout
	}

	wsConn, err := dialWithConflictRetry(&dialer, u.String(), headers, sessionID, relayWsURL, retryDelayFn)
	if err != nil {
		return nil, err
	}
	wsConn.SetReadLimit(maxWSReadBytes)

	var connCipher *e2ee.ConnCipher
	remoteEOF := false
	defer func() {
		if !remoteEOF && connCipher != nil {
			if eofRec, eofErr := connCipher.EncryptRecord(e2ee.RecordTypeEOF, []byte{}); eofErr == nil {
				_ = wsConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_ = wsConn.WriteMessage(websocket.BinaryMessage, eofRec)
			}
		}
		_ = wsConn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "lmdtfy-web done"),
			time.Now().Add(time.Second),
		)
		_ = wsConn.Close()
	}()

	// 1. E2EE handshake: send agent handshake, read and verify operator handshake.
	agentNonce, agentPacket, err := e2ee.BuildAgentHandshake(hk, sessionID)
	if err != nil {
		return nil, &RelayError{Code: 1, Message: "failed to build agent handshake", Err: err}
	}

	_ = wsConn.SetWriteDeadline(time.Now().Add(defaultWriteTimeout))
	if err := wsConn.WriteMessage(websocket.BinaryMessage, agentPacket); err != nil {
		return nil, &RelayError{Code: 1, Message: "failed to send agent handshake to relay", Err: err}
	}

	_ = wsConn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	msgType, opPacket, err := wsConn.ReadMessage()
	if err != nil {
		return nil, &RelayError{Code: 1, Message: "failed to read operator handshake from relay", Err: err}
	}
	if msgType != websocket.BinaryMessage {
		return nil, &RelayError{Code: 1, Message: "unexpected non-binary operator handshake message"}
	}

	opNonce, err := e2ee.VerifyOperatorHandshake(hk, sessionID, opPacket)
	if err != nil {
		return nil, &RelayError{Code: 1, Message: "operator handshake verification failed (tampered or mismatched key)", Err: err}
	}

	connCipher, err = e2ee.DeriveConnCipher(e2ee.RoleAgent, sessionID, secretKey, opNonce, agentNonce)
	if err != nil {
		return nil, &RelayError{Code: 1, Message: "failed to derive connection cipher", Err: err}
	}

	// 2. Encrypt and send request JSON.
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, &RelayError{Code: 1, Message: "failed to encode request", Err: err}
	}
	reqBytes = append(reqBytes, '\n')

	encReq, err := connCipher.EncryptRecord(e2ee.RecordTypeData, reqBytes)
	if err != nil {
		return nil, &RelayError{Code: 1, Message: "failed to encrypt request", Err: err}
	}

	_ = wsConn.SetWriteDeadline(time.Now().Add(defaultWriteTimeout))
	if err := wsConn.WriteMessage(websocket.BinaryMessage, encReq); err != nil {
		return nil, &RelayError{Code: 1, Message: "failed to send encrypted request", Err: err}
	}

	// 3. Read encrypted response record(s) until response JSON is received.
	deadline := time.Now().Add(requestTimeout)
	var respBuf bytes.Buffer
	for {
		_ = wsConn.SetReadDeadline(deadline)
		mt, raw, err := wsConn.ReadMessage()
		if err != nil {
			if respBuf.Len() > 0 {
				break
			}
			return nil, &RelayError{Code: 1, Message: "failed to read encrypted response from browser", Err: err}
		}
		if mt != websocket.BinaryMessage {
			continue
		}

		recType, plaintext, err := connCipher.DecryptRecord(raw)
		if err != nil {
			return nil, &RelayError{Code: 1, Message: "failed to decrypt response frame", Err: err}
		}

		switch recType {
		case e2ee.RecordTypeData:
			respBuf.Write(plaintext)
			if bytes.Contains(respBuf.Bytes(), []byte("\n")) {
				goto decodeResp
			}
		case e2ee.RecordTypeEOF:
			remoteEOF = true
			goto decodeResp
		default:
			return nil, &RelayError{Code: 1, Message: fmt.Sprintf("unexpected E2EE record type 0x%02x", recType)}
		}
	}

decodeResp:
	trimmed := bytes.TrimSpace(respBuf.Bytes())
	if len(trimmed) == 0 {
		return nil, &RelayError{Code: 1, Message: "received empty response from browser extension"}
	}

	var resp webproto.Response
	if err := json.Unmarshal(trimmed, &resp); err != nil {
		return nil, &RelayError{Code: 1, Message: "failed to parse response JSON from browser extension", Err: err}
	}
	if req.ID != "" && resp.ID != "" && resp.ID != req.ID {
		return nil, &RelayError{Code: 1, Message: fmt.Sprintf("response ID mismatch: expected %q, got %q", req.ID, resp.ID)}
	}

	return &resp, nil
}

func dialWithConflictRetry(
	dialer *websocket.Dialer,
	dialURL string,
	headers http.Header,
	sessionID string,
	displayRelayURL string,
	retryDelayFn func() time.Duration,
) (*websocket.Conn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		wsConn, httpResp, err := dialer.Dial(dialURL, headers)
		if err == nil {
			if httpResp != nil && httpResp.Body != nil {
				_ = httpResp.Body.Close()
			}
			return wsConn, nil
		}

		var statusCode int
		if httpResp != nil {
			statusCode = httpResp.StatusCode
			if httpResp.Body != nil {
				_ = httpResp.Body.Close()
			}
		}

		if statusCode == http.StatusConflict && attempt == 0 {
			time.Sleep(retryDelayFn())
			continue
		}

		return nil, classifyDialError(statusCode, sessionID, displayRelayURL, err)
	}
	return nil, errors.New("unreachable")
}

func classifyDialError(statusCode int, sessionID, relayWsURL string, err error) *RelayError {
	if statusCode == 0 {
		return &RelayError{
			Code:    2,
			Message: fmt.Sprintf("dtfm-web session is inactive (cannot connect to relay at %s)", relayWsURL),
			Err:     err,
		}
	}
	switch statusCode {
	case http.StatusForbidden:
		return &RelayError{Code: 1, Message: "relay authentication failed: invalid pairing token or secret key (HTTP 403 Forbidden)"}
	case http.StatusNotFound:
		return &RelayError{Code: 2, Message: fmt.Sprintf("dtfm-web session is inactive (relay session %q not found or browser extension is not sharing)", sessionID)}
	case http.StatusConflict:
		return &RelayError{Code: 1, Message: fmt.Sprintf("dtfm-web session %q is busy with another request (HTTP 409 Conflict)", sessionID)}
	case http.StatusBadRequest:
		return &RelayError{Code: 1, Message: fmt.Sprintf("invalid relay request (HTTP 400 Bad Request): %v", err)}
	case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		return &RelayError{Code: 2, Message: fmt.Sprintf("dtfm-web session is inactive (relay server unreachable: HTTP %d)", statusCode), Err: err}
	default:
		if statusCode >= 500 {
			return &RelayError{Code: 2, Message: fmt.Sprintf("dtfm-web session is inactive (relay server error HTTP %d)", statusCode), Err: err}
		}
		return &RelayError{Code: 1, Message: fmt.Sprintf("failed to connect to relay server (HTTP %d)", statusCode), Err: err}
	}
}
