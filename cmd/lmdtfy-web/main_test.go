// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iinozemtsev-lab/dtfm-web/pkg/webproto"
	"github.com/iinozemtsev-lab/dtfm/pkg/e2ee"
)

func TestCLIStatusDOMShot(t *testing.T) {
	sessionID, _ := e2ee.GenerateSessionID()
	secretKey, keyHex, _ := e2ee.GenerateSessionKey()
	token := sessionID + "#" + keyHex

	fakePNG := append(append([]byte{}, pngMagic...), []byte("FAKEPNGDATA")...)

	wsURL := startMockRelayAndOperator(t, sessionID, secretKey, func(req webproto.Request) webproto.Response {
		switch req.Cmd {
		case webproto.CmdStatus:
			return webproto.Response{
				ID: req.ID,
				OK: true,
				Tab: &webproto.TabInfo{
					ID:     12,
					Title:  "My Form",
					URL:    "https://portal.example/step1",
					Active: true,
					Origin: "https://portal.example",
				},
			}
		case webproto.CmdDOM:
			if req.Format == webproto.FormatJSON {
				return webproto.Response{
					ID:     req.ID,
					OK:     true,
					Format: webproto.FormatJSON,
					DOM:    json.RawMessage(`{"title":"My Form","fields":[]}`),
				}
			}
			return webproto.Response{
				ID:       req.ID,
				OK:       true,
				Format:   webproto.FormatMarkdown,
				Markdown: "# My Form\nURL: https://portal.example/step1\n",
			}
		case webproto.CmdShot:
			return webproto.Response{
				ID:          req.ID,
				OK:          true,
				MimeType:    "image/png",
				ImageBase64: base64.StdEncoding.EncodeToString(fakePNG),
			}
		default:
			return webproto.Response{ID: req.ID, OK: false, ErrorCode: webproto.ErrInvalidRequest, Error: "unknown"}
		}
	}, 0)

	// 1. status via flags
	var out, errBuf bytes.Buffer
	code := run([]string{"status", "--relay", token, "--relay-url", wsURL}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("status failed (code=%d): %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "status: LIVE (active)") || !strings.Contains(out.String(), "My Form") {
		t.Fatalf("unexpected status output: %q", out.String())
	}

	// 2. dom --format md via env vars
	t.Setenv("DTFM_WEB_RELAY", token)
	t.Setenv("DTFM_WEB_RELAY_URL", wsURL)

	out.Reset()
	errBuf.Reset()
	code = run([]string{"dom"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("dom md failed (code=%d): %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "# My Form") {
		t.Fatalf("unexpected dom md output: %q", out.String())
	}

	// 3. dom --format json
	out.Reset()
	errBuf.Reset()
	code = run([]string{"dom", "--format", "json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("dom json failed (code=%d): %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"title": "My Form"`) {
		t.Fatalf("unexpected dom json output: %q", out.String())
	}

	// 4. shot <out.png> with flags after positional arg
	outPath := filepath.Join(t.TempDir(), "capture.png")
	out.Reset()
	errBuf.Reset()
	code = run([]string{"shot", outPath, "--relay", token, "--relay-url", wsURL}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("shot failed (code=%d): %s", code, errBuf.String())
	}
	written, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", outPath, err)
	}
	if !bytes.Equal(written, fakePNG) {
		t.Fatalf("PNG bytes mismatch: got %x, want %x", written, fakePNG)
	}
}

func TestCLIShotTabNotActiveFailClosed(t *testing.T) {
	sessionID, _ := e2ee.GenerateSessionID()
	secretKey, keyHex, _ := e2ee.GenerateSessionKey()
	token := sessionID + "#" + keyHex

	wsURL := startMockRelayAndOperator(t, sessionID, secretKey, func(req webproto.Request) webproto.Response {
		return webproto.Response{
			ID:        req.ID,
			OK:        false,
			ErrorCode: webproto.ErrTabNotActive,
			Error:     "Shared tab is not active in its window",
		}
	}, 0)

	outPath := filepath.Join(t.TempDir(), "should-not-exist.png")
	var out, errBuf bytes.Buffer
	code := run([]string{"shot", outPath, "--relay", token, "--relay-url", wsURL}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("expected exit code 1 for ERR_TAB_NOT_ACTIVE, got %d", code)
	}
	if !strings.Contains(errBuf.String(), webproto.ErrTabNotActive) {
		t.Fatalf("expected ERR_TAB_NOT_ACTIVE in stderr, got %q", errBuf.String())
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Fatalf("expected screenshot file not to be created on ERR_TAB_NOT_ACTIVE")
	}
}

func TestCLIVersionAndHelp(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"--version"}, &out, &errBuf); code != 0 {
		t.Fatalf("--version failed: %d", code)
	}
	if !strings.HasPrefix(out.String(), "lmdtfy-web ") {
		t.Fatalf("unexpected version output: %q", out.String())
	}

	out.Reset()
	if code := run([]string{"--help"}, &out, &errBuf); code != 0 {
		t.Fatalf("--help failed: %d", code)
	}
	if !strings.Contains(out.String(), "DTFM_WEB_RELAY") {
		t.Fatalf("expected DTFM_WEB_RELAY in help output")
	}
}
