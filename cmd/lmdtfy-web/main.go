// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/iinozemtsev-lab/dtfm-web/pkg/webproto"
	"github.com/iinozemtsev-lab/dtfm/pkg/e2ee"
)

var version = "dev"

var pngMagic = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

func getVersion() string {
	if version != "" && version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
	}
	return "dev"
}

func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `lmdtfy-web — Stateless E2EE read-only browser bridge CLI for remote AI agents

Usage:
  lmdtfy-web status [--relay <session#key>] [--relay-url <url>]
  lmdtfy-web dom [--format md|json] [--relay <session#key>] [--relay-url <url>]
  lmdtfy-web shot <out.png> [--relay <session#key>] [--relay-url <url>]
  lmdtfy-web version
  lmdtfy-web -h, --help

Options:
  --relay            Session pairing token (<session-id>#<hex-key>) or magic link URL
  --relay-url        WebSocket relay endpoint URL (default: wss://relay.dtfm.dev/ws)
  --format           DOM output format for 'dom': md (default) or json
  -v, --version      Display version and exit
  -h, --help         Display help and exit

Environment Variables:
  DTFM_WEB_RELAY     Default pairing token when --relay is omitted
  DTFM_WEB_RELAY_URL Default relay endpoint URL when --relay-url is omitted

Exit Codes:
  0          Success
  1          CLI error, auth failure, or browser guard error (e.g. ERR_TAB_NOT_ACTIVE)
  2          Session inactive (tab not shared or relay unreachable)
`)
}

func isLoopbackHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// reorderFlags moves known flag tokens (and their values) ahead of positional args
// so users can write either `shot out.png --relay ...` or `shot --relay ... out.png`.
func reorderFlags(args []string, valueFlags map[string]bool) []string {
	var flagsOut []string
	var posOut []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			posOut = append(posOut, args[i:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flagsOut = append(flagsOut, arg)
			name := strings.TrimLeft(arg, "-")
			if !strings.Contains(name, "=") && valueFlags[name] && i+1 < len(args) {
				i++
				flagsOut = append(flagsOut, args[i])
			}
			continue
		}
		posOut = append(posOut, arg)
	}
	return append(flagsOut, posOut...)
}

func resolveRelayConfig(relayToken, relayURL string, stderr io.Writer) (*e2ee.RelayConfig, string, error) {
	if strings.TrimSpace(relayToken) == "" {
		relayToken = os.Getenv("DTFM_WEB_RELAY")
	}
	if strings.TrimSpace(relayURL) == "" {
		relayURL = os.Getenv("DTFM_WEB_RELAY_URL")
	}
	if strings.TrimSpace(relayToken) == "" {
		return nil, "", errors.New("missing pairing token: pass --relay <session#key> or set DTFM_WEB_RELAY")
	}

	cfg, err := e2ee.ParseRelayToken(relayToken, relayURL)
	if err != nil {
		return nil, "", fmt.Errorf("invalid relay token: %w", err)
	}

	targetURL := cfg.RelayURL
	if strings.TrimSpace(relayURL) != "" {
		targetURL = strings.TrimSpace(relayURL)
	}
	if targetURL == "" {
		targetURL = e2ee.DefaultRelayWsURL
	}

	if u, parseErr := url.Parse(targetURL); parseErr == nil && u.Scheme == "ws" && !isLoopbackHost(u.Hostname()) {
		fmt.Fprintf(stderr, "[warning: connecting over unencrypted ws:// to non-loopback relay host %s]\n", u.Hostname())
	}

	return cfg, targetURL, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithOptions(args, stdout, stderr, nil)
}

func runWithOptions(args []string, stdout, stderr io.Writer, opts *RelayOptions) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 1
	}

	var globalRelay string
	var globalRelayURL string
	subcmdIdx := -1

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") {
			subcmdIdx = i
			break
		}
		if (arg == "--relay" || arg == "-relay") && i+1 < len(args) {
			globalRelay = args[i+1]
			i++
		} else if strings.HasPrefix(arg, "--relay=") {
			globalRelay = strings.TrimPrefix(arg, "--relay=")
		} else if strings.HasPrefix(arg, "-relay=") {
			globalRelay = strings.TrimPrefix(arg, "-relay=")
		} else if (arg == "--relay-url" || arg == "-relay-url") && i+1 < len(args) {
			globalRelayURL = args[i+1]
			i++
		} else if strings.HasPrefix(arg, "--relay-url=") {
			globalRelayURL = strings.TrimPrefix(arg, "--relay-url=")
		} else if strings.HasPrefix(arg, "-relay-url=") {
			globalRelayURL = strings.TrimPrefix(arg, "-relay-url=")
		} else {
			subcmdIdx = i
			break
		}
	}

	if subcmdIdx == -1 {
		printUsage(stderr)
		return 1
	}

	remaining := args[subcmdIdx:]
	subcommand := remaining[0]
	subArgs := remaining[1:]

	if subcommand == "status" || subcommand == "dom" || subcommand == "shot" {
		var extra []string
		if globalRelay != "" {
			extra = append(extra, "--relay", globalRelay)
		}
		if globalRelayURL != "" {
			extra = append(extra, "--relay-url", globalRelayURL)
		}
		if len(extra) > 0 {
			subArgs = append(extra, subArgs...)
		}
	}

	switch subcommand {
	case "-v", "--version", "-version", "version":
		if len(subArgs) > 0 {
			fmt.Fprintf(stderr, "lmdtfy-web: %q does not accept extra arguments: %q\n", subcommand, subArgs)
			return 1
		}
		fmt.Fprintf(stdout, "lmdtfy-web %s\n", getVersion())
		return 0
	case "-h", "--help", "help":
		if len(subArgs) > 0 {
			fmt.Fprintf(stderr, "lmdtfy-web: %q does not accept extra arguments: %q\n", subcommand, subArgs)
			return 1
		}
		printUsage(stdout)
		return 0
	case "status":
		return runStatus(subArgs, stdout, stderr, opts)
	case "dom":
		return runDOM(subArgs, stdout, stderr, opts)
	case "shot":
		return runShot(subArgs, stdout, stderr, opts)
	default:
		fmt.Fprintf(stderr, "Unknown subcommand: %s\n", subcommand)
		printUsage(stderr)
		return 1
	}
}

func runStatus(args []string, stdout, stderr io.Writer, opts *RelayOptions) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	relay := fs.String("relay", "", "Session pairing token (<session-id>#<hex-key>)")
	relayURL := fs.String("relay-url", "", "WebSocket relay endpoint URL")
	if err := fs.Parse(reorderFlags(args, map[string]bool{"relay": true, "relay-url": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "status does not accept positional arguments: %v\n", fs.Args())
		return 1
	}

	cfg, targetURL, err := resolveRelayConfig(*relay, *relayURL, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	resp, err := DoRequest(targetURL, cfg.SessionID, cfg.SecretKey, webproto.Request{
		ID:  generateID(),
		Cmd: webproto.CmdStatus,
	}, opts)
	if err != nil {
		return printRelayError(stderr, err)
	}
	if !resp.OK {
		return printBrowserError(stderr, resp)
	}

	if resp.Tab != nil {
		activeLabel := "inactive (switched away)"
		if resp.Tab.Active {
			activeLabel = "active"
		}
		fmt.Fprintf(stdout, "status: LIVE (%s)\n", activeLabel)
		fmt.Fprintf(stdout, "title:  %s\n", resp.Tab.Title)
		fmt.Fprintf(stdout, "url:    %s\n", resp.Tab.URL)
		if resp.Tab.Origin != "" {
			fmt.Fprintf(stdout, "origin: %s\n", resp.Tab.Origin)
		}
	} else {
		fmt.Fprintln(stdout, "status: LIVE")
	}
	return 0
}

func runDOM(args []string, stdout, stderr io.Writer, opts *RelayOptions) int {
	fs := flag.NewFlagSet("dom", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", webproto.FormatMarkdown, "Output format: md or json")
	relay := fs.String("relay", "", "Session pairing token (<session-id>#<hex-key>)")
	relayURL := fs.String("relay-url", "", "WebSocket relay endpoint URL")
	if err := fs.Parse(reorderFlags(args, map[string]bool{"format": true, "relay": true, "relay-url": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "dom does not accept positional arguments: %v\n", fs.Args())
		return 1
	}

	fmtVal := strings.ToLower(strings.TrimSpace(*format))
	if fmtVal != webproto.FormatMarkdown && fmtVal != webproto.FormatJSON {
		fmt.Fprintf(stderr, "error: unsupported --format %q (expected md or json)\n", *format)
		return 1
	}

	cfg, targetURL, err := resolveRelayConfig(*relay, *relayURL, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	resp, err := DoRequest(targetURL, cfg.SessionID, cfg.SecretKey, webproto.Request{
		ID:     generateID(),
		Cmd:    webproto.CmdDOM,
		Format: fmtVal,
	}, opts)
	if err != nil {
		return printRelayError(stderr, err)
	}
	if !resp.OK {
		return printBrowserError(stderr, resp)
	}

	if fmtVal == webproto.FormatJSON {
		var pretty bytes.Buffer
		if len(resp.DOM) == 0 {
			fmt.Fprintln(stdout, "{}")
			return 0
		}
		if err := json.Indent(&pretty, resp.DOM, "", "  "); err != nil {
			fmt.Fprintln(stdout, string(resp.DOM))
			return 0
		}
		fmt.Fprintln(stdout, pretty.String())
		return 0
	}

	if resp.Markdown != "" {
		fmt.Fprint(stdout, resp.Markdown)
		if !strings.HasSuffix(resp.Markdown, "\n") {
			fmt.Fprintln(stdout)
		}
	}
	return 0
}

func runShot(args []string, stdout, stderr io.Writer, opts *RelayOptions) int {
	fs := flag.NewFlagSet("shot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	relay := fs.String("relay", "", "Session pairing token (<session-id>#<hex-key>)")
	relayURL := fs.String("relay-url", "", "WebSocket relay endpoint URL")
	if err := fs.Parse(reorderFlags(args, map[string]bool{"relay": true, "relay-url": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: lmdtfy-web shot <out.png> [--relay <session#key>] [--relay-url <url>]")
		return 1
	}
	outPath := fs.Arg(0)

	cfg, targetURL, err := resolveRelayConfig(*relay, *relayURL, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	resp, err := DoRequest(targetURL, cfg.SessionID, cfg.SecretKey, webproto.Request{
		ID:  generateID(),
		Cmd: webproto.CmdShot,
	}, opts)
	if err != nil {
		return printRelayError(stderr, err)
	}
	if !resp.OK {
		return printBrowserError(stderr, resp)
	}

	if resp.ImageBase64 == "" {
		fmt.Fprintln(stderr, "error: browser returned empty screenshot payload")
		return 1
	}

	pngBytes, err := base64.StdEncoding.DecodeString(resp.ImageBase64)
	if err != nil {
		fmt.Fprintf(stderr, "error: failed to decode base64 screenshot: %v\n", err)
		return 1
	}
	if !bytes.HasPrefix(pngBytes, pngMagic) {
		fmt.Fprintln(stderr, "error: decoded screenshot payload is not a valid PNG image")
		return 1
	}

	if err := os.WriteFile(outPath, pngBytes, 0o600); err != nil {
		fmt.Fprintf(stderr, "error: failed to write screenshot to %s: %v\n", outPath, err)
		return 1
	}

	fmt.Fprintf(stdout, "saved screenshot (%d bytes) to %s\n", len(pngBytes), outPath)
	return 0
}

func printRelayError(stderr io.Writer, err error) int {
	var rErr *RelayError
	if errors.As(err, &rErr) {
		fmt.Fprintf(stderr, "error: %v\n", rErr)
		return rErr.Code
	}
	fmt.Fprintf(stderr, "error: %v\n", err)
	return 1
}

func printBrowserError(stderr io.Writer, resp *webproto.Response) int {
	if resp.ErrorCode != "" {
		fmt.Fprintf(stderr, "error [%s]: %s\n", resp.ErrorCode, resp.Error)
	} else {
		fmt.Fprintf(stderr, "error: %s\n", resp.Error)
	}
	if resp.ErrorCode == webproto.ErrTabClosed {
		return 2
	}
	return 1
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
