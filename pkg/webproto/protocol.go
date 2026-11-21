// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package webproto

import "encoding/json"

const (
	CmdStatus = "status"
	CmdDOM    = "dom"
	CmdShot   = "shot"

	FormatMarkdown = "md"
	FormatJSON     = "json"

	ErrTabNotActive     = "ERR_TAB_NOT_ACTIVE"
	ErrTabClosed        = "ERR_TAB_CLOSED"
	ErrPermissionDenied = "ERR_PERMISSION_DENIED"
	ErrInvalidRequest   = "ERR_INVALID_REQUEST"
	ErrInternal         = "ERR_INTERNAL"
)

// Request is the E2EE JSON envelope sent from lmdtfy-web to the Chrome extension.
type Request struct {
	ID     string `json:"id"`
	Cmd    string `json:"cmd"`
	Format string `json:"format,omitempty"`
}

// TabInfo describes the pinned tab shared by the operator.
type TabInfo struct {
	ID     int    `json:"id"`
	Title  string `json:"title"`
	URL    string `json:"url"`
	Active bool   `json:"active"`
	Status string `json:"status"`
	Origin string `json:"origin"`
}

// Response is the E2EE JSON envelope returned by the Chrome extension to lmdtfy-web.
type Response struct {
	ID          string          `json:"id"`
	OK          bool            `json:"ok"`
	ErrorCode   string          `json:"error_code,omitempty"`
	Error       string          `json:"error,omitempty"`
	Tab         *TabInfo        `json:"tab,omitempty"`
	Format      string          `json:"format,omitempty"`
	Markdown    string          `json:"markdown,omitempty"`
	DOM         json.RawMessage `json:"dom,omitempty"`
	MimeType    string          `json:"mime_type,omitempty"`
	ImageBase64 string          `json:"image_base64,omitempty"`
}
