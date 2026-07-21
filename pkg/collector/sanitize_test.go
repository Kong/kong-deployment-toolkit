/*
Copyright © 2022 John Harris

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package collector

import (
	"strings"
	"testing"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain name", "my-workspace", "my-workspace"},
		{"path traversal", "../../evil", "____evil"},
		{"embedded traversal", "foo/../bar", "foo___bar"},
		{"backslash", `foo\bar`, "foo_bar"},
		{"control char", "foo\x00bar", "foo_bar"},
		{"repeated dots", "....", "__"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeFilename(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
			}
			if got != "" && (got == ".." || got == ".") {
				t.Errorf("sanitizeFilename(%q) = %q, still a directory-traversal token", tt.input, got)
			}
		})
	}
}

func TestSanitizeEnvVars(t *testing.T) {
	input := []string{
		"KONG_PG_PASSWORD=hunter2",
		"PATH=/usr/bin",
		"API_KEY=abc123",
		"TLS_CERT=-----BEGIN CERT-----",
		"malformed-entry-no-equals",
	}

	got := sanitizeEnvVars(input)

	want := []string{
		"KONG_PG_PASSWORD=<REDACTED>",
		"PATH=/usr/bin",
		"API_KEY=<REDACTED>",
		"TLS_CERT=<REDACTED>",
		"malformed-entry-no-equals",
	}

	if len(got) != len(want) {
		t.Fatalf("sanitizeEnvVars() returned %d entries, want %d", len(got), len(want))
	}

	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sanitizeEnvVars()[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	if input[0] != "KONG_PG_PASSWORD=hunter2" {
		t.Errorf("sanitizeEnvVars() mutated its input slice")
	}
}

func TestSanitizeKongEnvContent(t *testing.T) {
	input := "pg_password = hunter2\n" +
		"proxy_listen = 0.0.0.0:8000\n" +
		"cluster_cert_key = -----BEGIN PRIVATE KEY-----\n" +
		"admin_gui_session_conf = { \"secret\": \"x\" }\n" +
		"\n" +
		"# a comment line\n"

	got := sanitizeKongEnvContent(input)

	if contains := strings.Contains(got, "hunter2"); contains {
		t.Errorf("sanitizeKongEnvContent() left pg_password value un-redacted: %q", got)
	}
	if strings.Contains(got, "BEGIN PRIVATE KEY") {
		t.Errorf("sanitizeKongEnvContent() left cluster_cert_key value un-redacted: %q", got)
	}
	if !strings.Contains(got, "proxy_listen = 0.0.0.0:8000") {
		t.Errorf("sanitizeKongEnvContent() altered a non-sensitive line: %q", got)
	}
	if !strings.Contains(got, "pg_password = <REDACTED>") {
		t.Errorf("sanitizeKongEnvContent() did not redact pg_password in expected format: %q", got)
	}
}
