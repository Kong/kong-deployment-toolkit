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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetConfigValue(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  string
	}{
		{"simple value", "proxy_listen = 0.0.0.0:8000", "0.0.0.0:8000"},
		{"value containing an equals sign", "pg_dsn = postgres://u:p@h/db?opt=1", "postgres://u:p@h/db?opt=1"},
		{"no equals sign", "not-a-config-line", ""},
		{"empty value", "proxy_access_log =", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getConfigValue(tt.entry)
			if got != tt.want {
				t.Errorf("getConfigValue(%q) = %q, want %q", tt.entry, got, tt.want)
			}
		})
	}
}

func TestCollectAndLimitLogIncludesOldestLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")

	// Three short lines; the oldest ("line1") has no preceding newline in the
	// file and is only recovered by the post-loop flush.
	content := "line1\nline2\nline3\n"
	if err := os.WriteFile(logPath, []byte(content), 0600); err != nil {
		t.Fatalf("writing test log: %v", err)
	}

	envars := "proxy_access_log = " + logPath + "\n"
	workDir := t.TempDir()

	logName := collectAndLimitLog(envars, "proxy_access_log", "", 10, nil, workDir)
	if logName == "" {
		t.Fatalf("collectAndLimitLog() returned no log file")
	}

	got, err := os.ReadFile(logName)
	if err != nil {
		t.Fatalf("reading collected log: %v", err)
	}

	for _, want := range []string{"line1", "line2", "line3"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("collected log missing %q; got: %q", want, got)
		}
	}
}
