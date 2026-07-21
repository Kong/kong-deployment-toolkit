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
	"regexp"
	"strings"
)

// redactedValue replaces the value of any field identified as sensitive.
const redactedValue = "<REDACTED>"

// configKeyPattern matches Kong configuration/environment keys that carry secret
// material. It is used both for the Admin API root config (sanitizeRootConfig in
// kdd.go) and the VM .kong_env file (sanitizeKongEnvContent below), which share
// the same snake_case key naming convention.
var configKeyPattern = regexp.MustCompile(`(?i)(password|secret|_key$|_conf$|token|license_data)`)

// envVarPattern matches container/pod environment variable names that carry secret
// material. It is broader than configKeyPattern because env var names follow
// different conventions (e.g. API_KEY, TLS_CERT) than Kong's snake_case config keys.
var envVarPattern = regexp.MustCompile(`(?i)(password|secret|token|key|license|cert)`)

// controlCharPattern matches ASCII control characters that have no place in a filename.
var controlCharPattern = regexp.MustCompile(`[\x00-\x1f\x7f]`)

// filenameReplacer strips path separators and parent-directory references from
// externally-sourced names (Kong workspace/control-plane/container/pod names) before
// they are used to build an output filename, since these names originate from data
// the collector does not control (Admin API / Konnect / container runtime responses).
var filenameReplacer = strings.NewReplacer("/", "_", "\\", "_", "..", "_")

// sanitizeFilename makes an externally-sourced name safe to use as a filename
// component. It does not, by itself, make the result safe as a full path: callers
// must still join it under a known workDir.
func sanitizeFilename(name string) string {
	sanitized := filenameReplacer.Replace(name)
	sanitized = controlCharPattern.ReplaceAllString(sanitized, "_")
	return sanitized
}

// sanitizeEnvVars redacts the values of "NAME=value" environment variable entries
// (as returned by Docker's container inspect) whose name matches envVarPattern.
func sanitizeEnvVars(env []string) []string {
	sanitized := make([]string, len(env))
	for i, entry := range env {
		name, _, found := strings.Cut(entry, "=")
		if !found || !envVarPattern.MatchString(name) {
			sanitized[i] = entry
			continue
		}
		sanitized[i] = name + "=" + redactedValue
	}
	return sanitized
}

// sanitizeKongEnvContent redacts the values of "key = value" lines in a Kong
// .kong_env file whose key matches configKeyPattern.
func sanitizeKongEnvContent(content string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		key, _, found := strings.Cut(line, "=")
		if !found {
			continue
		}

		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" || !configKeyPattern.MatchString(trimmedKey) {
			continue
		}

		lines[i] = trimmedKey + " = " + redactedValue
	}

	return strings.Join(lines, "\n")
}
