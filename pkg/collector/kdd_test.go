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
	"testing"

	"github.com/stretchr/objx"
)

func TestSanitizeRootConfig(t *testing.T) {
	config := objx.Map{
		"version": "3.5.0.0",
		"configuration": objx.Map{
			"pg_host":             "localhost",
			"pg_password":         "hunter2",
			"smtp_password":       "smtpsecret",
			"keyring_private_key": "-----BEGIN PRIVATE KEY-----",
			"admin_gui_auth_conf": "{\"secret\":true}",
			"konnect_mode_token":  "eyJ...",
			"license_data":        "{\"license\":\"...\"}",
			"cluster_ca_cert":     "-----BEGIN CERTIFICATE-----", // public cert material, not secret
		},
	}

	sanitized := sanitizeRootConfig(config, true)

	confMap := sanitized.Get("configuration").ObjxMap()

	redactedKeys := []string{
		"pg_password",
		"smtp_password",
		"keyring_private_key",
		"admin_gui_auth_conf",
		"konnect_mode_token",
		"license_data",
	}
	for _, key := range redactedKeys {
		if confMap.Get(key).Str() != redactedValue {
			t.Errorf("sanitizeRootConfig() did not redact %q, got %v", key, confMap.Get(key))
		}
	}

	if confMap.Get("pg_host").Str() != "localhost" {
		t.Errorf("sanitizeRootConfig() altered non-sensitive key pg_host: %v", confMap.Get("pg_host"))
	}

	// The original map passed in must not be mutated.
	origConfMap := config["configuration"].(objx.Map)
	if origConfMap["pg_password"] != "hunter2" {
		t.Errorf("sanitizeRootConfig() mutated the original config map; pg_password = %v", origConfMap["pg_password"])
	}
}

func TestSanitizeRootConfigDisabled(t *testing.T) {
	config := objx.Map{
		"configuration": objx.Map{
			"pg_password": "hunter2",
		},
	}

	sanitized := sanitizeRootConfig(config, false)

	confMap := sanitized.Get("configuration").ObjxMap()
	if confMap.Get("pg_password").Str() != "hunter2" {
		t.Errorf("sanitizeRootConfig(sanitizeConfigs=false) redacted a value; want unchanged")
	}
}
