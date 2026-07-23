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

import "testing"

func TestConfigWithDefaults_Nil(t *testing.T) {
	var c *Config
	got := c.WithDefaults()

	if got.KongAddr != "http://localhost:8001" {
		t.Errorf("KongAddr = %q, want default", got.KongAddr)
	}
	if got.LineLimit != 1000 {
		t.Errorf("LineLimit = %d, want 1000", got.LineLimit)
	}
	if got.PrefixDir != "/usr/local/kong" {
		t.Errorf("PrefixDir = %q, want default", got.PrefixDir)
	}
	if len(got.TargetImages) == 0 {
		t.Errorf("TargetImages is empty, want defaults")
	}
}

func TestConfigWithDefaults_FillsUnsetFieldsOnly(t *testing.T) {
	c := &Config{
		KongAddr:  "https://custom:8444",
		LineLimit: 50,
	}

	got := c.WithDefaults()

	if got.KongAddr != "https://custom:8444" {
		t.Errorf("KongAddr = %q, want explicit value preserved", got.KongAddr)
	}
	if got.LineLimit != 50 {
		t.Errorf("LineLimit = %d, want explicit value preserved", got.LineLimit)
	}
	// Unset fields still get defaults.
	if got.PrefixDir != "/usr/local/kong" {
		t.Errorf("PrefixDir = %q, want default applied", got.PrefixDir)
	}
	if len(got.TargetImages) == 0 {
		t.Errorf("TargetImages is empty, want defaults applied")
	}
}

func TestConfigWithDefaults_NegativeLineLimitFallsBackToDefault(t *testing.T) {
	c := &Config{LineLimit: -5}

	got := c.WithDefaults()

	if got.LineLimit != 1000 {
		t.Errorf("LineLimit = %d, want 1000 (negative value should not reach the Docker API as a bogus Tail)", got.LineLimit)
	}
}

func TestConfigWithDefaults_DoesNotMutateOriginal(t *testing.T) {
	c := &Config{}
	_ = c.WithDefaults()

	if c.KongAddr != "" {
		t.Errorf("WithDefaults() mutated the original Config's KongAddr: %q", c.KongAddr)
	}
	if c.LineLimit != 0 {
		t.Errorf("WithDefaults() mutated the original Config's LineLimit: %d", c.LineLimit)
	}
}
