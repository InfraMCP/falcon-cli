// Copyright (c) 2026 CrowdStrike, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package cmdutil

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestIsSensitiveKey(t *testing.T) {
	cases := map[string]bool{
		"credentials":   true,
		"Credential":    true,
		"PASSWORD":      true,
		"client_secret": true,
		"api_key":       true,
		"apikey":        true,
		"token":         true,
		"name":          false,
		"subnet":        false,
		"id":            false,
		"description":   false,
	}
	for key, want := range cases {
		if got := isSensitiveKey(key); got != want {
			t.Errorf("isSensitiveKey(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestRedactSensitive_NestedMapsAndSlices(t *testing.T) {
	in := map[string]interface{}{
		"name": "scan1",
		"credentials": map[string]interface{}{
			"username": "svc",
			"password": "hunter2",
		},
		"targets": []interface{}{
			map[string]interface{}{"ip": "10.0.0.1", "token": "abc"},
		},
	}

	out, ok := redactSensitive(in).(map[string]interface{})
	if !ok {
		t.Fatalf("redactSensitive did not return a map")
	}

	// The whole credentials map is redacted (its key is sensitive).
	if out["credentials"] != redactedPlaceholder {
		t.Errorf("credentials = %v, want redacted", out["credentials"])
	}
	// Non-sensitive sibling is untouched.
	if out["name"] != "scan1" {
		t.Errorf("name = %v, want scan1", out["name"])
	}
	// Sensitive key nested inside a slice element is redacted.
	targets, ok := out["targets"].([]interface{})
	if !ok || len(targets) == 0 {
		t.Fatalf("targets not a non-empty slice: %v", out["targets"])
	}
	tgt, ok := targets[0].(map[string]interface{})
	if !ok {
		t.Fatalf("targets[0] not a map: %v", targets[0])
	}
	if tgt["token"] != redactedPlaceholder {
		t.Errorf("targets[0].token = %v, want redacted", tgt["token"])
	}
	if tgt["ip"] != "10.0.0.1" {
		t.Errorf("targets[0].ip = %v, want 10.0.0.1", tgt["ip"])
	}
}

func TestRedactSensitive_DoesNotMutateInput(t *testing.T) {
	in := map[string]interface{}{"password": "secret"}
	_ = redactSensitive(in)
	if in["password"] != "secret" {
		t.Errorf("input was mutated: password = %v", in["password"])
	}
}

func TestPrintDryRun_RedactsBodyAndSetsDefaults(t *testing.T) {
	var buf bytes.Buffer
	err := PrintDryRun(&buf, DryRunPlan{
		Action: "create",
		Method: "POST",
		Path:   "/netscan/entities/scans/v1",
		Body: map[string]interface{}{
			"name":        "s1",
			"credentials": map[string]interface{}{"password": "p"},
		},
	})
	if err != nil {
		t.Fatalf("PrintDryRun: %v", err)
	}

	var got DryRunPlan
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if !got.DryRun {
		t.Error("dry_run should be true")
	}
	if got.Note == "" {
		t.Error("a default note should be set")
	}
	if strings.Contains(buf.String(), "\"password\": \"p\"") || strings.Contains(buf.String(), "hunter") {
		t.Errorf("secret leaked into dry-run output:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), redactedPlaceholder) {
		t.Errorf("expected redaction placeholder in output:\n%s", buf.String())
	}
}

func TestPrintDryRun_TypedStructBodyRedacted(t *testing.T) {
	// A typed struct body (not a map) must still be redacted via the JSON
	// round-trip, so a group using a gofalcon request model is covered too.
	type cred struct {
		Password string `json:"password"`
	}
	type reqBody struct {
		Name        string `json:"name"`
		Credentials cred   `json:"credentials"`
	}
	var buf bytes.Buffer
	if err := PrintDryRun(&buf, DryRunPlan{Body: reqBody{Name: "x", Credentials: cred{Password: "leak"}}}); err != nil {
		t.Fatalf("PrintDryRun: %v", err)
	}
	if strings.Contains(buf.String(), "leak") {
		t.Errorf("secret leaked from typed body:\n%s", buf.String())
	}
}
