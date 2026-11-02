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
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

// redactedPlaceholder replaces the value of any sensitive field in dry-run output.
const redactedPlaceholder = "***REDACTED***"

// sensitiveKeySubstrings are matched case-insensitively against map keys; any
// key containing one has its value masked before a dry-run plan is printed, so
// a dry-run never echoes a secret to stdout or a captured log.
var sensitiveKeySubstrings = []string{
	"credential", "password", "secret", "token", "client_secret", "api_key", "apikey",
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, s := range sensitiveKeySubstrings {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// redactSensitive returns a deep copy of v with the values of any sensitive-named
// keys replaced by a placeholder. Non-map/slice values are returned unchanged.
// Used only for dry-run rendering; the real request body is never altered.
func redactSensitive(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			if isSensitiveKey(k) {
				out[k] = redactedPlaceholder
			} else {
				out[k] = redactSensitive(val)
			}
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, val := range t {
			out[i] = redactSensitive(val)
		}
		return out
	case []map[string]interface{}:
		out := make([]interface{}, len(t))
		for i, val := range t {
			out[i] = redactSensitive(val)
		}
		return out
	default:
		return v
	}
}

// AddConfirmFlag adds a --confirm flag that gates a mutating command. Without
// it, the command prints the request it *would* send and exits, matching the
// dry-run-by-default behaviour of the Falcon helper CLIs.
func AddConfirmFlag(cmd *cobra.Command, p *bool) {
	cmd.Flags().BoolVar(p, "confirm", false,
		"Actually perform the write. Without it, prints a dry-run plan and exits.")
}

// DryRunPlan describes a mutating request that would be sent with --confirm.
type DryRunPlan struct {
	DryRun bool        `json:"dry_run"`
	Note   string      `json:"note"`
	Action string      `json:"action,omitempty"`
	Method string      `json:"method,omitempty"`
	Path   string      `json:"path,omitempty"`
	IDs    []string    `json:"ids,omitempty"`
	Body   interface{} `json:"body,omitempty"`
}

// PrintDryRun renders a dry-run plan as indented JSON to w. The Body is
// normalised to a generic structure and any sensitive-named fields (e.g.
// credentials, password, secret, token) are redacted, so a dry-run never
// echoes a secret the user passed on the command line.
func PrintDryRun(w io.Writer, plan DryRunPlan) error {
	plan.DryRun = true
	if plan.Note == "" {
		plan.Note = "Re-run with --confirm to execute this write."
	}

	// Normalise Body (which may be a map or a typed struct) to a generic shape
	// via a JSON round-trip, then redact sensitive keys. Redaction is applied to
	// the printed copy only; the caller's real body is untouched. If the
	// round-trip fails, fall back to printing the body unredacted-structured is
	// not possible, so drop it rather than risk leaking an unredacted secret.
	if plan.Body != nil {
		if raw, err := json.Marshal(plan.Body); err == nil {
			var generic interface{}
			if err := json.Unmarshal(raw, &generic); err == nil {
				plan.Body = redactSensitive(generic)
			} else {
				plan.Body = redactedPlaceholder
			}
		} else {
			plan.Body = redactedPlaceholder
		}
	}

	b, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}
