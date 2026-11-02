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

	"github.com/spf13/cobra"
)

// AddConfirmFlag adds a --confirm flag that gates a mutating command. Without
// it, the command prints the request it *would* send and exits, matching the
// dry-run-by-default behaviour of the Falcon helper CLIs.
func AddConfirmFlag(cmd *cobra.Command, p *bool) {
	cmd.Flags().BoolVar(p, "confirm", false,
		"Actually perform the write. Without it, prints a dry-run plan and exits.")
}

// DryRunPlan describes a mutating request that would be sent with --confirm.
type DryRunPlan struct {
	DryRun bool   `json:"dry_run"`
	Note   string `json:"note"`
	Action string `json:"action,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	IDs    []string    `json:"ids,omitempty"`
	Body   interface{} `json:"body,omitempty"`
}

// PrintDryRun renders a dry-run plan as indented JSON to w.
func PrintDryRun(w io.Writer, plan DryRunPlan) error {
	plan.DryRun = true
	if plan.Note == "" {
		plan.Note = "Re-run with --confirm to execute this write."
	}
	b, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}
