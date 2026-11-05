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

// Package cases implements the "cases" command group: Falcon case management.
//
// It is the closest thing Falcon offers to recording the outcome of triaging a
// Cloud Security finding: a case holds a title, a markdown description, a
// severity, a status and an assignee, and can carry the finding's resource as
// custom evidence. The Cloud Security risk API itself is read-only — it cannot
// be commented on or assigned — so a case (or an external ticket) is where that
// write-up lives.
//
// There is no dedicated "comment" endpoint; `cases comment` appends a
// timestamped note to the case description, which is the API-supported way to
// add running commentary.
package cases

import (
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewCasesCmd represents the cases command group.
func NewCasesCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cases",
		Short: "Falcon case management",
		Long: templates.LongDesc(`Query and manage Falcon cases.

            A case records the outcome of an investigation — a title, a markdown
            write-up, a severity, a status and an assignee. Use it to capture
            triage of a Cloud Security finding (the risk API itself is read-only),
            or any other investigation.

            Reads run immediately. Writes (create, update, comment, assign,
            evidence) are dry-run by default; add --confirm to execute.`),
		Example: templates.Examples(`
            # Open cases, newest first
            falcon cases list --filter "status:'New'" --sort "created_timestamp.desc"

            # Full detail of one case
            falcon cases get --id <case-id> --output json

            # Open a case for a triaged finding, assign it (dry-run, then --confirm)
            falcon cases create --name "S3 public bucket — triage" \
                --description "See analysis." --severity high --assignee <user-uuid>

            # Add a note and change status
            falcon cases comment --id <case-id> --body "Confirmed false positive."
            falcon cases update --id <case-id> --status "In Progress"
        `),
	}

	cmd.AddCommand(newCmdList(f))
	cmd.AddCommand(newCmdGet(f))
	cmd.AddCommand(newCmdCreate(f))
	cmd.AddCommand(newCmdUpdate(f))
	cmd.AddCommand(newCmdComment(f))
	cmd.AddCommand(newCmdAssign(f))
	cmd.AddCommand(newCmdEvidence(f))
	return cmd
}

// severityLevels maps the --severity words to the API's numeric severity and
// the severity_info.level string the create/update bodies require.
var severityLevels = map[string]struct {
	num   int64
	level string
}{
	"informational": {10, "Informational"},
	"low":           {30, "Low"},
	"medium":        {50, "Medium"},
	"high":          {70, "High"},
	"critical":      {90, "Critical"},
}
