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

package cases

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/client/cases"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// severityWords lists the --severity choices for help text, lowest first.
func severityWords() string {
	words := make([]string, 0, len(severityLevels))
	for w := range severityLevels {
		words = append(words, w)
	}
	sort.Slice(words, func(i, j int) bool {
		return severityLevels[words[i]].num < severityLevels[words[j]].num
	})
	return strings.Join(words, ", ")
}

func newCmdCreate(f *factory.Factory) *cobra.Command {
	var (
		name, description, severity, status, assignee, descFormat string
		groupIDs, tags                                            []string
		confirm                                                   bool
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a case",
		Long: templates.LongDesc(`Create a case. Dry-run by default; add --confirm to execute.

            --severity is one of: ` + severityWords() + `. --description is
            markdown by default.`),
		Example: templates.Examples(`
            # Dry run — prints the request, calls nothing
            falcon cases create --name "S3 public bucket — triage" \
                --description "Analysis: ..." --severity high --status New --assignee <uuid>

            # Execute
            falcon cases create --name "..." --description "..." --severity high --confirm
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			sev, ok := severityLevels[strings.ToLower(severity)]
			if !ok {
				return fmt.Errorf("invalid --severity %q; one of: %s", severity, severityWords())
			}

			body := &models.OperationsCreateCaseRequest{
				Name:              cmdutil.StringPtr(name),
				Description:       cmdutil.StringPtr(description),
				DescriptionFormat: descFormat,
				Severity:          cmdutil.Int64Ptr(sev.num),
				SeverityInfo:      &models.SdkCaseSeverityInfoAssignment{Level: cmdutil.StringPtr(sev.level)},
				Status:            cmdutil.StringPtr(status),
				Evidence:          &models.OperationsCreateCaseRequestEvidence{},
				Tags:              tags,
			}
			if assignee != "" {
				body.AssignedToUserUUID = cmdutil.StringPtr(assignee)
			}
			if len(groupIDs) > 0 {
				body.AssignedToGroupIds = groupIDs
			}

			c, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}
			p := cases.NewEntitiesCasesPutV2Params()
			p.Body = body
			resp, err := c.Cases.EntitiesCasesPutV2(p)
			if dry.Intercepted(err) {
				return dry.Print(f.IOStreams.Out)
			}
			if err != nil {
				return cmdutil.HandleAPIError(err, "EntitiesCasesPutV2")
			}
			var created []*models.SdkCaseVM
			if resp.Payload != nil {
				created = resp.Payload.Resources
			}
			printWriteResult(f, "created case", created)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Case title (required)")
	cmd.Flags().StringVar(&description, "description", "", "Case body (markdown by default) (required)")
	cmd.Flags().StringVar(&severity, "severity", "", "Severity: "+severityWords()+" (required)")
	cmd.Flags().StringVar(&status, "status", "New", "Initial status")
	cmd.Flags().StringVar(&assignee, "assignee", "", "Assign to this user UUID")
	cmd.Flags().StringSliceVar(&groupIDs, "assignee-group", nil, "Assign to these group IDs (repeatable)")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "Case tag (repeatable)")
	cmd.Flags().StringVar(&descFormat, "description-format", "markdown", "Description format: markdown or plaintext")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("description")
	_ = cmd.MarkFlagRequired("severity")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}

func newCmdUpdate(f *factory.Factory) *cobra.Command {
	var (
		id, name, description, severity, status, assignee string
		confirm                                           bool
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a case",
		Long: templates.LongDesc(`Change a case's fields. Only the flags you pass are changed.
            Dry-run by default; add --confirm to execute.`),
		Example: templates.Examples(`
            falcon cases update --id <case-id> --status "In Progress"
            falcon cases update --id <case-id> --severity critical --confirm
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			fields := &models.OperationsCaseFieldChanges{}
			changed := false
			if name != "" {
				fields.Name = cmdutil.StringPtr(name)
				changed = true
			}
			if description != "" {
				fields.Description = cmdutil.StringPtr(description)
				changed = true
			}
			if status != "" {
				fields.Status = cmdutil.StringPtr(status)
				changed = true
			}
			if assignee != "" {
				fields.AssignedToUserUUID = cmdutil.StringPtr(assignee)
				changed = true
			}
			if severity != "" {
				sev, ok := severityLevels[strings.ToLower(severity)]
				if !ok {
					return fmt.Errorf("invalid --severity %q; one of: %s", severity, severityWords())
				}
				fields.Severity = cmdutil.Int64Ptr(sev.num)
				fields.SeverityInfo = &models.SdkCaseSeverityInfoUpdate{Level: cmdutil.StringPtr(sev.level)}
				changed = true
			}
			if !changed {
				return fmt.Errorf("nothing to update: pass at least one of --name --description --status --severity --assignee")
			}
			return patchCase(f, id, fields, confirm)
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "Case ID (required)")
	cmd.Flags().StringVar(&name, "name", "", "New title")
	cmd.Flags().StringVar(&description, "description", "", "Replace the description")
	cmd.Flags().StringVar(&severity, "severity", "", "New severity: "+severityWords())
	cmd.Flags().StringVar(&status, "status", "", "New status")
	cmd.Flags().StringVar(&assignee, "assignee", "", "Reassign to this user UUID")
	_ = cmd.MarkFlagRequired("id")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}

func newCmdAssign(f *factory.Factory) *cobra.Command {
	var id, assignee string
	var confirm bool

	cmd := &cobra.Command{
		Use:   "assign",
		Short: "Assign a case to a user",
		Long:  templates.LongDesc(`Assign a case to a user by UUID. Dry-run by default; add --confirm to execute.`),
		Example: templates.Examples(`
            falcon cases assign --id <case-id> --assignee <user-uuid> --confirm
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			fields := &models.OperationsCaseFieldChanges{AssignedToUserUUID: cmdutil.StringPtr(assignee)}
			return patchCase(f, id, fields, confirm)
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "Case ID (required)")
	cmd.Flags().StringVar(&assignee, "assignee", "", "User UUID to assign (required)")
	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("assignee")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}

func newCmdComment(f *factory.Factory) *cobra.Command {
	var id, body string
	var confirm bool

	cmd := &cobra.Command{
		Use:   "comment",
		Short: "Append a note to a case",
		Long: templates.LongDesc(`Append a timestamped note to a case's description.

            The Falcon case API has no separate comment endpoint, so a comment is
            added by appending to the markdown description. This fetches the
            current description, appends the note under a "---" rule, and updates
            the case. Dry-run by default; add --confirm to execute.`),
		Example: templates.Examples(`
            falcon cases comment --id <case-id> --body "Confirmed false positive: bucket is public by design."
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			existing, err := fetchCases(f, []string{id})
			if err != nil {
				return err
			}
			if len(existing) == 0 {
				return fmt.Errorf("case %s not found", id)
			}
			prev := cmdutil.Deref(existing[0].Description)
			note := fmt.Sprintf("%s\n\n---\n\n_%s UTC_\n\n%s",
				prev, time.Now().UTC().Format("2006-01-02 15:04"), body)
			fields := &models.OperationsCaseFieldChanges{Description: cmdutil.StringPtr(note)}
			return patchCase(f, id, fields, confirm)
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "Case ID (required)")
	cmd.Flags().StringVar(&body, "body", "", "Note text to append (required)")
	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("body")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}

func newCmdEvidence(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Attach evidence to a case",
	}

	var id, name, evType string
	var confirm bool
	add := &cobra.Command{
		Use:   "add",
		Short: "Attach a custom evidence item to a case",
		Long: templates.LongDesc(`Attach a named custom evidence item to a case — for example the CRN or
            ARN of the resource a Cloud Security finding is about. Dry-run by
            default; add --confirm to execute.`),
		Example: templates.Examples(`
            falcon cases evidence add --id <case-id> \
                --name "aws|123456789012|ap-southeast-2|AWS::S3::Bucket|my-bucket" --type crn
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			c, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}
			p := cases.NewEntitiesCustomEvidencePostV1Params()
			p.Body = &models.OperationsAddCustomEvidenceToCaseRequest{
				CaseID: cmdutil.StringPtr(id),
				Evidence: []*models.SdkCustomEvidence{
					{Name: cmdutil.StringPtr(name), Type: cmdutil.StringPtr(evType)},
				},
			}
			_, err = c.Cases.EntitiesCustomEvidencePostV1(p)
			if dry.Intercepted(err) {
				return dry.Print(f.IOStreams.Out)
			}
			if err != nil {
				return cmdutil.HandleAPIError(err, "EntitiesCustomEvidencePostV1")
			}
			fmt.Fprintf(f.IOStreams.Out, "Attached evidence to case %s\n", id)
			return nil
		},
	}
	add.Flags().StringVar(&id, "id", "", "Case ID (required)")
	add.Flags().StringVar(&name, "name", "", "Evidence value, e.g. a resource CRN/ARN (required)")
	add.Flags().StringVar(&evType, "type", "", "Evidence type label (required, e.g. crn, arn, url)")
	_ = add.MarkFlagRequired("id")
	_ = add.MarkFlagRequired("name")
	_ = add.MarkFlagRequired("type")
	cmdutil.AddConfirmFlag(add, &confirm)

	cmd.AddCommand(add)
	return cmd
}

// patchCase sends a field change, honouring the --confirm dry-run gate.
func patchCase(f *factory.Factory, id string, fields *models.OperationsCaseFieldChanges, confirm bool) error {
	c, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
	if err != nil {
		return err
	}
	p := cases.NewEntitiesCasesPatchV2Params()
	p.Body = &models.OperationsUpdateCaseRequest{ID: cmdutil.StringPtr(id), Fields: fields}
	resp, err := c.Cases.EntitiesCasesPatchV2(p)
	if dry.Intercepted(err) {
		return dry.Print(f.IOStreams.Out)
	}
	if err != nil {
		return cmdutil.HandleAPIError(err, "EntitiesCasesPatchV2")
	}
	var updated []*models.SdkCaseVM
	if resp.Payload != nil {
		updated = resp.Payload.Resources
	}
	printWriteResult(f, "updated case "+id, updated)
	return nil
}

// printWriteResult reports a case write, naming the resulting case ID when the
// response carries one.
func printWriteResult(f *factory.Factory, action string, resources []*models.SdkCaseVM) {
	ids := make([]string, 0, len(resources))
	for _, r := range resources {
		if r != nil {
			ids = append(ids, cmdutil.Deref(r.ID))
		}
	}
	if len(ids) > 0 {
		fmt.Fprintf(f.IOStreams.Out, "%s: %s\n", action, strings.Join(ids, ", "))
		return
	}
	fmt.Fprintf(f.IOStreams.Out, "%s\n", action)
}
