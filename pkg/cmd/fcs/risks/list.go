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

package risks

import (
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

type listOptions struct {
	Factory *factory.Factory

	Filter string
	Limit  int64
	Offset int64
	Sort   string
	Output string
	Table  cmdutil.TableFormattingOptions
	Client cmdutil.ClientFilterOptions
}

// NewCmdList represents the fcs risks list command.
func NewCmdList(f *factory.Factory) *cobra.Command {
	opts := &listOptions{Factory: f}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List cloud risks",
		Long:  templates.LongDesc(`List cloud security risks across your cloud accounts.`),
		Example: templates.Examples(`
            # List cloud risks
            falcon fcs risks list

            # Filter by severity (values: Low, Medium, High, Critical — title case)
            falcon fcs risks list --filter "severity:'High'"
            falcon fcs risks list --filter "severity:'Critical'"

            # Filter by cloud provider — use --grep (the cloud_provider filter field is not reliable)
            falcon fcs risks list --grep aws
            falcon fcs risks list --output json | jq '[.[] | select(.provider == "aws")]'

            # Sort descending (note: pipe separator, not dot)
            falcon fcs risks list --sort "severity|desc" --limit 50
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runList(opts)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.Filter)
	cmdutil.AddPaginationFlags(cmd, &opts.Limit, &opts.Offset, 100)
	cmdutil.AddSortFlag(cmd, &opts.Sort)
	cmdutil.AddOutputFlag(cmd, &opts.Output)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)

	return cmd
}

func runList(opts *listOptions) error {
	client, err := opts.Factory.FalconClient()
	if err != nil {
		return err
	}

	params := cloud_security.NewCombinedCloudRisksParams()
	params.Limit = &opts.Limit
	params.Offset = &opts.Offset
	if opts.Filter != "" {
		params.Filter = &opts.Filter
	}
	if opts.Sort != "" {
		params.Sort = &opts.Sort
	}

	// gofalcon v0.24.0 types remediation_plan and risk_summary as strings, but
	// the live API returns objects; re-encode them as JSON strings so decoding succeeds.
	resp, err := client.CloudSecurity.CombinedCloudRisks(params,
		cmdutil.RewriteBody(cmdutil.StringifyResourceFields("remediation_plan", "risk_summary")))
	if err != nil {
		return cmdutil.HandleAPIError(err, "list cloud risks")
	}

	var resources []*models.RisksUnionCloudRisk
	if resp.Payload != nil {
		resources = resp.Payload.Resources
	}

	def := &output.TableDefinition{
		Headers: []string{"ID", "SEVERITY", "TITLE", "PROVIDER", "STATUS", "CREATED"},
		RowFunc: func(item any) []string {
			r, ok := item.(*models.RisksUnionCloudRisk)
			if !ok || r == nil {
				return []string{"", "", "", "", "", ""}
			}
			return []string{
				cmdutil.Deref(r.ID),
				cmdutil.Deref(r.Severity),
				cmdutil.Deref(r.RuleName),
				cmdutil.Deref(r.Provider),
				cmdutil.Deref(r.Status),
				cmdutil.FormatDate(r.FirstSeen),
			}
		},
	}

	resources = output.FilterAndSort(resources, def, opts.Client.ToFilterOptions())

	tableOpts := opts.Table.ToOutputTableOptions()
	printer := output.NewPrinter(output.Format(opts.Output), def, tableOpts)
	return printer.Print(opts.Factory.IOStreams.Out, resources)
}
