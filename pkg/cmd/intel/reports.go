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

package intel

import (
	"strconv"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var reportTableDef = &output.TableDefinition{
	Headers: []string{"ID", "NAME", "SLUG"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.DomainNewsDocument)
		if !ok {
			return nil
		}

		id := ""
		if r.ID != nil {
			id = strconv.FormatInt(*r.ID, 10)
		}

		return []string{
			id,
			cmdutil.Deref(r.Name),
			cmdutil.Deref(r.Slug),
		}
	},
}

// newReportsCmd represents the intel reports command group.
func newReportsCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reports",
		Short: "Query finished intelligence reports",
		Long:  templates.LongDesc(`Query CrowdStrike finished intelligence reports.`),
		Example: templates.Examples(`
            # List intel reports
            falcon intel reports list
        `),
	}

	cmd.AddCommand(newReportsListCmd(f))
	return cmd
}

type reportsListOptions struct {
	Factory *factory.Factory
	filter  string
	sort    string
	limit   int64
	offset  int64
	out     string
	Table   cmdutil.TableFormattingOptions
	Client  cmdutil.ClientFilterOptions
}

// newReportsListCmd lists intel reports matching an optional FQL filter.
func newReportsListCmd(f *factory.Factory) *cobra.Command {
	opts := &reportsListOptions{Factory: f, limit: 100}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List finished intelligence reports",
		Long: templates.LongDesc(`List CrowdStrike finished intelligence reports.

            Returns full report entities in a single call, so the table shows the
            report ID, name and slug.`),
		Example: templates.Examples(`
            # List all intel reports
            falcon intel reports list

            # Filter by name, as JSON
            falcon intel reports list --filter "name:*'*ransomware*'" --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			qp := intel.NewQueryIntelReportEntitiesParams()
			qp.Filter = cmdutil.StringPtr(opts.filter)
			qp.Sort = cmdutil.StringPtr(opts.sort)
			qp.Limit = &opts.limit
			if opts.offset > 0 {
				qp.Offset = &opts.offset
			}

			resp, err := falconClient.Intel.QueryIntelReportEntities(qp)
			if err != nil {
				return cmdutil.HandleAPIError(err, "QueryIntelReportEntities")
			}

			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), reportTableDef, tableOpts)

			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []*models.DomainNewsDocument{})
			}
			resources := output.FilterAndSort(resp.Payload.Resources, reportTableDef, opts.Client.ToFilterOptions())
			return printer.Print(f.IOStreams.Out, resources)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmdutil.AddSortFlag(cmd, &opts.sort)
	cmdutil.AddPaginationFlags(cmd, &opts.limit, &opts.offset, 100)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)
	return cmd
}
