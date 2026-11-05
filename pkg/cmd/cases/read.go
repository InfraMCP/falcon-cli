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
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cases"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var caseTableDef = &output.TableDefinition{
	Headers: []string{"ID", "NAME", "SEVERITY", "STATUS", "ASSIGNED_TO", "CREATED"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.SdkCaseVM)
		if !ok || r == nil {
			return nil
		}
		severity := ""
		if r.SeverityInfo != nil {
			severity = cmdutil.Deref(r.SeverityInfo.Level)
		}
		assignee := ""
		if r.AssignedTo != nil {
			assignee = cmdutil.Deref(r.AssignedTo.FullName)
			if assignee == "" {
				assignee = cmdutil.Deref(r.AssignedTo.Email)
			}
		}
		return []string{
			cmdutil.Deref(r.ID),
			cmdutil.Deref(r.Name),
			severity,
			cmdutil.Deref(r.Status),
			assignee,
			cmdutil.FormatDate(r.CreatedTimestamp),
		}
	},
}

type listOptions struct {
	filter string
	q      string
	sort   string
	limit  int64
	offset int64
	out    string
	Table  cmdutil.TableFormattingOptions
	Client cmdutil.ClientFilterOptions
}

func newCmdList(f *factory.Factory) *cobra.Command {
	opts := &listOptions{limit: 100}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List cases",
		Long: templates.LongDesc(`List cases matching an optional FQL filter.

            This queries the matching case IDs and then fetches their full
            records in one follow-up call, so the table and --output json carry
            complete case detail. --sort takes "field.direction" (e.g.
            created_timestamp.desc).`),
		Example: templates.Examples(`
            # All cases
            falcon cases list

            # New cases, newest first
            falcon cases list --filter "status:'New'" --sort "created_timestamp.desc"

            # Free-text search
            falcon cases list --q "s3 bucket"
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := f.FalconClient()
			if err != nil {
				return err
			}

			qp := cases.NewQueriesCasesGetV1Params()
			if opts.filter != "" {
				qp.Filter = cmdutil.StringPtr(opts.filter)
			}
			if opts.q != "" {
				qp.Q = cmdutil.StringPtr(opts.q)
			}
			if opts.sort != "" {
				qp.Sort = cmdutil.StringPtr(opts.sort)
			}
			qp.Limit = cmdutil.Int64Ptr(opts.limit)
			if opts.offset > 0 {
				qp.Offset = cmdutil.Int64Ptr(opts.offset)
			}

			idResp, err := c.Cases.QueriesCasesGetV1(qp)
			if err != nil {
				return cmdutil.HandleAPIError(err, "QueriesCasesGetV1")
			}

			var ids []string
			if idResp.Payload != nil {
				ids = idResp.Payload.Resources
			}

			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), caseTableDef, tableOpts)
			if len(ids) == 0 {
				return printer.Print(f.IOStreams.Out, []*models.SdkCaseVM{})
			}

			resources, err := fetchCases(f, ids)
			if err != nil {
				return err
			}
			resources = output.FilterAndSort(resources, caseTableDef, opts.Client.ToFilterOptions())
			return printer.Print(f.IOStreams.Out, resources)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmd.Flags().StringVar(&opts.q, "q", "", "Free-text search across all case fields")
	cmd.Flags().StringVar(&opts.sort, "sort", "", `Sort as "field.direction" (e.g. created_timestamp.desc)`)
	cmdutil.AddPaginationFlags(cmd, &opts.limit, &opts.offset, 100)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)
	return cmd
}

func newCmdGet(f *factory.Factory) *cobra.Command {
	var ids []string
	opts := &listOptions{}

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get one or more cases by ID",
		Example: templates.Examples(`
            falcon cases get --ids <case-id>
            falcon cases get --ids <id1>,<id2> --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			resources, err := fetchCases(f, ids)
			if err != nil {
				return err
			}
			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), caseTableDef, tableOpts)
			return printer.Print(f.IOStreams.Out, resources)
		},
	}

	cmdutil.AddIDsFlag(cmd, &ids, true)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	return cmd
}

// fetchCases retrieves full case records for the given IDs.
func fetchCases(f *factory.Factory, ids []string) ([]*models.SdkCaseVM, error) {
	c, err := f.FalconClient()
	if err != nil {
		return nil, err
	}
	p := cases.NewEntitiesCasesPostV2Params()
	p.Body = &models.OperationsGetCasesByIDsRequest{Ids: ids}
	resp, err := c.Cases.EntitiesCasesPostV2(p)
	if err != nil {
		return nil, cmdutil.HandleAPIError(err, "EntitiesCasesPostV2")
	}
	if resp.Payload == nil {
		return []*models.SdkCaseVM{}, nil
	}
	return resp.Payload.Resources, nil
}
