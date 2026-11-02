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

package rtr

import (
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

type sessionsListOptions struct {
	Factory *factory.Factory
	filter  string
	sort    string
	limit   int64
	offset  string
	out     string
	Table   cmdutil.TableFormattingOptions
	Client  cmdutil.ClientFilterOptions
}

// sessionIDRow wraps a bare session-ID string so it prints through the table/filter path.
type sessionIDRow struct {
	SessionID string `json:"session_id"`
}

var sessionsTableDef = &output.TableDefinition{
	Headers: []string{"SESSION_ID"},
	RowFunc: func(item any) []string {
		r, ok := item.(sessionIDRow)
		if !ok {
			return nil
		}
		return []string{r.SessionID}
	},
}

// NewCmdSessionsList lists RTR session IDs matching an optional FQL filter.
func NewCmdSessionsList(f *factory.Factory) *cobra.Command {
	opts := &sessionsListOptions{Factory: f, limit: 100}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List RTR session IDs",
		Long:  templates.LongDesc(`List Real Time Response session IDs matching an optional FQL filter.`),
		Example: templates.Examples(`
            # List all RTR session IDs
            falcon rtr sessions list

            # Sessions for one host
            falcon rtr sessions list --filter "device_id:'<aid>'"
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := real_time_response.NewRTRListAllSessionsParams()
			p.Filter = cmdutil.StringPtr(opts.filter)
			p.Sort = cmdutil.StringPtr(opts.sort)
			p.Limit = &opts.limit
			if opts.offset != "" {
				p.Offset = &opts.offset
			}

			resp, err := falconClient.RealTimeResponse.RTRListAllSessions(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "RTRListAllSessions")
			}

			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), sessionsTableDef, tableOpts)

			rows := []sessionIDRow{}
			if resp.Payload != nil {
				for _, id := range resp.Payload.Resources {
					rows = append(rows, sessionIDRow{SessionID: id})
				}
			}
			rows = output.FilterAndSort(rows, sessionsTableDef, opts.Client.ToFilterOptions())
			return printer.Print(f.IOStreams.Out, rows)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmdutil.AddSortFlag(cmd, &opts.sort)
	cmd.Flags().Int64Var(&opts.limit, "limit", 100, "Maximum number of results to return")
	cmd.Flags().StringVar(&opts.offset, "offset", "", "Pagination offset token")
	cmdutil.AddOutputFlag(cmd, &opts.out)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)
	return cmd
}
