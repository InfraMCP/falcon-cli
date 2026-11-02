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

package hosts

import (
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var hostTableDef = &output.TableDefinition{
	Headers: []string{"HOSTNAME", "DEVICE_ID", "PLATFORM", "OS_VERSION", "STATUS", "LOCAL_IP", "LAST_SEEN"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.DeviceapiDeviceSwagger)
		if !ok {
			return nil
		}
		return []string{
			r.Hostname,
			cmdutil.Deref(r.DeviceID),
			r.ProductTypeDesc,
			r.OsVersion,
			r.Status,
			r.LocalIP,
			r.LastSeen,
		}
	},
}

type listOptions struct {
	Factory *factory.Factory
	filter  string
	sort    string
	limit   int64
	offset  int64
	out     string
	Table   cmdutil.TableFormattingOptions
	Client  cmdutil.ClientFilterOptions
}

// NewCmdList lists hosts matching an optional FQL filter.
func NewCmdList(f *factory.Factory) *cobra.Command {
	opts := &listOptions{Factory: f, limit: 100}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List hosts (devices)",
		Long: templates.LongDesc(`List hosts (devices) in your Falcon tenant.

            Resolves matching device IDs via FQL, then fetches full details for
            the page so the table shows hostname, platform, status and IP.`),
		Example: templates.Examples(`
            # List all hosts
            falcon hosts list

            # Windows hosts only
            falcon hosts list --filter "platform_name:'Windows'"

            # Hosts last seen before a date, as JSON
            falcon hosts list --filter "last_seen:<'2026-10-01'" --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			qp := hosts.NewQueryDevicesByFilterParams()
			qp.Filter = cmdutil.StringPtr(opts.filter)
			qp.Sort = cmdutil.StringPtr(opts.sort)
			qp.Limit = &opts.limit
			if opts.offset > 0 {
				qp.Offset = &opts.offset
			}

			qResp, err := falconClient.Hosts.QueryDevicesByFilter(qp)
			if err != nil {
				return cmdutil.HandleAPIError(err, "QueryDevicesByFilter")
			}

			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), hostTableDef, tableOpts)

			ids := []string{}
			if qResp.Payload != nil {
				ids = qResp.Payload.Resources
			}
			if len(ids) == 0 {
				return printer.Print(f.IOStreams.Out, []*models.DeviceapiDeviceSwagger{})
			}

			dp := hosts.NewPostDeviceDetailsV2Params()
			dp.Body = &models.MsaIdsRequest{Ids: ids}
			dResp, err := falconClient.Hosts.PostDeviceDetailsV2(dp)
			if err != nil {
				return cmdutil.HandleAPIError(err, "PostDeviceDetailsV2")
			}

			if dResp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []*models.DeviceapiDeviceSwagger{})
			}
			resources := output.FilterAndSort(dResp.Payload.Resources, hostTableDef, opts.Client.ToFilterOptions())
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
