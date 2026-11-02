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

package cloudgroups

import (
	"strconv"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewCmdList lists cloud groups (full entities) via the combined endpoint. Ports
// op_list from falcon-cloudgroups.py.
func NewCmdList(f *factory.Factory) *cobra.Command {
	opts := struct {
		filter string
		sort   string
		limit  int64
		offset int64
		out    string
	}{limit: 100}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List cloud groups (full entities)",
		Long:  templates.LongDesc(`List Falcon Cloud Security Cloud Groups, returning full group entities.`),
		Example: templates.Examples(`
            # List all cloud groups
            falcon fcs cloud-groups list

            # Filter by environment
            falcon fcs cloud-groups list --filter "environment:'prod'"

            # Output as JSON
            falcon fcs cloud-groups list --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := cloud_security.NewListCloudGroupsExternalParams()
			p.Filter = cmdutil.StringPtr(opts.filter)
			p.Sort = cmdutil.StringPtr(opts.sort)
			p.Limit = cmdutil.StringPtr(strconv.FormatInt(opts.limit, 10))
			if opts.offset > 0 {
				p.Offset = cmdutil.StringPtr(strconv.FormatInt(opts.offset, 10))
			}

			resp, err := falconClient.CloudSecurity.ListCloudGroupsExternal(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "ListCloudGroupsExternal")
			}

			printer := output.NewPrinter(output.Format(opts.out), cloudGroupTableDef)
			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []*models.AssetgroupmanagerV1CloudGroup{})
			}
			return printer.Print(f.IOStreams.Out, resp.Payload.Resources)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmdutil.AddSortFlag(cmd, &opts.sort)
	cmdutil.AddPaginationFlags(cmd, &opts.limit, &opts.offset, 100)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	return cmd
}
