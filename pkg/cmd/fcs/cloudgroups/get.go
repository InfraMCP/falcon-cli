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
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewCmdGet gets cloud groups by ID. Ports op_get from falcon-cloudgroups.py.
func NewCmdGet(f *factory.Factory) *cobra.Command {
	var ids []string
	var out string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get cloud groups by ID",
		Long:  templates.LongDesc(`Get one or more Falcon Cloud Security Cloud Groups by ID.`),
		Example: templates.Examples(`
            # Get specific cloud groups
            falcon fcs cloud-groups get --ids <uuid>

            # Multiple IDs as JSON
            falcon fcs cloud-groups get --ids <uuid1>,<uuid2> --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := cloud_security.NewListCloudGroupsByIDExternalParams()
			p.Ids = ids

			resp, err := falconClient.CloudSecurity.ListCloudGroupsByIDExternal(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "ListCloudGroupsByIDExternal")
			}

			printer := output.NewPrinter(output.Format(out), cloudGroupTableDef)
			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []*models.AssetgroupmanagerV1CloudGroup{})
			}
			return printer.Print(f.IOStreams.Out, resp.Payload.Resources)
		},
	}

	cmdutil.AddIDsFlag(cmd, &ids, true)
	cmdutil.AddOutputFlag(cmd, &out)
	return cmd
}
