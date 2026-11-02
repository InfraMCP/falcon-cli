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
	"fmt"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewCmdDelete deletes cloud groups by ID. Writes are gated behind --confirm.
// Ports op_delete from falcon-cloudgroups.py.
func NewCmdDelete(f *factory.Factory) *cobra.Command {
	var ids []string
	var confirm bool

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete cloud groups by ID",
		Long: templates.LongDesc(`Delete one or more Falcon Cloud Security Cloud Groups by ID.

            This is a mutating action. Without --confirm the command prints the
            request it would send and exits without calling the API.`),
		Example: templates.Examples(`
            # Dry-run (prints the plan, calls nothing)
            falcon fcs cloud-groups delete --ids <uuid>

            # Execute
            falcon fcs cloud-groups delete --ids <uuid1>,<uuid2> --confirm
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			if !confirm {
				return cmdutil.PrintDryRun(f.IOStreams.Out, cmdutil.DryRunPlan{
					Action: "DeleteCloudGroupsExternal",
					Method: "DELETE",
					Path:   "/cloud-security/entities/cloud-groups/v1",
					IDs:    ids,
				})
			}

			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := cloud_security.NewDeleteCloudGroupsExternalParams()
			p.Ids = ids

			if _, err := falconClient.CloudSecurity.DeleteCloudGroupsExternal(p); err != nil {
				return cmdutil.HandleAPIError(err, "DeleteCloudGroupsExternal")
			}

			fmt.Fprintf(f.IOStreams.Out, "Deleted %d cloud group(s)\n", len(ids))
			return nil
		},
	}

	cmdutil.AddIDsFlag(cmd, &ids, true)
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}
