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
	"encoding/json"
	"fmt"
	"os"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewCmdUpdate updates a cloud group by ID. Writes are gated behind --confirm.
// Ports op_update from falcon-cloudgroups.py, including --from-json.
//
// Note: the update selectors field does not support partial updates — it must
// include all existing selectors, matching the API contract.
func NewCmdUpdate(f *factory.Factory) *cobra.Command {
	var id string
	var body bodyOptions
	var confirm bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a cloud group",
		Long: templates.LongDesc(`Update a Falcon Cloud Security Cloud Group by ID.

            Provide the fields to change via flags, or pass the full group body
            with --from-json. When updating selectors, include all existing
            selectors — the API does not support partial selector updates.

            This is a mutating action. Without --confirm the command prints the
            request body it would send and exits without calling the API.`),
		Example: templates.Examples(`
            # Dry-run a name change
            falcon fcs cloud-groups update --id <uuid> --name "New Name"

            # Execute
            falcon fcs cloud-groups update --id <uuid> --name "New Name" --confirm

            # Update from a JSON file
            falcon fcs cloud-groups update --id <uuid> --from-json group.json --confirm
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			msg, err := buildUpdateMessage(id, &body)
			if err != nil {
				return err
			}

			if !confirm {
				return cmdutil.PrintDryRun(f.IOStreams.Out, cmdutil.DryRunPlan{
					Action: "UpdateCloudGroupExternal",
					Method: "PATCH",
					Path:   "/cloud-security/entities/cloud-groups/v1",
					IDs:    []string{id},
					Body:   msg,
				})
			}

			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := cloud_security.NewUpdateCloudGroupExternalParams()
			p.Group = msg

			resp, err := falconClient.CloudSecurity.UpdateCloudGroupExternal(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "UpdateCloudGroupExternal")
			}

			if resp.Payload != nil && len(resp.Payload.Resources) > 0 {
				fmt.Fprintf(f.IOStreams.Out, "Updated cloud group: %s\n", resp.Payload.Resources[0])
			} else {
				fmt.Fprintf(f.IOStreams.Out, "Updated cloud group: %s\n", id)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "Group ID to update")
	_ = cmd.MarkFlagRequired("id")
	addGroupBodyFlags(cmd, &body)
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}

// buildUpdateMessage resolves the update body from --from-json when given,
// otherwise from the body flags, keyed by the group ID in all cases.
func buildUpdateMessage(id string, opts *bodyOptions) (*models.AssetgroupmanagerV1UpdateCloudGroupMessage, error) {
	if opts.fromJSON != "" {
		raw, err := os.ReadFile(opts.fromJSON)
		if err != nil {
			return nil, fmt.Errorf("reading --from-json file: %w", err)
		}
		var msg models.AssetgroupmanagerV1UpdateCloudGroupMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			return nil, fmt.Errorf("parsing --from-json file: %w", err)
		}
		msg.ID = id
		return &msg, nil
	}
	return opts.updateMessage(id), nil
}
