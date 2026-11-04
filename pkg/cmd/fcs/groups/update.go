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

package groups

import (
	"fmt"
	"strings"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

func NewCmdUpdate(f *factory.Factory) *cobra.Command {
	opts := struct {
		id           string
		name         string
		description  string
		environment  string
		businessUnit string
	}{}

	var confirm bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a cloud group",
		Long:  templates.LongDesc(`Update an existing Falcon Cloud Security asset group.`),
		Example: templates.Examples(`
            # Update a cloud group name
            falcon fcs groups update --id <id> --name "New Name"
        `),
		RunE: func(cmd *cobra.Command, args []string) error {
			falconClient, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			p := cloud_security.NewUpdateCloudGroupExternalParams()
			p.Group = &models.AssetgroupmanagerV1UpdateCloudGroupMessage{
				ID:           opts.id,
				Name:         opts.name,
				Description:  &opts.description,
				Environment:  &opts.environment,
				BusinessUnit: &opts.businessUnit,
			}

			resp, err := falconClient.CloudSecurity.UpdateCloudGroupExternal(p)
			if err != nil {
				if strings.Contains(err.Error(), "cannot unmarshal") {
					return fmt.Errorf("UpdateCloudGroupExternal: request rejected by the API\n" +
						"  Feature flag fcs-fga-cloud-groups-external-endpoints may be disabled for this CID.\n" +
						"  Also ensure your API client has the 'Asset Groups: Write' scope")
				}
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "UpdateCloudGroupExternal")
			}

			if len(resp.Payload.Resources) > 0 {
				fmt.Fprintf(f.IOStreams.Out, "Updated cloud group: %s\n", resp.Payload.Resources[0])
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.id, "id", "", "Group ID to update")
	cmd.Flags().StringVar(&opts.name, "name", "", "New name")
	cmd.Flags().StringVar(&opts.description, "description", "", "New description")
	cmd.Flags().StringVar(&opts.environment, "environment", "", "New environment")
	cmd.Flags().StringVar(&opts.businessUnit, "business-unit", "", "New business unit")
	_ = cmd.MarkFlagRequired("id")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}
