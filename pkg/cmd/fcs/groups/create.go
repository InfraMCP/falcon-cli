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

func NewCmdCreate(f *factory.Factory) *cobra.Command {
	opts := struct {
		name         string
		description  string
		environment  string
		businessUnit string
	}{}

	var confirm bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a cloud group",
		Long:  templates.LongDesc(`Create a new Falcon Cloud Security asset group.`),
		Example: templates.Examples(`
            # Create a cloud group
            falcon fcs groups create --name "Production" --description "Production assets"
        `),
		RunE: func(cmd *cobra.Command, args []string) error {
			falconClient, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			p := cloud_security.NewCreateCloudGroupExternalParams()
			p.Body = &models.AssetgroupmanagerV1CreateCloudGroupRequest{
				Name:         &opts.name,
				Description:  &opts.description,
				Environment:  cmdutil.StringPtr(opts.environment),
				BusinessUnit: cmdutil.StringPtr(opts.businessUnit),
			}

			resp, err := falconClient.CloudSecurity.CreateCloudGroupExternal(p)
			if err != nil {
				// The assetgroupmanager error model has Code as string but the API
				// returns it as int — unmarshal fails before we see the HTTP status.
				// This most often means the fcs-fga-cloud-groups-external-endpoints
				// feature flag is disabled for this CID (fails with PermissionDenied).
				if strings.Contains(err.Error(), "cannot unmarshal") {
					return fmt.Errorf("CreateCloudGroupExternal: request rejected by the API\n" +
						"  The /cloud-security/entities/cloud-groups/v1 endpoint is gated by\n" +
						"  feature flag fcs-fga-cloud-groups-external-endpoints (off by default).\n" +
						"  Contact your Falcon admin to enable it for this CID.\n" +
						"  Also ensure your API client has the 'Asset Groups: Write' scope")
				}
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "CreateCloudGroupExternal")
			}

			if len(resp.Payload.Resources) > 0 {
				fmt.Fprintf(f.IOStreams.Out, "Created cloud group: %s\n", resp.Payload.Resources[0])
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.name, "name", "", "Group name")
	cmd.Flags().StringVar(&opts.description, "description", "", "Group description")
	cmd.Flags().StringVar(&opts.environment, "environment", "", "Environment label")
	cmd.Flags().StringVar(&opts.businessUnit, "business-unit", "", "Business unit label")
	_ = cmd.MarkFlagRequired("name")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}
