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

// NewCmdCreate creates a cloud group. Writes are gated behind --confirm. Ports
// op_create from falcon-cloudgroups.py, including --from-json.
func NewCmdCreate(f *factory.Factory) *cobra.Command {
	var body bodyOptions
	var confirm bool

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a cloud group",
		Long: templates.LongDesc(`Create a Falcon Cloud Security Cloud Group.

            Set business context, owners, and a cloud-resource selector via flags,
            or pass the full group body with --from-json.

            This is a mutating action. Without --confirm the command prints the
            request body it would send and exits without calling the API.`),
		Example: templates.Examples(`
            # Dry-run an AWS cloud group (prints the body, calls nothing)
            falcon fcs cloud-groups create --name "All Prod" --environment prod \
                --business-impact high --business-unit CSS \
                --owner a@example.com --account 111111111111

            # Execute
            falcon fcs cloud-groups create --name "All Prod" --environment prod --confirm

            # Create from a JSON file
            falcon fcs cloud-groups create --from-json group.json --confirm
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			req, err := buildCreateRequest(&body)
			if err != nil {
				return err
			}

			if !confirm {
				return cmdutil.PrintDryRun(f.IOStreams.Out, cmdutil.DryRunPlan{
					Action: "CreateCloudGroupExternal",
					Method: "POST",
					Path:   "/cloud-security/entities/cloud-groups/v1",
					Body:   req,
				})
			}

			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := cloud_security.NewCreateCloudGroupExternalParams()
			p.Body = req

			resp, err := falconClient.CloudSecurity.CreateCloudGroupExternal(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "CreateCloudGroupExternal")
			}

			if resp.Payload != nil && len(resp.Payload.Resources) > 0 {
				fmt.Fprintf(f.IOStreams.Out, "Created cloud group: %s\n", resp.Payload.Resources[0])
			} else {
				fmt.Fprintln(f.IOStreams.Out, "Created cloud group")
			}
			return nil
		},
	}

	addGroupBodyFlags(cmd, &body)
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}

// buildCreateRequest resolves the create body from --from-json when given,
// otherwise from the body flags, validating that a name is present.
func buildCreateRequest(opts *bodyOptions) (*models.AssetgroupmanagerV1CreateCloudGroupRequest, error) {
	if opts.fromJSON != "" {
		raw, err := os.ReadFile(opts.fromJSON)
		if err != nil {
			return nil, fmt.Errorf("reading --from-json file: %w", err)
		}
		var req models.AssetgroupmanagerV1CreateCloudGroupRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, fmt.Errorf("parsing --from-json file: %w", err)
		}
		if req.Name == nil || *req.Name == "" {
			return nil, fmt.Errorf("the group body in --from-json must include a name")
		}
		return &req, nil
	}

	if opts.name == "" {
		return nil, fmt.Errorf("--name is required (or use --from-json)")
	}
	return opts.createRequest(), nil
}
