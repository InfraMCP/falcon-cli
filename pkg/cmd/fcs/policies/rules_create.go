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

package policies

import (
	"fmt"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewCmdRulesCreate represents the fcs policies rules create command.
func NewCmdRulesCreate(f *factory.Factory) *cobra.Command {
	opts := struct {
		name        string
		description string
		severity    int64
		provider    string
		domain      string
		subdomain   string
		logic       string
	}{}

	var confirm bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a policy rule",
		Long:  templates.LongDesc(`Create a new Falcon Cloud Security policy rule.`),
		Example: templates.Examples(`
            # Create a custom rule
            falcon fcs policies rules create --name "My Custom Rule" --description "Checks for X" --provider AWS --domain CSPM --logic "resource.public == true"
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			logic := opts.logic
			if logic == "" {
				logic = "true"
			}

			params := cloud_policies.NewCreateRuleMixin0Params()
			params.Body = &models.CommonCreateRuleRequest{
				Name:        &opts.name,
				Description: &opts.description,
				Provider:    &opts.provider,
				Domain:      &opts.domain,
				Logic:       &logic,
			}

			resp, err := client.CloudPolicies.CreateRuleMixin0(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "create policy rule")
			}

			if resp.Payload != nil && len(resp.Payload.Resources) > 0 {
				rule := resp.Payload.Resources[0]
				fmt.Fprintf(f.IOStreams.Out, "Created rule: %s (%s)\n", deref(rule.Name), deref(rule.UUID))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.name, "name", "", "Rule name (required)")
	cmd.Flags().StringVar(&opts.description, "description", "", "Rule description (required)")
	cmd.Flags().StringVar(&opts.provider, "provider", "", "Cloud provider (AWS, Azure, GCP, OCI, General)")
	cmd.Flags().StringVar(&opts.domain, "domain", "CSPM", "Rule domain (CSPM, Runtime)")
	cmd.Flags().StringVar(&opts.logic, "logic", "", "Rule logic expression")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("description")
	_ = cmd.MarkFlagRequired("provider")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}
