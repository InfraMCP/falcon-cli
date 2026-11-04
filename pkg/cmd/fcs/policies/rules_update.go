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

// NewCmdRulesUpdate represents the fcs policies rules update command.
func NewCmdRulesUpdate(f *factory.Factory) *cobra.Command {
	opts := struct {
		id          string
		name        string
		description string
		severity    int64
	}{}

	var confirm bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a policy rule",
		Long:  templates.LongDesc(`Update an existing Falcon Cloud Security policy rule.`),
		Example: templates.Examples(`
            # Update a rule's severity
            falcon fcs policies rules update --id <uuid> --severity 4

            # Update a rule's name and description
            falcon fcs policies rules update --id <uuid> --name "Updated Name" --description "New desc"
        `),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			body := &models.CommonUpdateRuleRequest{
				UUID: &opts.id,
			}

			if cmd.Flags().Changed("name") {
				body.Name = opts.name
			}
			if cmd.Flags().Changed("description") {
				body.Description = opts.description
			}
			if cmd.Flags().Changed("severity") {
				body.Severity = opts.severity
			}

			params := cloud_policies.NewUpdateRuleParams()
			params.Body = body

			resp, err := client.CloudPolicies.UpdateRule(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "update policy rule")
			}

			if resp.Payload != nil && len(resp.Payload.Resources) > 0 {
				rule := resp.Payload.Resources[0]
				fmt.Fprintf(f.IOStreams.Out, "Updated rule: %s (%s)\n", deref(rule.Name), deref(rule.UUID))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.id, "id", "", "Rule UUID to update (required)")
	cmd.Flags().StringVar(&opts.name, "name", "", "New rule name")
	cmd.Flags().StringVar(&opts.description, "description", "", "New rule description")
	cmd.Flags().Int64Var(&opts.severity, "severity", 0, "New severity level (1=Informational, 2=Medium, 3=High, 4=Critical)")
	_ = cmd.MarkFlagRequired("id")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}
