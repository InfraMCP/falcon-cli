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

package suppression

import (
	"fmt"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewCmdGet represents the suppression get command.
func NewCmdGet(f *factory.Factory) *cobra.Command {
	var ids []string
	var out string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get suppression rules by ID",
		Long:  templates.LongDesc(`Get one or more suppression rules by their IDs.`),
		Example: templates.Examples(`
            # Get a specific suppression rule
            falcon fcs suppression get --ids <id>
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, err := f.FalconClient()
			if err != nil {
				return err
			}

			params := cloud_policies.NewGetSuppressionRulesParams()
			params.Ids = ids

			resp, err := client.CloudPolicies.GetSuppressionRules(params)
			if err != nil {
				return cmdutil.HandleAPIError(err, "get suppression rules")
			}

			printer := output.NewPrinter(output.Format(out), suppressionTable)
			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, nil)
			}
			return printer.Print(f.IOStreams.Out, resp.Payload.Resources)
		},
	}

	cmdutil.AddIDsFlag(cmd, &ids, true)
	cmdutil.AddOutputFlag(cmd, &out)
	return cmd
}

// NewCmdUpdate represents the suppression update command.
func NewCmdUpdate(f *factory.Factory) *cobra.Command {
	opts := struct {
		id                        string
		name                      string
		description               string
		suppressionReason         string
		suppressionExpirationDate string
	}{}

	var confirm bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a suppression rule",
		Long:  templates.LongDesc(`Update an existing suppression rule.`),
		Example: templates.Examples(`
            # Update a suppression rule's description
            falcon fcs suppression update --id <id> --description "Updated reason"

            # Set an expiration date
            falcon fcs suppression update --id <id> --expiration-date 2025-12-31
        `),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			body := &models.SuppressionrulesUpdateSuppressionRuleRequest{
				ID: &opts.id,
			}

			if cmd.Flags().Changed("name") {
				body.Name = opts.name
			}
			if cmd.Flags().Changed("description") {
				body.Description = &opts.description
			}
			if cmd.Flags().Changed("reason") {
				body.SuppressionReason = opts.suppressionReason
			}
			if cmd.Flags().Changed("expiration-date") {
				body.SuppressionExpirationDate = opts.suppressionExpirationDate
			}

			params := cloud_policies.NewUpdateSuppressionRuleParams()
			params.Body = body

			resp, err := client.CloudPolicies.UpdateSuppressionRule(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "update suppression rule")
			}

			if resp.Payload != nil && len(resp.Payload.Resources) > 0 {
				r := resp.Payload.Resources[0]
				fmt.Fprintf(f.IOStreams.Out, "Updated suppression rule: %s (%s)\n", cmdutil.Deref(r.Name), cmdutil.Deref(r.ID))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.id, "id", "", "Suppression rule ID (required)")
	cmd.Flags().StringVar(&opts.name, "name", "", "New name")
	cmd.Flags().StringVar(&opts.description, "description", "", "New description")
	cmd.Flags().StringVar(&opts.suppressionReason, "reason", "", "Suppression reason")
	cmd.Flags().StringVar(&opts.suppressionExpirationDate, "expiration-date", "", "Expiration date (YYYY-MM-DD)")
	_ = cmd.MarkFlagRequired("id")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}
