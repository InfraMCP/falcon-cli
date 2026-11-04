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
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

func NewCmdCreate(f *factory.Factory) *cobra.Command {
	opts := struct {
		name              string
		description       string
		domain            string
		subdomain         string
		scopeType         string
		suppressionReason string
		ruleSelectionType string
	}{}

	var confirm bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a suppression rule",
		Long:  templates.LongDesc(`Create a new CSPM suppression rule.`),
		Example: templates.Examples(`
            # Create a suppression rule
            falcon fcs suppression create --name "My Rule" --description "Suppress false positives"
        `),
		RunE: func(cmd *cobra.Command, args []string) error {
			falconClient, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			p := cloud_policies.NewCreateSuppressionRuleParams()
			p.Body = &models.SuppressionrulesCreateSuppressionRuleRequest{
				Name:              &opts.name,
				Description:       opts.description,
				Domain:            &opts.domain,
				Subdomain:         &opts.subdomain,
				ScopeType:         &opts.scopeType,
				SuppressionReason: &opts.suppressionReason,
				RuleSelectionType: &opts.ruleSelectionType,
			}

			resp, err := falconClient.CloudPolicies.CreateSuppressionRule(p)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "CreateSuppressionRule")
			}

			if len(resp.Payload.Resources) > 0 {
				fmt.Fprintf(f.IOStreams.Out, "Created suppression rule: %s\n", resp.Payload.Resources[0])
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.name, "name", "", "Name of the suppression rule")
	cmd.Flags().StringVar(&opts.description, "description", "", "Description of the suppression rule")
	cmd.Flags().StringVar(&opts.domain, "domain", "cspm", "Domain (default: cspm)")
	cmd.Flags().StringVar(&opts.subdomain, "subdomain", "IOM", "Subdomain (default: IOM)")
	cmd.Flags().StringVar(&opts.scopeType, "scope-type", "all_assets", "Scope type (default: all_assets)")
	cmd.Flags().StringVar(&opts.suppressionReason, "reason", "false_positive", "Suppression reason: false_positive, accepted_risk")
	cmd.Flags().StringVar(&opts.ruleSelectionType, "rule-selection-type", "rule_selection_filter", "Rule selection type")
	_ = cmd.MarkFlagRequired("name")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}
