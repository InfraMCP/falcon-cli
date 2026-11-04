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
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewOverridesCmd represents the fcs policies overrides command group.
func NewOverridesCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "overrides",
		Short: "Manage rule overrides",
		Long: templates.LongDesc(`
            Create, get, and delete rule overrides.
            Overrides allow you to change rule behavior for specific accounts or regions.`),
	}

	cmd.AddCommand(
		newCmdOverridesGet(f),
		newCmdOverridesCreate(f),
		newCmdOverridesDelete(f),
	)
	return cmd
}

var overrideTableDef = &output.TableDefinition{
	Headers: []string{"UUID", "RULE_ID", "TYPE", "CRN", "REGION", "REASON"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.ApimodelsRuleOverride)
		if !ok || r == nil {
			return nil
		}
		return []string{
			deref(r.UUID),
			r.RuleID,
			deref(r.OverrideType),
			deref(r.Crn),
			deref(r.TargetRegion),
			deref(r.Reason),
		}
	},
}

func newCmdOverridesGet(f *factory.Factory) *cobra.Command {
	var ids []string
	var out string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get rule overrides by ID",
		RunE: func(_ *cobra.Command, _ []string) error {
			client, err := f.FalconClient()
			if err != nil {
				return err
			}

			params := cloud_policies.NewGetRuleOverrideParams()
			params.Ids = ids

			resp, err := client.CloudPolicies.GetRuleOverride(params)
			if err != nil {
				return cmdutil.HandleAPIError(err, "get rule overrides")
			}

			printer := output.NewPrinter(output.Format(out), overrideTableDef)
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

func newCmdOverridesCreate(f *factory.Factory) *cobra.Command {
	opts := struct {
		ruleID       string
		overrideType string
		crn          string
		targetRegion string
		reason       string
		comment      string
		details      string
	}{}

	var confirm bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a rule override",
		Example: templates.Examples(`
            # Disable a rule for a specific account/region
            falcon fcs policies overrides create --rule-id <uuid> --type disable --crn <crn> --target-region us-east-1 --reason "Not applicable" --comment "Dev account" --details "{}"
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			params := cloud_policies.NewCreateRuleOverrideParams()
			params.Body = &models.CommonCreateRuleOverrideRequest{
				Overrides: []*models.CommonSingleCreateRuleOverrideRequest{
					{
						RuleID:           &opts.ruleID,
						OverrideType:     &opts.overrideType,
						Crn:              &opts.crn,
						TargetRegion:     &opts.targetRegion,
						Reason:           &opts.reason,
						Comment:          &opts.comment,
						OverridesDetails: &opts.details,
					},
				},
			}

			resp, err := client.CloudPolicies.CreateRuleOverride(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "create rule override")
			}

			if resp.Payload != nil && len(resp.Payload.Resources) > 0 {
				fmt.Fprintf(f.IOStreams.Out, "Created rule override: %s\n", resp.Payload.Resources[0])
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.ruleID, "rule-id", "", "Rule UUID to override (required)")
	cmd.Flags().StringVar(&opts.overrideType, "type", "", "Override type (disable, severity_change) (required)")
	cmd.Flags().StringVar(&opts.crn, "crn", "", "Cloud resource name / account scope (required)")
	cmd.Flags().StringVar(&opts.targetRegion, "target-region", "*", "Target region ('*' for all)")
	cmd.Flags().StringVar(&opts.reason, "reason", "", "Reason for override (required)")
	cmd.Flags().StringVar(&opts.comment, "comment", "", "Comment (required)")
	cmd.Flags().StringVar(&opts.details, "details", "{}", "Override details JSON")
	_ = cmd.MarkFlagRequired("rule-id")
	_ = cmd.MarkFlagRequired("type")
	_ = cmd.MarkFlagRequired("crn")
	_ = cmd.MarkFlagRequired("reason")
	_ = cmd.MarkFlagRequired("comment")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}

func newCmdOverridesDelete(f *factory.Factory) *cobra.Command {
	var ids []string

	var confirm bool
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete rule overrides",
		RunE: func(_ *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			params := cloud_policies.NewDeleteRuleOverrideParams()
			params.Ids = ids

			_, _, err = client.CloudPolicies.DeleteRuleOverride(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "delete rule overrides")
			}

			fmt.Fprintf(f.IOStreams.Out, "Deleted %d rule override(s)\n", len(ids))
			return nil
		},
	}

	cmdutil.AddIDsFlag(cmd, &ids, true)
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}
