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

package imageassessment

import (
	"fmt"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/image_assessment_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewImageAssessmentCmd represents the fcs image-assessment command group.
func NewImageAssessmentCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "image-assessment",
		Short: "Manage image assessment policies",
		Long: templates.LongDesc(`
            Manage container image assessment policies.
            Policies define how container images are scanned and evaluated for security issues.`),
	}

	cmd.AddCommand(
		newCmdPoliciesList(f),
		newCmdPoliciesCreate(f),
		newCmdPoliciesUpdate(f),
		newCmdPoliciesDelete(f),
	)
	return cmd
}

var policyTableDef = &output.TableDefinition{
	Headers: []string{"ID", "NAME", "DESCRIPTION", "ENABLED", "PRECEDENCE", "UPDATED"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.ModelsAPIPolicyEntity)
		if !ok || r == nil {
			return nil
		}
		enabled := "false"
		if r.IsEnabled != nil && *r.IsEnabled {
			enabled = "true"
		}
		precedence := ""
		if r.Precedence != nil {
			precedence = fmt.Sprintf("%d", *r.Precedence)
		}
		return []string{
			deref(r.PolicyID),
			deref(r.Name),
			deref(r.Description),
			enabled,
			precedence,
			deref(r.UpdatedAt),
		}
	},
}

func newCmdPoliciesList(f *factory.Factory) *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List image assessment policies",
		Long:  templates.LongDesc(`List all container image assessment policies.`),
		Example: templates.Examples(`
            # List all image assessment policies
            falcon fcs image-assessment list

            # Output as JSON
            falcon fcs image-assessment list --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, err := f.FalconClient()
			if err != nil {
				return err
			}

			params := image_assessment_policies.NewReadPoliciesParams()
			resp, err := client.ImageAssessmentPolicies.ReadPolicies(params)
			if err != nil {
				return cmdutil.HandleAPIError(err, "list image assessment policies")
			}

			printer := output.NewPrinter(output.Format(out), policyTableDef)
			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, nil)
			}
			return printer.Print(f.IOStreams.Out, resp.Payload.Resources)
		},
	}

	cmdutil.AddOutputFlag(cmd, &out)
	return cmd
}

func newCmdPoliciesCreate(f *factory.Factory) *cobra.Command {
	opts := struct {
		name        string
		description string
	}{}

	var confirm bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an image assessment policy",
		Example: templates.Examples(`
            # Create a new policy
            falcon fcs image-assessment create --name "Production Images" --description "Policy for prod"
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			params := image_assessment_policies.NewCreatePoliciesParams()
			params.Body = &models.ModelsCreatePolicyRequest{
				Name:        &opts.name,
				Description: opts.description,
			}

			resp, err := client.ImageAssessmentPolicies.CreatePolicies(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "create image assessment policy")
			}

			if resp.Payload != nil && len(resp.Payload.Resources) > 0 {
				p := resp.Payload.Resources[0]
				fmt.Fprintf(f.IOStreams.Out, "Created image assessment policy: %s (%s)\n", deref(p.Name), deref(p.PolicyID))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.name, "name", "", "Policy name (required)")
	cmd.Flags().StringVar(&opts.description, "description", "", "Policy description")
	_ = cmd.MarkFlagRequired("name")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}

func newCmdPoliciesUpdate(f *factory.Factory) *cobra.Command {
	opts := struct {
		id          string
		name        string
		description string
		enabled     bool
	}{}

	var confirm bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update an image assessment policy",
		Example: templates.Examples(`
            # Enable a policy
            falcon fcs image-assessment update --id <uuid> --enabled true

            # Rename a policy
            falcon fcs image-assessment update --id <uuid> --name "New Name"
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			params := image_assessment_policies.NewUpdatePoliciesParams()
			params.ID = opts.id
			params.Body = &models.ModelsPatchPolicyRequest{
				Name:        &opts.name,
				Description: &opts.description,
				IsEnabled:   &opts.enabled,
			}

			resp, err := client.ImageAssessmentPolicies.UpdatePolicies(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "update image assessment policy")
			}

			if resp.Payload != nil && len(resp.Payload.Resources) > 0 {
				p := resp.Payload.Resources[0]
				fmt.Fprintf(f.IOStreams.Out, "Updated image assessment policy: %s (%s)\n", deref(p.Name), deref(p.PolicyID))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.id, "id", "", "Policy UUID (required)")
	cmd.Flags().StringVar(&opts.name, "name", "", "Policy name")
	cmd.Flags().StringVar(&opts.description, "description", "", "Policy description")
	cmd.Flags().BoolVar(&opts.enabled, "enabled", true, "Whether the policy is enabled")
	_ = cmd.MarkFlagRequired("id")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}

func newCmdPoliciesDelete(f *factory.Factory) *cobra.Command {
	var id string

	var confirm bool
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete an image assessment policy",
		RunE: func(_ *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			params := image_assessment_policies.NewDeletePolicyParams()
			params.ID = id

			_, err = client.ImageAssessmentPolicies.DeletePolicy(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "delete image assessment policy")
			}

			fmt.Fprintf(f.IOStreams.Out, "Deleted image assessment policy: %s\n", id)
			return nil
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "Policy UUID to delete (required)")
	_ = cmd.MarkFlagRequired("id")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
