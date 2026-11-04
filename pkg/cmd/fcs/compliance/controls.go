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

package compliance

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

// NewCmdControls represents the compliance controls command group.
func NewCmdControls(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "controls",
		Short: "Manage compliance controls",
		Long:  templates.LongDesc(`List, get, create, update, and delete compliance controls within frameworks.`),
	}

	cmd.AddCommand(
		newCmdControlsList(f),
		newCmdControlsGet(f),
		newCmdControlsCreate(f),
		newCmdControlsDelete(f),
	)
	return cmd
}

var controlTableDef = &output.TableDefinition{
	Headers: []string{"CODE", "NAME", "AUTHORITY", "SECTION", "REQUIREMENT", "ORIGIN"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.ApimodelsControl)
		if !ok || r == nil {
			return nil
		}
		return []string{
			str(r.Code),
			str(r.Name),
			str(r.Authority),
			r.SectionName,
			r.Requirement,
			str(r.Origin),
		}
	},
}

func newCmdControlsList(f *factory.Factory) *cobra.Command {
	opts := struct {
		filter string
		limit  int64
		offset int64
		sort   string
		output string
		table  cmdutil.TableFormattingOptions
	}{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List compliance controls",
		Long:  templates.LongDesc(`List compliance controls with optional FQL filtering.`),
		Example: templates.Examples(`
            # List all controls
            falcon fcs compliance controls list

            # Filter by authority
            falcon fcs compliance controls list --filter "compliance_control_authority:'CIS'"
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, err := f.FalconClient()
			if err != nil {
				return err
			}

			params := cloud_policies.NewQueryComplianceControlsParams()
			params.Limit = &opts.limit
			params.Offset = &opts.offset
			if opts.filter != "" {
				params.Filter = &opts.filter
			}
			if opts.sort != "" {
				params.Sort = &opts.sort
			}

			queryResp, err := client.CloudPolicies.QueryComplianceControls(params)
			if err != nil {
				return cmdutil.HandleAPIError(err, "query compliance controls")
			}

			if queryResp.Payload == nil || len(queryResp.Payload.Resources) == 0 {
				printer := output.NewPrinter(output.Format(opts.output), controlTableDef)
				return printer.Print(f.IOStreams.Out, nil)
			}

			getParams := cloud_policies.NewGetComplianceControlsParams()
			getParams.Ids = queryResp.Payload.Resources

			getResp, err := client.CloudPolicies.GetComplianceControls(getParams)
			if err != nil {
				return cmdutil.HandleAPIError(err, "get compliance controls")
			}

			tableOpts := opts.table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.output), controlTableDef, tableOpts)
			return printer.Print(f.IOStreams.Out, getResp.Payload.Resources)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmdutil.AddPaginationFlags(cmd, &opts.limit, &opts.offset, 100)
	cmdutil.AddSortFlag(cmd, &opts.sort)
	cmdutil.AddOutputFlag(cmd, &opts.output)
	cmdutil.AddTableFormattingFlags(cmd, &opts.table)
	return cmd
}

func newCmdControlsGet(f *factory.Factory) *cobra.Command {
	var ids []string
	var out string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get compliance controls by ID",
		RunE: func(_ *cobra.Command, _ []string) error {
			client, err := f.FalconClient()
			if err != nil {
				return err
			}

			params := cloud_policies.NewGetComplianceControlsParams()
			params.Ids = ids

			resp, err := client.CloudPolicies.GetComplianceControls(params)
			if err != nil {
				return cmdutil.HandleAPIError(err, "get compliance controls")
			}

			printer := output.NewPrinter(output.Format(out), controlTableDef)
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

func newCmdControlsCreate(f *factory.Factory) *cobra.Command {
	opts := struct {
		name        string
		description string
		frameworkID string
		sectionName string
	}{}

	var confirm bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a compliance control",
		Example: templates.Examples(`
            # Create a control in a framework
            falcon fcs compliance controls create --name "Encryption at rest" --framework-id <uuid> --section-name "Data Protection"
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			params := cloud_policies.NewCreateComplianceControlParams()
			params.Body = &models.CommonCreateComplianceControlRequest{
				Name:        &opts.name,
				Description: &opts.description,
				FrameworkID: &opts.frameworkID,
				SectionName: &opts.sectionName,
			}

			resp, err := client.CloudPolicies.CreateComplianceControl(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "create compliance control")
			}

			if resp.Payload != nil && len(resp.Payload.Resources) > 0 {
				c := resp.Payload.Resources[0]
				fmt.Fprintf(f.IOStreams.Out, "Created compliance control: %s (%s)\n", str(c.Name), str(c.Code))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.name, "name", "", "Control name (required)")
	cmd.Flags().StringVar(&opts.description, "description", "", "Control description")
	cmd.Flags().StringVar(&opts.frameworkID, "framework-id", "", "Framework UUID (required)")
	cmd.Flags().StringVar(&opts.sectionName, "section-name", "", "Section name (required)")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("framework-id")
	_ = cmd.MarkFlagRequired("section-name")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}

func newCmdControlsDelete(f *factory.Factory) *cobra.Command {
	var ids []string

	var confirm bool
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete compliance controls",
		RunE: func(_ *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			params := cloud_policies.NewDeleteComplianceControlParams()
			params.Ids = ids

			_, err = client.CloudPolicies.DeleteComplianceControl(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "delete compliance controls")
			}

			fmt.Fprintf(f.IOStreams.Out, "Deleted %d compliance control(s)\n", len(ids))
			return nil
		},
	}

	cmdutil.AddIDsFlag(cmd, &ids, true)
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}
