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

package aspm

import (
	"strconv"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/a_s_p_m"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var integrationsTableDef = &output.TableDefinition{
	Headers: []string{"ID", "NAME", "TYPE", "ENABLED"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.TypesListIntegrationItem)
		if !ok {
			return nil
		}
		typeName := ""
		if r.IntegrationType != nil {
			typeName = r.IntegrationType.DisplayName
			if typeName == "" {
				typeName = r.IntegrationType.Name
			}
		}
		return []string{
			strconv.FormatInt(r.ID, 10),
			r.Name,
			typeName,
			strconv.FormatBool(r.Enabled),
		}
	},
}

// NewCmdIntegrations represents the aspm integrations command group.
func NewCmdIntegrations(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "integrations",
		Short: "ASPM integrations",
		Long:  templates.LongDesc(`Read the integrations configured in ASPM.`),
		Example: templates.Examples(`
            # List configured integrations
            falcon aspm integrations list
        `),
	}

	cmd.AddCommand(NewCmdIntegrationsList(f))
	return cmd
}

type integrationsListOptions struct {
	Factory         *factory.Factory
	category        string
	integrationType int64
	out             string
	Table           cmdutil.TableFormattingOptions
	Client          cmdutil.ClientFilterOptions
}

// NewCmdIntegrationsList lists configured ASPM integrations.
func NewCmdIntegrationsList(f *factory.Factory) *cobra.Command {
	opts := &integrationsListOptions{Factory: f}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List configured ASPM integrations",
		Long:  templates.LongDesc(`List the integrations configured in ASPM, optionally filtered by category or integration type ID.`),
		Example: templates.Examples(`
            # All integrations
            falcon aspm integrations list

            # Only one integration type (by numeric type ID)
            falcon aspm integrations list --integration-type 3

            # Full detail as JSON
            falcon aspm integrations list --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := a_s_p_m.NewGetIntegrationsParams()
			if opts.category != "" {
				p.Category = cmdutil.StringPtr(opts.category)
			}
			if opts.integrationType > 0 {
				p.IntegrationType = cmdutil.Int64Ptr(opts.integrationType)
			}

			resp, err := falconClient.Aspm.GetIntegrations(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "GetIntegrations")
			}

			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), integrationsTableDef, tableOpts)

			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []*models.TypesListIntegrationItem{})
			}

			resources := output.FilterAndSort(resp.Payload.Integrations, integrationsTableDef, opts.Client.ToFilterOptions())
			return printer.Print(f.IOStreams.Out, resources)
		},
	}

	cmd.Flags().StringVar(&opts.category, "category", "", "Filter by integration category")
	cmd.Flags().Int64Var(&opts.integrationType, "integration-type", 0, "Filter by numeric integration type ID")
	cmdutil.AddOutputFlag(cmd, &opts.out)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)
	return cmd
}
