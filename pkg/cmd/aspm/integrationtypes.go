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

var integrationTypesTableDef = &output.TableDefinition{
	Headers: []string{"ID", "NAME", "DISPLAY_NAME", "CONFIGURED", "ENABLED"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.TypesIntegrationType)
		if !ok {
			return nil
		}
		return []string{
			strconv.FormatInt(int64(r.ID), 10),
			r.Name,
			r.DisplayName,
			strconv.FormatBool(r.Configured),
			strconv.FormatBool(r.Enabled),
		}
	},
}

// NewCmdIntegrationTypes represents the aspm integration-types command group.
func NewCmdIntegrationTypes(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "integration-types",
		Aliases: []string{"integration-type"},
		Short:   "ASPM integration types",
		Long:    templates.LongDesc(`Read the integration types available in ASPM.`),
		Example: templates.Examples(`
            # List available integration types
            falcon aspm integration-types list
        `),
	}

	cmd.AddCommand(NewCmdIntegrationTypesList(f))
	return cmd
}

type integrationTypesListOptions struct {
	Factory *factory.Factory
	out     string
	Table   cmdutil.TableFormattingOptions
	Client  cmdutil.ClientFilterOptions
}

// NewCmdIntegrationTypesList lists the ASPM integration types.
func NewCmdIntegrationTypesList(f *factory.Factory) *cobra.Command {
	opts := &integrationTypesListOptions{Factory: f}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List ASPM integration types",
		Long:  templates.LongDesc(`List the integration types available in ASPM, with their numeric IDs (use an ID with "integrations list --integration-type").`),
		Example: templates.Examples(`
            # List integration types
            falcon aspm integration-types list

            # Full detail as JSON
            falcon aspm integration-types list --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := a_s_p_m.NewGetIntegrationTypesParams()
			resp, err := falconClient.Aspm.GetIntegrationTypes(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "GetIntegrationTypes")
			}

			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), integrationTypesTableDef, tableOpts)

			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []*models.TypesIntegrationType{})
			}

			resources := output.FilterAndSort(resp.Payload.Types, integrationTypesTableDef, opts.Client.ToFilterOptions())
			return printer.Print(f.IOStreams.Out, resources)
		},
	}

	cmdutil.AddOutputFlag(cmd, &opts.out)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)
	return cmd
}
