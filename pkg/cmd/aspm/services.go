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
	"encoding/json"
	"fmt"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/client/a_s_p_m"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewCmdServices represents the aspm services command group.
func NewCmdServices(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "services",
		Short: "ASPM services",
		Long:  templates.LongDesc(`Read ASPM service data: the violation-type taxonomy.`),
		Example: templates.Examples(`
            # The violation categories and types ASPM can report
            falcon aspm services violation-types
        `),
	}

	cmd.AddCommand(NewCmdServicesViolationTypes(f))
	return cmd
}

// NewCmdServicesViolationTypes prints the ASPM violation taxonomy.
func NewCmdServicesViolationTypes(f *factory.Factory) *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:     "violation-types",
		Aliases: []string{"violations"},
		Short:   "List ASPM violation categories and types",
		Long:    templates.LongDesc(`List the violation categories and violation types ASPM can report on services.`),
		Example: templates.Examples(`
            falcon aspm services violation-types
            falcon aspm services violation-types --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := a_s_p_m.NewGetServiceViolationTypesParams()
			resp, err := falconClient.Aspm.GetServiceViolationTypes(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "GetServiceViolationTypes")
			}

			var categories, violations []string
			if resp.Payload != nil {
				categories = resp.Payload.Categories
				violations = resp.Payload.Violations
			}

			if out == "json" {
				enc := json.NewEncoder(f.IOStreams.Out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string][]string{
					"categories": categories,
					"violations": violations,
				})
			}

			w := f.IOStreams.Out
			fmt.Fprintln(w, "Categories:")
			for _, c := range categories {
				fmt.Fprintf(w, "  %s\n", c)
			}
			fmt.Fprintln(w, "Violations:")
			for _, v := range violations {
				fmt.Fprintf(w, "  %s\n", v)
			}
			return nil
		},
	}

	cmdutil.AddOutputFlag(cmd, &out)
	return cmd
}
