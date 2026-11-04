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
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewCmdRulesDelete represents the fcs policies rules delete command.
func NewCmdRulesDelete(f *factory.Factory) *cobra.Command {
	var ids []string

	var confirm bool
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete policy rules",
		Long:  templates.LongDesc(`Delete one or more Falcon Cloud Security policy rules by UUID.`),
		Example: templates.Examples(`
            # Delete a rule
            falcon fcs policies rules delete --ids <uuid>

            # Delete multiple rules
            falcon fcs policies rules delete --ids <uuid1>,<uuid2>
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			params := cloud_policies.NewDeleteRuleMixin0Params()
			params.Ids = ids

			_, err = client.CloudPolicies.DeleteRuleMixin0(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "delete policy rules")
			}

			fmt.Fprintf(f.IOStreams.Out, "Deleted %d rule(s)\n", len(ids))
			return nil
		},
	}

	cmdutil.AddIDsFlag(cmd, &ids, true)
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}
