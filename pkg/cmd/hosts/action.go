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

package hosts

import (
	"fmt"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

type actionOptions struct {
	Factory *factory.Factory
	ids     []string
	confirm bool
	out     string
}

// NewCmdAction builds a confirm-gated host action command (contain, lift, hide, unhide).
// actionName is the Falcon device-action name sent to PerformActionV2.
func NewCmdAction(f *factory.Factory, use, short, actionName string) *cobra.Command {
	opts := &actionOptions{Factory: f}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long: templates.LongDesc(fmt.Sprintf(`%s.

            This is a mutating action. Without --confirm the command prints the
            request it would send and exits without calling the API.`, short)),
		Example: templates.Examples(fmt.Sprintf(`
            # Dry run (prints the plan, calls nothing)
            falcon hosts %s --ids <aid>

            # Execute
            falcon hosts %s --ids <aid> --confirm
        `, use, use)),
		RunE: func(_ *cobra.Command, _ []string) error {
			if !opts.confirm {
				return cmdutil.PrintDryRun(f.IOStreams.Out, cmdutil.DryRunPlan{
					Action: actionName,
					Method: "POST",
					Path:   "/devices/entities/devices-actions/v2",
					IDs:    opts.ids,
				})
			}

			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := hosts.NewPerformActionV2Params()
			p.ActionName = actionName
			p.Body = &models.MsaEntityActionRequestV2{Ids: opts.ids}

			resp, err := falconClient.Hosts.PerformActionV2(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "PerformActionV2")
			}

			printer := output.NewPrinter(output.Format(opts.out), nil)
			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []*models.MsaAffectedEntity{})
			}
			return printer.Print(f.IOStreams.Out, resp.Payload.Resources)
		},
	}

	cmdutil.AddIDsFlag(cmd, &opts.ids, true)
	cmdutil.AddConfirmFlag(cmd, &opts.confirm)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	return cmd
}
