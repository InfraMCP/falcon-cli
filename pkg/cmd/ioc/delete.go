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

package ioc

import (
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/ioc"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

type deleteOptions struct {
	Factory *factory.Factory
	ids     []string
	comment string
	confirm bool
	out     string
}

// NewCmdDelete deletes custom IOCs by ID. It is confirm-gated: without --confirm
// it prints the request it would send and exits without calling the API.
func NewCmdDelete(f *factory.Factory) *cobra.Command {
	opts := &deleteOptions{Factory: f}

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete custom IOCs by ID",
		Long: templates.LongDesc(`Delete one or more custom indicators of compromise (IOCs) by ID.

            This is a mutating action. Without --confirm the command prints the
            request it would send and exits without calling the API.`),
		Example: templates.Examples(`
            # Dry run (prints the plan, calls nothing)
            falcon ioc delete --ids <id1>,<id2>

            # Execute
            falcon ioc delete --ids <id1>,<id2> --confirm
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			if !opts.confirm {
				return cmdutil.PrintDryRun(f.IOStreams.Out, cmdutil.DryRunPlan{
					Action: "delete",
					Method: "DELETE",
					Path:   "/iocs/entities/indicators/v1",
					IDs:    opts.ids,
				})
			}

			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := ioc.NewIndicatorDeleteV1Params()
			p.Ids = opts.ids
			if opts.comment != "" {
				p.Comment = cmdutil.StringPtr(opts.comment)
			}

			resp, err := falconClient.Ioc.IndicatorDeleteV1(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "IndicatorDeleteV1")
			}

			printer := output.NewPrinter(output.Format(opts.out), nil)
			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []string{})
			}
			return printer.Print(f.IOStreams.Out, resp.Payload.Resources)
		},
	}

	cmdutil.AddIDsFlag(cmd, &opts.ids, true)
	cmd.Flags().StringVar(&opts.comment, "comment", "", "Audit-log comment recorded with the deletion")
	cmdutil.AddConfirmFlag(cmd, &opts.confirm)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	return cmd
}
