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
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

type createOptions struct {
	Factory     *factory.Factory
	value       string
	iocType     string
	action      string
	severity    string
	platforms   []string
	description string
	confirm     bool
	out         string
}

// NewCmdCreate creates a custom IOC. It is confirm-gated: without --confirm it
// prints the request it would send and exits without calling the API.
func NewCmdCreate(f *factory.Factory) *cobra.Command {
	opts := &createOptions{Factory: f}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a custom IOC",
		Long: templates.LongDesc(`Create a custom indicator of compromise (IOC).

            This is a mutating action. Without --confirm the command prints the
            request it would send and exits without calling the API.`),
		Example: templates.Examples(`
            # Dry run (prints the plan, calls nothing)
            falcon ioc create --value evil.example.com --type domain --action detect --severity high

            # Execute
            falcon ioc create --value evil.example.com --type domain --action detect --severity high --platforms windows,linux --confirm
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			indicator := &models.APIIndicatorCreateReqV1{
				Value:       opts.value,
				Type:        opts.iocType,
				Action:      opts.action,
				Severity:    opts.severity,
				Platforms:   opts.platforms,
				Description: opts.description,
			}

			if !opts.confirm {
				return cmdutil.PrintDryRun(f.IOStreams.Out, cmdutil.DryRunPlan{
					Action: "create",
					Method: "POST",
					Path:   "/iocs/entities/indicators/v1",
					Body:   &models.APIIndicatorCreateReqsV1{Indicators: []*models.APIIndicatorCreateReqV1{indicator}},
				})
			}

			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := ioc.NewIndicatorCreateV1Params()
			p.Body = &models.APIIndicatorCreateReqsV1{Indicators: []*models.APIIndicatorCreateReqV1{indicator}}

			resp, err := falconClient.Ioc.IndicatorCreateV1(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "IndicatorCreateV1")
			}

			tableOpts := opts.out
			printer := output.NewPrinter(output.Format(tableOpts), iocTableDef)
			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []*models.APIIndicatorV1{})
			}
			return printer.Print(f.IOStreams.Out, resp.Payload.Resources)
		},
	}

	cmd.Flags().StringVar(&opts.value, "value", "", "Indicator value (e.g. a domain, hash, or IP) (required)")
	cmd.Flags().StringVar(&opts.iocType, "type", "", "Indicator type (e.g. domain, ipv4, ipv6, md5, sha256) (required)")
	cmd.Flags().StringVar(&opts.action, "action", "", "Action to take on a match (e.g. detect, prevent, no_action) (required)")
	cmd.Flags().StringVar(&opts.severity, "severity", "", "Severity (e.g. informational, low, medium, high, critical)")
	cmd.Flags().StringSliceVar(&opts.platforms, "platforms", nil, "Target platforms (e.g. windows,mac,linux)")
	cmd.Flags().StringVar(&opts.description, "description", "", "Free-text description of the IOC")
	_ = cmd.MarkFlagRequired("value")
	_ = cmd.MarkFlagRequired("type")
	_ = cmd.MarkFlagRequired("action")
	cmdutil.AddConfirmFlag(cmd, &opts.confirm)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	return cmd
}
