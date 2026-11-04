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

package detections

import (
	"strconv"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/alerts"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var detectionTableDef = &output.TableDefinition{
	Headers: []string{"ID", "SEVERITY", "STATUS", "TACTIC", "TECHNIQUE", "TIMESTAMP", "HOSTNAME"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.DetectsAlert)
		if !ok {
			return nil
		}

		severity := ""
		if r.Severity != nil {
			severity = strconv.FormatInt(*r.Severity, 10)
		}
		if r.SeverityName != nil && *r.SeverityName != "" {
			severity = *r.SeverityName
		}

		timestamp := ""
		if r.Timestamp != nil {
			timestamp = r.Timestamp.String()
		}

		hostname := ""
		if r.Device != nil {
			hostname = r.Device.Hostname
		}

		return []string{
			cmdutil.Deref(r.CompositeID),
			severity,
			cmdutil.Deref(r.Status),
			cmdutil.Deref(r.Tactic),
			cmdutil.Deref(r.Technique),
			timestamp,
			hostname,
		}
	},
}

type listOptions struct {
	Factory *factory.Factory
	filter  string
	sort    string
	limit   int64
	offset  int64
	out     string
	Table   cmdutil.TableFormattingOptions
	Client  cmdutil.ClientFilterOptions
}

// NewCmdList lists detections (alerts) matching an optional FQL filter.
func NewCmdList(f *factory.Factory) *cobra.Command {
	opts := &listOptions{Factory: f, limit: 100}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List detections (alerts)",
		Long: templates.LongDesc(`List detections (alerts) in your Falcon tenant.

            Resolves matching alert composite IDs via FQL, then fetches full
            detail for the page so the table shows severity, status and the
            MITRE ATT&CK tactic/technique.`),
		Example: templates.Examples(`
            # List recent alerts
            falcon detections list

            # High-severity new alerts only
            falcon detections list --filter "severity:>=70+status:'new'"

            # Alerts created before a date, as JSON
            falcon detections list --filter "created_timestamp:<'2026-10-01'" --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			qp := alerts.NewQueryV2Params()
			qp.Filter = cmdutil.StringPtr(opts.filter)
			qp.Sort = cmdutil.StringPtr(opts.sort)
			qp.Limit = &opts.limit
			if opts.offset > 0 {
				qp.Offset = &opts.offset
			}

			qResp, err := falconClient.Alerts.QueryV2(qp)
			if err != nil {
				return cmdutil.HandleAPIError(err, "QueryV2")
			}

			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), detectionTableDef, tableOpts)

			ids := []string{}
			if qResp.Payload != nil {
				ids = qResp.Payload.Resources
			}
			if len(ids) == 0 {
				return printer.Print(f.IOStreams.Out, []*models.DetectsAlert{})
			}

			dp := alerts.NewPostEntitiesAlertsV1Params()
			dp.Body = &models.DetectsapiPostEntitiesAlertsV1Request{Ids: ids}
			dResp, err := falconClient.Alerts.PostEntitiesAlertsV1(dp) //nolint:staticcheck // deprecated in gofalcon v0.24.0; migrate separately
			if err != nil {
				return cmdutil.HandleAPIError(err, "PostEntitiesAlertsV1")
			}

			if dResp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []*models.DetectsAlert{})
			}
			resources := output.FilterAndSort(dResp.Payload.Resources, detectionTableDef, opts.Client.ToFilterOptions())
			return printer.Print(f.IOStreams.Out, resources)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmdutil.AddSortFlag(cmd, &opts.sort)
	cmdutil.AddPaginationFlags(cmd, &opts.limit, &opts.offset, 100)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)
	return cmd
}
