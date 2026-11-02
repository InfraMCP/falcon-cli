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
	"fmt"
	"strconv"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/alerts"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var aggregateTableDef = &output.TableDefinition{
	Headers: []string{"KEY", "COUNT"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.DetectsapiAggregationResultItem)
		if !ok {
			return nil
		}

		key := ""
		if r.Label != nil {
			key = fmt.Sprintf("%v", r.Label)
		}

		count := ""
		if r.Count != nil {
			count = strconv.FormatInt(*r.Count, 10)
		}

		return []string{key, count}
	},
}

type aggregateOptions struct {
	Factory *factory.Factory
	field   string
	filter  string
	size    int32
	out     string
	Table   cmdutil.TableFormattingOptions
	Client  cmdutil.ClientFilterOptions
}

// NewCmdAggregate returns aggregate (term-bucket) counts of alerts by a field.
func NewCmdAggregate(f *factory.Factory) *cobra.Command {
	opts := &aggregateOptions{Factory: f, size: 10}

	cmd := &cobra.Command{
		Use:   "aggregate",
		Short: "Aggregate detection (alert) counts by a field",
		Long: templates.LongDesc(`Aggregate detections (alerts) into term buckets for a single field.

            Returns the per-value document counts for the chosen field (for
            example status, severity_name, tactic or technique), optionally
            scoped by an FQL filter.`),
		Example: templates.Examples(`
            # Count alerts by status
            falcon detections aggregate --field status

            # Top 20 tactics among high-severity alerts
            falcon detections aggregate --field tactic --filter "severity:>=70" --size 20
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			size := opts.size
			req := &models.DetectsapiAggregateAlertQueryRequest{
				Name:   cmdutil.StringPtr("detections"),
				Type:   cmdutil.StringPtr("terms"),
				Field:  cmdutil.StringPtr(opts.field),
				Filter: cmdutil.StringPtr(opts.filter),
				Size:   &size,
			}

			p := alerts.NewGetAggregateV2Params()
			p.Body = []*models.DetectsapiAggregateAlertQueryRequest{req}

			resp, err := falconClient.Alerts.GetAggregateV2(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "GetAggregateV2")
			}

			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), aggregateTableDef, tableOpts)

			buckets := []*models.DetectsapiAggregationResultItem{}
			if resp.Payload != nil {
				for _, result := range resp.Payload.Resources {
					if result != nil {
						buckets = append(buckets, result.Buckets...)
					}
				}
			}
			if len(buckets) == 0 {
				return printer.Print(f.IOStreams.Out, []*models.DetectsapiAggregationResultItem{})
			}
			resources := output.FilterAndSort(buckets, aggregateTableDef, opts.Client.ToFilterOptions())
			return printer.Print(f.IOStreams.Out, resources)
		},
	}

	cmd.Flags().StringVar(&opts.field, "field", "status", "Field to aggregate on (e.g. status, severity_name, tactic, technique)")
	cmd.Flags().Int32Var(&opts.size, "size", 10, "Maximum number of term buckets to return")
	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)
	return cmd
}
