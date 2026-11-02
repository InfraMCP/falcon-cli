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

package intel

import (
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var indicatorTableDef = &output.TableDefinition{
	Headers: []string{"ID", "INDICATOR", "TYPE"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.DomainPublicIndicatorV3)
		if !ok {
			return nil
		}
		return []string{
			cmdutil.Deref(r.ID),
			cmdutil.Deref(r.Indicator),
			cmdutil.Deref(r.Type),
		}
	},
}

// newIndicatorsCmd represents the intel indicators command group.
func newIndicatorsCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "indicators",
		Short: "Query intel indicators of compromise",
		Long:  templates.LongDesc(`Query CrowdStrike threat intelligence indicators of compromise (IOCs).`),
		Example: templates.Examples(`
            # List intel indicators
            falcon intel indicators list
        `),
	}

	cmd.AddCommand(newListCmd(
		f,
		"List intel indicators of compromise (IOCs)",
		templates.LongDesc(`List CrowdStrike threat intelligence indicators of compromise.

            Returns full indicator entities in a single call, so the table shows
            the indicator ID, value and type.`),
		templates.Examples(`
            # List all intel indicators
            falcon intel indicators list

            # Domain indicators only, as JSON
            falcon intel indicators list --filter "type:'domain'" --output json
        `),
		indicatorTableDef,
		func(o *listOptions) ([]*models.DomainPublicIndicatorV3, error) {
			falconClient, err := f.FalconClient()
			if err != nil {
				return nil, err
			}
			qp := intel.NewQueryIntelIndicatorEntitiesParams()
			qp.Filter = cmdutil.StringPtr(o.filter)
			qp.Sort = cmdutil.StringPtr(o.sort)
			qp.Limit = &o.limit
			if o.offset > 0 {
				qp.Offset = &o.offset
			}
			resp, err := falconClient.Intel.QueryIntelIndicatorEntities(qp)
			if err != nil {
				return nil, cmdutil.HandleAPIError(err, "QueryIntelIndicatorEntities")
			}
			if resp.Payload == nil {
				return []*models.DomainPublicIndicatorV3{}, nil
			}
			return resp.Payload.Resources, nil
		},
	))
	return cmd
}
