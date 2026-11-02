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
	"strconv"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var reportTableDef = &output.TableDefinition{
	Headers: []string{"ID", "NAME", "SLUG"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.DomainNewsDocument)
		if !ok {
			return nil
		}

		id := ""
		if r.ID != nil {
			id = strconv.FormatInt(*r.ID, 10)
		}

		return []string{id, cmdutil.Deref(r.Name), cmdutil.Deref(r.Slug)}
	},
}

// newReportsCmd represents the intel reports command group.
func newReportsCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reports",
		Short: "Query finished intelligence reports",
		Long:  templates.LongDesc(`Query CrowdStrike finished intelligence reports.`),
		Example: templates.Examples(`
            # List intel reports
            falcon intel reports list
        `),
	}

	cmd.AddCommand(newListCmd(
		f,
		"List finished intelligence reports",
		templates.LongDesc(`List CrowdStrike finished intelligence reports.

            Returns full report entities in a single call, so the table shows the
            report ID, name and slug.`),
		templates.Examples(`
            # List all intel reports
            falcon intel reports list

            # Filter by name, as JSON
            falcon intel reports list --filter "name:*'*ransomware*'" --output json
        `),
		reportTableDef,
		func(o *listOptions) ([]*models.DomainNewsDocument, error) {
			falconClient, err := f.FalconClient()
			if err != nil {
				return nil, err
			}
			qp := intel.NewQueryIntelReportEntitiesParams()
			qp.Filter = cmdutil.StringPtr(o.filter)
			qp.Sort = cmdutil.StringPtr(o.sort)
			qp.Limit = &o.limit
			if o.offset > 0 {
				qp.Offset = &o.offset
			}
			resp, err := falconClient.Intel.QueryIntelReportEntities(qp)
			if err != nil {
				return nil, cmdutil.HandleAPIError(err, "QueryIntelReportEntities")
			}
			if resp.Payload == nil {
				return []*models.DomainNewsDocument{}, nil
			}
			return resp.Payload.Resources, nil
		},
	))
	return cmd
}
