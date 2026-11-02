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

var actorTableDef = &output.TableDefinition{
	Headers: []string{"ID", "NAME", "SLUG", "LAST_ACTIVITY"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.ActorActorDocument)
		if !ok {
			return nil
		}

		id := ""
		if r.ID != nil {
			id = strconv.FormatInt(*r.ID, 10)
		}

		lastActivity := ""
		if r.LastActivityDate != nil {
			lastActivity = strconv.FormatInt(*r.LastActivityDate, 10)
		}

		return []string{id, r.Name, r.Slug, lastActivity}
	},
}

// newActorsCmd represents the intel actors command group.
func newActorsCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "actors",
		Short: "Query intel actors (adversaries)",
		Long:  templates.LongDesc(`Query CrowdStrike threat intelligence actors (adversaries).`),
		Example: templates.Examples(`
            # List intel actors
            falcon intel actors list
        `),
	}

	cmd.AddCommand(newListCmd(
		f,
		"List intel actors (adversaries)",
		templates.LongDesc(`List CrowdStrike threat intelligence actors (adversaries).

            Returns full actor entities in a single call, so the table shows the
            actor ID, name, slug and last-activity date.`),
		templates.Examples(`
            # List all intel actors
            falcon intel actors list

            # Filter by name, as JSON
            falcon intel actors list --filter "name:*'*PANDA*'" --output json
        `),
		actorTableDef,
		func(o *listOptions) ([]*models.ActorActorDocument, error) {
			falconClient, err := f.FalconClient()
			if err != nil {
				return nil, err
			}
			qp := intel.NewQueryIntelActorEntitiesParams()
			qp.Filter = cmdutil.StringPtr(o.filter)
			qp.Sort = cmdutil.StringPtr(o.sort)
			qp.Limit = &o.limit
			if o.offset > 0 {
				qp.Offset = &o.offset
			}
			resp, err := falconClient.Intel.QueryIntelActorEntities(qp)
			if err != nil {
				return nil, cmdutil.HandleAPIError(err, "QueryIntelActorEntities")
			}
			if resp.Payload == nil {
				return []*models.ActorActorDocument{}, nil
			}
			return resp.Payload.Resources, nil
		},
	))
	return cmd
}
