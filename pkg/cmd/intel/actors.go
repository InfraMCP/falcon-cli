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

		return []string{
			id,
			r.Name,
			r.Slug,
			lastActivity,
		}
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

	cmd.AddCommand(newActorsListCmd(f))
	return cmd
}

type actorsListOptions struct {
	Factory *factory.Factory
	filter  string
	sort    string
	limit   int64
	offset  int64
	out     string
	Table   cmdutil.TableFormattingOptions
	Client  cmdutil.ClientFilterOptions
}

// newActorsListCmd lists intel actors matching an optional FQL filter.
func newActorsListCmd(f *factory.Factory) *cobra.Command {
	opts := &actorsListOptions{Factory: f, limit: 100}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List intel actors (adversaries)",
		Long: templates.LongDesc(`List CrowdStrike threat intelligence actors (adversaries).

            Returns full actor entities in a single call, so the table shows the
            actor ID, name, slug and last-activity date.`),
		Example: templates.Examples(`
            # List all intel actors
            falcon intel actors list

            # Filter by name, as JSON
            falcon intel actors list --filter "name:*'*PANDA*'" --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			qp := intel.NewQueryIntelActorEntitiesParams()
			qp.Filter = cmdutil.StringPtr(opts.filter)
			qp.Sort = cmdutil.StringPtr(opts.sort)
			qp.Limit = &opts.limit
			if opts.offset > 0 {
				qp.Offset = &opts.offset
			}

			resp, err := falconClient.Intel.QueryIntelActorEntities(qp)
			if err != nil {
				return cmdutil.HandleAPIError(err, "QueryIntelActorEntities")
			}

			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), actorTableDef, tableOpts)

			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []*models.ActorActorDocument{})
			}
			resources := output.FilterAndSort(resp.Payload.Resources, actorTableDef, opts.Client.ToFilterOptions())
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
