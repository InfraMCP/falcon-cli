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

package cloudgroups

import (
	"strings"

	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewCloudGroupsCmd represents the `fcs cloud-groups` command group.
//
// It ports the standalone falcon-cloudgroups.py helper into falcon-cli: full
// CRUD over Falcon Cloud Security Cloud Groups, including the richer group body
// (business context, owners, and cloud-resource selectors) that the Falcon MCP
// read-only tools do not cover. Writes (create/update/delete) are gated behind
// --confirm; without it each command prints the request it would send.
func NewCloudGroupsCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "cloud-groups",
		Aliases: []string{"cloudgroups"},
		Short:   "Manage cloud groups (full CRUD with selectors)",
		Long: templates.LongDesc(`List, get, create, update, and delete Falcon Cloud Security Cloud Groups.

            Unlike the read-only Cloud Groups tools in the Falcon MCP server, this
            command group can also create, update, and delete groups, and set the
            full group body: business context (environment, business unit,
            business impact), owners, and cloud-resource selectors (provider,
            account IDs, region and tag filters).

            Mutating commands are gated behind --confirm. Without it they print the
            request body they would send and exit without calling the API.`),
		Example: templates.Examples(`
            # List all cloud groups
            falcon fcs cloud-groups list

            # Filter by environment
            falcon fcs cloud-groups list --filter "environment:'prod'"

            # Get specific cloud groups
            falcon fcs cloud-groups get --ids <uuid>

            # Create an AWS cloud group (dry-run, then for real)
            falcon fcs cloud-groups create --name "All Prod" --environment prod \
                --business-impact high --business-unit CSS \
                --owner a@example.com --account 111111111111 --account 222222222222
            falcon fcs cloud-groups create ... --confirm

            # Create from a JSON file holding the full group body
            falcon fcs cloud-groups create --from-json group.json --confirm

            # Delete cloud groups
            falcon fcs cloud-groups delete --ids <uuid> --confirm
        `),
	}

	cmd.AddCommand(
		NewCmdList(f),
		NewCmdGet(f),
		NewCmdCreate(f),
		NewCmdUpdate(f),
		NewCmdDelete(f),
	)
	return cmd
}

// cloudGroupTableDef renders a cloud group as a table row. It surfaces the
// business-context fields and a compact summary of the cloud-resource selectors
// so `list`/`get` are useful without dropping to JSON.
var cloudGroupTableDef = &output.TableDefinition{
	Headers: []string{"ID", "NAME", "ENVIRONMENT", "BUSINESS_UNIT", "BUSINESS_IMPACT", "OWNERS", "SELECTORS"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.AssetgroupmanagerV1CloudGroup)
		if !ok {
			return nil
		}
		return []string{
			r.ID,
			r.Name,
			r.Environment,
			r.BusinessUnit,
			r.BusinessImpact,
			strings.Join(r.Owners, ","),
			selectorSummary(r.Selectors),
		}
	},
}

// selectorSummary produces a short "provider:N accounts" style description of a
// group's cloud-resource selectors for the table view. The full structure is
// available via `--output json`.
func selectorSummary(sel *models.AssetgroupmanagerV1CloudGroupSelectors) string {
	if sel == nil || len(sel.CloudResources) == 0 {
		return ""
	}
	parts := make([]string, 0, len(sel.CloudResources))
	for _, cr := range sel.CloudResources {
		if cr == nil {
			continue
		}
		provider := ""
		if cr.CloudProvider != nil {
			provider = *cr.CloudProvider
		}
		parts = append(parts, provider+":"+itoa(len(cr.AccountIds))+" accts")
	}
	return strings.Join(parts, " ")
}
