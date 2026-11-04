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

package codesecurity

import (
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	scmint "github.com/crowdstrike/gofalcon/falcon/client/code_security_scm_integration"
	scminv "github.com/crowdstrike/gofalcon/falcon/client/code_security_scm_inventory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// Preferred table columns, most useful first. Keys absent from a response are
// skipped, so these are hints, not a schema.
var (
	connCols      = []string{"uuid", "id", "name", "provider", "status", "organization", "repository_count", "last_synced_at", "created_at"}
	repoCols      = []string{"id", "name", "full_name", "provider", "visibility", "default_branch", "language", "connection_id", "updated_at"}
	branchCols    = []string{"name", "is_default", "commit", "protected", "updated_at"}
	exclusionCols = []string{"id", "pattern", "type", "description", "connection_id", "created_at"}
	branchCfgCols = []string{"id", "source", "connection_id", "repository_id", "mode", "branches", "patterns", "updated_at"}
	pullJobCols   = []string{"id", "status", "repository_id", "created_at", "completed_at"}
	aggCols       = []string{"value", "count"}
)

func newCmdConnections(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "connections",
		Aliases: []string{"connection", "conn"},
		Short:   "SCM connections",
		Long:    templates.LongDesc(`Read the source-code-management connections configured in Code Security.`),
	}

	{
		var provider string
		l := &listFlags{}
		list := &cobra.Command{
			Use:   "list",
			Short: "List SCM connections",
			Example: templates.Examples(`
                falcon code-security connections list
                falcon code-security connections list --provider github --output json
            `),
			RunE: func(_ *cobra.Command, _ []string) error {
				c, err := f.FalconClient()
				if err != nil {
					return err
				}
				p := scmint.NewListSCMConnectionsParams()
				p.Provider = cmdutil.StringPtr(provider)
				var body []byte
				if _, err := c.CodeSecurityScmIntegration.ListSCMConnections(p, cmdutil.CaptureBody(&body)); err != nil {
					return cmdutil.HandleAPIError(err, "ListSCMConnections")
				}
				return printRaw(f, l, body, connCols)
			},
		}
		list.Flags().StringVar(&provider, "provider", "", "Only connections for this SCM provider (e.g. github)")
		l.add(list)
		cmd.AddCommand(list)
	}

	{
		var id string
		l := &listFlags{}
		get := &cobra.Command{
			Use:     "get",
			Short:   "Get one SCM connection by UUID",
			Example: `  falcon code-security connections get --uuid <uuid> --output json`,
			RunE: func(_ *cobra.Command, _ []string) error {
				c, err := f.FalconClient()
				if err != nil {
					return err
				}
				p := scmint.NewGetSCMConnectionParams()
				p.UUID = id
				var body []byte
				if _, err := c.CodeSecurityScmIntegration.GetSCMConnection(p, cmdutil.CaptureBody(&body)); err != nil {
					return cmdutil.HandleAPIError(err, "GetSCMConnection")
				}
				return printRaw(f, l, body, connCols)
			},
		}
		get.Flags().StringVar(&id, "uuid", "", "Connection UUID (required)")
		_ = get.MarkFlagRequired("uuid")
		l.add(get)
		cmd.AddCommand(get)
	}
	return cmd
}

func newCmdRepositories(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "repositories",
		Aliases: []string{"repos", "repo"},
		Short:   "Repositories discovered through SCM connections",
	}

	{
		var filter, sort string
		var limit, offset int64
		l := &listFlags{}
		list := &cobra.Command{
			Use:   "list",
			Short: "List discovered repositories",
			Long: templates.LongDesc(`List the repositories Code Security discovered through your SCM connections.

                --sort takes "field.direction" (e.g. name.asc, created_date.desc).`),
			Example: templates.Examples(`
                falcon code-security repositories list --limit 50
                falcon code-security repos list --sort name.asc --output json
            `),
			RunE: func(_ *cobra.Command, _ []string) error {
				c, err := f.FalconClient()
				if err != nil {
					return err
				}
				p := scminv.NewListSCMRepositoriesParams()
				p.Filter = cmdutil.StringPtr(filter)
				p.Sort = cmdutil.StringPtr(sort)
				p.Limit = cmdutil.Int64Ptr(limit)
				if offset > 0 {
					p.Offset = cmdutil.Int64Ptr(offset)
				}
				var body []byte
				if _, err := c.CodeSecurityScmInventory.ListSCMRepositories(p, cmdutil.CaptureBody(&body)); err != nil {
					return cmdutil.HandleAPIError(err, "ListSCMRepositories")
				}
				return printRaw(f, l, body, repoCols)
			},
		}
		cmdutil.AddFilterFlag(list, &filter)
		list.Flags().StringVar(&sort, "sort", "", `Sort as "field.direction" (e.g. name.asc)`)
		cmdutil.AddPaginationFlags(list, &limit, &offset, 100)
		l.add(list)
		cmd.AddCommand(list)
	}

	{
		var repoID string
		l := &listFlags{}
		br := &cobra.Command{
			Use:     "branches",
			Short:   "List the branches of one repository",
			Example: `  falcon code-security repositories branches --repository-id <id>`,
			RunE: func(_ *cobra.Command, _ []string) error {
				c, err := f.FalconClient()
				if err != nil {
					return err
				}
				p := scminv.NewListSCMRepositoryBranchesParams()
				p.RepositoryID = repoID
				var body []byte
				if _, err := c.CodeSecurityScmInventory.ListSCMRepositoryBranches(p, cmdutil.CaptureBody(&body)); err != nil {
					return cmdutil.HandleAPIError(err, "ListSCMRepositoryBranches")
				}
				return printRaw(f, l, body, branchCols)
			},
		}
		br.Flags().StringVar(&repoID, "repository-id", "", "Repository ID (required)")
		_ = br.MarkFlagRequired("repository-id")
		l.add(br)
		cmd.AddCommand(br)
	}

	{
		var field, filter string
		l := &listFlags{}
		agg := &cobra.Command{
			Use:   "aggregate",
			Short: "Distinct values, with counts, of one repository field",
			Long: templates.LongDesc(`Return the distinct values of a repository field and how many repositories
                have each. Not every field can be aggregated; the API answers 400 for one
                that cannot ("visibility" is known to work).`),
			Example: templates.Examples(`
                falcon code-security repositories aggregate --field visibility
            `),
			RunE: func(_ *cobra.Command, _ []string) error {
				c, err := f.FalconClient()
				if err != nil {
					return err
				}
				p := scminv.NewGetSCMRepositoryAggregatesParams()
				p.Field = field
				p.Filter = cmdutil.StringPtr(filter)
				var body []byte
				if _, err := c.CodeSecurityScmInventory.GetSCMRepositoryAggregates(p, cmdutil.CaptureBody(&body)); err != nil {
					return cmdutil.HandleAPIError(err, "GetSCMRepositoryAggregates")
				}
				return printRaw(f, l, body, aggCols)
			},
		}
		agg.Flags().StringVar(&field, "field", "", "Repository field to aggregate (required, e.g. visibility)")
		_ = agg.MarkFlagRequired("field")
		cmdutil.AddFilterFlag(agg, &filter)
		l.add(agg)
		cmd.AddCommand(agg)
	}
	return cmd
}

func newCmdExclusions(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "exclusions",
		Aliases: []string{"exclusion"},
		Short:   "SCM scan exclusion rules",
	}

	var connID string
	l := &listFlags{}
	list := &cobra.Command{
		Use:     "list",
		Short:   "List the exclusion rules of one connection",
		Example: `  falcon code-security exclusions list --connection-id <uuid>`,
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := f.FalconClient()
			if err != nil {
				return err
			}
			p := scmint.NewListExclusionRulesParams()
			p.ConnectionID = connID
			var body []byte
			if _, err := c.CodeSecurityScmIntegration.ListExclusionRules(p, cmdutil.CaptureBody(&body)); err != nil {
				return cmdutil.HandleAPIError(err, "ListExclusionRules")
			}
			return printRaw(f, l, body, exclusionCols)
		},
	}
	list.Flags().StringVar(&connID, "connection-id", "", "Connection UUID (required)")
	_ = list.MarkFlagRequired("connection-id")
	l.add(list)
	cmd.AddCommand(list)
	return cmd
}

func newCmdBranchConfigs(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "branch-configs",
		Aliases: []string{"branch-config"},
		Short:   "Which branches Code Security scans",
	}

	var connID, repoIDs string
	l := &listFlags{}
	get := &cobra.Command{
		Use:   "get",
		Short: "Get the branch config of a connection or its repositories",
		Long: templates.LongDesc(`Get the branch configuration for a connection, or for specific repositories in
            it. Configs a repository inherits from its connection are included and
            marked with source=inherited.`),
		Example: templates.Examples(`
            falcon code-security branch-configs get --connection-id <uuid>
            falcon code-security branch-configs get --connection-id <uuid> --repository-ids <id1>,<id2>
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := f.FalconClient()
			if err != nil {
				return err
			}
			p := scmint.NewGetBranchConfigParams()
			p.ConnectionID = connID
			p.RepositoryIds = cmdutil.StringPtr(repoIDs)
			var body []byte
			if _, err := c.CodeSecurityScmIntegration.GetBranchConfig(p, cmdutil.CaptureBody(&body)); err != nil {
				return cmdutil.HandleAPIError(err, "GetBranchConfig")
			}
			items, err := branchConfigItems(body)
			if err != nil {
				return err
			}
			return printItems(f, l, items, branchCfgCols)
		},
	}
	get.Flags().StringVar(&connID, "connection-id", "", "Connection UUID (required)")
	_ = get.MarkFlagRequired("connection-id")
	get.Flags().StringVar(&repoIDs, "repository-ids", "", "Comma-separated repository IDs (default: the connection-level config)")
	l.add(get)
	cmd.AddCommand(get)
	return cmd
}

// branchConfigItems merges resources and inherited_resources, tagging each
// with a "source" key so the table shows where a config came from.
func branchConfigItems(body []byte) ([]map[string]any, error) {
	own, err := cmdutil.RawResources(body, "resources")
	if err != nil {
		return nil, err
	}
	inh, err := cmdutil.RawResources(body, "inherited_resources")
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(own)+len(inh))
	for _, m := range own {
		m["source"] = "own"
		out = append(out, m)
	}
	for _, m := range inh {
		m["source"] = "inherited"
		out = append(out, m)
	}
	return out, nil
}

func newCmdPullJobs(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "pull-jobs",
		Aliases: []string{"pull-job"},
		Short:   "Repository pull (fetch) jobs",
	}

	var id string
	l := &listFlags{}
	get := &cobra.Command{
		Use:     "get",
		Short:   "Get the status of one pull job",
		Example: `  falcon code-security pull-jobs get --id <pull-job-id>`,
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := f.FalconClient()
			if err != nil {
				return err
			}
			p := scminv.NewGetPullJobParams()
			p.PullJobID = id
			var body []byte
			if _, err := c.CodeSecurityScmInventory.GetPullJob(p, cmdutil.CaptureBody(&body)); err != nil {
				return cmdutil.HandleAPIError(err, "GetPullJob")
			}
			return printRaw(f, l, body, pullJobCols)
		},
	}
	get.Flags().StringVar(&id, "id", "", "Pull job ID (required)")
	_ = get.MarkFlagRequired("id")
	l.add(get)
	cmd.AddCommand(get)
	return cmd
}
