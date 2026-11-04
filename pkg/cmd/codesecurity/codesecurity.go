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

// Package codesecurity implements the "code-security" command group: Falcon
// Code Security source-code-management (SCM) integration and inventory.
//
// The SCM endpoints return untyped resources in gofalcon, so these commands
// keep the raw response body, render a table whose columns come from the keys
// the API actually returns, and print the full records with --output json.
package codesecurity

import (
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewCodeSecurityCmd represents the code-security command group.
func NewCodeSecurityCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "code-security",
		Aliases: []string{"codesec"},
		Short:   "Falcon Code Security (SCM integration and inventory)",
		Long: templates.LongDesc(`Query Falcon Code Security source-code-management data.

            Read SCM connections, the repositories discovered through them, their
            branches, scan exclusion rules, branch configurations and pull jobs.

            This first set of commands is read-only.`),
		Example: templates.Examples(`
            # SCM connections, then the repositories found through them
            falcon code-security connections list
            falcon code-security repositories list --limit 50

            # Exclusion rules and branch config for one connection
            falcon code-security exclusions list --connection-id <uuid>
            falcon code-security branch-configs get --connection-id <uuid>

            # Distinct values (with counts) of a repository field
            falcon code-security repositories aggregate --field visibility
        `),
	}

	cmd.AddCommand(newCmdConnections(f))
	cmd.AddCommand(newCmdRepositories(f))
	cmd.AddCommand(newCmdExclusions(f))
	cmd.AddCommand(newCmdBranchConfigs(f))
	cmd.AddCommand(newCmdPullJobs(f))
	return cmd
}
