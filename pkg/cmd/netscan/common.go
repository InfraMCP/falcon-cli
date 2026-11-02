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

package netscan

import (
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// listOptions holds the common query/pagination/output flags shared by every
// "list" subcommand in this group.
type listOptions struct {
	filter string
	sort   string
	limit  int64
	offset int64
	out    string
}

// addListFlags wires the shared list flags onto a command.
func addListFlags(cmd *cobra.Command, opts *listOptions) {
	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmdutil.AddSortFlag(cmd, &opts.sort)
	cmdutil.AddPaginationFlags(cmd, &opts.limit, &opts.offset, 100)
	cmdutil.AddOutputFlag(cmd, &opts.out)
}

// listQuery builds the common query map (filter/sort/offset/limit) for a list
// call, omitting empty/zero values so the API receives only what was set.
func (o *listOptions) listQuery() map[string][]string {
	q := map[string][]string{}
	if o.filter != "" {
		q["filter"] = []string{o.filter}
	}
	if o.sort != "" {
		q["sort"] = []string{o.sort}
	}
	if o.offset > 0 {
		q["offset"] = []string{intStr(o.offset)}
	}
	if o.limit > 0 {
		q["limit"] = []string{intStr(o.limit)}
	}
	return q
}

// printRaw emits a raw API map via the output.Printer. These endpoints return
// untyped maps, so there is no table definition; JSON (the default here) is the
// most useful format, but table/toon still render a best-effort view.
func printRaw(f *factory.Factory, out string, payload map[string]interface{}) error {
	format := output.Format(out)
	if format == output.FormatTable {
		// No typed table definition exists for raw maps; JSON is clearer.
		format = output.FormatJSON
	}
	printer := output.NewPrinter(format, nil)
	return printer.Print(f.IOStreams.Out, payload)
}

// runList executes a list/query call against query-style endpoints and prints
// the raw payload.
func runList(f *factory.Factory, opName, path string, opts *listOptions) error {
	payload, err := rawRequest(f, opName, rawParams{
		Method: "GET",
		Path:   path,
		Query:  opts.listQuery(),
	})
	if err != nil {
		return cmdutil.HandleAPIError(err, opName)
	}
	return printRaw(f, opts.out, payload)
}

// runGet executes an entities-get call (ids query) and prints the raw payload.
func runGet(f *factory.Factory, opName, path string, ids []string, out string) error {
	payload, err := rawRequest(f, opName, rawParams{
		Method: "GET",
		Path:   path,
		Query:  map[string][]string{"ids": ids},
	})
	if err != nil {
		return cmdutil.HandleAPIError(err, opName)
	}
	return printRaw(f, out, payload)
}

// runDelete performs a confirm-gated delete by IDs. Without --confirm it prints
// the dry-run plan and returns without calling the API.
func runDelete(f *factory.Factory, opName, path string, ids []string, confirm bool, out string) error {
	if !confirm {
		return cmdutil.PrintDryRun(f.IOStreams.Out, cmdutil.DryRunPlan{
			Method: "DELETE",
			Path:   path,
			IDs:    ids,
		})
	}
	payload, err := rawRequest(f, opName, rawParams{
		Method: "DELETE",
		Path:   path,
		Query:  map[string][]string{"ids": ids},
	})
	if err != nil {
		return cmdutil.HandleAPIError(err, opName)
	}
	return printRaw(f, out, payload)
}

// runWrite performs a confirm-gated create/update (POST/PATCH) with a JSON body.
// Without --confirm it prints the dry-run plan (including the body) and returns.
func runWrite(f *factory.Factory, opName, method, path string, body interface{}, confirm bool, out string) error {
	if !confirm {
		return cmdutil.PrintDryRun(f.IOStreams.Out, cmdutil.DryRunPlan{
			Method: method,
			Path:   path,
			Body:   body,
		})
	}
	payload, err := rawRequest(f, opName, rawParams{
		Method: method,
		Path:   path,
		Body:   body,
	})
	if err != nil {
		return cmdutil.HandleAPIError(err, opName)
	}
	return printRaw(f, out, payload)
}

// newListCmd builds a standard "list" subcommand for a query-style endpoint.
func newListCmd(f *factory.Factory, opName, path, short, example string) *cobra.Command {
	opts := &listOptions{limit: 100}
	cmd := &cobra.Command{
		Use:     "list",
		Short:   short,
		Long:    templates.LongDesc(short + "."),
		Example: templates.Examples(example),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runList(f, opName, path, opts)
		},
	}
	addListFlags(cmd, opts)
	return cmd
}

// newGetCmd builds a standard "get by IDs" subcommand for an entities endpoint.
func newGetCmd(f *factory.Factory, opName, path, short, example string) *cobra.Command {
	var ids []string
	var out string
	cmd := &cobra.Command{
		Use:     "get",
		Short:   short,
		Long:    templates.LongDesc(short + "."),
		Example: templates.Examples(example),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runGet(f, opName, path, ids, out)
		},
	}
	cmdutil.AddIDsFlag(cmd, &ids, true)
	cmdutil.AddOutputFlag(cmd, &out)
	return cmd
}

// newDeleteCmd builds a confirm-gated "delete by IDs" subcommand.
func newDeleteCmd(f *factory.Factory, opName, path, short, example string) *cobra.Command {
	var ids []string
	var confirm bool
	var out string
	cmd := &cobra.Command{
		Use:   "delete",
		Short: short,
		Long: templates.LongDesc(short + `.

            This is a mutating action. Without --confirm the command prints the
            request it would send and exits without calling the API.`),
		Example: templates.Examples(example),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDelete(f, opName, path, ids, confirm, out)
		},
	}
	cmdutil.AddIDsFlag(cmd, &ids, true)
	cmdutil.AddConfirmFlag(cmd, &confirm)
	cmdutil.AddOutputFlag(cmd, &out)
	return cmd
}
