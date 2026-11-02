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
	"github.com/spf13/cobra"
)

// listOptions holds the flags shared by every intel `list` subcommand.
type listOptions struct {
	filter string
	sort   string
	limit  int64
	offset int64
	out    string
	Table  cmdutil.TableFormattingOptions
	Client cmdutil.ClientFilterOptions
}

// queryFunc runs the entity query for one intel resource and returns its full
// entities. Each resource supplies its own closure (different SDK method and
// element type), which is what the three list commands actually differ by.
type queryFunc[T any] func(o *listOptions) ([]T, error)

// newListCmd builds a standard intel `list` subcommand. The shared flag set,
// printer wiring and client-side filter/sort live here once; the caller passes
// the resource's table definition and query closure. This is what keeps the
// actors/indicators/reports commands from being near-identical copies.
func newListCmd[T any](
	f *factory.Factory,
	short, long, example string,
	tableDef *output.TableDefinition,
	query queryFunc[T],
) *cobra.Command {
	opts := &listOptions{limit: 100}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   short,
		Long:    long,
		Example: example,
		RunE: func(_ *cobra.Command, _ []string) error {
			resources, err := query(opts)
			if err != nil {
				return err
			}
			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), tableDef, tableOpts)
			resources = output.FilterAndSort(resources, tableDef, opts.Client.ToFilterOptions())
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
