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
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/spf13/cobra"
)

// maxAutoColumns caps how many columns an auto-derived table shows; the rest
// remain in --output json and can be picked with --columns.
const maxAutoColumns = 7

// dynamicTable builds a table definition from the keys present in items.
// Preferred keys come first (in the given order) when present; other scalar
// keys follow alphabetically. With wantAll, every key is a column, which is
// how --columns can name any field.
func dynamicTable(items []map[string]any, preferred []string, wantAll bool) *output.TableDefinition {
	present := map[string]bool{}
	scalar := map[string]bool{}
	for _, it := range items {
		for k, v := range it {
			present[k] = true
			switch v.(type) {
			case map[string]any, []any:
			default:
				scalar[k] = true
			}
		}
	}

	var keys []string
	seen := map[string]bool{}
	for _, k := range preferred {
		if present[k] && !seen[k] {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range present {
		if !seen[k] && (wantAll || scalar[k]) {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	keys = append(keys, rest...)
	if !wantAll && len(keys) > maxAutoColumns {
		keys = keys[:maxAutoColumns]
	}
	if len(keys) == 0 {
		keys = preferred
	}

	headers := make([]string, len(keys))
	for i, k := range keys {
		headers[i] = strings.ToUpper(k)
	}
	return &output.TableDefinition{
		Headers: headers,
		RowFunc: func(item any) []string {
			m, ok := item.(map[string]any)
			if !ok {
				return nil
			}
			row := make([]string, len(keys))
			for i, k := range keys {
				row[i] = cellString(m[k])
			}
			return row
		},
	}
}

// cellString renders one value for a table cell.
func cellString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, cellString(e))
		}
		return strings.Join(parts, ",")
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(b)
	}
}

// listFlags are the presentation flags shared by every code-security read.
type listFlags struct {
	out    string
	Table  cmdutil.TableFormattingOptions
	Client cmdutil.ClientFilterOptions
}

func (l *listFlags) add(cmd *cobra.Command) {
	cmdutil.AddOutputFlag(cmd, &l.out)
	cmdutil.AddTableFormattingFlags(cmd, &l.Table)
	cmdutil.AddClientFilterFlags(cmd, &l.Client)
}

// printRaw decodes resources from a captured body and prints them.
func printRaw(f *factory.Factory, l *listFlags, body []byte, preferred []string) error {
	items, err := cmdutil.RawResources(body, "resources")
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return printItems(f, l, items, preferred)
}

func printItems(f *factory.Factory, l *listFlags, items []map[string]any, preferred []string) error {
	if items == nil {
		items = []map[string]any{}
	}
	def := dynamicTable(items, preferred, l.Table.Columns != "")
	items = output.FilterAndSort(items, def, l.Client.ToFilterOptions())
	printer := output.NewPrinter(output.Format(l.out), def, l.Table.ToOutputTableOptions())
	return printer.Print(f.IOStreams.Out, items)
}
