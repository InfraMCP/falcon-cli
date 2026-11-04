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

package aspm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/a_s_p_m"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var tagsTableDef = &output.TableDefinition{
	Headers: []string{"ID", "NAME", "VALUE", "TYPE", "SENSITIVE", "SERVICE_COUNT"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.TypesTagData)
		if !ok {
			return nil
		}
		var id, name, value, typ, sensitive string
		if r.Tag != nil {
			id = strconv.FormatInt(r.Tag.ID, 10)
			name = r.Tag.Name
			value = r.Tag.Value
			typ = r.Tag.Type
			sensitive = strconv.FormatBool(r.Tag.IsSensitive)
		}
		return []string{id, name, value, typ, sensitive, strconv.FormatInt(r.ServiceCount, 10)}
	},
}

// decodeTags parses a GetTags 200 body. The documented shape is an object
// ({"tags": [...], "totalCount": n}) but the live API returns a bare array,
// whose elements are either tag-data wrappers ({"tag": {...}, "serviceCount"})
// or bare tags. All three are accepted.
func decodeTags(body []byte) (*models.TypesTagsDataResponse, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return &models.TypesTagsDataResponse{}, nil
	}

	if trimmed[0] == '{' {
		var resp models.TypesTagsDataResponse
		if err := json.Unmarshal(trimmed, &resp); err != nil {
			return nil, err
		}
		return &resp, nil
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return nil, err
	}

	resp := &models.TypesTagsDataResponse{Tags: make([]*models.TypesTagData, 0, len(raw))}
	for _, r := range raw {
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(r, &probe); err != nil {
			return nil, err
		}
		if _, wrapped := probe["tag"]; wrapped {
			var d models.TypesTagData
			if err := json.Unmarshal(r, &d); err != nil {
				return nil, err
			}
			resp.Tags = append(resp.Tags, &d)
			continue
		}
		var t models.TypesTag
		if err := json.Unmarshal(r, &t); err != nil {
			return nil, err
		}
		resp.Tags = append(resp.Tags, &models.TypesTagData{Tag: &t})
	}
	resp.TotalCount = int64(len(resp.Tags))
	return resp, nil
}

// tolerantTagsReader swaps the SDK's strict 200 decoding for decodeTags and
// leaves every other status to the SDK reader, so error handling is unchanged.
type tolerantTagsReader struct {
	inner runtime.ClientResponseReader
}

func (r tolerantTagsReader) ReadResponse(resp runtime.ClientResponse, c runtime.Consumer) (any, error) {
	if resp.Code() != 200 {
		return r.inner.ReadResponse(resp, c)
	}
	body, err := io.ReadAll(resp.Body())
	if err != nil {
		return nil, err
	}
	parsed, err := decodeTags(body)
	if err != nil {
		return nil, fmt.Errorf("decode tags response: %w", err)
	}
	return &a_s_p_m.GetTagsOK{Payload: parsed}, nil
}

func tolerantTags(op *runtime.ClientOperation) {
	op.Reader = tolerantTagsReader{inner: op.Reader}
}

// NewCmdTags represents the aspm tags command group.
func NewCmdTags(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tags",
		Short: "ASPM tags",
		Long:  templates.LongDesc(`Read the tags defined in ASPM.`),
		Example: templates.Examples(`
            # List ASPM tags
            falcon aspm tags list
        `),
	}

	cmd.AddCommand(NewCmdTagsList(f))
	return cmd
}

type tagsListOptions struct {
	name     []string
	tagName  string
	isUnique bool
	limit    int64
	offset   int64
	out      string
	Table    cmdutil.TableFormattingOptions
	Client   cmdutil.ClientFilterOptions
}

// NewCmdTagsList lists ASPM tags.
func NewCmdTagsList(f *factory.Factory) *cobra.Command {
	opts := &tagsListOptions{limit: 100}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List ASPM tags",
		Long:  templates.LongDesc(`List the tags defined in ASPM, with the number of services each tag is applied to.`),
		Example: templates.Examples(`
            # All tags
            falcon aspm tags list

            # Filter by tag name
            falcon aspm tags list --tag-name environment

            # Full detail as JSON
            falcon aspm tags list --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := a_s_p_m.NewGetTagsParams()
			if len(opts.name) > 0 {
				p.Name = opts.name
			}
			if opts.tagName != "" {
				p.TagName = cmdutil.StringPtr(opts.tagName)
			}
			if opts.isUnique {
				p.IsUnique = cmdutil.Ptr(opts.isUnique)
			}
			p.Limit = cmdutil.Int64Ptr(opts.limit)
			if opts.offset > 0 {
				p.Offset = cmdutil.Int64Ptr(opts.offset)
			}

			resp, err := falconClient.Aspm.GetTags(p, tolerantTags)
			if err != nil {
				return cmdutil.HandleAPIError(err, "GetTags")
			}

			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), tagsTableDef, tableOpts)

			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []*models.TypesTagData{})
			}

			resources := output.FilterAndSort(resp.Payload.Tags, tagsTableDef, opts.Client.ToFilterOptions())
			return printer.Print(f.IOStreams.Out, resources)
		},
	}

	cmd.Flags().StringSliceVar(&opts.name, "name", nil, "Filter by tag name(s) (repeatable or comma-separated)")
	cmd.Flags().StringVar(&opts.tagName, "tag-name", "", "Filter by a single tag name")
	cmd.Flags().BoolVar(&opts.isUnique, "unique", false, "Return only unique tags")
	cmdutil.AddPaginationFlags(cmd, &opts.limit, &opts.offset, 100)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)
	return cmd
}
