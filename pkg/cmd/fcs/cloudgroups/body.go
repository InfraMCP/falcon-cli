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
	"strconv"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
)

// bodyOptions holds the flag-driven fields shared by `create` and `update`.
// It mirrors the group-body arguments of the falcon-cloudgroups.py helper.
type bodyOptions struct {
	name           string
	description    string
	businessUnit   string
	businessImpact string
	environment    string
	owners         []string

	provider string
	accounts []string
	regions  []string
	tags     []string

	fromJSON string
}

// addGroupBodyFlags registers the group-body flags on a create/update command,
// matching the names used by the Python helper.
func addGroupBodyFlags(cmd *cobra.Command, opts *bodyOptions) {
	cmd.Flags().StringVar(&opts.name, "name", "", "Group name (unique, case-insensitive)")
	cmd.Flags().StringVar(&opts.description, "description", "", "Group description")
	cmd.Flags().StringVar(&opts.businessUnit, "business-unit", "", "Business unit label")
	cmd.Flags().StringVar(&opts.businessImpact, "business-impact", "", "Business impact: high, moderate, or low")
	cmd.Flags().StringVar(&opts.environment, "environment", "", "Environment: dev, test, stage, or prod")
	cmd.Flags().StringArrayVar(&opts.owners, "owner", nil, "Owner email (repeatable)")

	cmd.Flags().StringVar(&opts.provider, "provider", "aws", "Cloud provider for the selector: aws, azure, gcp, or oci")
	cmd.Flags().StringArrayVar(&opts.accounts, "account", nil, "Account ID to include in the selector (repeatable)")
	cmd.Flags().StringArrayVar(&opts.regions, "region", nil, "Region filter for the selector (repeatable)")
	cmd.Flags().StringArrayVar(&opts.tags, "tag", nil, "Tag filter key=value for the selector (repeatable)")

	cmd.Flags().StringVar(&opts.fromJSON, "from-json", "", "Path to a JSON file holding the full group body (overrides the body flags)")
}

// cloudResourceSelector builds a single cloud-resource selector from the flag
// values, or nil when no selector fields were supplied. Ports _cloud_resource.
func (o *bodyOptions) cloudResourceSelector() *models.AssetgroupmanagerV1CloudResourceSelector {
	if len(o.accounts) == 0 && len(o.regions) == 0 && len(o.tags) == 0 {
		return nil
	}
	sel := &models.AssetgroupmanagerV1CloudResourceSelector{
		CloudProvider: cmdutil.StringPtr(o.provider),
		AccountIds:    o.accounts,
	}
	if len(o.regions) > 0 || len(o.tags) > 0 {
		sel.Filters = &models.AssetgroupmanagerV1CloudResourceFilters{
			Region: o.regions,
			Tags:   o.tags,
		}
	}
	return sel
}

// selectors wraps the cloud-resource selector in the write selectors envelope,
// or returns nil when there is nothing to select.
func (o *bodyOptions) selectors() *models.AssetgroupmanagerV1WriteCloudGroupSelectors {
	cr := o.cloudResourceSelector()
	if cr == nil {
		return nil
	}
	return &models.AssetgroupmanagerV1WriteCloudGroupSelectors{
		CloudResources: []*models.AssetgroupmanagerV1CloudResourceSelector{cr},
	}
}

// createRequest assembles the create request body from the flag values. Ports
// _group_body_from_args for the create path (name is required).
func (o *bodyOptions) createRequest() *models.AssetgroupmanagerV1CreateCloudGroupRequest {
	req := &models.AssetgroupmanagerV1CreateCloudGroupRequest{
		Name:           cmdutil.StringPtr(o.name),
		Description:    optStr(o.description),
		BusinessUnit:   optStr(o.businessUnit),
		BusinessImpact: optStr(o.businessImpact),
		Environment:    optStr(o.environment),
		Owners:         o.owners,
		Selectors:      o.selectors(),
	}
	return req
}

// updateMessage assembles the update request body from the flag values, keyed
// by the group ID. Ports _group_body_from_args for the update path.
func (o *bodyOptions) updateMessage(id string) *models.AssetgroupmanagerV1UpdateCloudGroupMessage {
	msg := &models.AssetgroupmanagerV1UpdateCloudGroupMessage{
		ID:             id,
		Name:           o.name,
		Description:    optStr(o.description),
		BusinessUnit:   optStr(o.businessUnit),
		BusinessImpact: optStr(o.businessImpact),
		Environment:    optStr(o.environment),
		Owners:         o.owners,
		Selectors:      o.selectors(),
	}
	return msg
}

// optStr returns a pointer to v, or nil when v is empty, so unset optional flags
// are omitted from the request body rather than sent as empty strings.
func optStr(v string) *string {
	if v == "" {
		return nil
	}
	return cmdutil.StringPtr(v)
}

// itoa is a tiny int->string helper for the selector table summary.
func itoa(n int) string {
	return strconv.Itoa(n)
}
