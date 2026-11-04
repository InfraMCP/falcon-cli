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

package iac

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/crowdstrike/gofalcon/falcon/client/cspg_iacapi"
	"github.com/go-openapi/runtime"
)

// Since gofalcon v0.23.0 the generated models.Rule type is shared with an
// unrelated (notification) rule schema, so IaC detections no longer decode:
// the live API sends rule.severity as a number but the model wants a string,
// and rule_uuid is gone. These local types mirror the IaC detection shape and
// are decoded directly, bypassing the SDK's 200 reader.

type iacRule struct {
	RuleUUID string          `json:"rule_uuid,omitempty"`
	Name     string          `json:"name,omitempty"`
	Severity json.RawMessage `json:"severity,omitempty"`
}

type iacDetection struct {
	DetectionUUID     string   `json:"detection_uuid,omitempty"`
	ResourceType      string   `json:"resource_type,omitempty"`
	FileName          string   `json:"file_name,omitempty"`
	MisconfiguredLine *int64   `json:"misconfigured_line,omitempty"`
	LastDetected      string   `json:"last_detected,omitempty"`
	Rule              *iacRule `json:"rule,omitempty"`

	// raw keeps the full record so --output json is lossless.
	raw json.RawMessage
}

// MarshalJSON emits the original record unchanged.
func (d *iacDetection) MarshalJSON() ([]byte, error) {
	if len(d.raw) > 0 {
		return d.raw, nil
	}
	type alias iacDetection
	return json.Marshal((*alias)(d))
}

type iacResponse struct {
	Resources []*iacDetection `json:"resources"`
}

func decodeDetections(body []byte) (*iacResponse, error) {
	var env struct {
		Resources []json.RawMessage `json:"resources"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	out := &iacResponse{Resources: make([]*iacDetection, 0, len(env.Resources))}
	for _, r := range env.Resources {
		d := &iacDetection{}
		if err := json.Unmarshal(r, d); err != nil {
			return nil, err
		}
		d.raw = r
		out.Resources = append(out.Resources, d)
	}
	return out, nil
}

// detectionsReader decodes 200 responses with decodeDetections into *out and
// defers every other status to the SDK reader, so error mapping is unchanged.
// The SDK method panics unless the reader yields *CombinedDetectionsOK, so an
// empty one is returned and the real data travels through out.
type detectionsReader struct {
	inner runtime.ClientResponseReader
	out   **iacResponse
}

func (r detectionsReader) ReadResponse(resp runtime.ClientResponse, c runtime.Consumer) (any, error) {
	if resp.Code() != 200 {
		return r.inner.ReadResponse(resp, c)
	}
	body, err := io.ReadAll(resp.Body())
	if err != nil {
		return nil, err
	}
	parsed, err := decodeDetections(body)
	if err != nil {
		return nil, fmt.Errorf("decode IaC detections: %w", err)
	}
	*r.out = parsed
	return &cspg_iacapi.CombinedDetectionsOK{}, nil
}

// withDetectionsReader returns a ClientOption that installs detectionsReader.
func withDetectionsReader(out **iacResponse) cspg_iacapi.ClientOption {
	return func(op *runtime.ClientOperation) {
		op.Reader = detectionsReader{inner: op.Reader, out: out}
	}
}

// ProbeOption returns a ClientOption that decodes CombinedDetections with the
// local IaC types and discards the result. For permission probes (fcs doctor),
// where only the status code matters.
func ProbeOption() cspg_iacapi.ClientOption {
	var discard *iacResponse
	return withDetectionsReader(&discard)
}
