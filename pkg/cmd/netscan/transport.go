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

// Package netscan manages CrowdStrike Falcon Network Vulnerability Assessment
// (NVA) resources: networks, scans, zones, scanners, templates and scan-runs.
//
// The /netscan/* endpoints are NOT present in gofalcon's typed client, so this
// package drives them through the SDK's configured transport using a generic
// request helper (see rawRequest). That reuses the SDK's authenticated HTTP
// client — OAuth2 client-credentials token, region autodiscovery, retry and
// rate-limit handling, and user-agent — without acquiring a token ourselves.
package netscan

import (
	"encoding/json"
	"io"
	"strconv"

	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// rawParams describes a single request to a raw (non-typed) Falcon endpoint.
type rawParams struct {
	// Method is the HTTP verb (GET, POST, PATCH, DELETE).
	Method string
	// Path is the API path, e.g. "/netscan/queries/networks/v1".
	Path string
	// Query holds query-string parameters. Values are sent in order; a key with
	// multiple values (e.g. ids) produces repeated query parameters.
	Query map[string][]string
	// Body, when non-nil, is JSON-marshalled and sent as the request body.
	Body interface{}
}

// rawRequest submits an arbitrary request through the gofalcon transport and
// decodes the JSON response into a generic map. On a non-2xx status it returns
// a *runtime.APIError carrying the status code, so cmdutil.HandleAPIError can
// map it to an actionable message exactly as it does for typed operations.
//
// opName is a human-readable label used in error messages (e.g. "QueryNetworks").
func rawRequest(f *factory.Factory, opName string, p rawParams) (map[string]interface{}, error) {
	falconClient, err := f.FalconClient()
	if err != nil {
		return nil, err
	}
	return rawRequestWithClient(falconClient, opName, p)
}

// rawRequestWithClient is the transport-level core of rawRequest, split out so
// the token/client acquisition and the request submission can be reasoned about
// (and tested) independently.
func rawRequestWithClient(c *client.CrowdStrikeAPISpecification, opName string, p rawParams) (map[string]interface{}, error) {
	writer := runtime.ClientRequestWriterFunc(func(req runtime.ClientRequest, _ strfmt.Registry) error {
		if err := req.SetHeaderParam("Accept", "application/json"); err != nil {
			return err
		}
		for k, vals := range p.Query {
			if len(vals) == 0 {
				continue
			}
			if err := req.SetQueryParam(k, vals...); err != nil {
				return err
			}
		}
		if p.Body != nil {
			if err := req.SetBodyParam(p.Body); err != nil {
				return err
			}
		}
		return nil
	})

	reader := runtime.ClientResponseReaderFunc(func(resp runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
		code := resp.Code()
		if code/100 != 2 {
			// Mirror gofalcon's typed readers: wrap the response so the code is
			// reachable via errors.As(err, *runtime.APIError) in HandleAPIError.
			payload := decodeBody(resp.Body())
			return nil, runtime.NewAPIError(opName, errResponse{resp: resp, payload: payload}, code)
		}
		out := map[string]interface{}{}
		if err := consumer.Consume(resp.Body(), &out); err != nil && err != io.EOF {
			return nil, err
		}
		return out, nil
	})

	op := &runtime.ClientOperation{
		ID:                 opName,
		Method:             p.Method,
		PathPattern:        p.Path,
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             writer,
		Reader:             reader,
	}

	result, err := c.Transport.Submit(op)
	if err != nil {
		return nil, err
	}
	out, _ := result.(map[string]interface{})
	return out, nil
}

// errResponse adapts a runtime.ClientResponse into an error payload whose
// String()/MarshalJSON reflect the server body, so runtime.APIError.Error()
// surfaces the API's own message in dry-run-less failures.
type errResponse struct {
	resp    runtime.ClientResponse
	payload map[string]interface{}
}

func (e errResponse) Code() int                    { return e.resp.Code() }
func (e errResponse) Message() string              { return e.resp.Message() }
func (e errResponse) GetHeader(s string) string    { return e.resp.GetHeader(s) }
func (e errResponse) GetHeaders(s string) []string { return e.resp.GetHeaders(s) }
func (e errResponse) Body() io.ReadCloser          { return e.resp.Body() }
func (e errResponse) MarshalJSON() ([]byte, error) { return json.Marshal(e.payload) }

// decodeBody best-effort decodes a response body into a map for error reporting.
func decodeBody(body io.ReadCloser) map[string]interface{} {
	if body == nil {
		return nil
	}
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil || len(data) == 0 {
		return nil
	}
	out := map[string]interface{}{}
	if json.Unmarshal(data, &out) == nil {
		return out
	}
	return map[string]interface{}{"raw": string(data)}
}

// intStr renders an int64 as a decimal string for use as a query value.
func intStr(v int64) string { return strconv.FormatInt(v, 10) }
