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

package cmdutil

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/go-openapi/runtime"
)

// rewrittenResponse is a ClientResponse whose body has been replaced. Code,
// message and headers pass through untouched.
type rewrittenResponse struct {
	runtime.ClientResponse
	body []byte
}

func (r rewrittenResponse) Body() io.ReadCloser {
	return io.NopCloser(bytes.NewReader(r.body))
}

// bodyRewriteReader rewrites 200 bodies with fn and then hands them to the
// SDK's own reader, so headers, the typed result and all error statuses are
// handled exactly as generated. If fn fails, the original body is used.
type bodyRewriteReader struct {
	inner runtime.ClientResponseReader
	fn    func([]byte) ([]byte, error)
}

func (r bodyRewriteReader) ReadResponse(resp runtime.ClientResponse, c runtime.Consumer) (any, error) {
	if resp.Code() != 200 {
		return r.inner.ReadResponse(resp, c)
	}
	body, err := io.ReadAll(resp.Body())
	if err != nil {
		return nil, err
	}
	if out, ferr := r.fn(body); ferr == nil {
		body = out
	}
	return r.inner.ReadResponse(rewrittenResponse{ClientResponse: resp, body: body}, c)
}

// RewriteBody returns a gofalcon ClientOption that rewrites a successful
// response body before the SDK decodes it. Use it to work around generated
// models that disagree with what the live API actually returns.
func RewriteBody(fn func([]byte) ([]byte, error)) func(*runtime.ClientOperation) {
	return func(op *runtime.ClientOperation) {
		op.Reader = bodyRewriteReader{inner: op.Reader, fn: fn}
	}
}

// StringifyResourceFields rewrites resources[*].<field> values that are JSON
// objects or arrays into JSON-encoded strings, for models that declare the
// field as a string. Scalars and missing fields are left alone, so the
// rewrite is a no-op once the SDK model is fixed.
func StringifyResourceFields(fields ...string) func([]byte) ([]byte, error) {
	return func(body []byte) ([]byte, error) {
		var env map[string]json.RawMessage
		if err := json.Unmarshal(body, &env); err != nil {
			return nil, err
		}
		rawRes, ok := env["resources"]
		if !ok {
			return body, nil
		}
		var resources []map[string]json.RawMessage
		if err := json.Unmarshal(rawRes, &resources); err != nil {
			return nil, err
		}
		changed := false
		for _, res := range resources {
			for _, f := range fields {
				v, ok := res[f]
				if !ok {
					continue
				}
				t := bytes.TrimSpace(v)
				if len(t) == 0 || (t[0] != '{' && t[0] != '[') {
					continue
				}
				s, err := json.Marshal(string(t))
				if err != nil {
					return nil, err
				}
				res[f] = s
				changed = true
			}
		}
		if !changed {
			return body, nil
		}
		newRes, err := json.Marshal(resources)
		if err != nil {
			return nil, err
		}
		env["resources"] = newRes
		return json.Marshal(env)
	}
}
