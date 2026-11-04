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
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// ErrDryRun is returned by an SDK call made through a dry-run client in place
// of sending a write. Callers check it with DryRun.Intercepted.
var ErrDryRun = errors.New("dry run: write not sent")

// DryRun records the writes a command would send. Create one with WriteClient.
type DryRun struct {
	mu    sync.Mutex
	plans []DryRunPlan
}

// Intercepted reports whether err means a write was recorded instead of sent.
func (d *DryRun) Intercepted(err error) bool {
	return d != nil && errors.Is(err, ErrDryRun)
}

// Print writes every recorded plan to w as indented JSON (secrets redacted).
func (d *DryRun) Print(w io.Writer) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, p := range d.plans {
		if err := PrintDryRun(w, p); err != nil {
			return err
		}
	}
	return nil
}

// Plans returns a copy of the recorded plans (for tests).
func (d *DryRun) Plans() []DryRunPlan {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]DryRunPlan(nil), d.plans...)
}

// WriteClient returns the client a mutating command should use.
//
// With confirm set, it is the real client and the returned *DryRun is nil.
// Without it, writes (any method other than GET/HEAD) are recorded rather
// than sent: the SDK call returns ErrDryRun and the plan — the exact method,
// path, query and body the SDK built — is available via DryRun.Print. Reads
// still reach the API, through a real client created on first use, so commands
// that fetch before they write keep working; a dry run that only writes needs
// no credentials at all.
func WriteClient(confirm bool, newClient func() (*client.CrowdStrikeAPISpecification, error)) (*client.CrowdStrikeAPISpecification, *DryRun, error) {
	if confirm {
		c, err := newClient()
		return c, nil, err
	}
	d := &DryRun{}
	t := &dryRunTransport{dry: d, newClient: newClient}
	return client.New(t, strfmt.Default), d, nil
}

type dryRunTransport struct {
	dry       *DryRun
	newClient func() (*client.CrowdStrikeAPISpecification, error)

	once    sync.Once
	readT   runtime.ClientTransport
	readErr error
}

func (t *dryRunTransport) Submit(op *runtime.ClientOperation) (any, error) {
	if m := strings.ToUpper(op.Method); m == http.MethodGet || m == http.MethodHead {
		t.once.Do(func() {
			c, err := t.newClient()
			if err != nil {
				t.readErr = err
				return
			}
			t.readT = c.Transport
		})
		if t.readErr != nil {
			return nil, t.readErr
		}
		return t.readT.Submit(op)
	}

	req := newRecordingRequest(op.Method, op.PathPattern)
	if op.Params != nil {
		if err := op.Params.WriteToRequest(req, strfmt.Default); err != nil {
			return nil, err
		}
	}

	plan := DryRunPlan{
		Action: op.ID,
		Method: strings.ToUpper(op.Method),
		Path:   req.renderPath(),
		Body:   req.body,
	}
	if ids := req.query["ids"]; len(ids) > 0 {
		plan.IDs = append([]string(nil), ids...)
	}

	t.dry.mu.Lock()
	t.dry.plans = append(t.dry.plans, plan)
	t.dry.mu.Unlock()
	return nil, ErrDryRun
}

// recordingRequest captures what an SDK params object writes into a request.
type recordingRequest struct {
	method  string
	pattern string
	path    map[string]string
	query   url.Values
	header  http.Header
	body    any
}

func newRecordingRequest(method, pattern string) *recordingRequest {
	return &recordingRequest{
		method:  method,
		pattern: pattern,
		path:    map[string]string{},
		query:   url.Values{},
		header:  http.Header{},
	}
}

// renderPath fills path parameters and appends the query string (sorted, so
// output is stable).
func (r *recordingRequest) renderPath() string {
	p := r.pattern
	for k, v := range r.path {
		p = strings.ReplaceAll(p, "{"+k+"}", url.PathEscape(v))
	}
	if len(r.query) == 0 {
		return p
	}
	keys := make([]string, 0, len(r.query))
	for k := range r.query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, v := range r.query[k] {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(k) + "=" + url.QueryEscape(v))
		}
	}
	return p + "?" + b.String()
}

func (r *recordingRequest) SetHeaderParam(k string, v ...string) error {
	r.header[http.CanonicalHeaderKey(k)] = v
	return nil
}
func (r *recordingRequest) GetHeaderParams() http.Header { return r.header }
func (r *recordingRequest) SetQueryParam(k string, v ...string) error {
	r.query[k] = v
	return nil
}
func (r *recordingRequest) SetFormParam(k string, v ...string) error {
	r.query[k] = v
	return nil
}
func (r *recordingRequest) SetPathParam(k, v string) error {
	r.path[k] = v
	return nil
}
func (r *recordingRequest) GetQueryParams() url.Values { return r.query }
func (r *recordingRequest) SetFileParam(string, ...runtime.NamedReadCloser) error {
	return nil
}
func (r *recordingRequest) SetBodyParam(v any) error {
	r.body = v
	return nil
}
func (r *recordingRequest) SetTimeout(time.Duration) error { return nil }
func (r *recordingRequest) GetMethod() string              { return r.method }
func (r *recordingRequest) GetPath() string                { return r.pattern }
func (r *recordingRequest) GetBody() []byte                { return nil }
func (r *recordingRequest) GetBodyParam() any              { return r.body }
func (r *recordingRequest) GetFileParam() map[string][]runtime.NamedReadCloser {
	return nil
}
