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
	"testing"

	"github.com/crowdstrike/falcon-cli/internal/testutil"
)

const sample = `{"resources":[{"detection_uuid":"d1","resource_type":"aws_s3_bucket","file_name":"main.tf","misconfigured_line":12,"last_detected":"2026-11-01T10:00:00Z","rule":{"rule_uuid":"r-9","name":"S3 public","severity":3}}]}`

func TestDecodeDetections_NumericSeverity(t *testing.T) {
	got, err := decodeDetections([]byte(sample))
	if err != nil || len(got.Resources) != 1 {
		t.Fatalf("decode failed: %v %+v", err, got)
	}
	row := iacTableDef.RowFunc(got.Resources[0])
	testutil.AssertRow(t, row, []string{"d1", "aws_s3_bucket", "main.tf", "12", "r-9", "2026-11-01"})
}

func TestDecodeDetections_JSONIsLossless(t *testing.T) {
	got, _ := decodeDetections([]byte(sample))
	b, err := json.Marshal(got.Resources[0])
	if err != nil || !testutil.ContainsAll(string(b), "\"severity\":3", "\"rule_uuid\":\"r-9\"") {
		t.Fatalf("json not lossless: %v %s", err, b)
	}
}

func TestIACTableDef_WrongType(t *testing.T) {
	if iacTableDef.RowFunc("x") != nil {
		t.Error("want nil row for wrong type")
	}
}
