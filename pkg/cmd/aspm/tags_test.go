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

package aspm

import (
	"testing"

	"github.com/crowdstrike/falcon-cli/internal/testutil"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

func TestDecodeTags_Object(t *testing.T) {
	got, err := decodeTags([]byte(`{"tags":[{"serviceCount":2,"tag":{"id":1,"name":"env"}}],"totalCount":1}`))
	if err != nil || len(got.Tags) != 1 || got.Tags[0].ServiceCount != 2 {
		t.Fatalf("object decode failed: %v %+v", err, got)
	}
}

func TestDecodeTags_ArrayOfTagData(t *testing.T) {
	got, err := decodeTags([]byte(`[{"serviceCount":3,"tag":{"id":7,"name":"team","value":"sec"}}]`))
	if err != nil || len(got.Tags) != 1 || got.Tags[0].Tag.Name != "team" || got.TotalCount != 1 {
		t.Fatalf("array decode failed: %v %+v", err, got)
	}
}

func TestDecodeTags_ArrayOfBareTags(t *testing.T) {
	got, err := decodeTags([]byte(`[{"id":9,"name":"bare","type":"user"}]`))
	if err != nil || len(got.Tags) != 1 || got.Tags[0].Tag == nil || got.Tags[0].Tag.ID != 9 {
		t.Fatalf("bare decode failed: %v %+v", err, got)
	}
}

func TestDecodeTags_EmptyAndInvalid(t *testing.T) {
	if got, err := decodeTags(nil); err != nil || len(got.Tags) != 0 {
		t.Errorf("empty body: %v %+v", err, got)
	}
	if _, err := decodeTags([]byte("not json")); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestTagsTableDef_RowFunc(t *testing.T) {
	row := tagsTableDef.RowFunc(&models.TypesTagData{
		ServiceCount: 9,
		Tag:          &models.TypesTag{ID: 5, Name: "environment", Value: "prod", Type: "user", IsSensitive: true},
	})
	testutil.AssertRow(t, row, []string{"5", "environment", "prod", "user", "true", "9"})
}

func TestTagsTableDef_RowFunc_NilTag(t *testing.T) {
	testutil.AssertRow(t, tagsTableDef.RowFunc(&models.TypesTagData{}), []string{"", "", "", "", "", "0"})
}
