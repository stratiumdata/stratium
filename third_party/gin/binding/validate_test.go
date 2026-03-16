// Copyright 2014 Manu Martinez-Almeida. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package binding

import "testing"

func TestDefaultValidatorNoop(t *testing.T) {
	var v defaultValidator
	if err := v.ValidateStruct(struct{}{}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
