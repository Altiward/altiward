// Copyright 2026 Phil Chatham
// SPDX-License-Identifier: Apache-2.0

package jose

import (
	"github.com/go-jose/go-jose/v3/json"
	"strings"
	"testing"
)

func TestNestingLimit(t *testing.T) {
	for _, open := range []string{"[", `{"value":`} {
		close := "]"
		if open != "[" {
			close = "}"
		}
		for _, depth := range []int{10000, 10001} {
			input := strings.Repeat(open, depth) + "0" + strings.Repeat(close, depth)
			wantValid := depth == 10000
			var value interface{}
			if err := json.Unmarshal([]byte(input), &value); (err == nil) != wantValid {
				t.Errorf("Unmarshal: depth %d, container %q: %v", depth, open, err)
			}
			decoder := json.NewDecoder(strings.NewReader(input))
			if err := decoder.Decode(&value); (err == nil) != wantValid {
				t.Errorf("Decode: depth %d, container %q: %v", depth, open, err)
			}
		}
	}
}
