// Package disasm provides tests for the Z80 disassembler implementation
package disasm

import (
	"testing"
)

// TestEmptyData tests handling of empty data
func TestEmptyData(t *testing.T) {
	d := New()
	_, err := d.Decode([]byte{})
	if err == nil {
		t.Errorf("expected error for empty data but got none")
	}
}
