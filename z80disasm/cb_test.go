// Package disasm provides tests for the Z80 disassembler implementation
package disasm

import (
	"testing"
)

// TestDecodeCB tests decoding of CB-prefixed Z80 instructions
func TestDecodeCB(t *testing.T) {
	d := New()

	tests := []struct {
		name     string
		data     []byte
		expected Instruction
		hasError bool
	}{
		{
			name: "RLC B",
			data: []byte{0xCB, 0x00},
			expected: Instruction{
				Mnemonic: "RLC B",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLC C",
			data: []byte{0xCB, 0x01},
			expected: Instruction{
				Mnemonic: "RLC C",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLC D",
			data: []byte{0xCB, 0x02},
			expected: Instruction{
				Mnemonic: "RLC D",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLC E",
			data: []byte{0xCB, 0x03},
			expected: Instruction{
				Mnemonic: "RLC E",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLC H",
			data: []byte{0xCB, 0x04},
			expected: Instruction{
				Mnemonic: "RLC H",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLC L",
			data: []byte{0xCB, 0x05},
			expected: Instruction{
				Mnemonic: "RLC L",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLC (HL)",
			data: []byte{0xCB, 0x06},
			expected: Instruction{
				Mnemonic: "RLC (HL)",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLC A",
			data: []byte{0xCB, 0x07},
			expected: Instruction{
				Mnemonic: "RLC A",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name:     "Insufficient data for CB prefix",
			data:     []byte{0xCB},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := d.Decode(tt.data)

			if tt.hasError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Mnemonic != tt.expected.Mnemonic {
				t.Errorf("mnemonic mismatch: got %q, want %q", result.Mnemonic, tt.expected.Mnemonic)
			}

			if result.Length != tt.expected.Length {
				t.Errorf("length mismatch: got %d, want %d", result.Length, tt.expected.Length)
			}

			if result.Address != tt.expected.Address {
				t.Errorf("address mismatch: got 0x%04X, want 0x%04X", result.Address, tt.expected.Address)
			}
		})
	}
}
