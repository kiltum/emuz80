// Package disasm provides tests for the Z80 disassembler implementation
package disasm

import (
	"testing"
)

// TestDecodeDD tests decoding of DD-prefixed Z80 instructions
func TestDecodeDD(t *testing.T) {
	d := New()

	tests := []struct {
		name     string
		data     []byte
		expected Instruction
		hasError bool
	}{
		{
			name: "LD IX, nn",
			data: []byte{0xDD, 0x21, 0x34, 0x12},
			expected: Instruction{
				Mnemonic: "LD IX, $1234",
				Length:   4,
				Address:  0x1234,
			},
		},
		{
			name: "ADD IX, BC",
			data: []byte{0xDD, 0x09},
			expected: Instruction{
				Mnemonic: "ADD IX, BC",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADD IX, DE",
			data: []byte{0xDD, 0x19},
			expected: Instruction{
				Mnemonic: "ADD IX, DE",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (nn), IX",
			data: []byte{0xDD, 0x22, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "LD ($3412), IX",
				Length:   4,
				Address:  0x3412,
			},
		},
		{
			name: "INC IX",
			data: []byte{0xDD, 0x23},
			expected: Instruction{
				Mnemonic: "INC IX",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "INC IXH",
			data: []byte{0xDD, 0x24},
			expected: Instruction{
				Mnemonic: "INC IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "DEC IXH",
			data: []byte{0xDD, 0x25},
			expected: Instruction{
				Mnemonic: "DEC IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXH, n",
			data: []byte{0xDD, 0x26, 0x42},
			expected: Instruction{
				Mnemonic: "LD IXH, $42",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADD IX, IX",
			data: []byte{0xDD, 0x29},
			expected: Instruction{
				Mnemonic: "ADD IX, IX",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IX, (nn)",
			data: []byte{0xDD, 0x2A, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "LD IX, ($3412)",
				Length:   4,
				Address:  0x3412,
			},
		},
		{
			name: "DEC IX",
			data: []byte{0xDD, 0x2B},
			expected: Instruction{
				Mnemonic: "DEC IX",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "INC IXL",
			data: []byte{0xDD, 0x2C},
			expected: Instruction{
				Mnemonic: "INC IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "DEC IXL",
			data: []byte{0xDD, 0x2D},
			expected: Instruction{
				Mnemonic: "DEC IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXL, n",
			data: []byte{0xDD, 0x2E, 0x42},
			expected: Instruction{
				Mnemonic: "LD IXL, $42",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "INC (IX+d)",
			data: []byte{0xDD, 0x34, 0x05},
			expected: Instruction{
				Mnemonic: "INC (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "DEC (IX+d)",
			data: []byte{0xDD, 0x35, 0x05},
			expected: Instruction{
				Mnemonic: "DEC (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IX+d), n",
			data: []byte{0xDD, 0x36, 0x05, 0x42},
			expected: Instruction{
				Mnemonic: "LD (IX+$05), $42",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADD IX, SP",
			data: []byte{0xDD, 0x39},
			expected: Instruction{
				Mnemonic: "ADD IX, SP",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD B, IXH",
			data: []byte{0xDD, 0x44},
			expected: Instruction{
				Mnemonic: "LD B, IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD B, IXL",
			data: []byte{0xDD, 0x45},
			expected: Instruction{
				Mnemonic: "LD B, IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD B, (IX+d)",
			data: []byte{0xDD, 0x46, 0x05},
			expected: Instruction{
				Mnemonic: "LD B, (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD C, IXH",
			data: []byte{0xDD, 0x4C},
			expected: Instruction{
				Mnemonic: "LD C, IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD C, IXL",
			data: []byte{0xDD, 0x4D},
			expected: Instruction{
				Mnemonic: "LD C, IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD C, (IX+d)",
			data: []byte{0xDD, 0x4E, 0x05},
			expected: Instruction{
				Mnemonic: "LD C, (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD D, IXH",
			data: []byte{0xDD, 0x54},
			expected: Instruction{
				Mnemonic: "LD D, IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD D, IXL",
			data: []byte{0xDD, 0x55},
			expected: Instruction{
				Mnemonic: "LD D, IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD D, (IX+d)",
			data: []byte{0xDD, 0x56, 0x05},
			expected: Instruction{
				Mnemonic: "LD D, (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD E, IXH",
			data: []byte{0xDD, 0x5C},
			expected: Instruction{
				Mnemonic: "LD E, IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD E, IXL",
			data: []byte{0xDD, 0x5D},
			expected: Instruction{
				Mnemonic: "LD E, IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD E, (IX+d)",
			data: []byte{0xDD, 0x5E, 0x05},
			expected: Instruction{
				Mnemonic: "LD E, (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXH, B",
			data: []byte{0xDD, 0x60},
			expected: Instruction{
				Mnemonic: "LD IXH, B",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXH, C",
			data: []byte{0xDD, 0x61},
			expected: Instruction{
				Mnemonic: "LD IXH, C",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXH, D",
			data: []byte{0xDD, 0x62},
			expected: Instruction{
				Mnemonic: "LD IXH, D",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXH, E",
			data: []byte{0xDD, 0x63},
			expected: Instruction{
				Mnemonic: "LD IXH, E",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXH, IXH",
			data: []byte{0xDD, 0x64},
			expected: Instruction{
				Mnemonic: "LD IXH, IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXH, IXL",
			data: []byte{0xDD, 0x65},
			expected: Instruction{
				Mnemonic: "LD IXH, IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD H, (IX+d)",
			data: []byte{0xDD, 0x66, 0x05},
			expected: Instruction{
				Mnemonic: "LD H, (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXH, A",
			data: []byte{0xDD, 0x67},
			expected: Instruction{
				Mnemonic: "LD IXH, A",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXL, B",
			data: []byte{0xDD, 0x68},
			expected: Instruction{
				Mnemonic: "LD IXL, B",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXL, C",
			data: []byte{0xDD, 0x69},
			expected: Instruction{
				Mnemonic: "LD IXL, C",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXL, D",
			data: []byte{0xDD, 0x6A},
			expected: Instruction{
				Mnemonic: "LD IXL, D",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXL, E",
			data: []byte{0xDD, 0x6B},
			expected: Instruction{
				Mnemonic: "LD IXL, E",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXL, IXH",
			data: []byte{0xDD, 0x6C},
			expected: Instruction{
				Mnemonic: "LD IXL, IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXL, IXL",
			data: []byte{0xDD, 0x6D},
			expected: Instruction{
				Mnemonic: "LD IXL, IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD L, (IX+d)",
			data: []byte{0xDD, 0x6E, 0x05},
			expected: Instruction{
				Mnemonic: "LD L, (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IXL, A",
			data: []byte{0xDD, 0x6F},
			expected: Instruction{
				Mnemonic: "LD IXL, A",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IX+d), B",
			data: []byte{0xDD, 0x70, 0x05},
			expected: Instruction{
				Mnemonic: "LD (IX+$05), B",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IX+d), C",
			data: []byte{0xDD, 0x71, 0x05},
			expected: Instruction{
				Mnemonic: "LD (IX+$05), C",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IX+d), D",
			data: []byte{0xDD, 0x72, 0x05},
			expected: Instruction{
				Mnemonic: "LD (IX+$05), D",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IX+d), E",
			data: []byte{0xDD, 0x73, 0x05},
			expected: Instruction{
				Mnemonic: "LD (IX+$05), E",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IX+d), H",
			data: []byte{0xDD, 0x74, 0x05},
			expected: Instruction{
				Mnemonic: "LD (IX+$05), H",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IX+d), L",
			data: []byte{0xDD, 0x75, 0x05},
			expected: Instruction{
				Mnemonic: "LD (IX+$05), L",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IX+d), A",
			data: []byte{0xDD, 0x77, 0x05},
			expected: Instruction{
				Mnemonic: "LD (IX+$05), A",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD A, IXH",
			data: []byte{0xDD, 0x7C},
			expected: Instruction{
				Mnemonic: "LD A, IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD A, IXL",
			data: []byte{0xDD, 0x7D},
			expected: Instruction{
				Mnemonic: "LD A, IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD A, (IX+d)",
			data: []byte{0xDD, 0x7E, 0x05},
			expected: Instruction{
				Mnemonic: "LD A, (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADD A, IXH",
			data: []byte{0xDD, 0x84},
			expected: Instruction{
				Mnemonic: "ADD A, IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADD A, IXL",
			data: []byte{0xDD, 0x85},
			expected: Instruction{
				Mnemonic: "ADD A, IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADD A, (IX+d)",
			data: []byte{0xDD, 0x86, 0x05},
			expected: Instruction{
				Mnemonic: "ADD A, (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADC A, IXH",
			data: []byte{0xDD, 0x8C},
			expected: Instruction{
				Mnemonic: "ADC A, IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADC A, IXL",
			data: []byte{0xDD, 0x8D},
			expected: Instruction{
				Mnemonic: "ADC A, IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADC A, (IX+d)",
			data: []byte{0xDD, 0x8E, 0x05},
			expected: Instruction{
				Mnemonic: "ADC A, (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "SUB IXH",
			data: []byte{0xDD, 0x94},
			expected: Instruction{
				Mnemonic: "SUB IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "SUB IXL",
			data: []byte{0xDD, 0x95},
			expected: Instruction{
				Mnemonic: "SUB IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "SUB (IX+d)",
			data: []byte{0xDD, 0x96, 0x05},
			expected: Instruction{
				Mnemonic: "SUB (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "SBC A, IXH",
			data: []byte{0xDD, 0x9C},
			expected: Instruction{
				Mnemonic: "SBC A, IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "SBC A, IXL",
			data: []byte{0xDD, 0x9D},
			expected: Instruction{
				Mnemonic: "SBC A, IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "SBC A, (IX+d)",
			data: []byte{0xDD, 0x9E, 0x05},
			expected: Instruction{
				Mnemonic: "SBC A, (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "AND IXH",
			data: []byte{0xDD, 0xA4},
			expected: Instruction{
				Mnemonic: "AND IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "AND IXL",
			data: []byte{0xDD, 0xA5},
			expected: Instruction{
				Mnemonic: "AND IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "AND (IX+d)",
			data: []byte{0xDD, 0xA6, 0x05},
			expected: Instruction{
				Mnemonic: "AND (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "XOR IXH",
			data: []byte{0xDD, 0xAC},
			expected: Instruction{
				Mnemonic: "XOR IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "XOR IXL",
			data: []byte{0xDD, 0xAD},
			expected: Instruction{
				Mnemonic: "XOR IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "XOR (IX+d)",
			data: []byte{0xDD, 0xAE, 0x05},
			expected: Instruction{
				Mnemonic: "XOR (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "OR IXH",
			data: []byte{0xDD, 0xB4},
			expected: Instruction{
				Mnemonic: "OR IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OR IXL",
			data: []byte{0xDD, 0xB5},
			expected: Instruction{
				Mnemonic: "OR IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OR (IX+d)",
			data: []byte{0xDD, 0xB6, 0x05},
			expected: Instruction{
				Mnemonic: "OR (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "CP IXH",
			data: []byte{0xDD, 0xBC},
			expected: Instruction{
				Mnemonic: "CP IXH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "CP IXL",
			data: []byte{0xDD, 0xBD},
			expected: Instruction{
				Mnemonic: "CP IXL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "CP (IX+d)",
			data: []byte{0xDD, 0xBE, 0x05},
			expected: Instruction{
				Mnemonic: "CP (IX+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "POP IX",
			data: []byte{0xDD, 0xE1},
			expected: Instruction{
				Mnemonic: "POP IX",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "EX (SP), IX",
			data: []byte{0xDD, 0xE3},
			expected: Instruction{
				Mnemonic: "EX (SP), IX",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "PUSH IX",
			data: []byte{0xDD, 0xE5},
			expected: Instruction{
				Mnemonic: "PUSH IX",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "JP (IX)",
			data: []byte{0xDD, 0xE9},
			expected: Instruction{
				Mnemonic: "JP (IX)",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD SP, IX",
			data: []byte{0xDD, 0xF9},
			expected: Instruction{
				Mnemonic: "LD SP, IX",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name:     "Insufficient data for DD prefix",
			data:     []byte{0xDD},
			hasError: true,
		},
		{
			name:     "Insufficient data for LD IX, nn",
			data:     []byte{0xDD, 0x21, 0x34},
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
