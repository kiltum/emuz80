// Package disasm provides tests for the Z80 disassembler implementation
package disasm

import (
	"testing"
)

// TestDecodeFD tests decoding of FD-prefixed Z80 instructions
func TestDecodeFD(t *testing.T) {
	d := New()

	tests := []struct {
		name     string
		data     []byte
		expected Instruction
		hasError bool
	}{
		{
			name: "LD IY, nn",
			data: []byte{0xFD, 0x21, 0x34, 0x12},
			expected: Instruction{
				Mnemonic: "LD IY, $1234",
				Length:   4,
				Address:  0x1234,
			},
		},
		{
			name: "ADD IY, BC",
			data: []byte{0xFD, 0x09},
			expected: Instruction{
				Mnemonic: "ADD IY, BC",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADD IY, DE",
			data: []byte{0xFD, 0x19},
			expected: Instruction{
				Mnemonic: "ADD IY, DE",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (nn), IY",
			data: []byte{0xFD, 0x22, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "LD ($3412), IY",
				Length:   4,
				Address:  0x3412,
			},
		},
		{
			name: "INC IY",
			data: []byte{0xFD, 0x23},
			expected: Instruction{
				Mnemonic: "INC IY",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "INC IYH",
			data: []byte{0xFD, 0x24},
			expected: Instruction{
				Mnemonic: "INC IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "DEC IYH",
			data: []byte{0xFD, 0x25},
			expected: Instruction{
				Mnemonic: "DEC IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYH, n",
			data: []byte{0xFD, 0x26, 0x42},
			expected: Instruction{
				Mnemonic: "LD IYH, $42",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADD IY, IY",
			data: []byte{0xFD, 0x29},
			expected: Instruction{
				Mnemonic: "ADD IY, IY",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IY, (nn)",
			data: []byte{0xFD, 0x2A, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "LD IY, ($3412)",
				Length:   4,
				Address:  0x3412,
			},
		},
		{
			name: "DEC IY",
			data: []byte{0xFD, 0x2B},
			expected: Instruction{
				Mnemonic: "DEC IY",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "INC IYL",
			data: []byte{0xFD, 0x2C},
			expected: Instruction{
				Mnemonic: "INC IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "DEC IYL",
			data: []byte{0xFD, 0x2D},
			expected: Instruction{
				Mnemonic: "DEC IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYL, n",
			data: []byte{0xFD, 0x2E, 0x42},
			expected: Instruction{
				Mnemonic: "LD IYL, $42",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "INC (IY+d)",
			data: []byte{0xFD, 0x34, 0x05},
			expected: Instruction{
				Mnemonic: "INC (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "DEC (IY+d)",
			data: []byte{0xFD, 0x35, 0x05},
			expected: Instruction{
				Mnemonic: "DEC (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IY+d), n",
			data: []byte{0xFD, 0x36, 0x05, 0x42},
			expected: Instruction{
				Mnemonic: "LD (IY+$05), $42",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADD IY, SP",
			data: []byte{0xFD, 0x39},
			expected: Instruction{
				Mnemonic: "ADD IY, SP",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD B, IYH",
			data: []byte{0xFD, 0x44},
			expected: Instruction{
				Mnemonic: "LD B, IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD B, IYL",
			data: []byte{0xFD, 0x45},
			expected: Instruction{
				Mnemonic: "LD B, IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD B, (IY+d)",
			data: []byte{0xFD, 0x46, 0x05},
			expected: Instruction{
				Mnemonic: "LD B, (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD C, IYH",
			data: []byte{0xFD, 0x4C},
			expected: Instruction{
				Mnemonic: "LD C, IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD C, IYL",
			data: []byte{0xFD, 0x4D},
			expected: Instruction{
				Mnemonic: "LD C, IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD C, (IY+d)",
			data: []byte{0xFD, 0x4E, 0x05},
			expected: Instruction{
				Mnemonic: "LD C, (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD D, IYH",
			data: []byte{0xFD, 0x54},
			expected: Instruction{
				Mnemonic: "LD D, IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD D, IYL",
			data: []byte{0xFD, 0x55},
			expected: Instruction{
				Mnemonic: "LD D, IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD D, (IY+d)",
			data: []byte{0xFD, 0x56, 0x05},
			expected: Instruction{
				Mnemonic: "LD D, (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD E, IYH",
			data: []byte{0xFD, 0x5C},
			expected: Instruction{
				Mnemonic: "LD E, IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD E, IYL",
			data: []byte{0xFD, 0x5D},
			expected: Instruction{
				Mnemonic: "LD E, IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD E, (IY+d)",
			data: []byte{0xFD, 0x5E, 0x05},
			expected: Instruction{
				Mnemonic: "LD E, (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYH, B",
			data: []byte{0xFD, 0x60},
			expected: Instruction{
				Mnemonic: "LD IYH, B",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYH, C",
			data: []byte{0xFD, 0x61},
			expected: Instruction{
				Mnemonic: "LD IYH, C",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYH, D",
			data: []byte{0xFD, 0x62},
			expected: Instruction{
				Mnemonic: "LD IYH, D",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYH, E",
			data: []byte{0xFD, 0x63},
			expected: Instruction{
				Mnemonic: "LD IYH, E",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYH, IYH",
			data: []byte{0xFD, 0x64},
			expected: Instruction{
				Mnemonic: "LD IYH, IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYH, IYL",
			data: []byte{0xFD, 0x65},
			expected: Instruction{
				Mnemonic: "LD IYH, IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD H, (IY+d)",
			data: []byte{0xFD, 0x66, 0x05},
			expected: Instruction{
				Mnemonic: "LD H, (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYH, A",
			data: []byte{0xFD, 0x67},
			expected: Instruction{
				Mnemonic: "LD IYH, A",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYL, B",
			data: []byte{0xFD, 0x68},
			expected: Instruction{
				Mnemonic: "LD IYL, B",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYL, C",
			data: []byte{0xFD, 0x69},
			expected: Instruction{
				Mnemonic: "LD IYL, C",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYL, D",
			data: []byte{0xFD, 0x6A},
			expected: Instruction{
				Mnemonic: "LD IYL, D",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYL, E",
			data: []byte{0xFD, 0x6B},
			expected: Instruction{
				Mnemonic: "LD IYL, E",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYL, IYH",
			data: []byte{0xFD, 0x6C},
			expected: Instruction{
				Mnemonic: "LD IYL, IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYL, IYL",
			data: []byte{0xFD, 0x6D},
			expected: Instruction{
				Mnemonic: "LD IYL, IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD L, (IY+d)",
			data: []byte{0xFD, 0x6E, 0x05},
			expected: Instruction{
				Mnemonic: "LD L, (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD IYL, A",
			data: []byte{0xFD, 0x6F},
			expected: Instruction{
				Mnemonic: "LD IYL, A",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IY+d), B",
			data: []byte{0xFD, 0x70, 0x05},
			expected: Instruction{
				Mnemonic: "LD (IY+$05), B",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IY+d), C",
			data: []byte{0xFD, 0x71, 0x05},
			expected: Instruction{
				Mnemonic: "LD (IY+$05), C",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IY+d), D",
			data: []byte{0xFD, 0x72, 0x05},
			expected: Instruction{
				Mnemonic: "LD (IY+$05), D",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IY+d), E",
			data: []byte{0xFD, 0x73, 0x05},
			expected: Instruction{
				Mnemonic: "LD (IY+$05), E",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IY+d), H",
			data: []byte{0xFD, 0x74, 0x05},
			expected: Instruction{
				Mnemonic: "LD (IY+$05), H",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IY+d), L",
			data: []byte{0xFD, 0x75, 0x05},
			expected: Instruction{
				Mnemonic: "LD (IY+$05), L",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (IY+d), A",
			data: []byte{0xFD, 0x77, 0x05},
			expected: Instruction{
				Mnemonic: "LD (IY+$05), A",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD A, IYH",
			data: []byte{0xFD, 0x7C},
			expected: Instruction{
				Mnemonic: "LD A, IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD A, IYL",
			data: []byte{0xFD, 0x7D},
			expected: Instruction{
				Mnemonic: "LD A, IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD A, (IY+d)",
			data: []byte{0xFD, 0x7E, 0x05},
			expected: Instruction{
				Mnemonic: "LD A, (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADD A, IYH",
			data: []byte{0xFD, 0x84},
			expected: Instruction{
				Mnemonic: "ADD A, IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADD A, IYL",
			data: []byte{0xFD, 0x85},
			expected: Instruction{
				Mnemonic: "ADD A, IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADD A, (IY+d)",
			data: []byte{0xFD, 0x86, 0x05},
			expected: Instruction{
				Mnemonic: "ADD A, (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADC A, IYH",
			data: []byte{0xFD, 0x8C},
			expected: Instruction{
				Mnemonic: "ADC A, IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADC A, IYL",
			data: []byte{0xFD, 0x8D},
			expected: Instruction{
				Mnemonic: "ADC A, IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADC A, (IY+d)",
			data: []byte{0xFD, 0x8E, 0x05},
			expected: Instruction{
				Mnemonic: "ADC A, (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "SUB IYH",
			data: []byte{0xFD, 0x94},
			expected: Instruction{
				Mnemonic: "SUB IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "SUB IYL",
			data: []byte{0xFD, 0x95},
			expected: Instruction{
				Mnemonic: "SUB IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "SUB (IY+d)",
			data: []byte{0xFD, 0x96, 0x05},
			expected: Instruction{
				Mnemonic: "SUB (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "SBC A, IYH",
			data: []byte{0xFD, 0x9C},
			expected: Instruction{
				Mnemonic: "SBC A, IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "SBC A, IYL",
			data: []byte{0xFD, 0x9D},
			expected: Instruction{
				Mnemonic: "SBC A, IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "SBC A, (IY+d)",
			data: []byte{0xFD, 0x9E, 0x05},
			expected: Instruction{
				Mnemonic: "SBC A, (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "AND IYH",
			data: []byte{0xFD, 0xA4},
			expected: Instruction{
				Mnemonic: "AND IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "AND IYL",
			data: []byte{0xFD, 0xA5},
			expected: Instruction{
				Mnemonic: "AND IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "AND (IY+d)",
			data: []byte{0xFD, 0xA6, 0x05},
			expected: Instruction{
				Mnemonic: "AND (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "XOR IYH",
			data: []byte{0xFD, 0xAC},
			expected: Instruction{
				Mnemonic: "XOR IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "XOR IYL",
			data: []byte{0xFD, 0xAD},
			expected: Instruction{
				Mnemonic: "XOR IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "XOR (IY+d)",
			data: []byte{0xFD, 0xAE, 0x05},
			expected: Instruction{
				Mnemonic: "XOR (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "OR IYH",
			data: []byte{0xFD, 0xB4},
			expected: Instruction{
				Mnemonic: "OR IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OR IYL",
			data: []byte{0xFD, 0xB5},
			expected: Instruction{
				Mnemonic: "OR IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OR (IY+d)",
			data: []byte{0xFD, 0xB6, 0x05},
			expected: Instruction{
				Mnemonic: "OR (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "CP IYH",
			data: []byte{0xFD, 0xBC},
			expected: Instruction{
				Mnemonic: "CP IYH",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "CP IYL",
			data: []byte{0xFD, 0xBD},
			expected: Instruction{
				Mnemonic: "CP IYL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "CP (IY+d)",
			data: []byte{0xFD, 0xBE, 0x05},
			expected: Instruction{
				Mnemonic: "CP (IY+$05)",
				Length:   3,
				Address:  0xFFFF,
			},
		},
		{
			name: "POP IY",
			data: []byte{0xFD, 0xE1},
			expected: Instruction{
				Mnemonic: "POP IY",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "EX (SP), IY",
			data: []byte{0xFD, 0xE3},
			expected: Instruction{
				Mnemonic: "EX (SP), IY",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "PUSH IY",
			data: []byte{0xFD, 0xE5},
			expected: Instruction{
				Mnemonic: "PUSH IY",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "JP (IY)",
			data: []byte{0xFD, 0xE9},
			expected: Instruction{
				Mnemonic: "JP (IY)",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD SP, IY",
			data: []byte{0xFD, 0xF9},
			expected: Instruction{
				Mnemonic: "LD SP, IY",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name:     "Insufficient data for FD prefix",
			data:     []byte{0xFD},
			hasError: true,
		},
		{
			name:     "Insufficient data for LD IY, nn",
			data:     []byte{0xFD, 0x21, 0x34},
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
