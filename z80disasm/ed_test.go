// Package disasm provides tests for the Z80 disassembler implementation
package disasm

import (
	"testing"
)

// TestDecodeED tests decoding of ED-prefixed Z80 instructions
func TestDecodeED(t *testing.T) {
	d := New()

	tests := []struct {
		name     string
		data     []byte
		expected Instruction
		hasError bool
	}{
		{
			name: "IN B, (C)",
			data: []byte{0xED, 0x40},
			expected: Instruction{
				Mnemonic: "IN B, (C)",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OUT (C), B",
			data: []byte{0xED, 0x41},
			expected: Instruction{
				Mnemonic: "OUT (C), B",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "SBC HL, BC",
			data: []byte{0xED, 0x42},
			expected: Instruction{
				Mnemonic: "SBC HL, BC",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (nn), BC",
			data: []byte{0xED, 0x43, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "LD ($3412), BC",
				Length:   4,
				Address:  0x3412,
			},
		},
		{
			name: "NEG",
			data: []byte{0xED, 0x44},
			expected: Instruction{
				Mnemonic: "NEG",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RETN",
			data: []byte{0xED, 0x45},
			expected: Instruction{
				Mnemonic: "RETN",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IM 0",
			data: []byte{0xED, 0x46},
			expected: Instruction{
				Mnemonic: "IM 0",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD I, A",
			data: []byte{0xED, 0x47},
			expected: Instruction{
				Mnemonic: "LD I, A",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IN C, (C)",
			data: []byte{0xED, 0x48},
			expected: Instruction{
				Mnemonic: "IN C, (C)",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OUT (C), C",
			data: []byte{0xED, 0x49},
			expected: Instruction{
				Mnemonic: "OUT (C), C",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADC HL, BC",
			data: []byte{0xED, 0x4A},
			expected: Instruction{
				Mnemonic: "ADC HL, BC",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD BC, (nn)",
			data: []byte{0xED, 0x4B, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "LD BC, ($3412)",
				Length:   4,
				Address:  0x3412,
			},
		},
		{
			name: "NEG (duplicate)",
			data: []byte{0xED, 0x4C},
			expected: Instruction{
				Mnemonic: "NEG",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RETI",
			data: []byte{0xED, 0x4D},
			expected: Instruction{
				Mnemonic: "RETI",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IM 0 (duplicate)",
			data: []byte{0xED, 0x4E},
			expected: Instruction{
				Mnemonic: "IM 0",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD R, A",
			data: []byte{0xED, 0x4F},
			expected: Instruction{
				Mnemonic: "LD R, A",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IN D, (C)",
			data: []byte{0xED, 0x50},
			expected: Instruction{
				Mnemonic: "IN D, (C)",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OUT (C), D",
			data: []byte{0xED, 0x51},
			expected: Instruction{
				Mnemonic: "OUT (C), D",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "SBC HL, DE",
			data: []byte{0xED, 0x52},
			expected: Instruction{
				Mnemonic: "SBC HL, DE",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (nn), DE",
			data: []byte{0xED, 0x53, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "LD ($3412), DE",
				Length:   4,
				Address:  0x3412,
			},
		},
		{
			name: "NEG (duplicate 2)",
			data: []byte{0xED, 0x54},
			expected: Instruction{
				Mnemonic: "NEG",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RETN (duplicate)",
			data: []byte{0xED, 0x55},
			expected: Instruction{
				Mnemonic: "RETN",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IM 1",
			data: []byte{0xED, 0x56},
			expected: Instruction{
				Mnemonic: "IM 1",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD A, I",
			data: []byte{0xED, 0x57},
			expected: Instruction{
				Mnemonic: "LD A, I",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IN E, (C)",
			data: []byte{0xED, 0x58},
			expected: Instruction{
				Mnemonic: "IN E, (C)",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OUT (C), E",
			data: []byte{0xED, 0x59},
			expected: Instruction{
				Mnemonic: "OUT (C), E",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADC HL, DE",
			data: []byte{0xED, 0x5A},
			expected: Instruction{
				Mnemonic: "ADC HL, DE",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD DE, (nn)",
			data: []byte{0xED, 0x5B, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "LD DE, ($3412)",
				Length:   4,
				Address:  0x3412,
			},
		},
		{
			name: "NEG (duplicate 3)",
			data: []byte{0xED, 0x5C},
			expected: Instruction{
				Mnemonic: "NEG",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RETN (duplicate 2)",
			data: []byte{0xED, 0x5D},
			expected: Instruction{
				Mnemonic: "RETN",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IM 2",
			data: []byte{0xED, 0x5E},
			expected: Instruction{
				Mnemonic: "IM 2",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD A, R",
			data: []byte{0xED, 0x5F},
			expected: Instruction{
				Mnemonic: "LD A, R",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IN H, (C)",
			data: []byte{0xED, 0x60},
			expected: Instruction{
				Mnemonic: "IN H, (C)",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OUT (C), H",
			data: []byte{0xED, 0x61},
			expected: Instruction{
				Mnemonic: "OUT (C), H",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "SBC HL, HL",
			data: []byte{0xED, 0x62},
			expected: Instruction{
				Mnemonic: "SBC HL, HL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (nn), HL",
			data: []byte{0xED, 0x63, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "LD ($3412), HL",
				Length:   4,
				Address:  0x3412,
			},
		},
		{
			name: "NEG (duplicate 4)",
			data: []byte{0xED, 0x64},
			expected: Instruction{
				Mnemonic: "NEG",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RETN (duplicate 3)",
			data: []byte{0xED, 0x65},
			expected: Instruction{
				Mnemonic: "RETN",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IM 0 (duplicate 2)",
			data: []byte{0xED, 0x66},
			expected: Instruction{
				Mnemonic: "IM 0",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RRD",
			data: []byte{0xED, 0x67},
			expected: Instruction{
				Mnemonic: "RRD",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IN L, (C)",
			data: []byte{0xED, 0x68},
			expected: Instruction{
				Mnemonic: "IN L, (C)",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OUT (C), L",
			data: []byte{0xED, 0x69},
			expected: Instruction{
				Mnemonic: "OUT (C), L",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADC HL, HL",
			data: []byte{0xED, 0x6A},
			expected: Instruction{
				Mnemonic: "ADC HL, HL",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD HL, (nn)",
			data: []byte{0xED, 0x6B, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "LD HL, ($3412)",
				Length:   4,
				Address:  0x3412,
			},
		},
		{
			name: "NEG (duplicate 5)",
			data: []byte{0xED, 0x6C},
			expected: Instruction{
				Mnemonic: "NEG",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RETN (duplicate 4)",
			data: []byte{0xED, 0x6D},
			expected: Instruction{
				Mnemonic: "RETN",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IM 0 (duplicate 3)",
			data: []byte{0xED, 0x6E},
			expected: Instruction{
				Mnemonic: "IM 0",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLD",
			data: []byte{0xED, 0x6F},
			expected: Instruction{
				Mnemonic: "RLD",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IN F, (C)",
			data: []byte{0xED, 0x70},
			expected: Instruction{
				Mnemonic: "IN F, (C)",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OUT (C), 0",
			data: []byte{0xED, 0x71},
			expected: Instruction{
				Mnemonic: "OUT (C), 0",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "SBC HL, SP",
			data: []byte{0xED, 0x72},
			expected: Instruction{
				Mnemonic: "SBC HL, SP",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD (nn), SP",
			data: []byte{0xED, 0x73, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "LD ($3412), SP",
				Length:   4,
				Address:  0x3412,
			},
		},
		{
			name: "NEG (duplicate 6)",
			data: []byte{0xED, 0x74},
			expected: Instruction{
				Mnemonic: "NEG",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RETN (duplicate 5)",
			data: []byte{0xED, 0x75},
			expected: Instruction{
				Mnemonic: "RETN",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IM 1 (duplicate)",
			data: []byte{0xED, 0x76},
			expected: Instruction{
				Mnemonic: "IM 1",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "NOP",
			data: []byte{0xED, 0x77},
			expected: Instruction{
				Mnemonic: "NOP",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IN A, (C)",
			data: []byte{0xED, 0x78},
			expected: Instruction{
				Mnemonic: "IN A, (C)",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OUT (C), A",
			data: []byte{0xED, 0x79},
			expected: Instruction{
				Mnemonic: "OUT (C), A",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADC HL, SP",
			data: []byte{0xED, 0x7A},
			expected: Instruction{
				Mnemonic: "ADC HL, SP",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD SP, (nn)",
			data: []byte{0xED, 0x7B, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "LD SP, ($3412)",
				Length:   4,
				Address:  0x3412,
			},
		},
		{
			name: "NEG (duplicate 7)",
			data: []byte{0xED, 0x7C},
			expected: Instruction{
				Mnemonic: "NEG",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RETN (duplicate 6)",
			data: []byte{0xED, 0x7D},
			expected: Instruction{
				Mnemonic: "RETN",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IM 2 (duplicate)",
			data: []byte{0xED, 0x7E},
			expected: Instruction{
				Mnemonic: "IM 2",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "NOP (duplicate)",
			data: []byte{0xED, 0x7F},
			expected: Instruction{
				Mnemonic: "NOP",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LDI",
			data: []byte{0xED, 0xA0},
			expected: Instruction{
				Mnemonic: "LDI",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "CPI",
			data: []byte{0xED, 0xA1},
			expected: Instruction{
				Mnemonic: "CPI",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "INI",
			data: []byte{0xED, 0xA2},
			expected: Instruction{
				Mnemonic: "INI",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OUTI",
			data: []byte{0xED, 0xA3},
			expected: Instruction{
				Mnemonic: "OUTI",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LDD",
			data: []byte{0xED, 0xA8},
			expected: Instruction{
				Mnemonic: "LDD",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "CPD",
			data: []byte{0xED, 0xA9},
			expected: Instruction{
				Mnemonic: "CPD",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "IND",
			data: []byte{0xED, 0xAA},
			expected: Instruction{
				Mnemonic: "IND",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OUTD",
			data: []byte{0xED, 0xAB},
			expected: Instruction{
				Mnemonic: "OUTD",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LDIR",
			data: []byte{0xED, 0xB0},
			expected: Instruction{
				Mnemonic: "LDIR",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "CPIR",
			data: []byte{0xED, 0xB1},
			expected: Instruction{
				Mnemonic: "CPIR",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "INIR",
			data: []byte{0xED, 0xB2},
			expected: Instruction{
				Mnemonic: "INIR",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OTIR",
			data: []byte{0xED, 0xB3},
			expected: Instruction{
				Mnemonic: "OTIR",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LDDR",
			data: []byte{0xED, 0xB8},
			expected: Instruction{
				Mnemonic: "LDDR",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "CPDR",
			data: []byte{0xED, 0xB9},
			expected: Instruction{
				Mnemonic: "CPDR",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "INDR",
			data: []byte{0xED, 0xBA},
			expected: Instruction{
				Mnemonic: "INDR",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "OTDR",
			data: []byte{0xED, 0xBB},
			expected: Instruction{
				Mnemonic: "OTDR",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name:     "Insufficient data for ED prefix",
			data:     []byte{0xED},
			hasError: true,
		},
		{
			name:     "Insufficient data for LD (nn), BC",
			data:     []byte{0xED, 0x43, 0x12},
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
