// Package disasm provides tests for the Z80 disassembler implementation
package disasm

import (
	"testing"
)

// TestDecodeUnprefixed tests decoding of unprefixed Z80 instructions
func TestDecodeUnprefixed(t *testing.T) {
	d := New()

	tests := []struct {
		name     string
		data     []byte
		expected Instruction
		hasError bool
	}{
		{
			name: "NOP",
			data: []byte{0x00},
			expected: Instruction{
				Mnemonic: "NOP",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD BC, nn",
			data: []byte{0x01, 0x34, 0x12},
			expected: Instruction{
				Mnemonic: "LD BC, $1234",
				Length:   3,
				Address:  0x1234,
			},
		},
		{
			name: "LD (BC), A",
			data: []byte{0x02},
			expected: Instruction{
				Mnemonic: "LD (BC), A",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "INC BC",
			data: []byte{0x03},
			expected: Instruction{
				Mnemonic: "INC BC",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "INC B",
			data: []byte{0x04},
			expected: Instruction{
				Mnemonic: "INC B",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "DEC B",
			data: []byte{0x05},
			expected: Instruction{
				Mnemonic: "DEC B",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD B, n",
			data: []byte{0x06, 0x42},
			expected: Instruction{
				Mnemonic: "LD B, $42",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLCA",
			data: []byte{0x07},
			expected: Instruction{
				Mnemonic: "RLCA",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "EX AF, AF'",
			data: []byte{0x08},
			expected: Instruction{
				Mnemonic: "EX AF, AF'",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "ADD HL, BC",
			data: []byte{0x09},
			expected: Instruction{
				Mnemonic: "ADD HL, BC",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD A, (BC)",
			data: []byte{0x0A},
			expected: Instruction{
				Mnemonic: "LD A, (BC)",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "DEC BC",
			data: []byte{0x0B},
			expected: Instruction{
				Mnemonic: "DEC BC",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "INC C",
			data: []byte{0x0C},
			expected: Instruction{
				Mnemonic: "INC C",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "DEC C",
			data: []byte{0x0D},
			expected: Instruction{
				Mnemonic: "DEC C",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD C, n",
			data: []byte{0x0E, 0xAB},
			expected: Instruction{
				Mnemonic: "LD C, $AB",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "RRCA",
			data: []byte{0x0F},
			expected: Instruction{
				Mnemonic: "RRCA",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "DJNZ e",
			data: []byte{0x10, 0x05},
			expected: Instruction{
				Mnemonic: "DJNZ $05",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "JR e",
			data: []byte{0x18, 0x0A},
			expected: Instruction{
				Mnemonic: "JR $0A",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "JR NZ, e",
			data: []byte{0x20, 0x05},
			expected: Instruction{
				Mnemonic: "JR NZ, $05",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "JR Z, e",
			data: []byte{0x28, 0x05},
			expected: Instruction{
				Mnemonic: "JR Z, $05",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "JR NC, e",
			data: []byte{0x30, 0x05},
			expected: Instruction{
				Mnemonic: "JR NC, $05",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "JR C, e",
			data: []byte{0x38, 0x05},
			expected: Instruction{
				Mnemonic: "JR C, $05",
				Length:   2,
				Address:  0xFFFF,
			},
		},
		{
			name: "LD HL, nn",
			data: []byte{0x21, 0xCD, 0xAB},
			expected: Instruction{
				Mnemonic: "LD HL, $ABCD",
				Length:   3,
				Address:  0xABCD,
			},
		},
		{
			name: "LD (nn), HL",
			data: []byte{0x22, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "LD ($3412), HL",
				Length:   3,
				Address:  0x3412,
			},
		},
		{
			name: "LD HL, (nn)",
			data: []byte{0x2A, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "LD HL, ($3412)",
				Length:   3,
				Address:  0x3412,
			},
		},
		{
			name: "INC DE",
			data: []byte{0x13},
			expected: Instruction{
				Mnemonic: "INC DE",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "INC HL",
			data: []byte{0x23},
			expected: Instruction{
				Mnemonic: "INC HL",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "INC SP",
			data: []byte{0x33},
			expected: Instruction{
				Mnemonic: "INC SP",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "DEC DE",
			data: []byte{0x1B},
			expected: Instruction{
				Mnemonic: "DEC DE",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "DEC HL",
			data: []byte{0x2B},
			expected: Instruction{
				Mnemonic: "DEC HL",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "DEC SP",
			data: []byte{0x3B},
			expected: Instruction{
				Mnemonic: "DEC SP",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "JP nn",
			data: []byte{0xC3, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "JP $3412",
				Length:   3,
				Address:  0x3412,
			},
		},
		{
			name: "JP NZ, nn",
			data: []byte{0xC2, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "JP NZ, $3412",
				Length:   3,
				Address:  0x3412,
			},
		},
		{
			name: "JP Z, nn",
			data: []byte{0xCA, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "JP Z, $3412",
				Length:   3,
				Address:  0x3412,
			},
		},
		{
			name: "JP NC, nn",
			data: []byte{0xD2, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "JP NC, $3412",
				Length:   3,
				Address:  0x3412,
			},
		},
		{
			name: "JP C, nn",
			data: []byte{0xDA, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "JP C, $3412",
				Length:   3,
				Address:  0x3412,
			},
		},
		{
			name: "JP PO, nn",
			data: []byte{0xE2, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "JP PO, $3412",
				Length:   3,
				Address:  0x3412,
			},
		},
		{
			name: "JP PE, nn",
			data: []byte{0xEA, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "JP PE, $3412",
				Length:   3,
				Address:  0x3412,
			},
		},
		{
			name: "JP P, nn",
			data: []byte{0xF2, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "JP P, $3412",
				Length:   3,
				Address:  0x3412,
			},
		},
		{
			name: "JP M, nn",
			data: []byte{0xFA, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "JP M, $3412",
				Length:   3,
				Address:  0x3412,
			},
		},
		{
			name: "CALL nn",
			data: []byte{0xCD, 0x12, 0x34},
			expected: Instruction{
				Mnemonic: "CALL $3412",
				Length:   3,
				Address:  0x3412,
			},
		},
		{
			name: "RET",
			data: []byte{0xC9},
			expected: Instruction{
				Mnemonic: "RET",
				Length:   1,
				Address:  0xFFFF,
			},
		},
		{
			name: "RST 00H",
			data: []byte{0xC7},
			expected: Instruction{
				Mnemonic: "RST 00H",
				Length:   1,
				Address:  0x0000,
			},
		},
		{
			name: "RST 08H",
			data: []byte{0xCF},
			expected: Instruction{
				Mnemonic: "RST 08H",
				Length:   1,
				Address:  0x0008,
			},
		},
		{
			name: "RST 10H",
			data: []byte{0xD7},
			expected: Instruction{
				Mnemonic: "RST 10H",
				Length:   1,
				Address:  0x0010,
			},
		},
		{
			name: "RST 18H",
			data: []byte{0xDF},
			expected: Instruction{
				Mnemonic: "RST 18H",
				Length:   1,
				Address:  0x0018,
			},
		},
		{
			name: "RST 20H",
			data: []byte{0xE7},
			expected: Instruction{
				Mnemonic: "RST 20H",
				Length:   1,
				Address:  0x0020,
			},
		},
		{
			name: "RST 28H",
			data: []byte{0xEF},
			expected: Instruction{
				Mnemonic: "RST 28H",
				Length:   1,
				Address:  0x0028,
			},
		},
		{
			name: "RST 30H",
			data: []byte{0xF7},
			expected: Instruction{
				Mnemonic: "RST 30H",
				Length:   1,
				Address:  0x0030,
			},
		},
		{
			name: "RST 38H",
			data: []byte{0xFF},
			expected: Instruction{
				Mnemonic: "RST 38H",
				Length:   1,
				Address:  0x0038,
			},
		},
		{
			name:     "Insufficient data for LD BC, nn",
			data:     []byte{0x01, 0x34},
			hasError: true,
		},
		{
			name: "Unknown opcode",
			data: []byte{0xFF},
			expected: Instruction{
				Mnemonic: "RST 38H",
				Length:   1,
				Address:  0x0038,
			},
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
