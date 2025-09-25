// Package disasm provides tests for the Z80 disassembler implementation
package disasm

import (
	"testing"
)

// TestDecodeFDCB tests decoding of undocumented FDCB-prefixed Z80 instructions
func TestDecodeFDCB(t *testing.T) {
	d := New()

	tests := []struct {
		name     string
		data     []byte
		expected Instruction
		hasError bool
	}{
		// RLC with register targeting (undocumented)
		{
			name: "RLC B",
			data: []byte{0xFD, 0xCB, 0x05, 0x00},
			expected: Instruction{
				Mnemonic: "RLC B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLC C",
			data: []byte{0xFD, 0xCB, 0x05, 0x01},
			expected: Instruction{
				Mnemonic: "RLC C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLC D",
			data: []byte{0xFD, 0xCB, 0x05, 0x02},
			expected: Instruction{
				Mnemonic: "RLC D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLC E",
			data: []byte{0xFD, 0xCB, 0x05, 0x03},
			expected: Instruction{
				Mnemonic: "RLC E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLC H",
			data: []byte{0xFD, 0xCB, 0x05, 0x04},
			expected: Instruction{
				Mnemonic: "RLC H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLC L",
			data: []byte{0xFD, 0xCB, 0x05, 0x05},
			expected: Instruction{
				Mnemonic: "RLC L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLC (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x06},
			expected: Instruction{
				Mnemonic: "RLC (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RLC A",
			data: []byte{0xFD, 0xCB, 0x05, 0x07},
			expected: Instruction{
				Mnemonic: "RLC A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// RRC with register targeting (undocumented)
		{
			name: "RRC B",
			data: []byte{0xFD, 0xCB, 0x05, 0x08},
			expected: Instruction{
				Mnemonic: "RRC B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RRC C",
			data: []byte{0xFD, 0xCB, 0x05, 0x09},
			expected: Instruction{
				Mnemonic: "RRC C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RRC D",
			data: []byte{0xFD, 0xCB, 0x05, 0x0A},
			expected: Instruction{
				Mnemonic: "RRC D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RRC E",
			data: []byte{0xFD, 0xCB, 0x05, 0x0B},
			expected: Instruction{
				Mnemonic: "RRC E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RRC H",
			data: []byte{0xFD, 0xCB, 0x05, 0x0C},
			expected: Instruction{
				Mnemonic: "RRC H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RRC L",
			data: []byte{0xFD, 0xCB, 0x05, 0x0D},
			expected: Instruction{
				Mnemonic: "RRC L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RRC (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x0E},
			expected: Instruction{
				Mnemonic: "RRC (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RRC A",
			data: []byte{0xFD, 0xCB, 0x05, 0x0F},
			expected: Instruction{
				Mnemonic: "RRC A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// RL with register targeting (undocumented)
		{
			name: "RL B",
			data: []byte{0xFD, 0xCB, 0x05, 0x10},
			expected: Instruction{
				Mnemonic: "RL B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RL C",
			data: []byte{0xFD, 0xCB, 0x05, 0x11},
			expected: Instruction{
				Mnemonic: "RL C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RL D",
			data: []byte{0xFD, 0xCB, 0x05, 0x12},
			expected: Instruction{
				Mnemonic: "RL D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RL E",
			data: []byte{0xFD, 0xCB, 0x05, 0x13},
			expected: Instruction{
				Mnemonic: "RL E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RL H",
			data: []byte{0xFD, 0xCB, 0x05, 0x14},
			expected: Instruction{
				Mnemonic: "RL H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RL L",
			data: []byte{0xFD, 0xCB, 0x05, 0x15},
			expected: Instruction{
				Mnemonic: "RL L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RL (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x16},
			expected: Instruction{
				Mnemonic: "RL (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RL A",
			data: []byte{0xFD, 0xCB, 0x05, 0x17},
			expected: Instruction{
				Mnemonic: "RL A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// RR with register targeting (undocumented)
		{
			name: "RR B",
			data: []byte{0xFD, 0xCB, 0x05, 0x18},
			expected: Instruction{
				Mnemonic: "RR B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RR C",
			data: []byte{0xFD, 0xCB, 0x05, 0x19},
			expected: Instruction{
				Mnemonic: "RR C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RR D",
			data: []byte{0xFD, 0xCB, 0x05, 0x1A},
			expected: Instruction{
				Mnemonic: "RR D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RR E",
			data: []byte{0xFD, 0xCB, 0x05, 0x1B},
			expected: Instruction{
				Mnemonic: "RR E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RR H",
			data: []byte{0xFD, 0xCB, 0x05, 0x1C},
			expected: Instruction{
				Mnemonic: "RR H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RR L",
			data: []byte{0xFD, 0xCB, 0x05, 0x1D},
			expected: Instruction{
				Mnemonic: "RR L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RR (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x1E},
			expected: Instruction{
				Mnemonic: "RR (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RR A",
			data: []byte{0xFD, 0xCB, 0x05, 0x1F},
			expected: Instruction{
				Mnemonic: "RR A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// SLA with register targeting (undocumented)
		{
			name: "SLA B",
			data: []byte{0xFD, 0xCB, 0x05, 0x20},
			expected: Instruction{
				Mnemonic: "SLA B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SLA C",
			data: []byte{0xFD, 0xCB, 0x05, 0x21},
			expected: Instruction{
				Mnemonic: "SLA C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SLA D",
			data: []byte{0xFD, 0xCB, 0x05, 0x22},
			expected: Instruction{
				Mnemonic: "SLA D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SLA E",
			data: []byte{0xFD, 0xCB, 0x05, 0x23},
			expected: Instruction{
				Mnemonic: "SLA E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SLA H",
			data: []byte{0xFD, 0xCB, 0x05, 0x24},
			expected: Instruction{
				Mnemonic: "SLA H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SLA L",
			data: []byte{0xFD, 0xCB, 0x05, 0x25},
			expected: Instruction{
				Mnemonic: "SLA L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SLA (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x26},
			expected: Instruction{
				Mnemonic: "SLA (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SLA A",
			data: []byte{0xFD, 0xCB, 0x05, 0x27},
			expected: Instruction{
				Mnemonic: "SLA A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// SRA with register targeting (undocumented)
		{
			name: "SRA B",
			data: []byte{0xFD, 0xCB, 0x05, 0x28},
			expected: Instruction{
				Mnemonic: "SRA B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SRA C",
			data: []byte{0xFD, 0xCB, 0x05, 0x29},
			expected: Instruction{
				Mnemonic: "SRA C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SRA D",
			data: []byte{0xFD, 0xCB, 0x05, 0x2A},
			expected: Instruction{
				Mnemonic: "SRA D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SRA E",
			data: []byte{0xFD, 0xCB, 0x05, 0x2B},
			expected: Instruction{
				Mnemonic: "SRA E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SRA H",
			data: []byte{0xFD, 0xCB, 0x05, 0x2C},
			expected: Instruction{
				Mnemonic: "SRA H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SRA L",
			data: []byte{0xFD, 0xCB, 0x05, 0x2D},
			expected: Instruction{
				Mnemonic: "SRA L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SRA (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x2E},
			expected: Instruction{
				Mnemonic: "SRA (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SRA A",
			data: []byte{0xFD, 0xCB, 0x05, 0x2F},
			expected: Instruction{
				Mnemonic: "SRA A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// SLL with register targeting (undocumented)
		{
			name: "SLL B",
			data: []byte{0xFD, 0xCB, 0x05, 0x30},
			expected: Instruction{
				Mnemonic: "SLL B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SLL C",
			data: []byte{0xFD, 0xCB, 0x05, 0x31},
			expected: Instruction{
				Mnemonic: "SLL C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SLL D",
			data: []byte{0xFD, 0xCB, 0x05, 0x32},
			expected: Instruction{
				Mnemonic: "SLL D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SLL E",
			data: []byte{0xFD, 0xCB, 0x05, 0x33},
			expected: Instruction{
				Mnemonic: "SLL E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SLL H",
			data: []byte{0xFD, 0xCB, 0x05, 0x34},
			expected: Instruction{
				Mnemonic: "SLL H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SLL L",
			data: []byte{0xFD, 0xCB, 0x05, 0x35},
			expected: Instruction{
				Mnemonic: "SLL L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SLL (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x36},
			expected: Instruction{
				Mnemonic: "SLL (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SLL A",
			data: []byte{0xFD, 0xCB, 0x05, 0x37},
			expected: Instruction{
				Mnemonic: "SLL A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// SRL with register targeting (undocumented)
		{
			name: "SRL B",
			data: []byte{0xFD, 0xCB, 0x05, 0x38},
			expected: Instruction{
				Mnemonic: "SRL B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SRL C",
			data: []byte{0xFD, 0xCB, 0x05, 0x39},
			expected: Instruction{
				Mnemonic: "SRL C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SRL D",
			data: []byte{0xFD, 0xCB, 0x05, 0x3A},
			expected: Instruction{
				Mnemonic: "SRL D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SRL E",
			data: []byte{0xFD, 0xCB, 0x05, 0x3B},
			expected: Instruction{
				Mnemonic: "SRL E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SRL H",
			data: []byte{0xFD, 0xCB, 0x05, 0x3C},
			expected: Instruction{
				Mnemonic: "SRL H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SRL L",
			data: []byte{0xFD, 0xCB, 0x05, 0x3D},
			expected: Instruction{
				Mnemonic: "SRL L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SRL (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x3E},
			expected: Instruction{
				Mnemonic: "SRL (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SRL A",
			data: []byte{0xFD, 0xCB, 0x05, 0x3F},
			expected: Instruction{
				Mnemonic: "SRL A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// BIT 0 with register targeting (undocumented)
		{
			name: "BIT 0, B",
			data: []byte{0xFD, 0xCB, 0x05, 0x40},
			expected: Instruction{
				Mnemonic: "BIT 0, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 0, C",
			data: []byte{0xFD, 0xCB, 0x05, 0x41},
			expected: Instruction{
				Mnemonic: "BIT 0, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 0, D",
			data: []byte{0xFD, 0xCB, 0x05, 0x42},
			expected: Instruction{
				Mnemonic: "BIT 0, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 0, E",
			data: []byte{0xFD, 0xCB, 0x05, 0x43},
			expected: Instruction{
				Mnemonic: "BIT 0, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 0, H",
			data: []byte{0xFD, 0xCB, 0x05, 0x44},
			expected: Instruction{
				Mnemonic: "BIT 0, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 0, L",
			data: []byte{0xFD, 0xCB, 0x05, 0x45},
			expected: Instruction{
				Mnemonic: "BIT 0, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 0, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x46},
			expected: Instruction{
				Mnemonic: "BIT 0, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 0, A",
			data: []byte{0xFD, 0xCB, 0x05, 0x47},
			expected: Instruction{
				Mnemonic: "BIT 0, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// BIT 1 with register targeting (undocumented)
		{
			name: "BIT 1, B",
			data: []byte{0xFD, 0xCB, 0x05, 0x48},
			expected: Instruction{
				Mnemonic: "BIT 1, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 1, C",
			data: []byte{0xFD, 0xCB, 0x05, 0x49},
			expected: Instruction{
				Mnemonic: "BIT 1, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 1, D",
			data: []byte{0xFD, 0xCB, 0x05, 0x4A},
			expected: Instruction{
				Mnemonic: "BIT 1, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 1, E",
			data: []byte{0xFD, 0xCB, 0x05, 0x4B},
			expected: Instruction{
				Mnemonic: "BIT 1, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 1, H",
			data: []byte{0xFD, 0xCB, 0x05, 0x4C},
			expected: Instruction{
				Mnemonic: "BIT 1, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 1, L",
			data: []byte{0xFD, 0xCB, 0x05, 0x4D},
			expected: Instruction{
				Mnemonic: "BIT 1, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 1, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x4E},
			expected: Instruction{
				Mnemonic: "BIT 1, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 1, A",
			data: []byte{0xFD, 0xCB, 0x05, 0x4F},
			expected: Instruction{
				Mnemonic: "BIT 1, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// BIT 2 with register targeting (undocumented)
		{
			name: "BIT 2, B",
			data: []byte{0xFD, 0xCB, 0x05, 0x50},
			expected: Instruction{
				Mnemonic: "BIT 2, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 2, C",
			data: []byte{0xFD, 0xCB, 0x05, 0x51},
			expected: Instruction{
				Mnemonic: "BIT 2, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 2, D",
			data: []byte{0xFD, 0xCB, 0x05, 0x52},
			expected: Instruction{
				Mnemonic: "BIT 2, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 2, E",
			data: []byte{0xFD, 0xCB, 0x05, 0x53},
			expected: Instruction{
				Mnemonic: "BIT 2, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 2, H",
			data: []byte{0xFD, 0xCB, 0x05, 0x54},
			expected: Instruction{
				Mnemonic: "BIT 2, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 2, L",
			data: []byte{0xFD, 0xCB, 0x05, 0x55},
			expected: Instruction{
				Mnemonic: "BIT 2, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 2, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x56},
			expected: Instruction{
				Mnemonic: "BIT 2, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 2, A",
			data: []byte{0xFD, 0xCB, 0x05, 0x57},
			expected: Instruction{
				Mnemonic: "BIT 2, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// BIT 3 with register targeting (undocumented)
		{
			name: "BIT 3, B",
			data: []byte{0xFD, 0xCB, 0x05, 0x58},
			expected: Instruction{
				Mnemonic: "BIT 3, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 3, C",
			data: []byte{0xFD, 0xCB, 0x05, 0x59},
			expected: Instruction{
				Mnemonic: "BIT 3, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 3, D",
			data: []byte{0xFD, 0xCB, 0x05, 0x5A},
			expected: Instruction{
				Mnemonic: "BIT 3, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 3, E",
			data: []byte{0xFD, 0xCB, 0x05, 0x5B},
			expected: Instruction{
				Mnemonic: "BIT 3, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 3, H",
			data: []byte{0xFD, 0xCB, 0x05, 0x5C},
			expected: Instruction{
				Mnemonic: "BIT 3, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 3, L",
			data: []byte{0xFD, 0xCB, 0x05, 0x5D},
			expected: Instruction{
				Mnemonic: "BIT 3, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 3, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x5E},
			expected: Instruction{
				Mnemonic: "BIT 3, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 3, A",
			data: []byte{0xFD, 0xCB, 0x05, 0x5F},
			expected: Instruction{
				Mnemonic: "BIT 3, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// BIT 4 with register targeting (undocumented)
		{
			name: "BIT 4, B",
			data: []byte{0xFD, 0xCB, 0x05, 0x60},
			expected: Instruction{
				Mnemonic: "BIT 4, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 4, C",
			data: []byte{0xFD, 0xCB, 0x05, 0x61},
			expected: Instruction{
				Mnemonic: "BIT 4, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 4, D",
			data: []byte{0xFD, 0xCB, 0x05, 0x62},
			expected: Instruction{
				Mnemonic: "BIT 4, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 4, E",
			data: []byte{0xFD, 0xCB, 0x05, 0x63},
			expected: Instruction{
				Mnemonic: "BIT 4, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 4, H",
			data: []byte{0xFD, 0xCB, 0x05, 0x64},
			expected: Instruction{
				Mnemonic: "BIT 4, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 4, L",
			data: []byte{0xFD, 0xCB, 0x05, 0x65},
			expected: Instruction{
				Mnemonic: "BIT 4, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 4, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x66},
			expected: Instruction{
				Mnemonic: "BIT 4, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 4, A",
			data: []byte{0xFD, 0xCB, 0x05, 0x67},
			expected: Instruction{
				Mnemonic: "BIT 4, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// BIT 5 with register targeting (undocumented)
		{
			name: "BIT 5, B",
			data: []byte{0xFD, 0xCB, 0x05, 0x68},
			expected: Instruction{
				Mnemonic: "BIT 5, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 5, C",
			data: []byte{0xFD, 0xCB, 0x05, 0x69},
			expected: Instruction{
				Mnemonic: "BIT 5, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 5, D",
			data: []byte{0xFD, 0xCB, 0x05, 0x6A},
			expected: Instruction{
				Mnemonic: "BIT 5, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 5, E",
			data: []byte{0xFD, 0xCB, 0x05, 0x6B},
			expected: Instruction{
				Mnemonic: "BIT 5, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 5, H",
			data: []byte{0xFD, 0xCB, 0x05, 0x6C},
			expected: Instruction{
				Mnemonic: "BIT 5, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 5, L",
			data: []byte{0xFD, 0xCB, 0x05, 0x6D},
			expected: Instruction{
				Mnemonic: "BIT 5, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 5, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x6E},
			expected: Instruction{
				Mnemonic: "BIT 5, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 5, A",
			data: []byte{0xFD, 0xCB, 0x05, 0x6F},
			expected: Instruction{
				Mnemonic: "BIT 5, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// BIT 6 with register targeting (undocumented)
		{
			name: "BIT 6, B",
			data: []byte{0xFD, 0xCB, 0x05, 0x70},
			expected: Instruction{
				Mnemonic: "BIT 6, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 6, C",
			data: []byte{0xFD, 0xCB, 0x05, 0x71},
			expected: Instruction{
				Mnemonic: "BIT 6, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 6, D",
			data: []byte{0xFD, 0xCB, 0x05, 0x72},
			expected: Instruction{
				Mnemonic: "BIT 6, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 6, E",
			data: []byte{0xFD, 0xCB, 0x05, 0x73},
			expected: Instruction{
				Mnemonic: "BIT 6, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 6, H",
			data: []byte{0xFD, 0xCB, 0x05, 0x74},
			expected: Instruction{
				Mnemonic: "BIT 6, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 6, L",
			data: []byte{0xFD, 0xCB, 0x05, 0x75},
			expected: Instruction{
				Mnemonic: "BIT 6, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 6, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x76},
			expected: Instruction{
				Mnemonic: "BIT 6, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 6, A",
			data: []byte{0xFD, 0xCB, 0x05, 0x77},
			expected: Instruction{
				Mnemonic: "BIT 6, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// BIT 7 with register targeting (undocumented)
		{
			name: "BIT 7, B",
			data: []byte{0xFD, 0xCB, 0x05, 0x78},
			expected: Instruction{
				Mnemonic: "BIT 7, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 7, C",
			data: []byte{0xFD, 0xCB, 0x05, 0x79},
			expected: Instruction{
				Mnemonic: "BIT 7, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 7, D",
			data: []byte{0xFD, 0xCB, 0x05, 0x7A},
			expected: Instruction{
				Mnemonic: "BIT 7, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 7, E",
			data: []byte{0xFD, 0xCB, 0x05, 0x7B},
			expected: Instruction{
				Mnemonic: "BIT 7, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 7, H",
			data: []byte{0xFD, 0xCB, 0x05, 0x7C},
			expected: Instruction{
				Mnemonic: "BIT 7, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 7, L",
			data: []byte{0xFD, 0xCB, 0x05, 0x7D},
			expected: Instruction{
				Mnemonic: "BIT 7, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 7, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x7E},
			expected: Instruction{
				Mnemonic: "BIT 7, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "BIT 7, A",
			data: []byte{0xFD, 0xCB, 0x05, 0x7F},
			expected: Instruction{
				Mnemonic: "BIT 7, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// RES 0 with register targeting (undocumented)
		{
			name: "RES 0, B",
			data: []byte{0xFD, 0xCB, 0x05, 0x80},
			expected: Instruction{
				Mnemonic: "RES 0, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 0, C",
			data: []byte{0xFD, 0xCB, 0x05, 0x81},
			expected: Instruction{
				Mnemonic: "RES 0, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 0, D",
			data: []byte{0xFD, 0xCB, 0x05, 0x82},
			expected: Instruction{
				Mnemonic: "RES 0, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 0, E",
			data: []byte{0xFD, 0xCB, 0x05, 0x83},
			expected: Instruction{
				Mnemonic: "RES 0, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 0, H",
			data: []byte{0xFD, 0xCB, 0x05, 0x84},
			expected: Instruction{
				Mnemonic: "RES 0, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 0, L",
			data: []byte{0xFD, 0xCB, 0x05, 0x85},
			expected: Instruction{
				Mnemonic: "RES 0, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 0, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x86},
			expected: Instruction{
				Mnemonic: "RES 0, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 0, A",
			data: []byte{0xFD, 0xCB, 0x05, 0x87},
			expected: Instruction{
				Mnemonic: "RES 0, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// RES 1 with register targeting (undocumented)
		{
			name: "RES 1, B",
			data: []byte{0xFD, 0xCB, 0x05, 0x88},
			expected: Instruction{
				Mnemonic: "RES 1, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 1, C",
			data: []byte{0xFD, 0xCB, 0x05, 0x89},
			expected: Instruction{
				Mnemonic: "RES 1, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 1, D",
			data: []byte{0xFD, 0xCB, 0x05, 0x8A},
			expected: Instruction{
				Mnemonic: "RES 1, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 1, E",
			data: []byte{0xFD, 0xCB, 0x05, 0x8B},
			expected: Instruction{
				Mnemonic: "RES 1, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 1, H",
			data: []byte{0xFD, 0xCB, 0x05, 0x8C},
			expected: Instruction{
				Mnemonic: "RES 1, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 1, L",
			data: []byte{0xFD, 0xCB, 0x05, 0x8D},
			expected: Instruction{
				Mnemonic: "RES 1, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 1, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x8E},
			expected: Instruction{
				Mnemonic: "RES 1, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 1, A",
			data: []byte{0xFD, 0xCB, 0x05, 0x8F},
			expected: Instruction{
				Mnemonic: "RES 1, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// RES 2 with register targeting (undocumented)
		{
			name: "RES 2, B",
			data: []byte{0xFD, 0xCB, 0x05, 0x90},
			expected: Instruction{
				Mnemonic: "RES 2, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 2, C",
			data: []byte{0xFD, 0xCB, 0x05, 0x91},
			expected: Instruction{
				Mnemonic: "RES 2, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 2, D",
			data: []byte{0xFD, 0xCB, 0x05, 0x92},
			expected: Instruction{
				Mnemonic: "RES 2, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 2, E",
			data: []byte{0xFD, 0xCB, 0x05, 0x93},
			expected: Instruction{
				Mnemonic: "RES 2, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 2, H",
			data: []byte{0xFD, 0xCB, 0x05, 0x94},
			expected: Instruction{
				Mnemonic: "RES 2, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 2, L",
			data: []byte{0xFD, 0xCB, 0x05, 0x95},
			expected: Instruction{
				Mnemonic: "RES 2, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 2, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x96},
			expected: Instruction{
				Mnemonic: "RES 2, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 2, A",
			data: []byte{0xFD, 0xCB, 0x05, 0x97},
			expected: Instruction{
				Mnemonic: "RES 2, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// RES 3 with register targeting (undocumented)
		{
			name: "RES 3, B",
			data: []byte{0xFD, 0xCB, 0x05, 0x98},
			expected: Instruction{
				Mnemonic: "RES 3, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 3, C",
			data: []byte{0xFD, 0xCB, 0x05, 0x99},
			expected: Instruction{
				Mnemonic: "RES 3, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 3, D",
			data: []byte{0xFD, 0xCB, 0x05, 0x9A},
			expected: Instruction{
				Mnemonic: "RES 3, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 3, E",
			data: []byte{0xFD, 0xCB, 0x05, 0x9B},
			expected: Instruction{
				Mnemonic: "RES 3, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 3, H",
			data: []byte{0xFD, 0xCB, 0x05, 0x9C},
			expected: Instruction{
				Mnemonic: "RES 3, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 3, L",
			data: []byte{0xFD, 0xCB, 0x05, 0x9D},
			expected: Instruction{
				Mnemonic: "RES 3, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 3, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0x9E},
			expected: Instruction{
				Mnemonic: "RES 3, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 3, A",
			data: []byte{0xFD, 0xCB, 0x05, 0x9F},
			expected: Instruction{
				Mnemonic: "RES 3, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// RES 4 with register targeting (undocumented)
		{
			name: "RES 4, B",
			data: []byte{0xFD, 0xCB, 0x05, 0xA0},
			expected: Instruction{
				Mnemonic: "RES 4, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 4, C",
			data: []byte{0xFD, 0xCB, 0x05, 0xA1},
			expected: Instruction{
				Mnemonic: "RES 4, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 4, D",
			data: []byte{0xFD, 0xCB, 0x05, 0xA2},
			expected: Instruction{
				Mnemonic: "RES 4, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 4, E",
			data: []byte{0xFD, 0xCB, 0x05, 0xA3},
			expected: Instruction{
				Mnemonic: "RES 4, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 4, H",
			data: []byte{0xFD, 0xCB, 0x05, 0xA4},
			expected: Instruction{
				Mnemonic: "RES 4, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 4, L",
			data: []byte{0xFD, 0xCB, 0x05, 0xA5},
			expected: Instruction{
				Mnemonic: "RES 4, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 4, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0xA6},
			expected: Instruction{
				Mnemonic: "RES 4, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 4, A",
			data: []byte{0xFD, 0xCB, 0x05, 0xA7},
			expected: Instruction{
				Mnemonic: "RES 4, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// RES 5 with register targeting (undocumented)
		{
			name: "RES 5, B",
			data: []byte{0xFD, 0xCB, 0x05, 0xA8},
			expected: Instruction{
				Mnemonic: "RES 5, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 5, C",
			data: []byte{0xFD, 0xCB, 0x05, 0xA9},
			expected: Instruction{
				Mnemonic: "RES 5, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 5, D",
			data: []byte{0xFD, 0xCB, 0x05, 0xAA},
			expected: Instruction{
				Mnemonic: "RES 5, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 5, E",
			data: []byte{0xFD, 0xCB, 0x05, 0xAB},
			expected: Instruction{
				Mnemonic: "RES 5, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 5, H",
			data: []byte{0xFD, 0xCB, 0x05, 0xAC},
			expected: Instruction{
				Mnemonic: "RES 5, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 5, L",
			data: []byte{0xFD, 0xCB, 0x05, 0xAD},
			expected: Instruction{
				Mnemonic: "RES 5, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 5, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0xAE},
			expected: Instruction{
				Mnemonic: "RES 5, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 5, A",
			data: []byte{0xFD, 0xCB, 0x05, 0xAF},
			expected: Instruction{
				Mnemonic: "RES 5, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// RES 6 with register targeting (undocumented)
		{
			name: "RES 6, B",
			data: []byte{0xFD, 0xCB, 0x05, 0xB0},
			expected: Instruction{
				Mnemonic: "RES 6, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 6, C",
			data: []byte{0xFD, 0xCB, 0x05, 0xB1},
			expected: Instruction{
				Mnemonic: "RES 6, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 6, D",
			data: []byte{0xFD, 0xCB, 0x05, 0xB2},
			expected: Instruction{
				Mnemonic: "RES 6, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 6, E",
			data: []byte{0xFD, 0xCB, 0x05, 0xB3},
			expected: Instruction{
				Mnemonic: "RES 6, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 6, H",
			data: []byte{0xFD, 0xCB, 0x05, 0xB4},
			expected: Instruction{
				Mnemonic: "RES 6, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 6, L",
			data: []byte{0xFD, 0xCB, 0x05, 0xB5},
			expected: Instruction{
				Mnemonic: "RES 6, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 6, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0xB6},
			expected: Instruction{
				Mnemonic: "RES 6, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 6, A",
			data: []byte{0xFD, 0xCB, 0x05, 0xB7},
			expected: Instruction{
				Mnemonic: "RES 6, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// RES 7 with register targeting (undocumented)
		{
			name: "RES 7, B",
			data: []byte{0xFD, 0xCB, 0x05, 0xB8},
			expected: Instruction{
				Mnemonic: "RES 7, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 7, C",
			data: []byte{0xFD, 0xCB, 0x05, 0xB9},
			expected: Instruction{
				Mnemonic: "RES 7, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 7, D",
			data: []byte{0xFD, 0xCB, 0x05, 0xBA},
			expected: Instruction{
				Mnemonic: "RES 7, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 7, E",
			data: []byte{0xFD, 0xCB, 0x05, 0xBB},
			expected: Instruction{
				Mnemonic: "RES 7, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 7, H",
			data: []byte{0xFD, 0xCB, 0x05, 0xBC},
			expected: Instruction{
				Mnemonic: "RES 7, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 7, L",
			data: []byte{0xFD, 0xCB, 0x05, 0xBD},
			expected: Instruction{
				Mnemonic: "RES 7, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 7, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0xBE},
			expected: Instruction{
				Mnemonic: "RES 7, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "RES 7, A",
			data: []byte{0xFD, 0xCB, 0x05, 0xBF},
			expected: Instruction{
				Mnemonic: "RES 7, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// SET 0 with register targeting (undocumented)
		{
			name: "SET 0, B",
			data: []byte{0xFD, 0xCB, 0x05, 0xC0},
			expected: Instruction{
				Mnemonic: "SET 0, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 0, C",
			data: []byte{0xFD, 0xCB, 0x05, 0xC1},
			expected: Instruction{
				Mnemonic: "SET 0, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 0, D",
			data: []byte{0xFD, 0xCB, 0x05, 0xC2},
			expected: Instruction{
				Mnemonic: "SET 0, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 0, E",
			data: []byte{0xFD, 0xCB, 0x05, 0xC3},
			expected: Instruction{
				Mnemonic: "SET 0, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 0, H",
			data: []byte{0xFD, 0xCB, 0x05, 0xC4},
			expected: Instruction{
				Mnemonic: "SET 0, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 0, L",
			data: []byte{0xFD, 0xCB, 0x05, 0xC5},
			expected: Instruction{
				Mnemonic: "SET 0, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 0, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0xC6},
			expected: Instruction{
				Mnemonic: "SET 0, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 0, A",
			data: []byte{0xFD, 0xCB, 0x05, 0xC7},
			expected: Instruction{
				Mnemonic: "SET 0, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// SET 1 with register targeting (undocumented)
		{
			name: "SET 1, B",
			data: []byte{0xFD, 0xCB, 0x05, 0xC8},
			expected: Instruction{
				Mnemonic: "SET 1, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 1, C",
			data: []byte{0xFD, 0xCB, 0x05, 0xC9},
			expected: Instruction{
				Mnemonic: "SET 1, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 1, D",
			data: []byte{0xFD, 0xCB, 0x05, 0xCA},
			expected: Instruction{
				Mnemonic: "SET 1, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 1, E",
			data: []byte{0xFD, 0xCB, 0x05, 0xCB},
			expected: Instruction{
				Mnemonic: "SET 1, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 1, H",
			data: []byte{0xFD, 0xCB, 0x05, 0xCC},
			expected: Instruction{
				Mnemonic: "SET 1, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 1, L",
			data: []byte{0xFD, 0xCB, 0x05, 0xCD},
			expected: Instruction{
				Mnemonic: "SET 1, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 1, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0xCE},
			expected: Instruction{
				Mnemonic: "SET 1, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 1, A",
			data: []byte{0xFD, 0xCB, 0x05, 0xCF},
			expected: Instruction{
				Mnemonic: "SET 1, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// SET 2 with register targeting (undocumented)
		{
			name: "SET 2, B",
			data: []byte{0xFD, 0xCB, 0x05, 0xD0},
			expected: Instruction{
				Mnemonic: "SET 2, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 2, C",
			data: []byte{0xFD, 0xCB, 0x05, 0xD1},
			expected: Instruction{
				Mnemonic: "SET 2, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 2, D",
			data: []byte{0xFD, 0xCB, 0x05, 0xD2},
			expected: Instruction{
				Mnemonic: "SET 2, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 2, E",
			data: []byte{0xFD, 0xCB, 0x05, 0xD3},
			expected: Instruction{
				Mnemonic: "SET 2, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 2, H",
			data: []byte{0xFD, 0xCB, 0x05, 0xD4},
			expected: Instruction{
				Mnemonic: "SET 2, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 2, L",
			data: []byte{0xFD, 0xCB, 0x05, 0xD5},
			expected: Instruction{
				Mnemonic: "SET 2, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 2, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0xD6},
			expected: Instruction{
				Mnemonic: "SET 2, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 2, A",
			data: []byte{0xFD, 0xCB, 0x05, 0xD7},
			expected: Instruction{
				Mnemonic: "SET 2, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// SET 3 with register targeting (undocumented)
		{
			name: "SET 3, B",
			data: []byte{0xFD, 0xCB, 0x05, 0xD8},
			expected: Instruction{
				Mnemonic: "SET 3, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 3, C",
			data: []byte{0xFD, 0xCB, 0x05, 0xD9},
			expected: Instruction{
				Mnemonic: "SET 3, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 3, D",
			data: []byte{0xFD, 0xCB, 0x05, 0xDA},
			expected: Instruction{
				Mnemonic: "SET 3, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 3, E",
			data: []byte{0xFD, 0xCB, 0x05, 0xDB},
			expected: Instruction{
				Mnemonic: "SET 3, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 3, H",
			data: []byte{0xFD, 0xCB, 0x05, 0xDC},
			expected: Instruction{
				Mnemonic: "SET 3, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 3, L",
			data: []byte{0xFD, 0xCB, 0x05, 0xDD},
			expected: Instruction{
				Mnemonic: "SET 3, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 3, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0xDE},
			expected: Instruction{
				Mnemonic: "SET 3, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 3, A",
			data: []byte{0xFD, 0xCB, 0x05, 0xDF},
			expected: Instruction{
				Mnemonic: "SET 3, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// SET 4 with register targeting (undocumented)
		{
			name: "SET 4, B",
			data: []byte{0xFD, 0xCB, 0x05, 0xE0},
			expected: Instruction{
				Mnemonic: "SET 4, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 4, C",
			data: []byte{0xFD, 0xCB, 0x05, 0xE1},
			expected: Instruction{
				Mnemonic: "SET 4, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 4, D",
			data: []byte{0xFD, 0xCB, 0x05, 0xE2},
			expected: Instruction{
				Mnemonic: "SET 4, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 4, E",
			data: []byte{0xFD, 0xCB, 0x05, 0xE3},
			expected: Instruction{
				Mnemonic: "SET 4, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 4, H",
			data: []byte{0xFD, 0xCB, 0x05, 0xE4},
			expected: Instruction{
				Mnemonic: "SET 4, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 4, L",
			data: []byte{0xFD, 0xCB, 0x05, 0xE5},
			expected: Instruction{
				Mnemonic: "SET 4, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 4, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0xE6},
			expected: Instruction{
				Mnemonic: "SET 4, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 4, A",
			data: []byte{0xFD, 0xCB, 0x05, 0xE7},
			expected: Instruction{
				Mnemonic: "SET 4, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// SET 5 with register targeting (undocumented)
		{
			name: "SET 5, B",
			data: []byte{0xFD, 0xCB, 0x05, 0xE8},
			expected: Instruction{
				Mnemonic: "SET 5, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 5, C",
			data: []byte{0xFD, 0xCB, 0x05, 0xE9},
			expected: Instruction{
				Mnemonic: "SET 5, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 5, D",
			data: []byte{0xFD, 0xCB, 0x05, 0xEA},
			expected: Instruction{
				Mnemonic: "SET 5, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 5, E",
			data: []byte{0xFD, 0xCB, 0x05, 0xEB},
			expected: Instruction{
				Mnemonic: "SET 5, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 5, H",
			data: []byte{0xFD, 0xCB, 0x05, 0xEC},
			expected: Instruction{
				Mnemonic: "SET 5, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 5, L",
			data: []byte{0xFD, 0xCB, 0x05, 0xED},
			expected: Instruction{
				Mnemonic: "SET 5, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 5, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0xEE},
			expected: Instruction{
				Mnemonic: "SET 5, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 5, A",
			data: []byte{0xFD, 0xCB, 0x05, 0xEF},
			expected: Instruction{
				Mnemonic: "SET 5, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// SET 6 with register targeting (undocumented)
		{
			name: "SET 6, B",
			data: []byte{0xFD, 0xCB, 0x05, 0xF0},
			expected: Instruction{
				Mnemonic: "SET 6, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 6, C",
			data: []byte{0xFD, 0xCB, 0x05, 0xF1},
			expected: Instruction{
				Mnemonic: "SET 6, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 6, D",
			data: []byte{0xFD, 0xCB, 0x05, 0xF2},
			expected: Instruction{
				Mnemonic: "SET 6, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 6, E",
			data: []byte{0xFD, 0xCB, 0x05, 0xF3},
			expected: Instruction{
				Mnemonic: "SET 6, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 6, H",
			data: []byte{0xFD, 0xCB, 0x05, 0xF4},
			expected: Instruction{
				Mnemonic: "SET 6, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 6, L",
			data: []byte{0xFD, 0xCB, 0x05, 0xF5},
			expected: Instruction{
				Mnemonic: "SET 6, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 6, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0xF6},
			expected: Instruction{
				Mnemonic: "SET 6, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 6, A",
			data: []byte{0xFD, 0xCB, 0x05, 0xF7},
			expected: Instruction{
				Mnemonic: "SET 6, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// SET 7 with register targeting (undocumented)
		{
			name: "SET 7, B",
			data: []byte{0xFD, 0xCB, 0x05, 0xF8},
			expected: Instruction{
				Mnemonic: "SET 7, B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 7, C",
			data: []byte{0xFD, 0xCB, 0x05, 0xF9},
			expected: Instruction{
				Mnemonic: "SET 7, C",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 7, D",
			data: []byte{0xFD, 0xCB, 0x05, 0xFA},
			expected: Instruction{
				Mnemonic: "SET 7, D",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 7, E",
			data: []byte{0xFD, 0xCB, 0x05, 0xFB},
			expected: Instruction{
				Mnemonic: "SET 7, E",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 7, H",
			data: []byte{0xFD, 0xCB, 0x05, 0xFC},
			expected: Instruction{
				Mnemonic: "SET 7, H",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 7, L",
			data: []byte{0xFD, 0xCB, 0x05, 0xFD},
			expected: Instruction{
				Mnemonic: "SET 7, L",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 7, (IY+$05)",
			data: []byte{0xFD, 0xCB, 0x05, 0xFE},
			expected: Instruction{
				Mnemonic: "SET 7, (IY+$05)",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name: "SET 7, A",
			data: []byte{0xFD, 0xCB, 0x05, 0xFF},
			expected: Instruction{
				Mnemonic: "SET 7, A",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		// Negative displacement tests
		{
			name: "RLC B with negative displacement",
			data: []byte{0xFD, 0xCB, 0xFB, 0x00},
			expected: Instruction{
				Mnemonic: "RLC B",
				Length:   4,
				Address:  0xFFFF,
			},
		},
		{
			name:     "Insufficient data for FDCB prefix",
			data:     []byte{0xFD, 0xCB, 0x05},
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
