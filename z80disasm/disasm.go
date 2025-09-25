// Package disasm provides a Z80 disassembler implementation
package disasm

import (
	"fmt"
)

// Instruction represents a decoded Z80 instruction
type Instruction struct {
	Mnemonic string // Human-readable instruction mnemonic
	Length   int    // Number of bytes the instruction occupies
	Address  uint16 // Address operand for jump/load instructions, 0xFFFF if not applicable
}

// Disassembler represents a Z80 disassembler
type Disassembler struct{}

// New creates a new Z80 disassembler
func New() *Disassembler {
	return &Disassembler{}
}

// Decode decodes a single Z80 instruction from a byte slice
// It returns the decoded instruction and any error encountered
func (d *Disassembler) Decode(data []byte) (*Instruction, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("no data to decode")
	}

	// Get the first opcode byte
	opcode := data[0]

	// Handle prefixed instructions (CB, DD, ED, FD prefixes)
	switch opcode {
	case 0xCB:
		return d.decodeCB(data)
	case 0xDD:
		return d.decodeDD(data)
	case 0xED:
		return d.decodeED(data)
	case 0xFD:
		return d.decodeFD(data)
	default:
		return d.decodeUnprefixed(opcode, data)
	}
}
