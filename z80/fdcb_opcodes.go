// Package z80 implements a Z80 CPU emulator with support for all documented
// and undocumented opcodes, flags, and registers.
package z80

// ExecuteFDCBOpcode executes a FD CB prefixed opcode
func (cpu *CPU) ExecuteFDCBOpcode() int {
	displacement := cpu.ReadDisplacement()
	opcode := cpu.ReadOpcode()
	cpu.R--
	addr := uint16(int32(cpu.IY) + int32(displacement))
	value := cpu.Memory.ReadByte(addr)
	cpu.MEMPTR = addr

	// Handle rotate and shift instructions (0x00-0x3F)
	if opcode <= 0x3F {
		return cpu.executeRotateShiftIndexedIY(opcode, addr, value)
	}

	// Handle bit test instructions (0x40-0x7F)
	if opcode >= 0x40 && opcode <= 0x7F {
		bitNum := uint((opcode >> 3) & 0x07)
		cpu.bitMem(bitNum, value, byte(addr>>8))
		return 20
	}

	// Handle reset bit instructions (0x80-0xBF)
	if opcode >= 0x80 && opcode <= 0xBF {
		return cpu.executeResetBitIndexedIY(opcode, addr, value)
	}

	// Handle set bit instructions (0xC0-0xFF)
	if opcode >= 0xC0 {
		return cpu.executeSetBitIndexedIY(opcode, addr, value)
	}

	// Unimplemented opcode
	return 23
}

// executeRotateShiftIndexedIY handles rotate and shift instructions for IY indexed addressing
func (cpu *CPU) executeRotateShiftIndexedIY(opcode byte, addr uint16, value byte) int {
	// Determine operation type from opcode bits 3-5
	opType := (opcode >> 3) & 0x07
	// Determine register from opcode bits 0-2
	reg := opcode & 0x07

	// Perform the operation
	var result byte
	switch opType {
	case 0: // RLC
		result = cpu.rlc(value)
	case 1: // RRC
		result = cpu.rrc(value)
	case 2: // RL
		result = cpu.rl(value)
	case 3: // RR
		result = cpu.rr(value)
	case 4: // SLA
		result = cpu.sla(value)
	case 5: // SRA
		result = cpu.sra(value)
	case 6: // SLL (Undocumented)
		result = cpu.sll(value)
	case 7: // SRL
		result = cpu.srl(value)
	default:
		result = value
	}

	// Store result in memory
	cpu.Memory.WriteByte(addr, result)

	// Store result in register if needed (except for (HL) case)
	if reg != 6 { // reg 6 is (HL) - no register store needed
		switch reg {
		case 0:
			cpu.B = result
		case 1:
			cpu.C = result
		case 2:
			cpu.D = result
		case 3:
			cpu.E = result
		case 4:
			cpu.H = result
		case 5:
			cpu.L = result
		case 7:
			cpu.A = result
		}
	}

	return 23
}

// executeResetBitIndexedIY handles reset bit instructions for IY indexed addressing
func (cpu *CPU) executeResetBitIndexedIY(opcode byte, addr uint16, value byte) int {
	bitNum := uint((opcode >> 3) & 0x07)
	reg := opcode & 0x07

	result := cpu.res(bitNum, value)
	cpu.Memory.WriteByte(addr, result)

	// Store result in register if needed (except for (HL) case)
	if reg != 6 { // reg 6 is (HL) - no register store needed
		switch reg {
		case 0:
			cpu.B = result
		case 1:
			cpu.C = result
		case 2:
			cpu.D = result
		case 3:
			cpu.E = result
		case 4:
			cpu.H = result
		case 5:
			cpu.L = result
		case 7:
			cpu.A = result
		}
	}

	return 23
}

// executeSetBitIndexedIY handles set bit instructions for IY indexed addressing
func (cpu *CPU) executeSetBitIndexedIY(opcode byte, addr uint16, value byte) int {
	bitNum := uint((opcode >> 3) & 0x07)
	reg := opcode & 0x07

	result := cpu.set(bitNum, value)
	cpu.Memory.WriteByte(addr, result)

	// Store result in register if needed (except for (HL) case)
	if reg != 6 { // reg 6 is (HL) - no register store needed
		switch reg {
		case 0:
			cpu.B = result
		case 1:
			cpu.C = result
		case 2:
			cpu.D = result
		case 3:
			cpu.E = result
		case 4:
			cpu.H = result
		case 5:
			cpu.L = result
		case 7:
			cpu.A = result
		}
	}

	return 23
}
