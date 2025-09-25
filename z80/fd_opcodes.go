// Package z80 implements a Z80 CPU emulator with support for all documented
// and undocumented opcodes, flags, and registers.
package z80

// ExecuteFDOpcode executes a FD-prefixed opcode and returns the number of T-states used
func (cpu *CPU) ExecuteFDOpcode(opcode byte) int {
	switch opcode {
	// Load instructions
	case 0x09: // ADD IY, BC
		oldIY := cpu.IY
		result := cpu.add16IY(cpu.IY, cpu.GetBC())
		cpu.MEMPTR = oldIY + 1
		cpu.IY = result
		return 15
	case 0x19: // ADD IY, DE
		oldIY := cpu.IY
		result := cpu.add16IY(cpu.IY, cpu.GetDE())
		cpu.MEMPTR = oldIY + 1
		cpu.IY = result
		return 15
	case 0x21: // LD IY, nn
		cpu.IY = cpu.ReadImmediateWord()
		return 14
	case 0x22: // LD (nn), IY
		addr := cpu.ReadImmediateWord()
		cpu.Memory.WriteWord(addr, cpu.IY)
		cpu.MEMPTR = addr + 1
		return 20
	case 0x23: // INC IY
		cpu.IY++
		return 10
	case 0x24: // INC IYH
		cpu.SetIYH(cpu.inc8(cpu.GetIYH()))
		return 8
	case 0x25: // DEC IYH
		cpu.SetIYH(cpu.dec8(cpu.GetIYH()))
		return 8
	case 0x26: // LD IYH, n
		cpu.SetIYH(cpu.ReadImmediateByte())
		return 11
	case 0x29: // ADD IY, IY
		oldIY := cpu.IY
		result := cpu.add16IY(cpu.IY, cpu.IY)
		cpu.MEMPTR = oldIY + 1
		cpu.IY = result
		return 15
	case 0x2A: // LD IY, (nn)
		addr := cpu.ReadImmediateWord()
		cpu.IY = cpu.Memory.ReadWord(addr)
		cpu.MEMPTR = addr + 1
		return 20
	case 0x2B: // DEC IY
		cpu.IY--
		return 10
	case 0x2C: // INC IYL
		cpu.SetIYL(cpu.inc8(cpu.GetIYL()))
		return 8
	case 0x2D: // DEC IYL
		cpu.SetIYL(cpu.dec8(cpu.GetIYL()))
		return 8
	case 0x2E: // LD IYL, n
		cpu.SetIYL(cpu.ReadImmediateByte())
		return 11
	case 0x34: // INC (IY+d)
		return cpu.executeIncDecIndexedIY(true)
	case 0x35: // DEC (IY+d)
		return cpu.executeIncDecIndexedIY(false)
	case 0x36: // LD (IY+d), n
		displacement := cpu.ReadDisplacement()
		value := cpu.ReadImmediateByte()
		addr := uint16(int32(cpu.IY) + int32(displacement))
		cpu.Memory.WriteByte(addr, value)
		cpu.MEMPTR = addr
		return 19
	case 0x39: // ADD IY, SP
		oldIY := cpu.IY
		result := cpu.add16IY(cpu.IY, cpu.SP)
		cpu.MEMPTR = oldIY + 1
		cpu.IY = result
		return 15

	// Load register from IY register
	case 0x44: // LD B, IYH
		cpu.B = cpu.GetIYH()
		return 8
	case 0x45: // LD B, IYL
		cpu.B = cpu.GetIYL()
		return 8
	case 0x46: // LD B, (IY+d)
		return cpu.executeLoadFromIndexedIY(0)
	case 0x4C: // LD C, IYH
		cpu.C = cpu.GetIYH()
		return 8
	case 0x4D: // LD C, IYL
		cpu.C = cpu.GetIYL()
		return 8
	case 0x4E: // LD C, (IY+d)
		return cpu.executeLoadFromIndexedIY(1)
	case 0x54: // LD D, IYH
		cpu.D = cpu.GetIYH()
		return 8
	case 0x55: // LD D, IYL
		cpu.D = cpu.GetIYL()
		return 8
	case 0x56: // LD D, (IY+d)
		return cpu.executeLoadFromIndexedIY(2)
	case 0x5C: // LD E, IYH
		cpu.E = cpu.GetIYH()
		return 8
	case 0x5D: // LD E, IYL
		cpu.E = cpu.GetIYL()
		return 8
	case 0x5E: // LD E, (IY+d)
		return cpu.executeLoadFromIndexedIY(3)
	case 0x60: // LD IYH, B
		cpu.SetIYH(cpu.B)
		return 8
	case 0x61: // LD IYH, C
		cpu.SetIYH(cpu.C)
		return 8
	case 0x62: // LD IYH, D
		cpu.SetIYH(cpu.D)
		return 8
	case 0x63: // LD IYH, E
		cpu.SetIYH(cpu.E)
		return 8
	case 0x64: // LD IYH, IYH
		// No operation needed
		return 8
	case 0x65: // LD IYH, IYL
		cpu.SetIYH(cpu.GetIYL())
		return 8
	case 0x66: // LD H, (IY+d)
		return cpu.executeLoadFromIndexedIY(4)
	case 0x67: // LD IYH, A
		cpu.SetIYH(cpu.A)
		return 8
	case 0x68: // LD IYL, B
		cpu.SetIYL(cpu.B)
		return 8
	case 0x69: // LD IYL, C
		cpu.SetIYL(cpu.C)
		return 8
	case 0x6A: // LD IYL, D
		cpu.SetIYL(cpu.D)
		return 8
	case 0x6B: // LD IYL, E
		cpu.SetIYL(cpu.E)
		return 8
	case 0x6C: // LD IYL, IYH
		cpu.SetIYL(cpu.GetIYH())
		return 8
	case 0x6D: // LD IYL, IYL
		// No operation needed
		return 8
	case 0x6E: // LD L, (IY+d)
		return cpu.executeLoadFromIndexedIY(5)
	case 0x6F: // LD IYL, A
		cpu.SetIYL(cpu.A)
		return 8
	case 0x70: // LD (IY+d), B
		return cpu.executeStoreToIndexedIY(cpu.B)
	case 0x71: // LD (IY+d), C
		return cpu.executeStoreToIndexedIY(cpu.C)
	case 0x72: // LD (IY+d), D
		return cpu.executeStoreToIndexedIY(cpu.D)
	case 0x73: // LD (IY+d), E
		return cpu.executeStoreToIndexedIY(cpu.E)
	case 0x74: // LD (IY+d), H
		return cpu.executeStoreToIndexedIY(cpu.H)
	case 0x75: // LD (IY+d), L
		return cpu.executeStoreToIndexedIY(cpu.L)
	case 0x77: // LD (IY+d), A
		return cpu.executeStoreToIndexedIY(cpu.A)
	case 0x7C: // LD A, IYH
		cpu.A = cpu.GetIYH()
		return 8
	case 0x7D: // LD A, IYL
		cpu.A = cpu.GetIYL()
		return 8
	case 0x7E: // LD A, (IY+d)
		return cpu.executeLoadFromIndexedIY(7)

	// Arithmetic and logic instructions
	case 0x84: // ADD A, IYH
		cpu.add8(cpu.GetIYH())
		return 8
	case 0x85: // ADD A, IYL
		cpu.add8(cpu.GetIYL())
		return 8
	case 0x86: // ADD A, (IY+d)
		return cpu.executeALUIndexedIY(0)
	case 0x8C: // ADC A, IYH
		cpu.adc8(cpu.GetIYH())
		return 8
	case 0x8D: // ADC A, IYL
		cpu.adc8(cpu.GetIYL())
		return 8
	case 0x8E: // ADC A, (IY+d)
		return cpu.executeALUIndexedIY(1)
	case 0x94: // SUB IYH
		cpu.sub8(cpu.GetIYH())
		return 8
	case 0x95: // SUB IYL
		cpu.sub8(cpu.GetIYL())
		return 8
	case 0x96: // SUB (IY+d)
		return cpu.executeALUIndexedIY(2)
	case 0x9C: // SBC A, IYH
		cpu.sbc8(cpu.GetIYH())
		return 8
	case 0x9D: // SBC A, IYL
		cpu.sbc8(cpu.GetIYL())
		return 8
	case 0x9E: // SBC A, (IY+d)
		return cpu.executeALUIndexedIY(3)
	case 0xA4: // AND IYH
		cpu.and8(cpu.GetIYH())
		return 8
	case 0xA5: // AND IYL
		cpu.and8(cpu.GetIYL())
		return 8
	case 0xA6: // AND (IY+d)
		return cpu.executeALUIndexedIY(4)
	case 0xAC: // XOR IYH
		cpu.xor8(cpu.GetIYH())
		return 8
	case 0xAD: // XOR IYL
		cpu.xor8(cpu.GetIYL())
		return 8
	case 0xAE: // XOR (IY+d)
		return cpu.executeALUIndexedIY(5)
	case 0xB4: // OR IYH
		cpu.or8(cpu.GetIYH())
		return 8
	case 0xB5: // OR IYL
		cpu.or8(cpu.GetIYL())
		return 8
	case 0xB6: // OR (IY+d)
		return cpu.executeALUIndexedIY(6)
	case 0xBC: // CP IYH
		cpu.cp8(cpu.GetIYH())
		return 8
	case 0xBD: // CP IYL
		cpu.cp8(cpu.GetIYL())
		return 8
	case 0xBE: // CP (IY+d)
		return cpu.executeALUIndexedIY(7)

	// POP and PUSH instructions
	case 0xE1: // POP IY
		cpu.IY = cpu.Pop()
		return 14
	case 0xE3: // EX (SP), IY
		temp := cpu.Memory.ReadWord(cpu.SP)
		cpu.Memory.WriteWord(cpu.SP, cpu.IY)
		cpu.IY = temp
		cpu.MEMPTR = cpu.IY
		return 23
	case 0xE5: // PUSH IY
		cpu.Push(cpu.IY)
		return 15
	case 0xE9: // JP (IY)
		cpu.PC = cpu.IY
		return 8
	case 0xF9: // LD SP, IY
		cpu.SP = cpu.IY
		return 10

	// Handle FD CB prefix (IY with displacement and CB operations)
	case 0xCB: // FD CB prefix
		return cpu.ExecuteFDCBOpcode()

	case 0x00: // Extended NOP (undocumented)
		// FD 00 is an undocumented instruction that acts as an extended NOP
		// It consumes the FD prefix and the 00 opcode but executes as a NOP
		// Takes 8 cycles total (4 for FD prefix fetch + 4 for 00 opcode fetch)
		return 8
	default:
		// Unimplemented opcode - treat as regular opcode
		// This handles cases where FD is followed by a normal opcode
		return cpu.ExecuteOpcode(opcode)
	}
}

// executeIncDecIndexedIY handles INC/DEC (IY+d) instructions
func (cpu *CPU) executeIncDecIndexedIY(isInc bool) int {
	displacement := cpu.ReadDisplacement()
	addr := uint16(int32(cpu.IY) + int32(displacement))
	value := cpu.Memory.ReadByte(addr)
	var result byte
	if isInc {
		result = cpu.inc8(value)
	} else {
		result = cpu.dec8(value)
	}
	cpu.Memory.WriteByte(addr, result)
	cpu.MEMPTR = addr
	return 23
}

// executeLoadFromIndexedIY handles LD r, (IY+d) instructions
func (cpu *CPU) executeLoadFromIndexedIY(reg byte) int {
	displacement := cpu.ReadDisplacement()
	addr := uint16(int32(cpu.IY) + int32(displacement))
	value := cpu.Memory.ReadByte(addr)

	switch reg {
	case 0:
		cpu.B = value
	case 1:
		cpu.C = value
	case 2:
		cpu.D = value
	case 3:
		cpu.E = value
	case 4:
		cpu.H = value
	case 5:
		cpu.L = value
	case 7:
		cpu.A = value
	}

	cpu.MEMPTR = addr
	return 19
}

// executeStoreToIndexedIY handles LD (IY+d), r instructions
func (cpu *CPU) executeStoreToIndexedIY(value byte) int {
	displacement := cpu.ReadDisplacement()
	addr := uint16(int32(cpu.IY) + int32(displacement))
	cpu.Memory.WriteByte(addr, value)
	cpu.MEMPTR = addr
	return 19
}

// executeALUIndexedIY handles ALU operations with (IY+d) operand
func (cpu *CPU) executeALUIndexedIY(opType byte) int {
	displacement := cpu.ReadDisplacement()
	addr := uint16(int32(cpu.IY) + int32(displacement))
	value := cpu.Memory.ReadByte(addr)

	switch opType {
	case 0: // ADD
		cpu.add8(value)
	case 1: // ADC
		cpu.adc8(value)
	case 2: // SUB
		cpu.sub8(value)
	case 3: // SBC
		cpu.sbc8(value)
	case 4: // AND
		cpu.and8(value)
	case 5: // XOR
		cpu.xor8(value)
	case 6: // OR
		cpu.or8(value)
	case 7: // CP
		cpu.cp8(value)
	}

	cpu.MEMPTR = addr
	return 19
}

// add16IY adds two 16-bit values for IY register and updates flags
func (cpu *CPU) add16IY(a, b uint16) uint16 {
	result := a + b
	cpu.SetFlagState(FLAG_C, result < a)
	cpu.SetFlagState(FLAG_H, (a&0x0FFF)+(b&0x0FFF) > 0x0FFF)
	cpu.ClearFlag(FLAG_N)
	// For IY operations, we update X and Y flags from high byte of result
	cpu.UpdateFlags3and5FromAddress(result)
	return result
}
