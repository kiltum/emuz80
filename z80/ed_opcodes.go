// Package z80 implements a Z80 CPU emulator with support for all documented
// and undocumented opcodes, flags, and registers.
package z80

import "fmt"

// ExecuteEDOpcode executes an ED-prefixed opcode and returns the number of T-states used
func (cpu *CPU) ExecuteEDOpcode(opcode byte) int {
	switch opcode {
	// Block transfer instructions
	case 0xA0: // LDI
		cpu.ldi()
		return 16
	case 0xA1: // CPI
		cpu.cpi()
		return 16
	case 0xA2: // INI
		cpu.ini()
		return 16
	case 0xA3: // OUTI
		cpu.outi()
		return 16
	case 0xA8: // LDD
		cpu.ldd()
		return 16
	case 0xA9: // CPD
		cpu.cpd()
		return 16
	case 0xAA: // IND
		cpu.ind()
		return 16
	case 0xAB: // OUTD
		cpu.outd()
		return 16
	case 0xB0: // LDIR
		return cpu.ldir()
	case 0xB1: // CPIR
		return cpu.cpir()
	case 0xB2: // INIR
		return cpu.inir()
	case 0xB3: // OTIR
		return cpu.otir()
	case 0xB8: // LDDR
		return cpu.lddr()
	case 0xB9: // CPDR
		return cpu.cpdr()
	case 0xBA: // INDR
		return cpu.indr()
	case 0xBB: // OTDR
		return cpu.otdr()

	// 8-bit load instructions
	case 0x40: // IN B, (C)
		return cpu.executeIN(0)
	case 0x41: // OUT (C), B
		return cpu.executeOUT(0)
	case 0x42: // SBC HL, BC
		result := cpu.sbc16WithMEMPTR(cpu.GetHL(), cpu.GetBC())
		cpu.SetHL(result)
		return 15
	case 0x43: // LD (nn), BC
		addr := cpu.ReadImmediateWord()
		cpu.Memory.WriteWord(addr, cpu.GetBC())
		// MEMPTR = addr + 1
		cpu.MEMPTR = addr + 1
		return 20
	case 0x44, 0x4C, 0x54, 0x5C, 0x64, 0x6C, 0x74, 0x7C: // NEG (various undocumented versions)
		cpu.neg()
		return 8
	case 0x45, 0x55, 0x5D, 0x65, 0x6D, 0x75, 0x7D: // RETN (various undocumented versions)
		cpu.retn()
		return 14
	case 0x46, 0x4E, 0x66: // IM 0 (various undocumented versions)
		cpu.IM = 0
		return 8
	case 0x47: // LD I, A
		cpu.I = cpu.A
		return 9
	case 0x48: // IN C, (C)
		return cpu.executeIN(1)
	case 0x49: // OUT (C), C
		return cpu.executeOUT(1)
	case 0x4A: // ADC HL, BC
		result := cpu.adc16WithMEMPTR(cpu.GetHL(), cpu.GetBC())
		cpu.SetHL(result)
		return 15
	case 0x4B: // LD BC, (nn)
		addr := cpu.ReadImmediateWord()
		cpu.SetBC(cpu.Memory.ReadWord(addr))
		// MEMPTR = addr + 1
		cpu.MEMPTR = addr + 1
		return 20
	case 0x4D: // RETI
		cpu.reti()
		return 14
	case 0x4F: // LD R, A
		// R register is only 7 bits, bit 7 remains unchanged
		//cpu.R = (cpu.R & 0x80) | (cpu.A & 0x7F)
		cpu.R = cpu.A // fix zen80 tests
		return 9
	case 0x50: // IN D, (C)
		return cpu.executeIN(2)
	case 0x51: // OUT (C), D
		return cpu.executeOUT(2)
	case 0x52: // SBC HL, DE
		result := cpu.sbc16WithMEMPTR(cpu.GetHL(), cpu.GetDE())
		cpu.SetHL(result)
		return 15
	case 0x53: // LD (nn), DE
		addr := cpu.ReadImmediateWord()
		cpu.Memory.WriteWord(addr, cpu.GetDE())
		// MEMPTR = addr + 1
		cpu.MEMPTR = addr + 1
		return 20
	case 0x56, 0x76: // IM 1 (various undocumented versions)
		cpu.IM = 1
		return 8
	case 0x57: // LD A, I
		cpu.ldAI()
		return 9
	case 0x58: // IN E, (C)
		return cpu.executeIN(3)
	case 0x59: // OUT (C), E
		return cpu.executeOUT(3)
	case 0x5A: // ADC HL, DE
		result := cpu.adc16WithMEMPTR(cpu.GetHL(), cpu.GetDE())
		cpu.SetHL(result)
		return 15
	case 0x5B: // LD DE, (nn)
		addr := cpu.ReadImmediateWord()
		cpu.SetDE(cpu.Memory.ReadWord(addr))
		// MEMPTR = addr + 1
		cpu.MEMPTR = addr + 1
		return 20
	case 0x5E, 0x7E: // IM 2 (various undocumented versions)
		cpu.IM = 2
		return 8
	case 0x5F: // LD A, R
		cpu.ldAR()
		return 9
	case 0x60: // IN H, (C)
		return cpu.executeIN(4)
	case 0x61: // OUT (C), H
		return cpu.executeOUT(4)
	case 0x62: // SBC HL, HL
		result := cpu.sbc16WithMEMPTR(cpu.GetHL(), cpu.GetHL())
		cpu.SetHL(result)
		return 15
	case 0x63: // LD (nn), HL
		addr := cpu.ReadImmediateWord()
		cpu.Memory.WriteWord(addr, cpu.GetHL())
		// MEMPTR = addr + 1
		cpu.MEMPTR = addr + 1
		return 20
	case 0x67: // RRD
		cpu.rrd()
		return 18
	case 0x68: // IN L, (C)
		return cpu.executeIN(5)
	case 0x69: // OUT (C), L
		return cpu.executeOUT(5)
	case 0x6A: // ADC HL, HL
		result := cpu.adc16WithMEMPTR(cpu.GetHL(), cpu.GetHL())
		cpu.SetHL(result)
		return 15
	case 0x6B: // LD HL, (nn)
		addr := cpu.ReadImmediateWord()
		cpu.SetHL(cpu.Memory.ReadWord(addr))
		// MEMPTR = addr + 1
		cpu.MEMPTR = addr + 1
		return 20
	case 0x6F: // RLD
		cpu.rld()
		return 18
	case 0x70: // IN (C) (Undocumented - input to dummy register)
		bc := cpu.GetBC() // Save BC before doing anything
		value := cpu.inC()
		cpu.UpdateSZXYFlags(value)
		cpu.ClearFlag(FLAG_H)
		cpu.ClearFlag(FLAG_N)
		// Set PV flag based on parity of the result
		cpu.SetFlagState(FLAG_PV, cpu.parity(value))
		// MEMPTR = BC + 1 (using the original BC value)
		cpu.MEMPTR = bc + 1
		return 12
	case 0x71: // OUT (C), 0 (Undocumented)
		cpu.outC(0)
		// MEMPTR = BC + 1
		cpu.MEMPTR = cpu.GetBC() + 1
		return 12
	case 0x72: // SBC HL, SP
		result := cpu.sbc16WithMEMPTR(cpu.GetHL(), cpu.SP)
		cpu.SetHL(result)
		return 15
	case 0x73: // LD (nn), SP
		addr := cpu.ReadImmediateWord()
		cpu.Memory.WriteWord(addr, cpu.SP)
		// MEMPTR = addr + 1
		cpu.MEMPTR = addr + 1
		return 20
	case 0x78: // IN A, (C)
		return cpu.executeIN(7)
	case 0x79: // OUT (C), A
		return cpu.executeOUT(7)
	case 0x7A: // ADC HL, SP
		result := cpu.adc16WithMEMPTR(cpu.GetHL(), cpu.SP)
		cpu.SetHL(result)
		return 15
	case 0x7B: // LD SP, (nn)
		addr := cpu.ReadImmediateWord()
		cpu.SP = cpu.Memory.ReadWord(addr)
		// MEMPTR = addr + 1
		cpu.MEMPTR = addr + 1
		return 20
	case 0x80: // endefined NOP
		return 8
	case 0x6e:
		return 8

	default:
		panic(fmt.Sprintf("ED unexpected code %x", opcode))
	}
}

// executeIN handles the IN r, (C) instructions
func (cpu *CPU) executeIN(reg byte) int {
	bc := cpu.GetBC()
	value := cpu.inC()

	// Update flags
	cpu.UpdateSZXYFlags(value)
	cpu.ClearFlag(FLAG_H)
	cpu.ClearFlag(FLAG_N)
	// Set PV flag based on parity of the result
	cpu.SetFlagState(FLAG_PV, cpu.parity(value))
	// MEMPTR = BC + 1 (using the original BC value)
	cpu.MEMPTR = bc + 1

	// Set the appropriate register
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

	return 12
}

// executeOUT handles the OUT (C), r instructions
func (cpu *CPU) executeOUT(reg byte) int {
	var value byte

	// Get the appropriate register value
	switch reg {
	case 0:
		value = cpu.B
	case 1:
		value = cpu.C
	case 2:
		value = cpu.D
	case 3:
		value = cpu.E
	case 4:
		value = cpu.H
	case 5:
		value = cpu.L
	case 7:
		value = cpu.A
	}

	cpu.outC(value)
	// MEMPTR = BC + 1
	cpu.MEMPTR = cpu.GetBC() + 1

	return 12
}

// ldi loads byte from (HL) to (DE), increments pointers, decrements BC
func (cpu *CPU) ldi() {
	value := cpu.Memory.ReadByte(cpu.GetHL())
	cpu.Memory.WriteByte(cpu.GetDE(), value)

	cpu.SetDE(cpu.GetDE() + 1)
	cpu.SetHL(cpu.GetHL() + 1)
	cpu.SetBC(cpu.GetBC() - 1)

	// FIXED: Calculate X and Y flags FIRST, preserving S, Z, C
	n := value + cpu.A
	cpu.F = (cpu.F & (FLAG_S | FLAG_Z | FLAG_C)) | (n & FLAG_X) | ((n & 0x02) << 4)

	// THEN set the other flags
	cpu.ClearFlag(FLAG_H)
	cpu.SetFlagState(FLAG_PV, cpu.GetBC() != 0)
	cpu.ClearFlag(FLAG_N)
}

// cpi compares A with (HL), increments HL, decrements BC
func (cpu *CPU) cpi() {
	value := cpu.Memory.ReadByte(cpu.GetHL())
	result := cpu.A - value

	cpu.SetHL(cpu.GetHL() + 1)
	cpu.SetBC(cpu.GetBC() - 1)

	cpu.SetFlag(FLAG_N, true)
	cpu.UpdateSZFlags(result)

	// Set H flag if borrow from bit 4
	cpu.SetFlagState(FLAG_H, (cpu.A&0x0F) < (value&0x0F))

	// For CPI, F3 and F5 flags come from (A - (HL) - H_flag)
	// where H_flag is the half-carry flag AFTER the instruction
	temp := result - boolToByte(cpu.GetFlag(FLAG_H))
	cpu.SetFlagState(FLAG_3, (temp&0x08) != 0) // Bit 3
	cpu.SetFlagState(FLAG_5, (temp&0x02) != 0) // Bit 1

	if cpu.GetBC() != 0 {
		cpu.SetFlag(FLAG_PV, true)
	} else {
		cpu.ClearFlag(FLAG_PV)
	}

	// Set MEMPTR = PC - 1
	cpu.MEMPTR = cpu.PC - 1
}

// ini inputs byte to (HL), increments HL, decrements B
func (cpu *CPU) ini() {
	value := cpu.IO.ReadPort(uint16(cpu.C) | (uint16(cpu.B) << 8))
	cpu.Memory.WriteByte(cpu.GetHL(), value)
	cpu.SetHL(cpu.GetHL() + 1)
	origbc := cpu.GetBC()
	cpu.B--

	// Enhanced: Accurate flag calculation for INI
	k := int(value) + int((cpu.C+1)&0xFF)

	cpu.SetFlagState(FLAG_Z, cpu.B == 0)
	cpu.SetFlagState(FLAG_S, cpu.B&0x80 != 0)
	cpu.SetFlagState(FLAG_N, (value&0x80) != 0)
	cpu.SetFlagState(FLAG_H, k > 0xFF)
	cpu.SetFlagState(FLAG_C, k > 0xFF)
	// P/V flag is parity of ((k & 0x07) XOR B)
	cpu.SetFlagState(FLAG_PV, cpu.parity(uint8(k&0x07)^cpu.B))
	// X and Y flags from B register
	cpu.F = (cpu.F & 0xD7) | (cpu.B & (FLAG_3 | FLAG_5))

	cpu.MEMPTR = origbc + 1

}

// Helper function to calculate parity
func parity(val uint8) bool {
	count := 0
	for i := 0; i < 8; i++ {
		if val&(1<<i) != 0 {
			count++
		}
	}
	return count%2 == 0
}

// outi outputs byte from (HL) to port, increments HL, decrements B
func (cpu *CPU) outi() {
	val := cpu.Memory.ReadByte(cpu.GetHL())
	cpu.B--
	cpu.IO.WritePort(cpu.GetBC(), val)
	cpu.SetHL(cpu.GetHL() + 1)

	// Enhanced: Accurate flag calculation for OUTI
	// Note: Use L after HL increment
	k := int(val) + int(cpu.L)

	cpu.SetFlagState(FLAG_Z, cpu.B == 0)
	cpu.SetFlagState(FLAG_S, cpu.B&0x80 != 0)
	cpu.SetFlagState(FLAG_N, (val&0x80) != 0)
	cpu.SetFlagState(FLAG_H, k > 0xFF)
	cpu.SetFlagState(FLAG_C, k > 0xFF)
	// P/V flag is parity of ((k & 0x07) XOR B)
	pvVal := uint8(k&0x07) ^ cpu.B
	cpu.SetFlagState(FLAG_PV, parity(pvVal))
	// X and Y flags from B register
	cpu.F = (cpu.F & 0xD7) | (cpu.B & (FLAG_X | FLAG_Y))

	cpu.MEMPTR = cpu.GetBC() + 1
}

func (cpu *CPU) ldd() {
	value := cpu.Memory.ReadByte(cpu.GetHL())
	cpu.Memory.WriteByte(cpu.GetDE(), value)
	cpu.SetHL(cpu.GetHL() - 1)
	cpu.SetDE(cpu.GetDE() - 1)
	cpu.SetBC(cpu.GetBC() - 1)

	// FIXED: Calculate X and Y flags FIRST, preserving S, Z, C
	n := value + cpu.A
	cpu.F = (cpu.F & (FLAG_S | FLAG_Z | FLAG_C)) | (n & FLAG_X) | ((n & 0x02) << 4)

	// THEN set the other flags
	cpu.ClearFlag(FLAG_H)
	cpu.SetFlagState(FLAG_PV, cpu.GetBC() != 0)
	cpu.ClearFlag(FLAG_N)

}

// cpd compares A with (HL), decrements HL, decrements BC
func (cpu *CPU) cpd() {
	// HUMAN:Working for fuse test, but failed on zexall
	// value := cpu.Memory.ReadByte(cpu.GetHL())
	// result := cpu.A - value

	// cpu.SetHL(cpu.GetHL() - 1)
	// cpu.SetBC(cpu.GetBC() - 1)

	// cpu.SetFlag(FLAG_N, true)
	// cpu.UpdateSZFlags(result)
	// // For CPD, X and Y flags come from (A - (HL) - H_flag)
	// // where H_flag is the half-carry flag AFTER the instruction
	// temp := result - boolToByte(cpu.GetFlag(FLAG_H))
	// cpu.SetFlagState(FLAG_3, (temp&0x08) != 0) // Bit 3
	// cpu.SetFlagState(FLAG_5, (temp&0x02) != 0) // Bit 1

	// // Set H flag if borrow from bit 4
	// cpu.SetFlagState(FLAG_H, (cpu.A&0x0F) < (value&0x0F))

	// if cpu.GetBC() != 0 {
	// 	cpu.SetFlag(FLAG_PV, true)
	// } else {
	// 	cpu.ClearFlag(FLAG_PV)
	// }
	// cpu.MEMPTR--

	val := cpu.Memory.ReadByte(cpu.GetHL())
	result := int16(cpu.A) - int16(val)
	cpu.SetHL(cpu.GetHL() - 1)
	cpu.SetBC(cpu.GetBC() - 1)

	cpu.SetFlagState(FLAG_S, uint8(result)&0x80 != 0)
	cpu.SetFlagState(FLAG_Z, uint8(result) == 0)
	cpu.SetFlagState(FLAG_H, (int8(cpu.A&0x0F)-int8(val&0x0F)) < 0)
	cpu.SetFlagState(FLAG_PV, cpu.GetBC() != 0)
	cpu.SetFlagState(FLAG_N, true)

	// Y flag calculation - preserve S, Z, H, PV, N, C flags
	n := uint8(result)
	if cpu.GetFlag(FLAG_H) {
		n--
	}
	cpu.F = (cpu.F & (FLAG_S | FLAG_Z | FLAG_H | FLAG_PV | FLAG_N | FLAG_C)) | (n & FLAG_X) | ((n & 0x02) << 4)
	cpu.MEMPTR--

}

// ind inputs byte to (HL), decrements HL, decrements B
func (cpu *CPU) ind() {
	val := cpu.IO.ReadPort(cpu.GetBC())
	cpu.Memory.WriteByte(cpu.GetHL(), val)
	cpu.SetHL(cpu.GetHL() - 1)
	cpu.MEMPTR = cpu.GetBC() - 1
	cpu.B--

	// Enhanced: Accurate flag calculation for IND
	// Note: Based on Z80 documentation, k = val + C (not C-1)
	// HUMAN: based on fuse test , ITS + C-1
	//k := int(val) + int(cpu.C)

	cpu.SetFlagState(FLAG_Z, cpu.B == 0)
	cpu.SetFlagState(FLAG_S, cpu.B&0x80 != 0)
	cpu.SetFlagState(FLAG_N, (val&0x80) != 0)
	// HUMAN : here was error
	// cpu.SetFlagState(FLAG_H, k > 0xFF)
	// cpu.SetFlagState(FLAG_C, k > 0xFF)
	// // P/V flag is parity of ((k & 0x07) XOR B)
	// pvVal := uint8(k&0x07) ^ cpu.B
	// cpu.SetFlagState(FLAG_PV, parity(pvVal))

	diff := uint16(cpu.C-1) + uint16(val)
	cpu.SetFlagState(FLAG_H, diff > 0xFF)
	cpu.SetFlagState(FLAG_C, diff > 0xFF)
	temp := byte((diff & 0x07) ^ uint16(cpu.B))
	parity := byte(0)
	for i := 0; i < 8; i++ {
		parity ^= (temp >> i) & 1
	}
	cpu.SetFlagState(FLAG_PV, parity == 0)

	// X and Y flags from B register
	cpu.F = (cpu.F & 0xD7) | (cpu.B & (FLAG_X | FLAG_Y))

}

// outd outputs byte from (HL) to port, decrements HL, decrements B
func (cpu *CPU) outd() {
	val := cpu.Memory.ReadByte(cpu.GetHL())
	cpu.B--
	cpu.IO.WritePort(uint16(cpu.C)|(uint16(cpu.B)<<8), val)
	cpu.SetHL(cpu.GetHL() - 1)

	k := uint16(val) + uint16(cpu.L)

	cpu.SetFlagState(FLAG_Z, cpu.B == 0)
	cpu.SetFlagState(FLAG_S, cpu.B&0x80 != 0)
	cpu.SetFlagState(FLAG_N, (val&0x80) != 0)
	cpu.SetFlagState(FLAG_H, k > 0xFF)
	cpu.SetFlagState(FLAG_C, k > 0xFF)
	// P/V flag is parity of ((k & 0x07) XOR B)
	pvVal := uint8(k&0x07) ^ cpu.B
	cpu.SetFlagState(FLAG_PV, parity(pvVal))
	// X and Y flags from B register
	cpu.F = (cpu.F & 0xD7) | (cpu.B & (FLAG_X | FLAG_Y))

	cpu.MEMPTR = cpu.GetBC() - 1
}

// ldir repeated LDI until BC=0
func (cpu *CPU) ldir() int {
	cpu.ldi()

	// Add T-states for this iteration (21 for continuing, 16 for final)
	if cpu.GetBC() != 0 {
		cpu.PC -= 2
		cpu.MEMPTR = cpu.PC + 1
		return 21
	} else {
		return 16
	}
}

// cpir repeated CPI until BC=0 or A=(HL)
func (cpu *CPU) cpir() int {

	cpu.cpi()

	if cpu.GetBC() != 0 && !cpu.GetFlag(FLAG_Z) {

		cpu.PC -= 2 // Repeat instruction

		// Return T-states for continuing iteration
		return 21
	} else {
		// Return T-states for final iteration
		cpu.MEMPTR = cpu.PC
		return 16
	}
}

// inir repeated INI until B=0
func (cpu *CPU) inir() int {

	cpu.ini()

	if cpu.B != 0 {
		cpu.PC -= 2 // Repeat instruction
		// Return T-states for continuing iteration
		return 21
	} else {
		// Set MEMPTR to PC+1 at the end of the instruction
		//cpu.MEMPTR = cpu.PC
		// Return T-states for final iteration
		return 16
	}
}

// otir repeated OUTI until B=0
func (cpu *CPU) otir() int {

	cpu.outi()

	if cpu.B != 0 {
		cpu.PC -= 2 // Repeat instruction
		// Return T-states for continuing iteration
		return 21
	} else {
		// Return T-states for final iteration
		return 16
	}
}

// lddr repeated LDD until BC=0
func (cpu *CPU) lddr() int {

	// Execute one LDD operation
	cpu.ldd()

	// Add T-states for this iteration (21 for continuing, 16 for final)
	if cpu.GetBC() != 0 {
		cpu.PC -= 2
		cpu.MEMPTR = cpu.PC + 1
		return 21
	} else {
		return 16

	}
}

// cpdr repeated CPD until BC=0 or A=(HL)
func (cpu *CPU) cpdr() int {

	cpu.cpd()

	if cpu.GetBC() != 0 && !cpu.GetFlag(FLAG_Z) {
		cpu.PC -= 2 // Repeat instruction
		// Return T-states for continuing iteration
		cpu.MEMPTR = cpu.PC + 1
		return 21
	} else {
		cpu.MEMPTR = cpu.PC - 2
		// Return T-states for final iteration
		return 16
	}
}

// indr repeated IND until B=0
func (cpu *CPU) indr() int {
	cpu.ind()

	if cpu.B != 0 {
		cpu.PC -= 2 // Repeat instruction
		// Return T-states for continuing iteration
		return 21
	} else {
		// Return T-states for final iteration
		return 16
	}
}

// otdr repeated OUTD until B=0
func (cpu *CPU) otdr() int {

	cpu.outd()

	if cpu.B != 0 {
		cpu.PC -= 2 // Repeat instruction
		// Return T-states for continuing iteration
		return 21
	} else {
		return 16
	}
}

// inC reads from port (BC)
func (cpu *CPU) inC() byte {
	return cpu.IO.ReadPort(cpu.GetBC())
}

// outC writes to port (BC)
func (cpu *CPU) outC(value byte) {
	cpu.IO.WritePort(cpu.GetBC(), value)
}

// sbc16 subtracts 16-bit value with carry from HL
func (cpu *CPU) sbc16(val1, val2 uint16) uint16 {
	carry := int32(0)
	if cpu.GetFlag(FLAG_C) {
		carry = 1
	}
	result := int32(val1) - int32(val2) - carry
	halfCarry := (int16(val1&0x0FFF) - int16(val2&0x0FFF) - int16(carry)) < 0
	overflow := ((val1^val2)&0x8000 != 0) && ((val1^uint16(result))&0x8000 != 0)

	res16 := uint16(result)

	cpu.SetFlagState(FLAG_S, res16&0x8000 != 0)
	cpu.SetFlagState(FLAG_Z, res16 == 0)
	cpu.SetFlagState(FLAG_H, halfCarry)
	cpu.SetFlagState(FLAG_PV, overflow)
	cpu.SetFlagState(FLAG_N, true)
	cpu.SetFlagState(FLAG_C, result < 0)
	// FIX: Set X and Y flags from high byte of result
	cpu.SetFlagState(FLAG_X, uint8(res16>>8)&FLAG_X != 0)
	cpu.SetFlagState(FLAG_Y, uint8(res16>>8)&FLAG_Y != 0)
	cpu.MEMPTR = val1 + 1
	return res16
}

// sbc16WithMEMPTR subtracts 16-bit value with carry from HL and sets MEMPTR
func (cpu *CPU) sbc16WithMEMPTR(a, b uint16) uint16 {
	result := cpu.sbc16(a, b)
	cpu.MEMPTR = a + 1
	return result
}

// adc16 adds 16-bit value with carry to HL
func (cpu *CPU) adc16(val1, val2 uint16) uint16 {
	carry := uint32(0)
	if cpu.GetFlag(FLAG_C) {
		carry = 1
	}
	result := uint32(val1) + uint32(val2) + carry
	halfCarry := (val1&0x0FFF + val2&0x0FFF + uint16(carry)) > 0x0FFF
	overflow := ((val1^val2)&0x8000 == 0) && ((val1^uint16(result))&0x8000 != 0)

	res16 := uint16(result)

	cpu.SetFlagState(FLAG_S, res16&0x8000 != 0)
	cpu.SetFlagState(FLAG_Z, res16 == 0)
	cpu.SetFlagState(FLAG_H, halfCarry)
	cpu.SetFlagState(FLAG_PV, overflow)
	cpu.SetFlagState(FLAG_N, false)
	cpu.SetFlagState(FLAG_C, result > 0xFFFF)
	// FIX: Set X and Y flags from high byte of result
	cpu.SetFlagState(FLAG_X, uint8(res16>>8)&FLAG_X != 0)
	cpu.SetFlagState(FLAG_Y, uint8(res16>>8)&FLAG_Y != 0)
	cpu.MEMPTR = val1 + 1

	return res16
}

// adc16WithMEMPTR adds 16-bit value with carry to HL and sets MEMPTR
func (cpu *CPU) adc16WithMEMPTR(a, b uint16) uint16 {
	result := cpu.adc16(a, b)
	cpu.MEMPTR = a + 1
	return result
}

// neg negates the accumulator
func (cpu *CPU) neg() {
	value := cpu.A
	cpu.A = 0
	cpu.sub8(value)
}

// retn returns from interrupt and restores IFF1 from IFF2
func (cpu *CPU) retn() {
	cpu.PC = cpu.Pop()
	cpu.MEMPTR = cpu.PC
	cpu.IFF1 = cpu.IFF2
}

// reti returns from interrupt (same as retn for Z80)
func (cpu *CPU) reti() {
	cpu.PC = cpu.Pop()
	cpu.MEMPTR = cpu.PC
	cpu.IFF1 = cpu.IFF2
}

// ldAI loads I register into A and updates flags
func (cpu *CPU) ldAI() {
	cpu.A = cpu.I
	cpu.UpdateSZXYFlags(cpu.A)
	cpu.ClearFlag(FLAG_H)
	cpu.ClearFlag(FLAG_N)
	cpu.SetFlagState(FLAG_PV, cpu.IFF2)
}

// ldAR loads R register into A and updates flags
func (cpu *CPU) ldAR() {
	// Load the R register into A
	cpu.A = cpu.R
	cpu.UpdateSZXYFlags(cpu.A)
	cpu.ClearFlag(FLAG_H)
	cpu.ClearFlag(FLAG_N)
	cpu.SetFlagState(FLAG_PV, cpu.IFF2)
}

// rrd rotates digit between A and (HL) right
func (cpu *CPU) rrd() {
	value := cpu.Memory.ReadByte(cpu.GetHL())
	ah := cpu.A & 0xF0
	al := cpu.A & 0x0F
	hl := value

	// A bits 3-0 go to HL bits 7-4
	// HL bits 7-4 go to HL bits 3-0
	// HL bits 3-0 go to A bits 3-0
	cpu.A = ah | (hl & 0x0F)
	newHL := ((hl & 0xF0) >> 4) | (al << 4)
	cpu.Memory.WriteByte(cpu.GetHL(), newHL)

	cpu.UpdateSZXYPVFlags(cpu.A)
	cpu.ClearFlag(FLAG_H)
	cpu.ClearFlag(FLAG_N)

	// Set MEMPTR = HL + 1
	cpu.MEMPTR = cpu.GetHL() + 1
}

// rld rotates digit between A and (HL) left
func (cpu *CPU) rld() {
	value := cpu.Memory.ReadByte(cpu.GetHL())
	ah := cpu.A & 0xF0
	al := cpu.A & 0x0F
	hl := value

	// A bits 3-0 go to HL bits 3-0
	// HL bits 3-0 go to HL bits 7-4
	// HL bits 7-4 go to A bits 3-0
	cpu.A = ah | (hl >> 4)
	newHL := ((hl & 0x0F) << 4) | al
	cpu.Memory.WriteByte(cpu.GetHL(), newHL)

	cpu.UpdateSZXYPVFlags(cpu.A)
	cpu.ClearFlag(FLAG_H)
	cpu.ClearFlag(FLAG_N)

	// Set MEMPTR = HL + 1
	cpu.MEMPTR = cpu.GetHL() + 1
}
