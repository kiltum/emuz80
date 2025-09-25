package z80

import "testing"

// Test ADD A,n sets all flags correctly including undocumented X/Y.
func TestADD_A_n_Flags(t *testing.T) {
	cpu, mem, _ := testCPU()
	// 3E 7F = LD A,0x7F; C6 01 = ADD A,0x01
	loadProgram(cpu, mem, 0x0000, 0x3E, 0x7F, 0xC6, 0x01)
	mustStep(t, cpu)      // LD A,7F
	c := mustStep(t, cpu) // ADD A,01

	assertEq(t, cpu.A, byte(0x80), "A after ADD")
	assertFlag(t, cpu, FLAG_S, true, "S")
	assertFlag(t, cpu, FLAG_Z, false, "Z")
	assertFlag(t, cpu, FLAG_H, true, "H half-carry")
	assertFlag(t, cpu, FLAG_PV, true, "P/V overflow")
	assertFlag(t, cpu, FLAG_N, false, "N")
	assertFlag(t, cpu, FLAG_C, false, "C")
	// X and Y from result
	assertFlag(t, cpu, FLAG_X, (cpu.A&FLAG_X) != 0, "X from result")
	assertFlag(t, cpu, FLAG_Y, (cpu.A&FLAG_Y) != 0, "Y from result")

	// Quick timing smoke-check (not strict because conditional)
	assertEq(t, c, 7, "cycles for ADD A,n should be 7")
}

// CP n sets X/Y from the OPERAND per implementation fixes.
func TestCP_n_XYFromOperand(t *testing.T) {
	cpu, mem, _ := testCPU()
	// A=0x20; FE 08 = CP 0x08 -> result 0x18 (not stored). X/Y should copy from operand 0x08.
	loadProgram(cpu, mem, 0x0000, 0x3E, 0x20, 0xFE, 0x08)
	mustStep(t, cpu) // LD A,20
	mustStep(t, cpu) // CP 08

	// For CP, X/Y come from the operand (0x08 has X=1, Y=0).
	assertFlag(t, cpu, FLAG_X, true, "CP X from operand")
	assertFlag(t, cpu, FLAG_Y, false, "CP Y from operand")
	// N must be set for CP
	assertFlag(t, cpu, FLAG_N, true, "N set for CP")
}

// INC/DEC r affect flags and preserve C; X/Y come from result.
func TestINC_DEC_r_Flags(t *testing.T) {
	cpu, mem, _ := testCPU()
	// Set C flag first to ensure INC/DEC don't change it.
	cpu.SetFlag(FLAG_C, true)

	// 06 7F = LD B,7F; 04 = INC B; 05 = DEC B
	loadProgram(cpu, mem, 0x0000, 0x06, 0x7F, 0x04, 0x05)
	mustStep(t, cpu) // LD B,7F

	mustStep(t, cpu) // INC B -> 0x80
	assertEq(t, cpu.B, byte(0x80), "INC B result")
	assertFlag(t, cpu, FLAG_PV, true, "INC overflow at 7F->80")
	assertFlag(t, cpu, FLAG_C, true, "C preserved across INC")

	mustStep(t, cpu) // DEC B -> 0x7F
	assertEq(t, cpu.B, byte(0x7F), "DEC B result")
	assertFlag(t, cpu, FLAG_PV, true, "DEC overflow at 80->7F")
	assertFlag(t, cpu, FLAG_C, true, "C preserved across DEC")
}
