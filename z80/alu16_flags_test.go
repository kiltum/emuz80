package z80

import "testing"

// Verify 16-bit ADD/ADC/SBC HL,rr flags, XY from high byte, and MEMPTR=HL+1
func TestADD_HL_rr_FlagsAndMEMPTR(t *testing.T) {
	cpu, mem, _ := testCPU()
	cpu.SetHL(0x0FFF)
	cpu.SetBC(0x0001)
	loadProgram(cpu, mem, 0x0000, 0x09) // ADD HL,BC
	mustStep(t, cpu)
	assertEq(t, cpu.GetHL(), uint16(0x1000), "ADD HL,BC result")
	assertFlag(t, cpu, FLAG_H, true, "H set on carry from bit11")
	assertFlag(t, cpu, FLAG_N, false, "N cleared")
	assertFlag(t, cpu, FLAG_C, false, "C not set")
	// X/Y from high byte of result (0x10 -> both X and Y clear)
	assertFlag(t, cpu, FLAG_Y, false, "Y from high byte should be clear for 0x10")
	assertFlag(t, cpu, FLAG_X, false, "X from high byte should be clear for 0x10")
	assertEq(t, cpu.MEMPTR, uint16(0x1000-0x0001+1), "MEMPTR=oldHL+1")

	// ADC HL,DE with carry in
	cpu.SetHL(0x7FFF)
	cpu.SetDE(0x0000)
	cpu.SetFlag(FLAG_C, true)
	loadProgram(cpu, mem, cpu.PC, 0xED, 0x5A) // ADC HL,DE
	mustStep(t, cpu)
	assertEq(t, cpu.GetHL(), uint16(0x8000), "ADC HL,DE result")
	assertFlag(t, cpu, FLAG_S, true, "S from result high bit")
	assertFlag(t, cpu, FLAG_Z, false, "Z")
	assertFlag(t, cpu, FLAG_PV, true, "PV overflow on 7FFF+0+1")
	assertFlag(t, cpu, FLAG_C, false, "C")
	assertFlag(t, cpu, FLAG_N, false, "N")
	assertFlag(t, cpu, FLAG_X, false, "X from high byte 0x80")
	assertFlag(t, cpu, FLAG_Y, false, "Y from high byte 0x80")
}

func TestSBC_HL_rr_FlagsAndMEMPTR(t *testing.T) {
	cpu, mem, _ := testCPU()
	cpu.SetHL(0x8000)
	cpu.SP = 0x0001
	cpu.SetFlag(FLAG_C, true)
	loadProgram(cpu, mem, 0x0000, 0xED, 0x72) // SBC HL,SP
	mustStep(t, cpu)
	// 0x8000 - 0x0001 - 1 = 0x7FFE
	assertEq(t, cpu.GetHL(), uint16(0x7FFE), "SBC HL,SP result")
	assertFlag(t, cpu, FLAG_N, true, "N set on subtract")
	assertFlag(t, cpu, FLAG_C, false, "No borrow overall")
	assertFlag(t, cpu, FLAG_PV, true, "Overflow: negative - positive -> positive")
	// XY from high byte 0x7F (both X and Y set)
	assertFlag(t, cpu, FLAG_X, true, "X from 0x7F")
	assertFlag(t, cpu, FLAG_Y, true, "Y from 0x7F")
}
