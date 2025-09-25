package z80

import "testing"

// BIT n,(IX+d)/(IY+d): X/Y must come from MEMPTR high byte, cycles 20 for BIT on indexed (no write-back).
func TestBIT_IXIY_Displacement_FlagsAndTiming(t *testing.T) {
	// IX case
	cpu, mem, _ := testCPU()
	cpu.IX = 0x3000
	mem.WriteByte(0x3005, 0x80)                           // bit 7 set
	loadProgram(cpu, mem, 0x0000, 0xDD, 0xCB, 0x05, 0x7E) // BIT 7,(IX+5)
	c := mustStep(t, cpu)
	// Z=0, S=1 for bit7 set
	assertFlag(t, cpu, FLAG_Z, false, "BIT Z")
	assertFlag(t, cpu, FLAG_S, true, "BIT S for bit7")
	// X/Y from MEMPTR high byte
	memptrHi := byte(cpu.MEMPTR >> 8)
	assertFlag(t, cpu, FLAG_X, (memptrHi&FLAG_X) != 0, "X from MEMPTR high (IX)")
	assertFlag(t, cpu, FLAG_Y, (memptrHi&FLAG_Y) != 0, "Y from MEMPTR high (IX)")
	assertEq(t, c, 20, "cycles for DDCB BIT (IX+d) should be 20")

	// IY case
	cpu, mem, _ = testCPU()
	cpu.IY = 0x4000
	mem.WriteByte(0x4002, 0x01)                           // bit 0 set
	loadProgram(cpu, mem, 0x0000, 0xFD, 0xCB, 0x02, 0x46) // BIT 0,(IY+2)
	c = mustStep(t, cpu)
	assertFlag(t, cpu, FLAG_Z, false, "BIT Z (IY)")
	memptrHi = byte(cpu.MEMPTR >> 8)
	assertFlag(t, cpu, FLAG_X, (memptrHi&FLAG_X) != 0, "X from MEMPTR high (IY)")
	assertFlag(t, cpu, FLAG_Y, (memptrHi&FLAG_Y) != 0, "Y from MEMPTR high (IY)")
	assertEq(t, c, 20, "cycles for FDCB BIT (IY+d) should be 20")
}
