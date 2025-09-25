package z80

import "testing"

// BIT n,(HL) must set X/Y from MEMPTR high byte (implementation note in prefix_cb.go).
func TestBIT_HL_XYFromMEMPTRHigh(t *testing.T) {
	cpu, mem, _ := testCPU()
	// Put value at 0x4000, set HL=0x4000, then CB 7E = BIT 7,(HL)
	mem.WriteByte(0x4000, 0x80) // bit 7 set
	cpu.SetHL(0x4000)
	loadProgram(cpu, mem, 0x0000, 0xCB, 0x7E)
	c := mustStep(t, cpu)

	// For BIT 7,(HL), Z=0, S=1, PV mirrors Z, H=1, N=0.
	assertFlag(t, cpu, FLAG_Z, false, "BIT Z")
	// In our implementation, executeCB overrides X/Y with MEMPTR high.
	memptrHi := byte(cpu.MEMPTR >> 8)
	assertFlag(t, cpu, FLAG_X, (memptrHi&FLAG_X) != 0, "X from MEMPTR high")
	assertFlag(t, cpu, FLAG_Y, (memptrHi&FLAG_Y) != 0, "Y from MEMPTR high")

	assertEq(t, c, 12, "cycles for BIT n,(HL)")
}

// RLC (HL): verify write-back and timing 15 cycles.
func TestRLC_HL_WriteBackAndTiming(t *testing.T) {
	cpu, mem, _ := testCPU()
	cpu.SetHL(0x2000)
	mem.WriteByte(0x2000, 0x81)               // 1000 0001 -> RLC -> 0000 0011, C=1
	loadProgram(cpu, mem, 0x0000, 0xCB, 0x06) // RLC (HL)
	c := mustStep(t, cpu)
	assertEq(t, mem.ReadByte(0x2000), byte(0x03), "RLC(HL) write-back")
	assertFlag(t, cpu, FLAG_C, true, "C set after RLC")
	assertEq(t, c, 15, "cycles for RLC (HL)")
}
