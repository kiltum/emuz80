package z80

import "testing"

// Ensure SCF, CCF, CPL set X/Y from A (regression locks).
func TestSCF_CCF_CPL_XY_FromA(t *testing.T) {
	cpu, mem, _ := testCPU()
	// Make A have both X/Y set -> e.g., 0x28
	loadProgram(cpu, mem, 0x0000, 0x3E, 0x28, 0x37, 0x3F, 0x2F) // LD A,28 ; SCF ; CCF ; CPL
	mustStep(t, cpu)                                            // LD
	mustStep(t, cpu)                                            // SCF
	assertFlag(t, cpu, FLAG_X, true, "SCF X from A")
	assertFlag(t, cpu, FLAG_Y, true, "SCF Y from A")
	mustStep(t, cpu) // CCF
	assertFlag(t, cpu, FLAG_X, true, "CCF X from A")
	assertFlag(t, cpu, FLAG_Y, true, "CCF Y from A")
	mustStep(t, cpu) // CPL (A becomes ^A)
	assertFlag(t, cpu, FLAG_X, (cpu.A&FLAG_X) != 0, "CPL X from new A")
	assertFlag(t, cpu, FLAG_Y, (cpu.A&FLAG_Y) != 0, "CPL Y from new A")
}
