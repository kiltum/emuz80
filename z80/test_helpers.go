package z80

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// mockMemory is a simple 64K RAM that satisfies Memory interface.
type mockMemory struct {
	data [65536]byte
}

func (m *mockMemory) ReadByte(address uint16) byte         { return m.data[address] }
func (m *mockMemory) WriteByte(address uint16, value byte) { m.data[address] = value }
func (m *mockMemory) ReadWord(address uint16) uint16 {
	lo := m.data[address]
	hi := m.data[address+1]
	return (uint16(hi) << 8) | uint16(lo)
}
func (m *mockMemory) WriteWord(address uint16, value uint16) {
	m.data[address] = byte(value)
	m.data[address+1] = byte(value >> 8)
}

// mockIO is a trivial port device.
type mockIO struct {
	lastOut   map[uint16]byte
	inVals    map[uint16]byte
	interrupt bool
}

func newMockIO() *mockIO {
	return &mockIO{lastOut: make(map[uint16]byte), inVals: make(map[uint16]byte), interrupt: false}
}

func (io *mockIO) ReadPort(port uint16) byte         { return io.inVals[port] }
func (io *mockIO) WritePort(port uint16, value byte) { io.lastOut[port] = value }
func (io *mockIO) CheckInterrupt() bool              { return io.interrupt }

// testCPU creates a CPU with empty RAM/IO and PC=0, SP=0xFFFF.
func testCPU() (*CPU, *mockMemory, *mockIO) {
	mem := &mockMemory{}
	io := newMockIO()
	cpu := New(mem, io)
	cpu.SP = 0xFFFF
	cpu.PC = 0x0000
	return cpu, mem, io
}

// loadProgram writes bytes at address and sets PC to that address.
func loadProgram(cpu *CPU, mem *mockMemory, addr uint16, bytes ...byte) {
	for i, b := range bytes {
		mem.WriteByte(addr+uint16(i), b)
	}
	cpu.PC = addr
}

// mustStep runs one instruction and logs an error if cycles <= 0.
// Returns cycles consumed.
func mustStep(t *testing.T, cpu *CPU) int {
	c := cpu.ExecuteOneInstruction()
	if c <= 0 {
		t.Errorf("ExecuteOneInstruction returned invalid cycles: %d", c)
	}
	return c
}

// assert helper shortcuts (non-fatal).
func assertEq[T comparable](t *testing.T, got, want T, msg string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v, want %v", msg, got, want)
	}
}

func assertFlag(t *testing.T, cpu *CPU, flag byte, want bool, msg string) {
	t.Helper()
	if cpu.GetFlag(flag) != want {
		t.Errorf("%s: flag 0x%02X got %v, want %v (F=%02X)", msg, flag, cpu.GetFlag(flag), want, cpu.F)
	}
}

// hexdump prints a compact hex + ascii line dump suitable for test logs.
func hexdump(p []byte, width int) string {
	if width <= 0 {
		width = 16
	}
	var b strings.Builder
	for i := 0; i < len(p); i += width {
		end := i + width
		if end > len(p) {
			end = len(p)
		}
		b.WriteString(fmt.Sprintf("%08X  ", i))
		for j := i; j < end; j++ {
			b.WriteString(fmt.Sprintf("%02x ", p[j]))
		}
		for j := end; j < i+width; j++ {
			b.WriteString("   ")
		}
		b.WriteString(" |")
		for j := i; j < end; j++ {
			c := p[j]
			if c < 32 || c > 126 {
				c = '.'
			}
			b.WriteByte(c)
		}
		b.WriteString("|\n")
	}
	return b.String()
}

// small helper to timestamp messages consistently
func ts() string { return time.Now().Format("15:04:05.000") }
