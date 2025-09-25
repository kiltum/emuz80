package main

import (
	"fmt"
	"io/ioutil"

	"z80"
)

// Memory64K represents 64KB of memory
type Memory64K struct {
	data [0x10000]byte // 64KB = 65536 bytes
}

// ReadByte reads a byte from memory
func (m *Memory64K) ReadByte(address uint16) byte {
	return m.data[address]
}

// WriteByte writes a byte to memory
func (m *Memory64K) WriteByte(address uint16, value byte) {
	m.data[address] = value
}

// ReadWord reads a word from memory
func (m *Memory64K) ReadWord(address uint16) uint16 {
	return uint16(m.data[address]) | (uint16(m.data[address+1]) << 8)
}

// WriteWord writes a word to memory
func (m *Memory64K) WriteWord(address uint16, value uint16) {
	m.data[address] = byte(value)
	m.data[address+1] = byte(value >> 8)
}

// IOHandler handles I/O operations
type IOHandler struct{}

// ReadPort reads from an I/O port
func (io *IOHandler) ReadPort(port uint16) byte {
	return 0xFF // Default value
}

// WritePort writes to an I/O port
func (io *IOHandler) WritePort(port uint16, value byte) {
	// No I/O port handling needed for BDOS calls
}

// CheckInterrupt checks for interrupts
func (io *IOHandler) CheckInterrupt() bool {
	return false
}

// handleBDOSCall handles CP/M BDOS calls
func handleBDOSCall(cpu *z80.CPU, memory *Memory64K) {
	// BDOS is called by jumping to 0x0005
	// Function number is in register C
	// Parameters are in other registers depending on the function

	function := cpu.C

	switch function {
	case 2: // Print character (character in E)
		fmt.Print(string(cpu.E))
	case 9: // Print string (string address in DE)
		addr := cpu.GetDE()
		// Read characters from memory until we encounter '$'
		for {
			char := memory.ReadByte(addr)
			if char == '$' {
				break
			}
			fmt.Print(string(char))
			addr++
		}
	}

	// In a real CP/M system, after handling the BDOS call,
	// execution would return to the caller via a RET instruction.
	// We simulate this by popping the return address from the stack
	// and setting the PC to that address.

	// Pop return address from stack
	lowByte := memory.ReadByte(cpu.SP)
	cpu.SP++
	highByte := memory.ReadByte(cpu.SP)
	cpu.SP++
	returnAddress := (uint16(highByte) << 8) | uint16(lowByte)

	// Set PC to return address
	cpu.PC = returnAddress
}

// loadZEXALL loads the zexall.com file into memory at address 0x100
func loadZEXALL(memory *Memory64K, filename string) error {
	// Load file data
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", filename, err)
	}

	// Load into memory at address 0x100
	loadAddress := uint16(0x100)
	for i, b := range data {
		addr := uint32(loadAddress) + uint32(i)
		if addr < 0x10000 {
			memory.data[uint16(addr)] = b
		} else {
			break // Memory overflow protection
		}
	}

	return nil
}

func main() {
	// Create memory and IO instances
	memory := &Memory64K{}
	io := &IOHandler{}

	// Create CPU instance
	cpu := z80.New(memory, io)

	// Set up initial state for CP/M program
	// Stack pointer typically starts at 0xFFFF in CP/M programs
	cpu.SP = 0xFFFF

	// Program counter starts at 0x100 for .COM files
	cpu.PC = 0x100

	fmt.Printf("ZEXDOC\n")
	// Load zexall.com file
	err := loadZEXALL(memory, "zexdoc.com")
	if err != nil {
		fmt.Printf("Error: Could not load zexdoc.com: %v\n", err)
		fmt.Println("Exiting program.")
		return
	}

	// Execute instructions
	for {
		// Check if program has ended (PC = 0x0000)
		if cpu.PC == 0x0000 {
			fmt.Println("Program ended (PC reached 0x0000)")
			break
		}

		// Check if this is a BDOS call (PC = 0x0005)
		if cpu.PC == 0x0005 {
			handleBDOSCall(cpu, memory)
			// After handling BDOS call, continue execution
			continue
		}

		// Execute one instruction
		ticks := cpu.ExecuteOneInstruction()
		_ = ticks // Ignore ticks for now

		// Optional: Add a safety counter to prevent infinite loops during development
		// You can remove this once everything is working properly
	}

	fmt.Printf("ZEXALL\n")

	cpu.SP = 0xFFFF

	// Program counter starts at 0x100 for .COM files
	cpu.PC = 0x100

	// Load zexall.com file
	err = loadZEXALL(memory, "zexall.com")
	if err != nil {
		fmt.Printf("Error: Could not load zexall.com: %v\n", err)
		fmt.Println("Exiting program.")
		return
	}

	// Execute instructions
	for {
		// Check if program has ended (PC = 0x0000)
		if cpu.PC == 0x0000 {
			fmt.Println("Program ended (PC reached 0x0000)")
			break
		}

		// Check if this is a BDOS call (PC = 0x0005)
		if cpu.PC == 0x0005 {
			handleBDOSCall(cpu, memory)
			// After handling BDOS call, continue execution
			continue
		}

		// Execute one instruction
		ticks := cpu.ExecuteOneInstruction()
		_ = ticks // Ignore ticks for now

		// Optional: Add a safety counter to prevent infinite loops during development
		// You can remove this once everything is working properly
	}

}
