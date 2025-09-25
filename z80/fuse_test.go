package z80

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	disasm "github.com/kiltum/emuz80/z80disasm"
)

// Test represents a single Z80 test case
type Test struct {
	Name        string
	Description string
	Input       TestInput
	Expected    TestExpected
}

// TestInput represents the input data for a test
type TestInput struct {
	Registers   []string
	I           string
	R           string
	IFF1        string
	IFF2        string
	IM          string
	Halted      string
	TStates     string
	MemorySetup []MemoryBlock
}

// TestExpected represents the expected output for a test
type TestExpected struct {
	Events        []Event
	FinalState    []string
	I             string
	R             string
	IFF1          string
	IFF2          string
	IM            string
	Halted        string
	TStates       string
	ChangedMemory []MemoryBlock
}

// MemoryBlock represents a block of memory
type MemoryBlock struct {
	Address string
	Bytes   []string
}

// SimpleIO implements the IO interface for testing
type SimpleIO struct {
	ports [65536]byte
}

func (io *SimpleIO) ReadPort(port uint16) byte {
	// For IN instructions, return the high byte of the port address
	// This matches the test expectations where A register value is used as high byte
	return byte(port >> 8)
}

func (io *SimpleIO) WritePort(port uint16, value byte) {
	io.ports[port] = value
}

func (io *SimpleIO) CheckInterrupt() bool {
	return false
}

// LoadMemoryBlocks loads memory blocks into the memory
func (m *mockMemory) LoadMemoryBlocks(blocks []MemoryBlock, t *testing.T) error {
	for _, block := range blocks {
		// Parse the address
		addr, err := strconv.ParseUint(block.Address, 16, 16)
		if err != nil {
			return fmt.Errorf("invalid address %s: %v", block.Address, err)
		}

		// Load each byte
		baseAddr := uint16(addr)
		for i, byteStr := range block.Bytes {
			value, err := strconv.ParseUint(byteStr, 16, 8)
			if err != nil {
				return fmt.Errorf("invalid byte value %s: %v", byteStr, err)
			}
			address := baseAddr + uint16(i)
			byteValue := byte(value)
			m.WriteByte(address, byteValue)

			// Debug output
			if t != nil {
				t.Logf("Load: %04X->%02X", address, byteValue)
			}
		}
	}
	return nil
}

// Event represents a single event in the test execution
type Event struct {
	Time    string
	Type    string
	Address string
	Data    string
}

// FlagNames represents the bit names for the F register
var FlagNames = []string{"S", "Z", "5", "H", "3", "P/V", "N", "C"}

// decodeF converts F register value to bit representation string
func decodeF(fReg string) string {
	// Convert hex string to integer
	fValue, err := strconv.ParseUint(fReg, 16, 8)
	if err != nil {
		return "Invalid F register"
	}

	// Decode F register bits (SZ5H3PNC)
	bits := make([]byte, 8)
	for i := 0; i < 8; i++ {
		if fValue&(1<<(7-i)) != 0 {
			bits[i] = '1'
		} else {
			bits[i] = '0'
		}
	}

	// Build the flag representation
	flagRepr := ""
	for i, name := range FlagNames {
		flagRepr += fmt.Sprintf(" %s:%c", name, bits[i])
	}

	return fmt.Sprintf("%s (%s)", fReg, strings.Trim(flagRepr, " "))
}

// parseHex parses a hex string to uint16
func parseHex(hexStr string) (uint16, error) {
	val, err := strconv.ParseUint(hexStr, 16, 16)
	if err != nil {
		return 0, err
	}
	return uint16(val), nil
}

// parseBool parses a string to bool
func parseBool(boolStr string) bool {
	return boolStr == "1"
}

// parseByte parses a hex string to byte
func parseByte(hexStr string) (byte, error) {
	val, err := strconv.ParseUint(hexStr, 16, 8)
	if err != nil {
		return 0, err
	}
	return byte(val), nil
}

// RegisterInfo holds information about a register for loading/comparison
type RegisterInfo struct {
	Name     string
	Index    int
	LoadFunc func(*CPU, uint16)
	GetFunc  func(*CPU) uint16
}

// loadRegisters loads register values from the test input into the CPU
func loadRegisters(cpu *CPU, registers []string, t *testing.T) {
	if len(registers) < 13 {
		return
	}

	registerMap := []RegisterInfo{
		{"AF", 0, func(c *CPU, v uint16) { c.SetAF(v) }, func(c *CPU) uint16 { return c.GetAF() }},
		{"BC", 1, func(c *CPU, v uint16) { c.SetBC(v) }, func(c *CPU) uint16 { return c.GetBC() }},
		{"DE", 2, func(c *CPU, v uint16) { c.SetDE(v) }, func(c *CPU) uint16 { return c.GetDE() }},
		{"HL", 3, func(c *CPU, v uint16) { c.SetHL(v) }, func(c *CPU) uint16 { return c.GetHL() }},
		{"AF'", 4, func(c *CPU, v uint16) { c.SetAF_(v) }, func(c *CPU) uint16 { return c.GetAF_() }},
		{"BC'", 5, func(c *CPU, v uint16) { c.SetBC_(v) }, func(c *CPU) uint16 { return c.GetBC_() }},
		{"DE'", 6, func(c *CPU, v uint16) { c.SetDE_(v) }, func(c *CPU) uint16 { return c.GetDE_() }},
		{"HL'", 7, func(c *CPU, v uint16) { c.SetHL_(v) }, func(c *CPU) uint16 { return c.GetHL_() }},
		{"IX", 8, func(c *CPU, v uint16) { c.IX = v }, func(c *CPU) uint16 { return c.IX }},
		{"IY", 9, func(c *CPU, v uint16) { c.IY = v }, func(c *CPU) uint16 { return c.IY }},
		{"SP", 10, func(c *CPU, v uint16) { c.SP = v }, func(c *CPU) uint16 { return c.SP }},
		{"PC", 11, func(c *CPU, v uint16) { c.PC = v }, func(c *CPU) uint16 { return c.PC }},
		{"MEMPTR", 12, func(c *CPU, v uint16) { c.MEMPTR = v }, func(c *CPU) uint16 { return c.MEMPTR }},
	}

	for _, regInfo := range registerMap {
		if regInfo.Index < len(registers) {
			if value, err := parseHex(registers[regInfo.Index]); err == nil {
				regInfo.LoadFunc(cpu, value)
				if t != nil {
					//t.Logf("Loaded %s: 0x%04X", regInfo.Name, value)
				}
			} else if t != nil {
				t.Logf("Failed to parse %s register value: %s", regInfo.Name, registers[regInfo.Index])
			}
		}
	}
}

// compareRegisters compares CPU registers with expected values and returns mismatches
func compareRegisters(cpu *CPU, expected []string, t *testing.T) []string {
	if len(expected) < 13 {
		return nil
	}

	var mismatches []string

	registerMap := []RegisterInfo{
		{"AF", 0, nil, func(c *CPU) uint16 { return c.GetAF() }},
		{"BC", 1, nil, func(c *CPU) uint16 { return c.GetBC() }},
		{"DE", 2, nil, func(c *CPU) uint16 { return c.GetDE() }},
		{"HL", 3, nil, func(c *CPU) uint16 { return c.GetHL() }},
		{"AF'", 4, nil, func(c *CPU) uint16 { return c.GetAF_() }},
		{"BC'", 5, nil, func(c *CPU) uint16 { return c.GetBC_() }},
		{"DE'", 6, nil, func(c *CPU) uint16 { return c.GetDE_() }},
		{"HL'", 7, nil, func(c *CPU) uint16 { return c.GetHL_() }},
		{"IX", 8, nil, func(c *CPU) uint16 { return c.IX }},
		{"IY", 9, nil, func(c *CPU) uint16 { return c.IY }},
		{"SP", 10, nil, func(c *CPU) uint16 { return c.SP }},
		{"PC", 11, nil, func(c *CPU) uint16 { return c.PC }},
		{"MEMPTR", 12, nil, func(c *CPU) uint16 { return c.MEMPTR }},
	}

	for _, regInfo := range registerMap {
		if regInfo.Index < len(expected) {
			if expectedValue, err := parseHex(expected[regInfo.Index]); err == nil {
				actualValue := regInfo.GetFunc(cpu)
				if actualValue != expectedValue {
					mismatches = append(mismatches, fmt.Sprintf("%s: expected 0x%04X, got 0x%04X", regInfo.Name, expectedValue, actualValue))

					// Add F flag bit details for AF register
					if regInfo.Name == "AF" || regInfo.Name == "AF'" {
						expectedF := fmt.Sprintf("%02X", expectedValue&0xFF)
						actualF := fmt.Sprintf("%02X", actualValue&0xFF)
						mismatches = append(mismatches, fmt.Sprintf("  Expected F: %s", decodeF(expectedF)))
						mismatches = append(mismatches, fmt.Sprintf("  Actual F:   %s", decodeF(actualF)))
					}
				}
			} else if t != nil {
				t.Logf("Failed to parse expected %s register value: %s", regInfo.Name, expected[regInfo.Index])
			}
		}
	}

	return mismatches
}

// decodeInstructions decodes instructions starting from address 0x0000
// and logs them until a NOP instruction is encountered (after address 0) or safety limit is reached
func decodeInstructions(d *disasm.Disassembler, memory *mockMemory, t *testing.T) {
	address := uint16(0x0000)

	for {
		// Create a buffer with the bytes at the current address
		buffer := make([]byte, 4) // Read up to 4 bytes for longer instructions
		for i := 0; i < 4; i++ {
			buffer[i] = memory.ReadByte(address + uint16(i))
		}

		// Decode the instruction at the current address
		instruction, err := d.Decode(buffer)
		if err != nil {
			t.Logf("Failed to decode instruction at 0x%04X: %v", address, err)
			break
		}

		// Stop decoding if we encounter a NOP instruction and address > 0
		if instruction.Mnemonic == "NOP" && address > 0 {
			break
		}

		// Log the decoded instruction
		//t.Logf("Decoded instruction at 0x%04X: %s", address, instruction.Mnemonic)

		// Move to the next instruction
		address += uint16(instruction.Length)

		// Safety check to prevent infinite loops
		if address > 0x1000 {
			t.Logf("Stopping decode at 0x%04X: Reached safety limit", address)
			break
		}
	}
}

// executeInstructions executes CPU instructions until reaching the expected T-states
func executeInstructions(cpu *CPU, memory *mockMemory, d *disasm.Disassembler, expectedTStates int, t *testing.T) {
	totalTicks := 0
	for totalTicks < expectedTStates {
		// Capture the PC before executing the instruction for proper logging
		pcBefore := cpu.PC

		// Read bytes at current PC for disassembly before execution
		buffer := make([]byte, 4) // Read up to 4 bytes for longer instructions
		for i := 0; i < 4; i++ {
			buffer[i] = memory.ReadByte(cpu.PC + uint16(i))
		}

		// Decode the instruction at the current address before execution
		instruction, err := d.Decode(buffer)
		if err != nil {
			t.Logf("Failed to decode instruction at 0x%04X: %v", cpu.PC, err)
			// Continue execution even if we can't decode
		}

		// Execute the instruction
		tickCount := cpu.ExecuteOneInstruction()
		totalTicks += tickCount

		// Log the executed instruction
		if err == nil && instruction != nil {
			t.Logf("Executed %s at 0x%04X, ticks: %d, total: %d/%d", instruction.Mnemonic, pcBefore, tickCount, totalTicks, expectedTStates)
		} else {
			t.Logf("Executed instruction at 0x%04X, ticks: %d, total: %d/%d", pcBefore, tickCount, totalTicks, expectedTStates)
		}
	}
}

// compareInternalState compares CPU internal state with expected values and returns mismatches
func compareInternalState(cpu *CPU, expected TestExpected, t *testing.T) []string {
	var mismatches []string

	// Compare internal state
	if expectedI, err := parseByte(expected.I); err == nil {
		if cpu.I != expectedI {
			mismatches = append(mismatches, fmt.Sprintf("I: expected 0x%02X, got 0x%02X", expectedI, cpu.I))
		}
	}
	if expectedR, err := parseByte(expected.R); err == nil {
		if cpu.R != expectedR {
			mismatches = append(mismatches, fmt.Sprintf("R: expected 0x%02X, got 0x%02X", expectedR, cpu.R))
		}
	}
	expectedIFF1 := parseBool(expected.IFF1)
	if cpu.IFF1 != expectedIFF1 {
		mismatches = append(mismatches, fmt.Sprintf("IFF1: expected %t, got %t", expectedIFF1, cpu.IFF1))
	}
	expectedIFF2 := parseBool(expected.IFF2)
	if cpu.IFF2 != expectedIFF2 {
		mismatches = append(mismatches, fmt.Sprintf("IFF2: expected %t, got %t", expectedIFF2, cpu.IFF2))
	}
	if expectedIM, err := parseByte(expected.IM); err == nil {
		if cpu.IM != expectedIM {
			mismatches = append(mismatches, fmt.Sprintf("IM: expected 0x%02X, got 0x%02X", expectedIM, cpu.IM))
		}
	}
	expectedHALT := parseBool(expected.Halted)
	if cpu.HALT != expectedHALT {
		mismatches = append(mismatches, fmt.Sprintf("HALT: expected %t, got %t", expectedHALT, cpu.HALT))
	}

	return mismatches
}

// compareMemory compares memory contents with expected values and returns mismatches
func compareMemory(memory *mockMemory, expected []MemoryBlock, t *testing.T) []string {
	var mismatches []string

	for _, block := range expected {
		// Parse the address
		addr, err := strconv.ParseUint(block.Address, 16, 16)
		if err != nil {
			mismatches = append(mismatches, fmt.Sprintf("Invalid address %s in expected memory block", block.Address))
			continue
		}

		// Compare each byte and group consecutive mismatches
		baseAddr := uint16(addr)
		var expectedBytes []string
		var actualBytes []string
		startAddress := baseAddr

		for i, expectedByteStr := range block.Bytes {
			expectedByte, err := strconv.ParseUint(expectedByteStr, 16, 8)
			if err != nil {
				mismatches = append(mismatches, fmt.Sprintf("Invalid byte value %s in expected memory block", expectedByteStr))
				continue
			}

			address := baseAddr + uint16(i)
			actualByte := memory.ReadByte(address)

			if actualByte != byte(expectedByte) {
				expectedBytes = append(expectedBytes, fmt.Sprintf("%02X", byte(expectedByte)))
				actualBytes = append(actualBytes, fmt.Sprintf("%02X", actualByte))
			} else {
				// If we have accumulated mismatches and hit a match, flush the accumulated mismatches
				if len(expectedBytes) > 0 {
					mismatches = append(mismatches, fmt.Sprintf("Memory at 0x%04X: expected %s\n got %s", startAddress, strings.Join(expectedBytes, " "), strings.Join(actualBytes, " ")))
					expectedBytes = []string{}
					actualBytes = []string{}
					startAddress = address + 1
				} else {
					startAddress = address + 1
				}
			}
		}

		// Flush any remaining mismatches
		if len(expectedBytes) > 0 {
			mismatches = append(mismatches, fmt.Sprintf("Exp: 0x%04X %s\nCur:        %s", startAddress, strings.Join(expectedBytes, " "), strings.Join(actualBytes, " ")))
		}
	}

	return mismatches
}

// buildDebugInfo creates debug information for test failures
func buildDebugInfo(initialRegisters []string, cpu *CPU, expected []string) []string {
	var debugInfo []string

	// Add header with register names
	debugInfo = append(debugInfo, "       AF    BC    DE    HL    AF'   BC'   DE'   HL'   IX    IY    SP    PC  MEMPTR")

	// Add initial register state in one line
	initialLine := ""
	for i := 0; i < 13; i++ {
		if i < len(initialRegisters) {
			initialLine += fmt.Sprintf("%-6s", initialRegisters[i])
		} else {
			initialLine += "0000  "
		}
	}
	debugInfo = append(debugInfo, "Ini: "+initialLine)

	// Add current emulator register state in one line
	currentLine := fmt.Sprintf(
		"%04X  %04X  %04X  %04X  %04X  %04X  %04X  %04X  %04X  %04X  %04X  %04X  %04X",
		cpu.GetAF(), cpu.GetBC(), cpu.GetDE(), cpu.GetHL(),
		cpu.GetAF_(), cpu.GetBC_(), cpu.GetDE_(), cpu.GetHL_(),
		cpu.IX, cpu.IY, cpu.SP, cpu.PC, cpu.MEMPTR)
	debugInfo = append(debugInfo, "Cur: "+currentLine)

	// Add expected register state in one line
	expectedLine := ""
	for i := 0; i < 13; i++ {
		if i < len(expected) {
			expectedLine += fmt.Sprintf("%-6s", strings.ToUpper(expected[i]))
		} else {
			expectedLine += "0000  "
		}
	}
	debugInfo = append(debugInfo, "Exp: "+expectedLine)

	return debugInfo
}

// executeZ80Test executes a single Z80 test case
func executeZ80Test(t *testing.T, test Test) {
	// Create memory and IO instances
	memory := &mockMemory{}
	io := &SimpleIO{}

	// Load initial memory state
	if err := memory.LoadMemoryBlocks(test.Input.MemorySetup, t); err != nil {
		t.Errorf("Failed to load memory blocks: %v", err)
		return
	}

	// Create CPU instance
	cpu := New(memory, io)

	// Capture initial register state for debugging
	initialRegisters := make([]string, 13)
	copy(initialRegisters, test.Input.Registers)

	// Load input registers and state
	loadRegisters(cpu, test.Input.Registers, t)

	// Parse internal state
	if i, err := parseByte(test.Input.I); err == nil {
		cpu.I = i
	}
	if r, err := parseByte(test.Input.R); err == nil {
		cpu.R = r
	}
	cpu.IFF1 = parseBool(test.Input.IFF1)
	cpu.IFF2 = parseBool(test.Input.IFF2)
	if im, err := parseByte(test.Input.IM); err == nil {
		cpu.IM = im
	}
	cpu.HALT = parseBool(test.Input.Halted)

	// Create disassembler and decode instructions starting at address 0x0000
	d := disasm.New()
	decodeInstructions(d, memory, t)

	// Parse T-states from input (this is the actual tick count to use)
	inputTStates, err := strconv.Atoi(test.Input.TStates)
	if err != nil {
		t.Errorf("Failed to parse input T-states: %v", err)
		return
	}

	// Execute instructions until we reach the input T-states
	executeInstructions(cpu, memory, d, inputTStates, t)

	// Compare emulator registers with expected values
	matches := true
	var mismatchDetails []string

	if len(test.Expected.FinalState) >= 13 {
		// Compare registers using the helper function
		registerMismatches := compareRegisters(cpu, test.Expected.FinalState, t)
		if len(registerMismatches) > 0 {
			matches = false
			mismatchDetails = append(mismatchDetails, registerMismatches...)
		}
	}

	// Compare internal state
	internalStateMismatches := compareInternalState(cpu, test.Expected, t)
	if len(internalStateMismatches) > 0 {
		matches = false
		mismatchDetails = append(mismatchDetails, internalStateMismatches...)
	}

	// Compare memory contents
	memoryMismatches := compareMemory(memory, test.Expected.ChangedMemory, t)
	if len(memoryMismatches) > 0 {
		matches = false
		mismatchDetails = append(mismatchDetails, memoryMismatches...)
	}

	if matches {
		t.Logf("Test %s PASSED: All registers and memory match expected values", test.Name)
	} else {
		// Add debug information when test fails
		debugInfo := buildDebugInfo(initialRegisters, cpu, test.Expected.FinalState)

		// Combine all information
		allDetails := append(mismatchDetails, debugInfo...)
		t.Errorf("Test %s FAILED:\n%s", test.Name, strings.Join(allDetails, "\n"))
	}
}

// readTests reads all tests from tests.in file
func readTests() ([]Test, error) {
	file, err := os.Open("testdata/tests.in")
	if err != nil {
		return nil, fmt.Errorf("failed to open tests.in: %v", err)
	}
	defer file.Close()

	var tests []Test
	scanner := bufio.NewScanner(file)

	var currentTest *Test
	var readingMemory bool

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" || line == "-1" {
			if currentTest != nil && readingMemory {
				readingMemory = false
			}
			continue
		}

		// Check if this is a test name (starts with alphanumeric characters)
		if isTestName(line) && !readingMemory {
			// Save previous test if exists
			if currentTest != nil {
				tests = append(tests, *currentTest)
			}

			// Start new test
			currentTest = &Test{
				Name:        line,
				Description: line,
				Input:       TestInput{},
				Expected:    TestExpected{},
			}
			continue
		}

		// Parse registers line
		if currentTest != nil && len(strings.Fields(line)) >= 13 && !readingMemory {
			fields := strings.Fields(line)
			if len(fields) >= 13 {
				currentTest.Input.Registers = fields[:13]
				continue
			}
		}

		// Parse flags line (6 or 7 fields, not ending with -1)
		if currentTest != nil && len(strings.Fields(line)) >= 6 && !strings.HasSuffix(strings.TrimSpace(line), "-1") && !readingMemory {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				currentTest.Input.I = fields[0]
				currentTest.Input.R = fields[1]
				currentTest.Input.IFF1 = fields[2]
				currentTest.Input.IFF2 = fields[3]
				currentTest.Input.IM = fields[4]
				currentTest.Input.Halted = fields[5]
				if len(fields) > 6 {
					currentTest.Input.TStates = fields[6]
				}
				continue
			}
		}

		// Parse memory setup (lines ending with -1)
		if currentTest != nil && strings.Contains(line, " ") && strings.HasSuffix(strings.TrimSpace(line), "-1") && !strings.HasPrefix(line, "    ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// Memory block
				address := fields[0]
				bytes := fields[1 : len(fields)-1]

				currentTest.Input.MemorySetup = append(currentTest.Input.MemorySetup, MemoryBlock{
					Address: address,
					Bytes:   bytes,
				})
				readingMemory = true
				continue
			}
		}
	}

	// Add last test
	if currentTest != nil {
		tests = append(tests, *currentTest)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading tests.in: %v", err)
	}

	return tests, nil
}

// isTestName checks if a line is a test name
func isTestName(line string) bool {
	if line == "" {
		return false
	}
	// Simple check: test names are usually alphanumeric with underscores
	for _, r := range line {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

// readExpectedTests reads expected results from tests.expected
func readExpectedTests() (map[string]TestExpected, error) {
	file, err := os.Open("testdata/tests.expected")
	if err != nil {
		return nil, fmt.Errorf("failed to open tests.expected: %v", err)
	}
	defer file.Close()

	expected := make(map[string]TestExpected)
	scanner := bufio.NewScanner(file)

	var currentName string
	var readingEvents bool

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t") // Keep leading spaces for event detection

		// Skip empty lines
		if line == "" {
			continue
		}

		// Check if this is a test name (first non-indented line)
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && isTestName(strings.TrimSpace(line)) {
			currentName = strings.TrimSpace(line)
			expected[currentName] = TestExpected{}
			readingEvents = true
			continue
		}

		// Parse events (lines starting with spaces and numbers)
		if readingEvents && strings.HasPrefix(line, "    ") && len(strings.Fields(strings.TrimSpace(line))) >= 3 {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 3 {
				event := Event{
					Time:    fields[0],
					Type:    fields[1],
					Address: fields[2],
				}
				if len(fields) > 3 {
					event.Data = fields[3]
				}
				// Add event to the current test
				temp := expected[currentName]
				temp.Events = append(temp.Events, event)
				expected[currentName] = temp
			}
			continue
		}

		// Check if we're transitioning from events to final state (registers line)
		if (readingEvents || len(expected[currentName].Events) == 0) && len(strings.Fields(line)) >= 13 {
			readingEvents = false

			// Parse final registers
			fields := strings.Fields(line)
			if len(fields) >= 13 {
				temp := expected[currentName]
				temp.FinalState = fields[:13]
				expected[currentName] = temp
			}
			continue
		}

		// Parse changed memory
		if strings.Contains(line, " ") && strings.HasSuffix(strings.TrimSpace(line), "-1") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				address := fields[0]
				bytes := fields[1 : len(fields)-1]

				temp := expected[currentName]
				temp.ChangedMemory = append(temp.ChangedMemory, MemoryBlock{
					Address: address,
					Bytes:   bytes,
				})
				expected[currentName] = temp

				// Debug output
				//fmt.Printf("Parsed memory block for test %s: address=%s, bytes=%v\n", currentName, address, bytes)
			}
			continue
		}

		// Parse final flags (the line after registers, with 7 fields)
		// Only process this if we have final state and the line doesn't end with -1
		if len(expected[currentName].FinalState) > 0 && len(strings.Fields(line)) >= 7 &&
			!strings.HasPrefix(line, " ") && !strings.HasSuffix(strings.TrimSpace(line), "-1") {
			fields := strings.Fields(line)
			if len(fields) >= 7 {
				temp := expected[currentName]
				temp.I = fields[0]
				temp.R = fields[1]
				temp.IFF1 = fields[2]
				temp.IFF2 = fields[3]
				temp.IM = fields[4]
				temp.Halted = fields[5]
				temp.TStates = fields[6]
				expected[currentName] = temp
			}
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading tests.expected: %v", err)
	}

	return expected, nil
}

// TestZ80 runs all Z80 tests
func TestFuse(t *testing.T) {
	// Read input tests
	inputTests, err := readTests()
	if err != nil {
		t.Fatalf("Failed to read tests: %v", err)
	}

	// Read expected results
	expectedTests, err := readExpectedTests()
	if err != nil {
		t.Fatalf("Failed to read expected results: %v", err)
	}

	// Run each test
	for _, test := range inputTests {
		t.Run(test.Name, func(t *testing.T) {
			// Find expected result for this test
			expected, found := expectedTests[test.Name]
			if !found {
				t.Fatalf("Expected result not found for test %s", test.Name)
			}

			// Update test with expected data
			test.Expected = expected

			// Execute the test (will fail as this is a stub)
			executeZ80Test(t, test)
		})
	}
}
