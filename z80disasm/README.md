# Z80 Disassembler

A Go package for disassembling Z80 processor instructions.

## Overview

This package provides a Z80 disassembler implementation that can decode Z80 machine code into human-readable assembly mnemonics. It supports all standard Z80 instructions including:

- Unprefixed instructions
- CB-prefixed instructions (bit manipulation, rotation, and shifting)
- DD-prefixed instructions (IX register indexing)
- ED-prefixed instructions (extended instructions)
- FD-prefixed instructions (IY register indexing)

## Installation

```bash
go get github.com/kiltum/emuz80/z80disasm
```

## Usage

```go
package main

import (
    "fmt"
    "github.com/kiltum/emuz80/z80disasm"
)

func main() {
    // Create a new disassembler
    d := disasm.New()
    
    // Decode a simple instruction (NOP)
    data := []byte{0x00}
    instruction, err := d.Decode(data)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    fmt.Printf("Mnemonic: %s\n", instruction.Mnemonic)
    fmt.Printf("Length: %d bytes\n", instruction.Length)
}
```

## Features

- Complete Z80 instruction set support
- Detailed instruction information including length and address operands
- Error handling for malformed or incomplete instructions
- Comprehensive test suite

## License

This project is licensed under the MIT License.
