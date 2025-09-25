# Z80 ZEX Test Suite

This directory contains a boilerplate for running Z80 processor tests, specifically designed for the ZEXALL.COM test suite.

## Features

- 64KB memory implementation
- Z80 CPU emulation using the z80 package
- BDOS call handling for CP/M functions:
  - Print character (function 2)
  - Print string (function 9)
- Proper CALL/RET simulation for BDOS calls
- Program termination detection (when PC reaches 0x0000)

## Setup

1. Place the zexall.com file in this directory
2. Run with: `go run .`

## Behavior

- If zexall.com is not found, the program will exit with an error message
- When the file is loaded successfully, the Z80 emulator will execute the test suite
- BDOS calls for character and string output are properly handled
- Program termination is detected when PC reaches 0x0000

## Implementation Details

The boilerplate includes:
- Memory management for 64KB address space
- I/O handling for CP/M system calls
- CPU initialization for CP/M programs
- Execution loop with termination condition
