package disasm

import (
	"fmt"
)

// decodeFD decodes FD-prefixed instructions (IY register)
func (d *Disassembler) decodeFD(data []byte) (*Instruction, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("insufficient data for FD prefix")
	}

	opcode := data[1]

	// Handle FD prefixed instructions
	switch opcode {
	case 0x09:
		return &Instruction{Mnemonic: "ADD IY, BC", Length: 2, Address: 0xFFFF}, nil
	case 0x19:
		return &Instruction{Mnemonic: "ADD IY, DE", Length: 2, Address: 0xFFFF}, nil
	case 0x21:
		if len(data) < 4 {
			return nil, fmt.Errorf("insufficient data for LD IY, nn")
		}
		nn := uint16(data[3])<<8 | uint16(data[2])
		return &Instruction{Mnemonic: fmt.Sprintf("LD IY, $%04X", nn), Length: 4, Address: nn}, nil
	case 0x22:
		if len(data) < 4 {
			return nil, fmt.Errorf("insufficient data for LD (nn), IY")
		}
		nn := uint16(data[3])<<8 | uint16(data[2])
		return &Instruction{Mnemonic: fmt.Sprintf("LD ($%04X), IY", nn), Length: 4, Address: nn}, nil
	case 0x23:
		return &Instruction{Mnemonic: "INC IY", Length: 2, Address: 0xFFFF}, nil
	case 0x24:
		return &Instruction{Mnemonic: "INC IYH", Length: 2, Address: 0xFFFF}, nil
	case 0x25:
		return &Instruction{Mnemonic: "DEC IYH", Length: 2, Address: 0xFFFF}, nil
	case 0x26:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD IYH, n")
		}
		n := data[2]
		return &Instruction{Mnemonic: fmt.Sprintf("LD IYH, $%02X", n), Length: 3, Address: 0xFFFF}, nil
	case 0x29:
		return &Instruction{Mnemonic: "ADD IY, IY", Length: 2, Address: 0xFFFF}, nil
	case 0x2A:
		if len(data) < 4 {
			return nil, fmt.Errorf("insufficient data for LD IY, (nn)")
		}
		nn := uint16(data[3])<<8 | uint16(data[2])
		return &Instruction{Mnemonic: fmt.Sprintf("LD IY, ($%04X)", nn), Length: 4, Address: nn}, nil
	case 0x2B:
		return &Instruction{Mnemonic: "DEC IY", Length: 2, Address: 0xFFFF}, nil
	case 0x2C:
		return &Instruction{Mnemonic: "INC IYL", Length: 2, Address: 0xFFFF}, nil
	case 0x2D:
		return &Instruction{Mnemonic: "DEC IYL", Length: 2, Address: 0xFFFF}, nil
	case 0x2E:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD IYL, n")
		}
		n := data[2]
		return &Instruction{Mnemonic: fmt.Sprintf("LD IYL, $%02X", n), Length: 3, Address: 0xFFFF}, nil
	case 0x34:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for INC (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("INC (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("INC (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x35:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for DEC (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("DEC (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("DEC (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x36:
		if len(data) < 4 {
			return nil, fmt.Errorf("insufficient data for LD (IY+d), n")
		}
		disp := int8(data[2])
		n := data[3]
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY+$%02X), $%02X", disp, n), Length: 4, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY-$%02X), $%02X", -disp, n), Length: 4, Address: 0xFFFF}, nil
		}
	case 0x39:
		return &Instruction{Mnemonic: "ADD IY, SP", Length: 2, Address: 0xFFFF}, nil
	case 0x44:
		return &Instruction{Mnemonic: "LD B, IYH", Length: 2, Address: 0xFFFF}, nil
	case 0x45:
		return &Instruction{Mnemonic: "LD B, IYL", Length: 2, Address: 0xFFFF}, nil
	case 0x46:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD B, (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD B, (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD B, (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x4C:
		return &Instruction{Mnemonic: "LD C, IYH", Length: 2, Address: 0xFFFF}, nil
	case 0x4D:
		return &Instruction{Mnemonic: "LD C, IYL", Length: 2, Address: 0xFFFF}, nil
	case 0x4E:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD C, (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD C, (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD C, (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x54:
		return &Instruction{Mnemonic: "LD D, IYH", Length: 2, Address: 0xFFFF}, nil
	case 0x55:
		return &Instruction{Mnemonic: "LD D, IYL", Length: 2, Address: 0xFFFF}, nil
	case 0x56:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD D, (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD D, (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD D, (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x5C:
		return &Instruction{Mnemonic: "LD E, IYH", Length: 2, Address: 0xFFFF}, nil
	case 0x5D:
		return &Instruction{Mnemonic: "LD E, IYL", Length: 2, Address: 0xFFFF}, nil
	case 0x5E:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD E, (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD E, (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD E, (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x60:
		return &Instruction{Mnemonic: "LD IYH, B", Length: 2, Address: 0xFFFF}, nil
	case 0x61:
		return &Instruction{Mnemonic: "LD IYH, C", Length: 2, Address: 0xFFFF}, nil
	case 0x62:
		return &Instruction{Mnemonic: "LD IYH, D", Length: 2, Address: 0xFFFF}, nil
	case 0x63:
		return &Instruction{Mnemonic: "LD IYH, E", Length: 2, Address: 0xFFFF}, nil
	case 0x64:
		return &Instruction{Mnemonic: "LD IYH, IYH", Length: 2, Address: 0xFFFF}, nil
	case 0x65:
		return &Instruction{Mnemonic: "LD IYH, IYL", Length: 2, Address: 0xFFFF}, nil
	case 0x66:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD H, (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD H, (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD H, (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x67:
		return &Instruction{Mnemonic: "LD IYH, A", Length: 2, Address: 0xFFFF}, nil
	case 0x68:
		return &Instruction{Mnemonic: "LD IYL, B", Length: 2, Address: 0xFFFF}, nil
	case 0x69:
		return &Instruction{Mnemonic: "LD IYL, C", Length: 2, Address: 0xFFFF}, nil
	case 0x6A:
		return &Instruction{Mnemonic: "LD IYL, D", Length: 2, Address: 0xFFFF}, nil
	case 0x6B:
		return &Instruction{Mnemonic: "LD IYL, E", Length: 2, Address: 0xFFFF}, nil
	case 0x6C:
		return &Instruction{Mnemonic: "LD IYL, IYH", Length: 2, Address: 0xFFFF}, nil
	case 0x6D:
		return &Instruction{Mnemonic: "LD IYL, IYL", Length: 2, Address: 0xFFFF}, nil
	case 0x6E:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD L, (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD L, (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD L, (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x6F:
		return &Instruction{Mnemonic: "LD IYL, A", Length: 2, Address: 0xFFFF}, nil
	case 0x70:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD (IY+d), B")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY+$%02X), B", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY-$%02X), B", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x71:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD (IY+d), C")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY+$%02X), C", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY-$%02X), C", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x72:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD (IY+d), D")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY+$%02X), D", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY-$%02X), D", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x73:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD (IY+d), E")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY+$%02X), E", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY-$%02X), E", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x74:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD (IY+d), H")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY+$%02X), H", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY-$%02X), H", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x75:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD (IY+d), L")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY+$%02X), L", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY-$%02X), L", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x77:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD (IY+d), A")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY+$%02X), A", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD (IY-$%02X), A", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x7C:
		return &Instruction{Mnemonic: "LD A, IYH", Length: 2, Address: 0xFFFF}, nil
	case 0x7D:
		return &Instruction{Mnemonic: "LD A, IYL", Length: 2, Address: 0xFFFF}, nil
	case 0x7E:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for LD A, (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("LD A, (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("LD A, (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x84:
		return &Instruction{Mnemonic: "ADD A, IYH", Length: 2, Address: 0xFFFF}, nil
	case 0x85:
		return &Instruction{Mnemonic: "ADD A, IYL", Length: 2, Address: 0xFFFF}, nil
	case 0x86:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for ADD A, (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("ADD A, (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("ADD A, (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x8C:
		return &Instruction{Mnemonic: "ADC A, IYH", Length: 2, Address: 0xFFFF}, nil
	case 0x8D:
		return &Instruction{Mnemonic: "ADC A, IYL", Length: 2, Address: 0xFFFF}, nil
	case 0x8E:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for ADC A, (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("ADC A, (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("ADC A, (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x94:
		return &Instruction{Mnemonic: "SUB IYH", Length: 2, Address: 0xFFFF}, nil
	case 0x95:
		return &Instruction{Mnemonic: "SUB IYL", Length: 2, Address: 0xFFFF}, nil
	case 0x96:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for SUB (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("SUB (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("SUB (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0x9C:
		return &Instruction{Mnemonic: "SBC A, IYH", Length: 2, Address: 0xFFFF}, nil
	case 0x9D:
		return &Instruction{Mnemonic: "SBC A, IYL", Length: 2, Address: 0xFFFF}, nil
	case 0x9E:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for SBC A, (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("SBC A, (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("SBC A, (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0xA4:
		return &Instruction{Mnemonic: "AND IYH", Length: 2, Address: 0xFFFF}, nil
	case 0xA5:
		return &Instruction{Mnemonic: "AND IYL", Length: 2, Address: 0xFFFF}, nil
	case 0xA6:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for AND (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("AND (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("AND (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0xAC:
		return &Instruction{Mnemonic: "XOR IYH", Length: 2, Address: 0xFFFF}, nil
	case 0xAD:
		return &Instruction{Mnemonic: "XOR IYL", Length: 2, Address: 0xFFFF}, nil
	case 0xAE:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for XOR (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("XOR (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("XOR (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0xB4:
		return &Instruction{Mnemonic: "OR IYH", Length: 2, Address: 0xFFFF}, nil
	case 0xB5:
		return &Instruction{Mnemonic: "OR IYL", Length: 2, Address: 0xFFFF}, nil
	case 0xB6:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for OR (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("OR (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("OR (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0xBC:
		return &Instruction{Mnemonic: "CP IYH", Length: 2, Address: 0xFFFF}, nil
	case 0xBD:
		return &Instruction{Mnemonic: "CP IYL", Length: 2, Address: 0xFFFF}, nil
	case 0xBE:
		if len(data) < 3 {
			return nil, fmt.Errorf("insufficient data for CP (IY+d)")
		}
		disp := int8(data[2])
		if disp >= 0 {
			return &Instruction{Mnemonic: fmt.Sprintf("CP (IY+$%02X)", disp), Length: 3, Address: 0xFFFF}, nil
		} else {
			return &Instruction{Mnemonic: fmt.Sprintf("CP (IY-$%02X)", -disp), Length: 3, Address: 0xFFFF}, nil
		}
	case 0xCB:
		if len(data) < 4 {
			return nil, fmt.Errorf("insufficient data for FD CB prefix")
		}
		disp := int8(data[2])
		cbOpcode := data[3]

		// Handle FDCB prefixed instructions
		switch cbOpcode {
		// RLC B through RLC A (undocumented)
		case 0x00:
			return &Instruction{Mnemonic: "RLC B", Length: 4, Address: 0xFFFF}, nil
		case 0x01:
			return &Instruction{Mnemonic: "RLC C", Length: 4, Address: 0xFFFF}, nil
		case 0x02:
			return &Instruction{Mnemonic: "RLC D", Length: 4, Address: 0xFFFF}, nil
		case 0x03:
			return &Instruction{Mnemonic: "RLC E", Length: 4, Address: 0xFFFF}, nil
		case 0x04:
			return &Instruction{Mnemonic: "RLC H", Length: 4, Address: 0xFFFF}, nil
		case 0x05:
			return &Instruction{Mnemonic: "RLC L", Length: 4, Address: 0xFFFF}, nil
		case 0x07:
			return &Instruction{Mnemonic: "RLC A", Length: 4, Address: 0xFFFF}, nil
		// RLC (IY+d) - documented
		case 0x06:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("RLC (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("RLC (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// RRC B through RRC A (undocumented)
		case 0x08:
			return &Instruction{Mnemonic: "RRC B", Length: 4, Address: 0xFFFF}, nil
		case 0x09:
			return &Instruction{Mnemonic: "RRC C", Length: 4, Address: 0xFFFF}, nil
		case 0x0A:
			return &Instruction{Mnemonic: "RRC D", Length: 4, Address: 0xFFFF}, nil
		case 0x0B:
			return &Instruction{Mnemonic: "RRC E", Length: 4, Address: 0xFFFF}, nil
		case 0x0C:
			return &Instruction{Mnemonic: "RRC H", Length: 4, Address: 0xFFFF}, nil
		case 0x0D:
			return &Instruction{Mnemonic: "RRC L", Length: 4, Address: 0xFFFF}, nil
		case 0x0F:
			return &Instruction{Mnemonic: "RRC A", Length: 4, Address: 0xFFFF}, nil
		// RRC (IY+d) - documented
		case 0x0E:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("RRC (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("RRC (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// RL B through RL A (undocumented)
		case 0x10:
			return &Instruction{Mnemonic: "RL B", Length: 4, Address: 0xFFFF}, nil
		case 0x11:
			return &Instruction{Mnemonic: "RL C", Length: 4, Address: 0xFFFF}, nil
		case 0x12:
			return &Instruction{Mnemonic: "RL D", Length: 4, Address: 0xFFFF}, nil
		case 0x13:
			return &Instruction{Mnemonic: "RL E", Length: 4, Address: 0xFFFF}, nil
		case 0x14:
			return &Instruction{Mnemonic: "RL H", Length: 4, Address: 0xFFFF}, nil
		case 0x15:
			return &Instruction{Mnemonic: "RL L", Length: 4, Address: 0xFFFF}, nil
		case 0x17:
			return &Instruction{Mnemonic: "RL A", Length: 4, Address: 0xFFFF}, nil
		// RL (IY+d) - documented
		case 0x16:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("RL (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("RL (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// RR B through RR A (undocumented)
		case 0x18:
			return &Instruction{Mnemonic: "RR B", Length: 4, Address: 0xFFFF}, nil
		case 0x19:
			return &Instruction{Mnemonic: "RR C", Length: 4, Address: 0xFFFF}, nil
		case 0x1A:
			return &Instruction{Mnemonic: "RR D", Length: 4, Address: 0xFFFF}, nil
		case 0x1B:
			return &Instruction{Mnemonic: "RR E", Length: 4, Address: 0xFFFF}, nil
		case 0x1C:
			return &Instruction{Mnemonic: "RR H", Length: 4, Address: 0xFFFF}, nil
		case 0x1D:
			return &Instruction{Mnemonic: "RR L", Length: 4, Address: 0xFFFF}, nil
		case 0x1F:
			return &Instruction{Mnemonic: "RR A", Length: 4, Address: 0xFFFF}, nil
		// RR (IY+d) - documented
		case 0x1E:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("RR (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("RR (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// SLA B through SLA A (undocumented)
		case 0x20:
			return &Instruction{Mnemonic: "SLA B", Length: 4, Address: 0xFFFF}, nil
		case 0x21:
			return &Instruction{Mnemonic: "SLA C", Length: 4, Address: 0xFFFF}, nil
		case 0x22:
			return &Instruction{Mnemonic: "SLA D", Length: 4, Address: 0xFFFF}, nil
		case 0x23:
			return &Instruction{Mnemonic: "SLA E", Length: 4, Address: 0xFFFF}, nil
		case 0x24:
			return &Instruction{Mnemonic: "SLA H", Length: 4, Address: 0xFFFF}, nil
		case 0x25:
			return &Instruction{Mnemonic: "SLA L", Length: 4, Address: 0xFFFF}, nil
		case 0x27:
			return &Instruction{Mnemonic: "SLA A", Length: 4, Address: 0xFFFF}, nil
		// SLA (IY+d) - documented
		case 0x26:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("SLA (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("SLA (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// SRA B through SRA A (undocumented)
		case 0x28:
			return &Instruction{Mnemonic: "SRA B", Length: 4, Address: 0xFFFF}, nil
		case 0x29:
			return &Instruction{Mnemonic: "SRA C", Length: 4, Address: 0xFFFF}, nil
		case 0x2A:
			return &Instruction{Mnemonic: "SRA D", Length: 4, Address: 0xFFFF}, nil
		case 0x2B:
			return &Instruction{Mnemonic: "SRA E", Length: 4, Address: 0xFFFF}, nil
		case 0x2C:
			return &Instruction{Mnemonic: "SRA H", Length: 4, Address: 0xFFFF}, nil
		case 0x2D:
			return &Instruction{Mnemonic: "SRA L", Length: 4, Address: 0xFFFF}, nil
		case 0x2F:
			return &Instruction{Mnemonic: "SRA A", Length: 4, Address: 0xFFFF}, nil
		// SRA (IY+d) - documented
		case 0x2E:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("SRA (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("SRA (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// SLL B through SLL A (undocumented)
		case 0x30:
			return &Instruction{Mnemonic: "SLL B", Length: 4, Address: 0xFFFF}, nil
		case 0x31:
			return &Instruction{Mnemonic: "SLL C", Length: 4, Address: 0xFFFF}, nil
		case 0x32:
			return &Instruction{Mnemonic: "SLL D", Length: 4, Address: 0xFFFF}, nil
		case 0x33:
			return &Instruction{Mnemonic: "SLL E", Length: 4, Address: 0xFFFF}, nil
		case 0x34:
			return &Instruction{Mnemonic: "SLL H", Length: 4, Address: 0xFFFF}, nil
		case 0x35:
			return &Instruction{Mnemonic: "SLL L", Length: 4, Address: 0xFFFF}, nil
		case 0x37:
			return &Instruction{Mnemonic: "SLL A", Length: 4, Address: 0xFFFF}, nil
		// SLL (IY+d) - Undocumented
		case 0x36:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("SLL (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("SLL (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// SRL B through SRL A (undocumented)
		case 0x38:
			return &Instruction{Mnemonic: "SRL B", Length: 4, Address: 0xFFFF}, nil
		case 0x39:
			return &Instruction{Mnemonic: "SRL C", Length: 4, Address: 0xFFFF}, nil
		case 0x3A:
			return &Instruction{Mnemonic: "SRL D", Length: 4, Address: 0xFFFF}, nil
		case 0x3B:
			return &Instruction{Mnemonic: "SRL E", Length: 4, Address: 0xFFFF}, nil
		case 0x3C:
			return &Instruction{Mnemonic: "SRL H", Length: 4, Address: 0xFFFF}, nil
		case 0x3D:
			return &Instruction{Mnemonic: "SRL L", Length: 4, Address: 0xFFFF}, nil
		case 0x3F:
			return &Instruction{Mnemonic: "SRL A", Length: 4, Address: 0xFFFF}, nil
		// SRL (IY+d) - documented
		case 0x3E:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("SRL (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("SRL (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// BIT b, r (undocumented)
		// BIT 0, r
		case 0x40:
			return &Instruction{Mnemonic: "BIT 0, B", Length: 4, Address: 0xFFFF}, nil
		case 0x41:
			return &Instruction{Mnemonic: "BIT 0, C", Length: 4, Address: 0xFFFF}, nil
		case 0x42:
			return &Instruction{Mnemonic: "BIT 0, D", Length: 4, Address: 0xFFFF}, nil
		case 0x43:
			return &Instruction{Mnemonic: "BIT 0, E", Length: 4, Address: 0xFFFF}, nil
		case 0x44:
			return &Instruction{Mnemonic: "BIT 0, H", Length: 4, Address: 0xFFFF}, nil
		case 0x45:
			return &Instruction{Mnemonic: "BIT 0, L", Length: 4, Address: 0xFFFF}, nil
		case 0x47:
			return &Instruction{Mnemonic: "BIT 0, A", Length: 4, Address: 0xFFFF}, nil
		// BIT 0, (IY+d) - documented
		case 0x46:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 0, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 0, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// BIT 1, r
		case 0x48:
			return &Instruction{Mnemonic: "BIT 1, B", Length: 4, Address: 0xFFFF}, nil
		case 0x49:
			return &Instruction{Mnemonic: "BIT 1, C", Length: 4, Address: 0xFFFF}, nil
		case 0x4A:
			return &Instruction{Mnemonic: "BIT 1, D", Length: 4, Address: 0xFFFF}, nil
		case 0x4B:
			return &Instruction{Mnemonic: "BIT 1, E", Length: 4, Address: 0xFFFF}, nil
		case 0x4C:
			return &Instruction{Mnemonic: "BIT 1, H", Length: 4, Address: 0xFFFF}, nil
		case 0x4D:
			return &Instruction{Mnemonic: "BIT 1, L", Length: 4, Address: 0xFFFF}, nil
		case 0x4F:
			return &Instruction{Mnemonic: "BIT 1, A", Length: 4, Address: 0xFFFF}, nil
		// BIT 1, (IY+d) - documented
		case 0x4E:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 1, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 1, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// BIT 2, r
		case 0x50:
			return &Instruction{Mnemonic: "BIT 2, B", Length: 4, Address: 0xFFFF}, nil
		case 0x51:
			return &Instruction{Mnemonic: "BIT 2, C", Length: 4, Address: 0xFFFF}, nil
		case 0x52:
			return &Instruction{Mnemonic: "BIT 2, D", Length: 4, Address: 0xFFFF}, nil
		case 0x53:
			return &Instruction{Mnemonic: "BIT 2, E", Length: 4, Address: 0xFFFF}, nil
		case 0x54:
			return &Instruction{Mnemonic: "BIT 2, H", Length: 4, Address: 0xFFFF}, nil
		case 0x55:
			return &Instruction{Mnemonic: "BIT 2, L", Length: 4, Address: 0xFFFF}, nil
		case 0x57:
			return &Instruction{Mnemonic: "BIT 2, A", Length: 4, Address: 0xFFFF}, nil
		// BIT 2, (IY+d) - documented
		case 0x56:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 2, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 2, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// BIT 3, r
		case 0x58:
			return &Instruction{Mnemonic: "BIT 3, B", Length: 4, Address: 0xFFFF}, nil
		case 0x59:
			return &Instruction{Mnemonic: "BIT 3, C", Length: 4, Address: 0xFFFF}, nil
		case 0x5A:
			return &Instruction{Mnemonic: "BIT 3, D", Length: 4, Address: 0xFFFF}, nil
		case 0x5B:
			return &Instruction{Mnemonic: "BIT 3, E", Length: 4, Address: 0xFFFF}, nil
		case 0x5C:
			return &Instruction{Mnemonic: "BIT 3, H", Length: 4, Address: 0xFFFF}, nil
		case 0x5D:
			return &Instruction{Mnemonic: "BIT 3, L", Length: 4, Address: 0xFFFF}, nil
		case 0x5F:
			return &Instruction{Mnemonic: "BIT 3, A", Length: 4, Address: 0xFFFF}, nil
		// BIT 3, (IY+d) - documented
		case 0x5E:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 3, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 3, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// BIT 4, r
		case 0x60:
			return &Instruction{Mnemonic: "BIT 4, B", Length: 4, Address: 0xFFFF}, nil
		case 0x61:
			return &Instruction{Mnemonic: "BIT 4, C", Length: 4, Address: 0xFFFF}, nil
		case 0x62:
			return &Instruction{Mnemonic: "BIT 4, D", Length: 4, Address: 0xFFFF}, nil
		case 0x63:
			return &Instruction{Mnemonic: "BIT 4, E", Length: 4, Address: 0xFFFF}, nil
		case 0x64:
			return &Instruction{Mnemonic: "BIT 4, H", Length: 4, Address: 0xFFFF}, nil
		case 0x65:
			return &Instruction{Mnemonic: "BIT 4, L", Length: 4, Address: 0xFFFF}, nil
		case 0x67:
			return &Instruction{Mnemonic: "BIT 4, A", Length: 4, Address: 0xFFFF}, nil
		// BIT 4, (IY+d) - documented
		case 0x66:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 4, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 4, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// BIT 5, r
		case 0x68:
			return &Instruction{Mnemonic: "BIT 5, B", Length: 4, Address: 0xFFFF}, nil
		case 0x69:
			return &Instruction{Mnemonic: "BIT 5, C", Length: 4, Address: 0xFFFF}, nil
		case 0x6A:
			return &Instruction{Mnemonic: "BIT 5, D", Length: 4, Address: 0xFFFF}, nil
		case 0x6B:
			return &Instruction{Mnemonic: "BIT 5, E", Length: 4, Address: 0xFFFF}, nil
		case 0x6C:
			return &Instruction{Mnemonic: "BIT 5, H", Length: 4, Address: 0xFFFF}, nil
		case 0x6D:
			return &Instruction{Mnemonic: "BIT 5, L", Length: 4, Address: 0xFFFF}, nil
		case 0x6F:
			return &Instruction{Mnemonic: "BIT 5, A", Length: 4, Address: 0xFFFF}, nil
		// BIT 5, (IY+d) - documented
		case 0x6E:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 5, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 5, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// BIT 6, r
		case 0x70:
			return &Instruction{Mnemonic: "BIT 6, B", Length: 4, Address: 0xFFFF}, nil
		case 0x71:
			return &Instruction{Mnemonic: "BIT 6, C", Length: 4, Address: 0xFFFF}, nil
		case 0x72:
			return &Instruction{Mnemonic: "BIT 6, D", Length: 4, Address: 0xFFFF}, nil
		case 0x73:
			return &Instruction{Mnemonic: "BIT 6, E", Length: 4, Address: 0xFFFF}, nil
		case 0x74:
			return &Instruction{Mnemonic: "BIT 6, H", Length: 4, Address: 0xFFFF}, nil
		case 0x75:
			return &Instruction{Mnemonic: "BIT 6, L", Length: 4, Address: 0xFFFF}, nil
		case 0x77:
			return &Instruction{Mnemonic: "BIT 6, A", Length: 4, Address: 0xFFFF}, nil
		// BIT 6, (IY+d) - documented
		case 0x76:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 6, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 6, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// BIT 7, r
		case 0x78:
			return &Instruction{Mnemonic: "BIT 7, B", Length: 4, Address: 0xFFFF}, nil
		case 0x79:
			return &Instruction{Mnemonic: "BIT 7, C", Length: 4, Address: 0xFFFF}, nil
		case 0x7A:
			return &Instruction{Mnemonic: "BIT 7, D", Length: 4, Address: 0xFFFF}, nil
		case 0x7B:
			return &Instruction{Mnemonic: "BIT 7, E", Length: 4, Address: 0xFFFF}, nil
		case 0x7C:
			return &Instruction{Mnemonic: "BIT 7, H", Length: 4, Address: 0xFFFF}, nil
		case 0x7D:
			return &Instruction{Mnemonic: "BIT 7, L", Length: 4, Address: 0xFFFF}, nil
		case 0x7F:
			return &Instruction{Mnemonic: "BIT 7, A", Length: 4, Address: 0xFFFF}, nil
		// BIT 7, (IY+d) - documented
		case 0x7E:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 7, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("BIT 7, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// RES b, r (undocumented)
		// RES 0, r
		case 0x80:
			return &Instruction{Mnemonic: "RES 0, B", Length: 4, Address: 0xFFFF}, nil
		case 0x81:
			return &Instruction{Mnemonic: "RES 0, C", Length: 4, Address: 0xFFFF}, nil
		case 0x82:
			return &Instruction{Mnemonic: "RES 0, D", Length: 4, Address: 0xFFFF}, nil
		case 0x83:
			return &Instruction{Mnemonic: "RES 0, E", Length: 4, Address: 0xFFFF}, nil
		case 0x84:
			return &Instruction{Mnemonic: "RES 0, H", Length: 4, Address: 0xFFFF}, nil
		case 0x85:
			return &Instruction{Mnemonic: "RES 0, L", Length: 4, Address: 0xFFFF}, nil
		case 0x87:
			return &Instruction{Mnemonic: "RES 0, A", Length: 4, Address: 0xFFFF}, nil
		// RES 0, (IY+d) - documented
		case 0x86:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 0, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 0, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// RES 1, r
		case 0x88:
			return &Instruction{Mnemonic: "RES 1, B", Length: 4, Address: 0xFFFF}, nil
		case 0x89:
			return &Instruction{Mnemonic: "RES 1, C", Length: 4, Address: 0xFFFF}, nil
		case 0x8A:
			return &Instruction{Mnemonic: "RES 1, D", Length: 4, Address: 0xFFFF}, nil
		case 0x8B:
			return &Instruction{Mnemonic: "RES 1, E", Length: 4, Address: 0xFFFF}, nil
		case 0x8C:
			return &Instruction{Mnemonic: "RES 1, H", Length: 4, Address: 0xFFFF}, nil
		case 0x8D:
			return &Instruction{Mnemonic: "RES 1, L", Length: 4, Address: 0xFFFF}, nil
		case 0x8F:
			return &Instruction{Mnemonic: "RES 1, A", Length: 4, Address: 0xFFFF}, nil
		// RES 1, (IY+d) - documented
		case 0x8E:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 1, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 1, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// RES 2, r
		case 0x90:
			return &Instruction{Mnemonic: "RES 2, B", Length: 4, Address: 0xFFFF}, nil
		case 0x91:
			return &Instruction{Mnemonic: "RES 2, C", Length: 4, Address: 0xFFFF}, nil
		case 0x92:
			return &Instruction{Mnemonic: "RES 2, D", Length: 4, Address: 0xFFFF}, nil
		case 0x93:
			return &Instruction{Mnemonic: "RES 2, E", Length: 4, Address: 0xFFFF}, nil
		case 0x94:
			return &Instruction{Mnemonic: "RES 2, H", Length: 4, Address: 0xFFFF}, nil
		case 0x95:
			return &Instruction{Mnemonic: "RES 2, L", Length: 4, Address: 0xFFFF}, nil
		case 0x97:
			return &Instruction{Mnemonic: "RES 2, A", Length: 4, Address: 0xFFFF}, nil
		// RES 2, (IY+d) - documented
		case 0x96:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 2, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 2, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// RES 3, r
		case 0x98:
			return &Instruction{Mnemonic: "RES 3, B", Length: 4, Address: 0xFFFF}, nil
		case 0x99:
			return &Instruction{Mnemonic: "RES 3, C", Length: 4, Address: 0xFFFF}, nil
		case 0x9A:
			return &Instruction{Mnemonic: "RES 3, D", Length: 4, Address: 0xFFFF}, nil
		case 0x9B:
			return &Instruction{Mnemonic: "RES 3, E", Length: 4, Address: 0xFFFF}, nil
		case 0x9C:
			return &Instruction{Mnemonic: "RES 3, H", Length: 4, Address: 0xFFFF}, nil
		case 0x9D:
			return &Instruction{Mnemonic: "RES 3, L", Length: 4, Address: 0xFFFF}, nil
		case 0x9F:
			return &Instruction{Mnemonic: "RES 3, A", Length: 4, Address: 0xFFFF}, nil
		// RES 3, (IY+d) - documented
		case 0x9E:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 3, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 3, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// RES 4, r
		case 0xA0:
			return &Instruction{Mnemonic: "RES 4, B", Length: 4, Address: 0xFFFF}, nil
		case 0xA1:
			return &Instruction{Mnemonic: "RES 4, C", Length: 4, Address: 0xFFFF}, nil
		case 0xA2:
			return &Instruction{Mnemonic: "RES 4, D", Length: 4, Address: 0xFFFF}, nil
		case 0xA3:
			return &Instruction{Mnemonic: "RES 4, E", Length: 4, Address: 0xFFFF}, nil
		case 0xA4:
			return &Instruction{Mnemonic: "RES 4, H", Length: 4, Address: 0xFFFF}, nil
		case 0xA5:
			return &Instruction{Mnemonic: "RES 4, L", Length: 4, Address: 0xFFFF}, nil
		case 0xA7:
			return &Instruction{Mnemonic: "RES 4, A", Length: 4, Address: 0xFFFF}, nil
		// RES 4, (IY+d) - documented
		case 0xA6:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 4, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 4, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// RES 5, r
		case 0xA8:
			return &Instruction{Mnemonic: "RES 5, B", Length: 4, Address: 0xFFFF}, nil
		case 0xA9:
			return &Instruction{Mnemonic: "RES 5, C", Length: 4, Address: 0xFFFF}, nil
		case 0xAA:
			return &Instruction{Mnemonic: "RES 5, D", Length: 4, Address: 0xFFFF}, nil
		case 0xAB:
			return &Instruction{Mnemonic: "RES 5, E", Length: 4, Address: 0xFFFF}, nil
		case 0xAC:
			return &Instruction{Mnemonic: "RES 5, H", Length: 4, Address: 0xFFFF}, nil
		case 0xAD:
			return &Instruction{Mnemonic: "RES 5, L", Length: 4, Address: 0xFFFF}, nil
		case 0xAF:
			return &Instruction{Mnemonic: "RES 5, A", Length: 4, Address: 0xFFFF}, nil
		// RES 5, (IY+d) - documented
		case 0xAE:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 5, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 5, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// RES 6, r
		case 0xB0:
			return &Instruction{Mnemonic: "RES 6, B", Length: 4, Address: 0xFFFF}, nil
		case 0xB1:
			return &Instruction{Mnemonic: "RES 6, C", Length: 4, Address: 0xFFFF}, nil
		case 0xB2:
			return &Instruction{Mnemonic: "RES 6, D", Length: 4, Address: 0xFFFF}, nil
		case 0xB3:
			return &Instruction{Mnemonic: "RES 6, E", Length: 4, Address: 0xFFFF}, nil
		case 0xB4:
			return &Instruction{Mnemonic: "RES 6, H", Length: 4, Address: 0xFFFF}, nil
		case 0xB5:
			return &Instruction{Mnemonic: "RES 6, L", Length: 4, Address: 0xFFFF}, nil
		case 0xB7:
			return &Instruction{Mnemonic: "RES 6, A", Length: 4, Address: 0xFFFF}, nil
		// RES 6, (IY+d) - documented
		case 0xB6:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 6, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 6, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// RES 7, r
		case 0xB8:
			return &Instruction{Mnemonic: "RES 7, B", Length: 4, Address: 0xFFFF}, nil
		case 0xB9:
			return &Instruction{Mnemonic: "RES 7, C", Length: 4, Address: 0xFFFF}, nil
		case 0xBA:
			return &Instruction{Mnemonic: "RES 7, D", Length: 4, Address: 0xFFFF}, nil
		case 0xBB:
			return &Instruction{Mnemonic: "RES 7, E", Length: 4, Address: 0xFFFF}, nil
		case 0xBC:
			return &Instruction{Mnemonic: "RES 7, H", Length: 4, Address: 0xFFFF}, nil
		case 0xBD:
			return &Instruction{Mnemonic: "RES 7, L", Length: 4, Address: 0xFFFF}, nil
		case 0xBF:
			return &Instruction{Mnemonic: "RES 7, A", Length: 4, Address: 0xFFFF}, nil
		// RES 7, (IY+d) - documented
		case 0xBE:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 7, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("RES 7, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// SET b, r (undocumented)
		// SET 0, r
		case 0xC0:
			return &Instruction{Mnemonic: "SET 0, B", Length: 4, Address: 0xFFFF}, nil
		case 0xC1:
			return &Instruction{Mnemonic: "SET 0, C", Length: 4, Address: 0xFFFF}, nil
		case 0xC2:
			return &Instruction{Mnemonic: "SET 0, D", Length: 4, Address: 0xFFFF}, nil
		case 0xC3:
			return &Instruction{Mnemonic: "SET 0, E", Length: 4, Address: 0xFFFF}, nil
		case 0xC4:
			return &Instruction{Mnemonic: "SET 0, H", Length: 4, Address: 0xFFFF}, nil
		case 0xC5:
			return &Instruction{Mnemonic: "SET 0, L", Length: 4, Address: 0xFFFF}, nil
		case 0xC7:
			return &Instruction{Mnemonic: "SET 0, A", Length: 4, Address: 0xFFFF}, nil
		// SET 0, (IY+d) - documented
		case 0xC6:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 0, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 0, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// SET 1, r
		case 0xC8:
			return &Instruction{Mnemonic: "SET 1, B", Length: 4, Address: 0xFFFF}, nil
		case 0xC9:
			return &Instruction{Mnemonic: "SET 1, C", Length: 4, Address: 0xFFFF}, nil
		case 0xCA:
			return &Instruction{Mnemonic: "SET 1, D", Length: 4, Address: 0xFFFF}, nil
		case 0xCB:
			return &Instruction{Mnemonic: "SET 1, E", Length: 4, Address: 0xFFFF}, nil
		case 0xCC:
			return &Instruction{Mnemonic: "SET 1, H", Length: 4, Address: 0xFFFF}, nil
		case 0xCD:
			return &Instruction{Mnemonic: "SET 1, L", Length: 4, Address: 0xFFFF}, nil
		case 0xCF:
			return &Instruction{Mnemonic: "SET 1, A", Length: 4, Address: 0xFFFF}, nil
		// SET 1, (IY+d) - documented
		case 0xCE:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 1, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 1, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// SET 2, r
		case 0xD0:
			return &Instruction{Mnemonic: "SET 2, B", Length: 4, Address: 0xFFFF}, nil
		case 0xD1:
			return &Instruction{Mnemonic: "SET 2, C", Length: 4, Address: 0xFFFF}, nil
		case 0xD2:
			return &Instruction{Mnemonic: "SET 2, D", Length: 4, Address: 0xFFFF}, nil
		case 0xD3:
			return &Instruction{Mnemonic: "SET 2, E", Length: 4, Address: 0xFFFF}, nil
		case 0xD4:
			return &Instruction{Mnemonic: "SET 2, H", Length: 4, Address: 0xFFFF}, nil
		case 0xD5:
			return &Instruction{Mnemonic: "SET 2, L", Length: 4, Address: 0xFFFF}, nil
		case 0xD7:
			return &Instruction{Mnemonic: "SET 2, A", Length: 4, Address: 0xFFFF}, nil
		// SET 2, (IY+d) - documented
		case 0xD6:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 2, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 2, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// SET 3, r
		case 0xD8:
			return &Instruction{Mnemonic: "SET 3, B", Length: 4, Address: 0xFFFF}, nil
		case 0xD9:
			return &Instruction{Mnemonic: "SET 3, C", Length: 4, Address: 0xFFFF}, nil
		case 0xDA:
			return &Instruction{Mnemonic: "SET 3, D", Length: 4, Address: 0xFFFF}, nil
		case 0xDB:
			return &Instruction{Mnemonic: "SET 3, E", Length: 4, Address: 0xFFFF}, nil
		case 0xDC:
			return &Instruction{Mnemonic: "SET 3, H", Length: 4, Address: 0xFFFF}, nil
		case 0xDD:
			return &Instruction{Mnemonic: "SET 3, L", Length: 4, Address: 0xFFFF}, nil
		case 0xDF:
			return &Instruction{Mnemonic: "SET 3, A", Length: 4, Address: 0xFFFF}, nil
		// SET 3, (IY+d) - documented
		case 0xDE:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 3, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 3, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// SET 4, r
		case 0xE0:
			return &Instruction{Mnemonic: "SET 4, B", Length: 4, Address: 0xFFFF}, nil
		case 0xE1:
			return &Instruction{Mnemonic: "SET 4, C", Length: 4, Address: 0xFFFF}, nil
		case 0xE2:
			return &Instruction{Mnemonic: "SET 4, D", Length: 4, Address: 0xFFFF}, nil
		case 0xE3:
			return &Instruction{Mnemonic: "SET 4, E", Length: 4, Address: 0xFFFF}, nil
		case 0xE4:
			return &Instruction{Mnemonic: "SET 4, H", Length: 4, Address: 0xFFFF}, nil
		case 0xE5:
			return &Instruction{Mnemonic: "SET 4, L", Length: 4, Address: 0xFFFF}, nil
		case 0xE7:
			return &Instruction{Mnemonic: "SET 4, A", Length: 4, Address: 0xFFFF}, nil
		// SET 4, (IY+d) - documented
		case 0xE6:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 4, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 4, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// SET 5, r
		case 0xE8:
			return &Instruction{Mnemonic: "SET 5, B", Length: 4, Address: 0xFFFF}, nil
		case 0xE9:
			return &Instruction{Mnemonic: "SET 5, C", Length: 4, Address: 0xFFFF}, nil
		case 0xEA:
			return &Instruction{Mnemonic: "SET 5, D", Length: 4, Address: 0xFFFF}, nil
		case 0xEB:
			return &Instruction{Mnemonic: "SET 5, E", Length: 4, Address: 0xFFFF}, nil
		case 0xEC:
			return &Instruction{Mnemonic: "SET 5, H", Length: 4, Address: 0xFFFF}, nil
		case 0xED:
			return &Instruction{Mnemonic: "SET 5, L", Length: 4, Address: 0xFFFF}, nil
		case 0xEF:
			return &Instruction{Mnemonic: "SET 5, A", Length: 4, Address: 0xFFFF}, nil
		// SET 5, (IY+d) - documented
		case 0xEE:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 5, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 5, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// SET 6, r
		case 0xF0:
			return &Instruction{Mnemonic: "SET 6, B", Length: 4, Address: 0xFFFF}, nil
		case 0xF1:
			return &Instruction{Mnemonic: "SET 6, C", Length: 4, Address: 0xFFFF}, nil
		case 0xF2:
			return &Instruction{Mnemonic: "SET 6, D", Length: 4, Address: 0xFFFF}, nil
		case 0xF3:
			return &Instruction{Mnemonic: "SET 6, E", Length: 4, Address: 0xFFFF}, nil
		case 0xF4:
			return &Instruction{Mnemonic: "SET 6, H", Length: 4, Address: 0xFFFF}, nil
		case 0xF5:
			return &Instruction{Mnemonic: "SET 6, L", Length: 4, Address: 0xFFFF}, nil
		case 0xF7:
			return &Instruction{Mnemonic: "SET 6, A", Length: 4, Address: 0xFFFF}, nil
		// SET 6, (IY+d) - documented
		case 0xF6:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 6, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 6, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		// SET 7, r
		case 0xF8:
			return &Instruction{Mnemonic: "SET 7, B", Length: 4, Address: 0xFFFF}, nil
		case 0xF9:
			return &Instruction{Mnemonic: "SET 7, C", Length: 4, Address: 0xFFFF}, nil
		case 0xFA:
			return &Instruction{Mnemonic: "SET 7, D", Length: 4, Address: 0xFFFF}, nil
		case 0xFB:
			return &Instruction{Mnemonic: "SET 7, E", Length: 4, Address: 0xFFFF}, nil
		case 0xFC:
			return &Instruction{Mnemonic: "SET 7, H", Length: 4, Address: 0xFFFF}, nil
		case 0xFD:
			return &Instruction{Mnemonic: "SET 7, L", Length: 4, Address: 0xFFFF}, nil
		case 0xFF:
			return &Instruction{Mnemonic: "SET 7, A", Length: 4, Address: 0xFFFF}, nil
		// SET 7, (IY+d) - documented
		case 0xFE:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 7, (IY+$%02X)", disp), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("SET 7, (IY-$%02X)", -disp), Length: 4, Address: 0xFFFF}, nil
			}
		default:
			if disp >= 0 {
				return &Instruction{Mnemonic: fmt.Sprintf("FD CB $%02X $%02X", disp, cbOpcode), Length: 4, Address: 0xFFFF}, nil
			} else {
				return &Instruction{Mnemonic: fmt.Sprintf("FD CB -$%02X $%02X", -disp, cbOpcode), Length: 4, Address: 0xFFFF}, nil
			}
		}
	case 0xE1:
		return &Instruction{Mnemonic: "POP IY", Length: 2, Address: 0xFFFF}, nil
	case 0xE3:
		return &Instruction{Mnemonic: "EX (SP), IY", Length: 2, Address: 0xFFFF}, nil
	case 0xE5:
		return &Instruction{Mnemonic: "PUSH IY", Length: 2, Address: 0xFFFF}, nil
	case 0xE9:
		return &Instruction{Mnemonic: "JP (IY)", Length: 2, Address: 0xFFFF}, nil
	case 0xF9:
		return &Instruction{Mnemonic: "LD SP, IY", Length: 2, Address: 0xFFFF}, nil
	default:
		// Try to decode as unprefixed instruction with IY
		inst, err := d.decodeUnprefixed(opcode, data[1:])
		if err != nil {
			return nil, err
		}
		// Adjust length for FD prefix
		inst.Length++
		return inst, nil
	}
}
