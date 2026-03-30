package ropgadget

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	capstone "github.com/moloch--/go-capstone"
)

type Section struct {
	Name    string
	Offset  uint64
	Size    uint64
	Vaddr   uint64
	Opcodes []byte
}

func (s Section) Clone() Section {
	out := s
	out.Opcodes = append([]byte(nil), s.Opcodes...)
	return out
}

type LoadedBinary struct {
	FileName     string
	RawBinary    []byte
	Format       string
	Arch         capstone.Arch
	Mode         capstone.Mode
	Endian       capstone.Mode
	EntryPoint   uint64
	ExecSections []Section
	DataSections []Section
}

func (b *LoadedBinary) AddressDigits() int {
	if b.Mode == capstone.Mode32 {
		return 8
	}
	return 16
}

func (b *LoadedBinary) SearchMode(opts Options) capstone.Mode {
	mode := b.Mode
	switch b.Arch {
	case capstone.ArchARM:
		if opts.Thumb || opts.RawMode == "thumb" {
			mode = capstone.ModeThumb
		} else {
			mode = capstone.ModeARM
		}
	case capstone.ArchAArch64:
		mode = capstone.ModeARM
	case capstone.ArchRISCV:
		mode = capstone.ModeRISCV64 | capstone.ModeRISCVC
	}
	return mode | b.Endian
}

type DecodedInstruction struct {
	Address  uint64
	Size     uint16
	Bytes    []byte
	Mnemonic string
	OpStr    string
}

func (i DecodedInstruction) Text() string {
	if strings.TrimSpace(i.OpStr) == "" {
		return strings.TrimSpace(i.Mnemonic)
	}
	return strings.TrimSpace(i.Mnemonic + " " + i.OpStr)
}

type Gadget struct {
	Vaddr uint64
	Text  string
	Bytes []byte
	Prev  []byte
	Insts []DecodedInstruction
}

type Match struct {
	Address uint64
	Value   string
}

type Result struct {
	Mode     string
	Binary   *LoadedBinary
	Gadgets  []Gadget
	Matches  []Match
	ROPChain string
	Messages []string
}

type Console struct {
	ctx     context.Context
	opts    *Options
	writer  io.Writer
	bin     *LoadedBinary
	offset  uint64
	gadgets []Gadget
}

func normalizedInstruction(insn capstone.Instruction) DecodedInstruction {
	return DecodedInstruction{
		Address:  insn.Address,
		Size:     insn.Size,
		Bytes:    append([]byte(nil), insn.Bytes...),
		Mnemonic: strings.TrimSpace(insn.Mnemonic),
		OpStr:    strings.TrimSpace(insn.OpStr),
	}
}

func formatAddress(digits int, value uint64) string {
	return fmt.Sprintf("0x%0*x", digits, value)
}

func regexMustCompile(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	return regexp.MustCompile(pattern)
}
