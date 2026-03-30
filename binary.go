package ropgadget

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"strings"

	capstone "github.com/moloch--/go-capstone"
)

const (
	machoAttrSomeInstructions = 0x00000400
	machoAttrPureInstructions = 0x80000000
)

func LoadBinary(opts Options) (*LoadedBinary, error) {
	raw, err := os.ReadFile(opts.Binary)
	if err != nil {
		return nil, fmt.Errorf("[Error] Can't open the binary or binary not found")
	}

	if opts.RawArch != "" {
		return loadRawBinary(opts.Binary, raw, opts)
	}

	reader := bytes.NewReader(raw)
	switch {
	case len(raw) >= 4 && bytes.Equal(raw[:4], []byte{0x7f, 'E', 'L', 'F'}):
		return loadELF(opts.Binary, raw, reader)
	case len(raw) >= 2 && bytes.Equal(raw[:2], []byte{'M', 'Z'}):
		return loadPE(opts.Binary, raw, reader)
	case len(raw) >= 4 && bytes.Equal(raw[:4], []byte{0xca, 0xfe, 0xba, 0xbe}):
		return loadFatMachO(opts.Binary, raw, reader)
	case len(raw) >= 4 && (bytes.Equal(raw[:4], []byte{0xce, 0xfa, 0xed, 0xfe}) ||
		bytes.Equal(raw[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) ||
		bytes.Equal(raw[:4], []byte{0xfe, 0xed, 0xfa, 0xce}) ||
		bytes.Equal(raw[:4], []byte{0xfe, 0xed, 0xfa, 0xcf})):
		return loadMachO(opts.Binary, raw, reader)
	default:
		return nil, fmt.Errorf("[Error] Binary format not supported")
	}
}

func loadRawBinary(fileName string, raw []byte, opts Options) (*LoadedBinary, error) {
	archMap := map[string]capstone.Arch{
		"x86":   capstone.ArchX86,
		"arm":   capstone.ArchARM,
		"arm64": capstone.ArchAArch64,
		"sparc": capstone.ArchSPARC,
		"mips":  capstone.ArchMIPS,
		"ppc":   capstone.ArchPPC,
		"riscv": capstone.ArchRISCV,
	}
	modeMap := map[string]capstone.Mode{
		"16":    capstone.Mode16,
		"32":    capstone.Mode32,
		"64":    capstone.Mode64,
		"arm":   capstone.ModeARM,
		"thumb": capstone.ModeThumb,
		"riscv": capstone.ModeRISCV64 | capstone.ModeRISCVC,
	}
	endianMap := map[string]capstone.Mode{
		"":       capstone.ModeLittleEndian,
		"little": capstone.ModeLittleEndian,
		"big":    capstone.ModeBigEndian,
	}

	arch, ok := archMap[opts.RawArch]
	if !ok {
		return nil, fmt.Errorf("[Error] Raw.getArch() - Architecture not supported. Only supported: x86 arm arm64 sparc mips ppc")
	}
	modeValue := opts.RawMode
	if opts.Thumb {
		modeValue = "thumb"
	}
	mode, ok := modeMap[modeValue]
	if !ok {
		return nil, fmt.Errorf("[Error] Raw.getArchMode() - Mode not supported. Only supported: 32 64 arm thumb")
	}
	endian := capstone.ModeLittleEndian
	if arch != capstone.ArchX86 {
		value, ok := endianMap[opts.RawEndian]
		if !ok {
			return nil, fmt.Errorf("[Error] Raw.getArchEndian() - Endianness not supported. Only supported: little big")
		}
		endian = value
	}

	return &LoadedBinary{
		FileName:  fileName,
		RawBinary: raw,
		Format:    "Raw",
		Arch:      arch,
		Mode:      mode,
		Endian:    endian,
		ExecSections: []Section{{
			Name:    "raw",
			Offset:  0,
			Size:    uint64(len(raw)),
			Vaddr:   0,
			Opcodes: append([]byte(nil), raw...),
		}},
	}, nil
}

func loadELF(fileName string, raw []byte, reader *bytes.Reader) (*LoadedBinary, error) {
	f, err := elf.NewFile(reader)
	if err != nil {
		return nil, err
	}

	out := &LoadedBinary{
		FileName:   fileName,
		RawBinary:  raw,
		Format:     "ELF",
		EntryPoint: f.Entry,
	}

	switch f.Machine {
	case elf.EM_386, elf.EM_X86_64:
		out.Arch = capstone.ArchX86
	case elf.EM_ARM:
		out.Arch = capstone.ArchARM
	case elf.EM_AARCH64:
		out.Arch = capstone.ArchAArch64
	case elf.EM_MIPS:
		out.Arch = capstone.ArchMIPS
	case elf.EM_PPC, elf.EM_PPC64:
		out.Arch = capstone.ArchPPC
	case elf.EM_SPARC:
		out.Arch = capstone.ArchSPARC
	case elf.EM_RISCV:
		out.Arch = capstone.ArchRISCV
	default:
		return nil, fmt.Errorf("[Error] ELF.getArch() - Architecture not supported")
	}

	switch f.Class {
	case elf.ELFCLASS32:
		out.Mode = capstone.Mode32
	case elf.ELFCLASS64:
		out.Mode = capstone.Mode64
	default:
		return nil, fmt.Errorf("[Error] ELF.getArchMode() - Bad Arch size")
	}

	switch f.ByteOrder.String() {
	case "BigEndian":
		out.Endian = capstone.ModeBigEndian
	default:
		out.Endian = capstone.ModeLittleEndian
	}

	for _, prog := range f.Progs {
		if prog.Flags&elf.PF_X == 0 {
			continue
		}
		data, err := io.ReadAll(prog.Open())
		if err != nil {
			continue
		}
		out.ExecSections = append(out.ExecSections, Section{
			Name:    prog.Type.String(),
			Offset:  prog.Off,
			Size:    uint64(len(data)),
			Vaddr:   prog.Vaddr,
			Opcodes: data,
		})
	}

	for _, section := range f.Sections {
		if section.Flags&elf.SHF_EXECINSTR != 0 || section.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		data, err := section.Data()
		if err != nil {
			continue
		}
		out.DataSections = append(out.DataSections, Section{
			Name:    section.Name,
			Offset:  section.Offset,
			Size:    uint64(len(data)),
			Vaddr:   section.Addr,
			Opcodes: data,
		})
	}

	return out, nil
}

func loadPE(fileName string, raw []byte, reader *bytes.Reader) (*LoadedBinary, error) {
	f, err := pe.NewFile(reader)
	if err != nil {
		return nil, err
	}

	out := &LoadedBinary{
		FileName:  fileName,
		RawBinary: raw,
		Format:    "PE",
		Endian:    capstone.ModeLittleEndian,
	}

	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_I386, pe.IMAGE_FILE_MACHINE_AMD64:
		out.Arch = capstone.ArchX86
	case pe.IMAGE_FILE_MACHINE_ARM, pe.IMAGE_FILE_MACHINE_ARMNT:
		out.Arch = capstone.ArchARM
	case pe.IMAGE_FILE_MACHINE_ARM64:
		out.Arch = capstone.ArchAArch64
	default:
		return nil, fmt.Errorf("[Error] PE.getArch() - Bad Arch")
	}

	imageBase := uint64(0)
	switch hdr := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		out.Mode = capstone.Mode32
		imageBase = uint64(hdr.ImageBase)
		out.EntryPoint = imageBase + uint64(hdr.AddressOfEntryPoint)
	case *pe.OptionalHeader64:
		out.Mode = capstone.Mode64
		imageBase = hdr.ImageBase
		out.EntryPoint = imageBase + uint64(hdr.AddressOfEntryPoint)
	default:
		return nil, fmt.Errorf("[Error] PE.getArch() - Bad arch size")
	}

	for _, section := range f.Sections {
		data, err := section.Data()
		if err != nil {
			continue
		}
		entry := Section{
			Name:    strings.TrimRight(string(section.Name[:]), "\x00"),
			Offset:  uint64(section.Offset),
			Size:    uint64(len(data)),
			Vaddr:   uint64(section.VirtualAddress) + imageBase,
			Opcodes: data,
		}
		if section.Characteristics&0x20000000 != 0 {
			out.ExecSections = append(out.ExecSections, entry)
		}
		if section.Characteristics&0x80000000 != 0 {
			out.DataSections = append(out.DataSections, entry)
		}
	}

	return out, nil
}

func loadMachO(fileName string, raw []byte, reader *bytes.Reader) (*LoadedBinary, error) {
	f, err := macho.NewFile(reader)
	if err != nil {
		return nil, err
	}
	return makeMachOResult(fileName, raw, "Mach-O", []*macho.File{f})
}

func loadFatMachO(fileName string, raw []byte, reader *bytes.Reader) (*LoadedBinary, error) {
	ff, err := macho.NewFatFile(reader)
	if err != nil {
		return nil, err
	}
	files := make([]*macho.File, 0, len(ff.Arches))
	for _, arch := range ff.Arches {
		files = append(files, arch.File)
	}
	return makeMachOResult(fileName, raw, "Universal", files)
}

func makeMachOResult(fileName string, raw []byte, format string, files []*macho.File) (*LoadedBinary, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("[Error] Binary format not supported")
	}

	out := &LoadedBinary{
		FileName:  fileName,
		RawBinary: raw,
		Format:    format,
	}

	first := files[0]
	switch first.Cpu {
	case macho.Cpu386, macho.CpuAmd64:
		out.Arch = capstone.ArchX86
	case macho.CpuArm:
		out.Arch = capstone.ArchARM
	case macho.CpuArm64:
		out.Arch = capstone.ArchAArch64
	case macho.CpuPpc, macho.CpuPpc64:
		out.Arch = capstone.ArchPPC
	default:
		return nil, fmt.Errorf("[Error] MACHO.getArch() - Architecture not supported")
	}

	switch first.Magic {
	case macho.Magic32:
		out.Mode = capstone.Mode32
	case macho.Magic64:
		out.Mode = capstone.Mode64
	default:
		return nil, fmt.Errorf("[Error] MACHO.getArchMode() - Bad Arch size")
	}

	if first.ByteOrder.String() == "BigEndian" {
		out.Endian = capstone.ModeBigEndian
	} else {
		out.Endian = capstone.ModeLittleEndian
	}

	for _, file := range files {
		for _, section := range file.Sections {
			data, err := section.Data()
			if err != nil {
				continue
			}
			entry := Section{
				Name:    section.Name,
				Offset:  uint64(section.Offset),
				Size:    uint64(len(data)),
				Vaddr:   section.Addr,
				Opcodes: data,
			}
			if section.Name == "__text" && out.EntryPoint == 0 {
				out.EntryPoint = section.Addr
			}
			if section.Flags&machoAttrSomeInstructions != 0 || section.Flags&machoAttrPureInstructions != 0 {
				out.ExecSections = append(out.ExecSections, entry)
			} else {
				out.DataSections = append(out.DataSections, entry)
			}
		}
	}

	return out, nil
}
