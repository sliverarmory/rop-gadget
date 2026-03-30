package ropgadget

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func FormatResult(opts Options, result *Result) string {
	if result == nil {
		return ""
	}
	var builder strings.Builder
	for _, message := range result.Messages {
		builder.WriteString(message)
		builder.WriteByte('\n')
	}

	switch result.Mode {
	case "string":
		builder.WriteString("Strings information\n============================================================\n")
		if !opts.Silent {
			for _, match := range result.Matches {
				builder.WriteString(fmt.Sprintf("%s : %s\n", formatAddress(result.Binary.AddressDigits(), match.Address), match.Value))
			}
		}
	case "opcode":
		builder.WriteString("Opcodes information\n============================================================\n")
		if !opts.Silent {
			for _, match := range result.Matches {
				builder.WriteString(fmt.Sprintf("%s : %s\n", formatAddress(result.Binary.AddressDigits(), match.Address), match.Value))
			}
		}
	case "memstr":
		builder.WriteString("Memory bytes information\n=======================================================\n")
		if !opts.Silent {
			for _, match := range result.Matches {
				builder.WriteString(fmt.Sprintf("%s : '%s'\n", formatAddress(result.Binary.AddressDigits(), match.Address), match.Value))
			}
		}
	case "mipsrop":
		builder.WriteString(fmt.Sprintf("MIPS ROP (%s)\n============================================================\n", opts.MIPSROP))
		if !opts.Silent {
			for _, gadget := range result.Gadgets {
				builder.WriteString(formatGadgetLine(result.Binary, opts, gadget))
				builder.WriteByte('\n')
			}
		}
		builder.WriteString(fmt.Sprintf("\nUnique gadgets found: %d\n", len(result.Gadgets)))
	default:
		if !opts.Silent {
			builder.WriteString("Gadgets information\n============================================================\n")
			for _, gadget := range result.Gadgets {
				builder.WriteString(formatGadgetLine(result.Binary, opts, gadget))
				builder.WriteByte('\n')
			}
			builder.WriteString(fmt.Sprintf("\nUnique gadgets found: %d\n", len(result.Gadgets)))
		}
		if result.ROPChain != "" {
			builder.WriteString(result.ROPChain)
			if !strings.HasSuffix(result.ROPChain, "\n") {
				builder.WriteByte('\n')
			}
		}
	}
	return builder.String()
}

func formatGadgetLine(bin *LoadedBinary, opts Options, gadget Gadget) string {
	var builder strings.Builder
	builder.WriteString(formatAddress(bin.AddressDigits(), gadget.Vaddr))
	if !opts.NoInstr && gadget.Text != "" {
		builder.WriteString(" : ")
		builder.WriteString(gadget.Text)
	}
	if opts.Dump {
		builder.WriteString(" // ")
		builder.WriteString(hex.EncodeToString(gadget.Bytes))
	}
	return builder.String()
}

func FormatVersion() string {
	return fmt.Sprintf("Version:        %s\nAuthor:         Jonathan Salwan\nAuthor page:    https://twitter.com/JonathanSalwan\nProject page:   http://shell-storm.org/project/ROPgadget/\n", VersionString())
}
