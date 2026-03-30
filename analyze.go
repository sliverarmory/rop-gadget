package ropgadget

import (
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

func Analyze(ctx context.Context, opts Options) (*Result, error) {
	opts.Normalize()
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	offset, err := ParseOffset(opts.Offset)
	if err != nil {
		return nil, err
	}

	bin, err := LoadBinary(opts)
	if err != nil {
		return nil, err
	}

	switch opts.SearchMode() {
	case "string":
		return analyzeStringSearch(bin, opts, offset)
	case "opcode":
		return analyzeOpcodeSearch(bin, opts, offset)
	case "memstr":
		return analyzeMemStrSearch(bin, opts, offset)
	case "mipsrop":
		return analyzeMIPSROP(ctx, bin, opts, offset)
	default:
		return analyzeGadgets(ctx, bin, opts, offset)
	}
}

func analyzeGadgets(ctx context.Context, bin *LoadedBinary, opts Options, offset uint64) (*Result, error) {
	finder, err := newGadgetFinder(ctx, bin, opts, offset)
	if err != nil {
		return nil, err
	}
	defer finder.Close()

	gadgets, err := finder.Find()
	if err != nil {
		return nil, err
	}
	gadgets = dedupeAndSort(opts, gadgets)
	gadgets, messages, err := applyFilters(opts, bin, gadgets)
	if err != nil {
		return nil, err
	}

	result := &Result{
		Mode:     "gadgets",
		Binary:   bin,
		Gadgets:  gadgets,
		Messages: messages,
	}
	if opts.ROPChain {
		result.ROPChain = GenerateROPChain(bin, gadgets, offset)
	}
	return result, nil
}

func analyzeStringSearch(bin *LoadedBinary, opts Options, offset uint64) (*Result, error) {
	result := &Result{Mode: "string", Binary: bin}
	for _, section := range bin.DataSections {
		ranged := sectionInRange(section, opts)
		if ranged == nil {
			continue
		}
		matches, err := findRegexMatches(*ranged, opts.String, offset)
		if err != nil {
			return nil, err
		}
		result.Matches = append(result.Matches, matches...)
	}
	return result, nil
}

func analyzeOpcodeSearch(bin *LoadedBinary, opts Options, offset uint64) (*Result, error) {
	opcode, err := hex.DecodeString(strings.TrimSpace(opts.Opcode))
	if err != nil {
		return nil, err
	}
	result := &Result{Mode: "opcode", Binary: bin}
	for _, section := range bin.ExecSections {
		ranged := sectionInRange(section, opts)
		if ranged == nil {
			continue
		}
		result.Matches = append(result.Matches, findOpcodeMatches(*ranged, opcode, offset)...)
	}
	return result, nil
}

func analyzeMemStrSearch(bin *LoadedBinary, opts Options, offset uint64) (*Result, error) {
	sections := make([]Section, 0, len(bin.ExecSections)+len(bin.DataSections))
	for _, section := range bin.ExecSections {
		if ranged := sectionInRange(section, opts); ranged != nil {
			sections = append(sections, *ranged)
		}
	}
	for _, section := range bin.DataSections {
		if ranged := sectionInRange(section, opts); ranged != nil {
			sections = append(sections, *ranged)
		}
	}
	return &Result{
		Mode:    "memstr",
		Binary:  bin,
		Matches: findMemStrMatches(sections, opts.MemStr, offset),
	}, nil
}

func analyzeMIPSROP(ctx context.Context, bin *LoadedBinary, opts Options, offset uint64) (*Result, error) {
	result, err := analyzeGadgets(ctx, bin, opts, offset)
	if err != nil {
		return nil, err
	}
	var patterns []*regexp.Regexp
	switch opts.MIPSROP {
	case "stackfinder":
		patterns = []*regexp.Regexp{regexp.MustCompile(`addiu .*, \$sp`)}
	case "system":
		patterns = []*regexp.Regexp{regexp.MustCompile(`addiu \$a0, \$sp`)}
	case "tails":
		patterns = []*regexp.Regexp{
			regexp.MustCompile(`lw \$t[0-9], 0x[0-9a-z]{0,4}\(\$s[0-9]`),
			regexp.MustCompile(`move \$t9, \$(s|a|v)`),
		}
	case "lia0":
		patterns = []*regexp.Regexp{regexp.MustCompile(`li \$a0`)}
	case "registers":
		patterns = []*regexp.Regexp{regexp.MustCompile(`lw \$ra, 0x[0-9a-z]{0,4}\(\$sp`)}
	default:
		return nil, fmt.Errorf("Unrecognized option %s\nAccepted options stackfinder|system|tails|lia0|registers", opts.MIPSROP)
	}
	filtered := make([]Gadget, 0, len(result.Gadgets))
	for _, gadget := range result.Gadgets {
		for _, pattern := range patterns {
			if pattern.MatchString(gadget.Text) {
				filtered = append(filtered, gadget)
				break
			}
		}
	}
	result.Mode = "mipsrop"
	result.Gadgets = filtered
	return result, nil
}
