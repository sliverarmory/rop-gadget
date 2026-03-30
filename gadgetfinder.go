package ropgadget

import (
	"bytes"
	"context"
	"encoding/hex"
	"regexp"
	"slices"
	"strings"

	capstone "github.com/moloch--/go-capstone"
)

const prevBytesWindow = 9

type gadgetFinder struct {
	ctx      context.Context
	bin      *LoadedBinary
	opts     Options
	offset   uint64
	filterRE *regexp.Regexp
	engine   *capstone.Engine
}

func newGadgetFinder(ctx context.Context, bin *LoadedBinary, opts Options, offset uint64) (*gadgetFinder, error) {
	filterExpr := ""
	switch bin.Arch {
	case capstone.ArchX86:
		filterExpr = "db|int3"
	case capstone.ArchAArch64:
		filterExpr = "brk|smc|hvc"
	}
	if opts.Filter != "" {
		if filterExpr != "" {
			filterExpr += "|"
		}
		filterExpr += opts.Filter
	}

	engine, err := capstone.Open(ctx, bin.Arch, bin.SearchMode(opts), capstone.WithSyntax(capstone.SyntaxDefault))
	if err != nil {
		return nil, err
	}
	var compiled *regexp.Regexp
	if filterExpr != "" {
		compiled = regexp.MustCompile("(" + filterExpr + ")$")
	}

	return &gadgetFinder{
		ctx:      ctx,
		bin:      bin,
		opts:     opts,
		offset:   offset,
		filterRE: compiled,
		engine:   engine,
	}, nil
}

func (f *gadgetFinder) Close() error {
	if f.engine == nil {
		return nil
	}
	return f.engine.Close(f.ctx)
}

func (f *gadgetFinder) Find() ([]Gadget, error) {
	var gadgets []Gadget
	for _, section := range f.bin.ExecSections {
		ranged := sectionInRange(section, f.opts)
		if ranged == nil {
			continue
		}
		found, err := f.findSection(*ranged)
		if err != nil {
			return nil, err
		}
		gadgets = append(gadgets, found...)
	}
	return gadgets, nil
}

func (f *gadgetFinder) findSection(section Section) ([]Gadget, error) {
	switch f.bin.Arch {
	case capstone.ArchX86:
		return f.findX86Section(section)
	default:
		return f.findFixedWidthSection(section)
	}
}

func (f *gadgetFinder) findX86Section(section Section) ([]Gadget, error) {
	opcodes := section.Opcodes
	starterSet := x86CandidateStarterSet()
	gadgets := make([]Gadget, 0, 64)

	for ref := 0; ref < len(opcodes); ref++ {
		if _, ok := starterSet[opcodes[ref]]; !ok {
			continue
		}
		insns, err := f.engine.DisassembleCount(f.ctx, opcodes[ref:], section.Vaddr+uint64(ref), 2)
		if err != nil || len(insns) == 0 {
			continue
		}
		decoded := make([]DecodedInstruction, 0, len(insns))
		for _, insn := range insns {
			decoded = append(decoded, normalizedInstruction(insn))
		}
		termSize, kind := f.classifyTerminal(decoded)
		if termSize == 0 || kind == "" {
			continue
		}
		gadgets = append(gadgets, f.walkBack(section, ref, termSize)...)
	}
	return gadgets, nil
}

func (f *gadgetFinder) findFixedWidthSection(section Section) ([]Gadget, error) {
	step := naturalAlignment(f.bin, f.opts)
	if step <= 0 {
		step = 1
	}
	gadgets := make([]Gadget, 0, 64)
	for ref := 0; ref < len(section.Opcodes); ref++ {
		if (section.Vaddr+uint64(ref))%uint64(step) != 0 {
			continue
		}
		insns, err := f.engine.DisassembleCount(f.ctx, section.Opcodes[ref:], section.Vaddr+uint64(ref), 2)
		if err != nil || len(insns) == 0 {
			continue
		}
		decoded := make([]DecodedInstruction, 0, len(insns))
		for _, insn := range insns {
			decoded = append(decoded, normalizedInstruction(insn))
		}
		termSize, kind := f.classifyTerminal(decoded)
		if termSize == 0 || kind == "" {
			continue
		}
		gadgets = append(gadgets, f.walkBack(section, ref, termSize)...)
	}
	return gadgets, nil
}

func (f *gadgetFinder) walkBack(section Section, ref int, termSize int) []Gadget {
	step := naturalAlignment(f.bin, f.opts)
	if step <= 0 {
		step = 1
	}
	if f.opts.Align > 0 {
		step = f.opts.Align
	}

	end := ref + termSize
	if end > len(section.Opcodes) {
		return nil
	}

	gadgets := make([]Gadget, 0, f.opts.Depth)
	for i := 0; i < f.opts.Depth; i++ {
		start := ref
		if f.bin.Arch == capstone.ArchX86 {
			start = ref - i
		} else {
			start = ref - (i * step)
		}
		if start < 0 {
			continue
		}
		if step > 1 && (section.Vaddr+uint64(start))%uint64(step) != 0 {
			continue
		}

		chunk := section.Opcodes[start:end]
		insns, err := f.engine.Disassemble(f.ctx, chunk, section.Vaddr+uint64(start))
		if err != nil || len(insns) == 0 {
			continue
		}
		total := 0
		decoded := make([]DecodedInstruction, 0, len(insns))
		for _, insn := range insns {
			decoded = append(decoded, normalizedInstruction(insn))
			total += int(insn.Size)
		}
		if total != len(chunk) {
			continue
		}
		tail := terminalTail(decoded, termSize)
		termSize2, kind := f.classifyTerminal(tail)
		if termSize2 == 0 || kind == "" || termSize2 != termSize {
			continue
		}
		if f.passClean(decoded) {
			continue
		}

		gadget := Gadget{
			Vaddr: f.offset + section.Vaddr + uint64(start),
			Text:  joinInstructionText(decoded),
			Bytes: append([]byte(nil), chunk...),
			Insts: decoded,
		}
		if f.opts.CallPreceded {
			pstart := start - prevBytesWindow
			if pstart < 0 {
				pstart = 0
			}
			gadget.Prev = append([]byte(nil), section.Opcodes[pstart:start]...)
		}
		gadgets = append(gadgets, gadget)
	}
	return gadgets
}

func terminalTail(insts []DecodedInstruction, termSize int) []DecodedInstruction {
	if len(insts) == 0 || termSize <= 0 {
		return nil
	}
	total := 0
	for i := len(insts) - 1; i >= 0; i-- {
		total += int(insts[i].Size)
		if total == termSize {
			return insts[i:]
		}
		if total > termSize {
			return nil
		}
	}
	return nil
}

func naturalAlignment(bin *LoadedBinary, opts Options) int {
	switch bin.Arch {
	case capstone.ArchARM:
		if opts.Thumb || opts.RawMode == "thumb" {
			return 2
		}
		return 4
	case capstone.ArchAArch64:
		return 4
	case capstone.ArchMIPS, capstone.ArchPPC, capstone.ArchSPARC:
		return 4
	case capstone.ArchRISCV:
		return 2
	default:
		return 1
	}
}

func joinInstructionText(insts []DecodedInstruction) string {
	parts := make([]string, 0, len(insts))
	for _, inst := range insts {
		parts = append(parts, strings.ReplaceAll(inst.Text(), "  ", " "))
	}
	return strings.Join(parts, " ; ")
}

func (f *gadgetFinder) classifyTerminal(insts []DecodedInstruction) (int, string) {
	if len(insts) == 0 {
		return 0, ""
	}
	switch f.bin.Arch {
	case capstone.ArchX86:
		return f.classifyX86Terminal(insts)
	case capstone.ArchARM:
		return f.classifyARMTerminal(insts)
	case capstone.ArchAArch64:
		return f.classifyARM64Terminal(insts)
	case capstone.ArchMIPS:
		return f.classifyMIPSTerminal(insts)
	case capstone.ArchPPC:
		return f.classifyPPCTerminal(insts)
	case capstone.ArchSPARC:
		return f.classifySPARCTerminal(insts)
	case capstone.ArchRISCV:
		return f.classifyRISCVTerminal(insts)
	default:
		return 0, ""
	}
}

func (f *gadgetFinder) classifyX86Terminal(insts []DecodedInstruction) (int, string) {
	first := insts[0].Text()
	if !f.opts.NoROP && isX86Ret(insts[0]) {
		return int(insts[0].Size), "rop"
	}
	if !f.opts.NoJOP && isX86JumpOrCall(insts[0]) {
		return int(insts[0].Size), "jop"
	}
	if !f.opts.NoSYS && isX86Sys(insts[0]) {
		return int(insts[0].Size), "sys"
	}
	if !f.opts.NoSYS && len(insts) > 1 && isX86Sys(insts[0]) && isX86Ret(insts[1]) {
		return int(insts[0].Size + insts[1].Size), "sys"
	}
	if !f.opts.NoSYS && strings.HasPrefix(first, "call ") && strings.Contains(first, "gs:") {
		return int(insts[0].Size), "sys"
	}
	return 0, ""
}

func (f *gadgetFinder) classifyARMTerminal(insts []DecodedInstruction) (int, string) {
	text := insts[0].Text()
	if f.opts.Thumb || f.opts.RawMode == "thumb" {
		if !f.opts.NoJOP && (strings.HasPrefix(text, "bx ") || strings.HasPrefix(text, "blx ") || strings.HasPrefix(text, "pop ") || strings.HasPrefix(text, "ldm")) {
			return int(insts[0].Size), "jop"
		}
		if !f.opts.NoSYS && strings.HasPrefix(text, "svc ") {
			return int(insts[0].Size), "sys"
		}
		return 0, ""
	}
	if !f.opts.NoJOP && (strings.HasPrefix(text, "bx ") || strings.HasPrefix(text, "blx ") || strings.HasPrefix(text, "ldm")) {
		return int(insts[0].Size), "jop"
	}
	if !f.opts.NoSYS && strings.HasPrefix(text, "svc") {
		return int(insts[0].Size), "sys"
	}
	return 0, ""
}

func (f *gadgetFinder) classifyARM64Terminal(insts []DecodedInstruction) (int, string) {
	text := insts[0].Text()
	if !f.opts.NoROP && strings.HasPrefix(text, "ret") {
		return int(insts[0].Size), "rop"
	}
	if !f.opts.NoJOP && (strings.HasPrefix(text, "br ") || strings.HasPrefix(text, "blr ")) {
		return int(insts[0].Size), "jop"
	}
	return 0, ""
}

func (f *gadgetFinder) classifyMIPSTerminal(insts []DecodedInstruction) (int, string) {
	text := insts[0].Text()
	if !f.opts.NoJOP && (strings.HasPrefix(text, "jr ") || strings.HasPrefix(text, "jalr ") || strings.HasPrefix(text, "j ") || strings.HasPrefix(text, "jal ")) {
		return int(insts[0].Size), "jop"
	}
	if !f.opts.NoSYS && strings.HasPrefix(text, "syscall") {
		return int(insts[0].Size), "sys"
	}
	return 0, ""
}

func (f *gadgetFinder) classifyPPCTerminal(insts []DecodedInstruction) (int, string) {
	text := insts[0].Text()
	if !f.opts.NoROP && slices.Contains([]string{"blr", "blrl", "bctr", "bctrl"}, text) {
		return int(insts[0].Size), "rop"
	}
	if !f.opts.NoJOP && strings.HasPrefix(text, "bl ") {
		return int(insts[0].Size), "jop"
	}
	if !f.opts.NoSYS && (text == "sc" || text == "scv") {
		return int(insts[0].Size), "sys"
	}
	return 0, ""
}

func (f *gadgetFinder) classifySPARCTerminal(insts []DecodedInstruction) (int, string) {
	text := insts[0].Text()
	if !f.opts.NoROP && slices.Contains([]string{"retl", "ret", "restore"}, text) {
		return int(insts[0].Size), "rop"
	}
	if !f.opts.NoJOP && strings.HasPrefix(text, "jmp ") {
		return int(insts[0].Size), "jop"
	}
	return 0, ""
}

func (f *gadgetFinder) classifyRISCVTerminal(insts []DecodedInstruction) (int, string) {
	text := insts[0].Text()
	if !f.opts.NoROP && (text == "c.ret" || text == "ret") {
		return int(insts[0].Size), "rop"
	}
	if !f.opts.NoJOP && (strings.HasPrefix(text, "jalr ") || strings.HasPrefix(text, "j ") || strings.HasPrefix(text, "jal ") ||
		strings.HasPrefix(text, "beq") || strings.HasPrefix(text, "bne") || strings.HasPrefix(text, "c.j") || strings.HasPrefix(text, "c.jr") || strings.HasPrefix(text, "c.jalr")) {
		return int(insts[0].Size), "jop"
	}
	if !f.opts.NoSYS && (text == "ecall" || text == "scall") {
		return int(insts[0].Size), "sys"
	}
	return 0, ""
}

func isX86Ret(inst DecodedInstruction) bool {
	text := inst.Text()
	switch {
	case text == "ret", strings.HasPrefix(text, "ret "):
		return true
	case text == "retf", strings.HasPrefix(text, "retf "):
		return true
	case strings.HasSuffix(text, " ret") && (strings.HasPrefix(text, "rep") || strings.HasPrefix(text, "bnd")):
		return true
	default:
		return false
	}
}

func isX86JumpOrCall(inst DecodedInstruction) bool {
	text := inst.Text()
	return strings.HasPrefix(text, "jmp ") || strings.HasPrefix(text, "call ") ||
		strings.HasPrefix(text, "notrack jmp ") || strings.HasPrefix(text, "notrack call ")
}

func isX86Sys(inst DecodedInstruction) bool {
	text := inst.Text()
	return strings.HasPrefix(text, "int ") ||
		text == "sysenter" ||
		text == "syscall" ||
		text == "sysret" ||
		text == "sysretq" ||
		text == "iret" ||
		text == "iretd" ||
		text == "iretq" ||
		(strings.HasPrefix(text, "call ") && strings.Contains(text, "gs:"))
}

func (f *gadgetFinder) passClean(insts []DecodedInstruction) bool {
	if len(insts) == 0 {
		return true
	}
	if f.bin.Arch == capstone.ArchX86 && passCleanX86(insts, f.opts.MultiBr) {
		return true
	}
	if f.filterRE != nil {
		for _, inst := range insts {
			if f.filterRE.MatchString(strings.Fields(inst.Text())[0]) {
				return true
			}
		}
	}
	return false
}

func passCleanX86(insts []DecodedInstruction, multibr bool) bool {
	branches := map[string]struct{}{
		"ret": {}, "retf": {}, "int": {}, "sysenter": {}, "jmp": {}, "call": {}, "syscall": {}, "iret": {}, "iretd": {}, "iretq": {}, "sysret": {}, "sysretq": {},
	}
	last := firstToken(insts[len(insts)-1].Text())
	if _, ok := branches[last]; !ok && !isX86Ret(insts[len(insts)-1]) {
		return true
	}
	if !multibr {
		for _, inst := range insts[:len(insts)-1] {
			token := firstToken(inst.Text())
			if _, ok := branches[token]; ok {
				return true
			}
			if strings.Contains(token, "ret") {
				return true
			}
		}
	}
	return false
}

func firstToken(text string) string {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func findRegexMatches(section Section, expr string, offset uint64) ([]Match, error) {
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}
	all := re.FindAllIndex(section.Opcodes, -1)
	out := make([]Match, 0, len(all))
	for _, match := range all {
		value := string(section.Opcodes[match[0]:match[1]])
		printable := make([]byte, len(value))
		for i := range value {
			b := value[i]
			if b >= 32 && b <= 126 {
				printable[i] = b
			} else {
				printable[i] = '.'
			}
		}
		out = append(out, Match{
			Address: offset + section.Vaddr + uint64(match[0]),
			Value:   string(printable),
		})
	}
	return out, nil
}

func findOpcodeMatches(section Section, opcode []byte, offset uint64) []Match {
	out := []Match{}
	for idx := 0; idx < len(section.Opcodes); {
		pos := bytes.Index(section.Opcodes[idx:], opcode)
		if pos < 0 {
			break
		}
		abs := idx + pos
		out = append(out, Match{
			Address: offset + section.Vaddr + uint64(abs),
			Value:   strings.ToLower(bytesToHex(opcode)),
		})
		idx = abs + 1
	}
	return out
}

func findMemStrMatches(sections []Section, memstr string, offset uint64) []Match {
	out := make([]Match, 0, len(memstr))
	for _, char := range []byte(memstr) {
		for _, section := range sections {
			pos := bytes.IndexByte(section.Opcodes, char)
			if pos < 0 {
				continue
			}
			out = append(out, Match{
				Address: offset + section.Vaddr + uint64(pos),
				Value:   string([]byte{char}),
			})
			break
		}
	}
	return out
}

func bytesToHex(in []byte) string {
	return hex.EncodeToString(in)
}
