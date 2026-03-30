package ropgadget

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	capstone "github.com/moloch--/go-capstone"
)

func sectionInRange(section Section, opts Options) *Section {
	rangeStart, rangeEnd, err := ParseRange(opts.Range)
	if err != nil || (rangeStart == 0 && rangeEnd == 0) {
		clone := section.Clone()
		return &clone
	}

	clone := section.Clone()
	sectionStart := clone.Vaddr
	sectionEnd := clone.Vaddr + clone.Size
	if rangeEnd < sectionStart || rangeStart > sectionEnd {
		return nil
	}
	if rangeStart > sectionStart {
		diff := rangeStart - sectionStart
		if diff >= uint64(len(clone.Opcodes)) {
			return nil
		}
		clone.Opcodes = clone.Opcodes[diff:]
		clone.Vaddr += diff
		clone.Offset += diff
		clone.Size -= diff
	}
	if rangeEnd < sectionEnd {
		diff := sectionEnd - rangeEnd
		if diff >= uint64(len(clone.Opcodes)) {
			return nil
		}
		clone.Opcodes = clone.Opcodes[:len(clone.Opcodes)-int(diff)]
		clone.Size -= diff
	}
	if len(clone.Opcodes) == 0 || clone.Size == 0 {
		return nil
	}
	return &clone
}

func applyFilters(opts Options, bin *LoadedBinary, gadgets []Gadget) ([]Gadget, []string, error) {
	if opts.Only != "" {
		allowed := strings.Split(opts.Only, "|")
		gadgets = slices.DeleteFunc(gadgets, func(g Gadget) bool {
			for _, part := range strings.Split(g.Text, " ; ") {
				fields := strings.Fields(part)
				if len(fields) == 0 || !slices.Contains(allowed, fields[0]) {
					return true
				}
			}
			return false
		})
	}

	if opts.Range != "" {
		start, end, err := ParseRange(opts.Range)
		if err != nil {
			return nil, nil, err
		}
		if start != 0 || end != 0 {
			gadgets = slices.DeleteFunc(gadgets, func(g Gadget) bool {
				return g.Vaddr < start || g.Vaddr > end
			})
		}
	}

	if opts.Regexp != "" {
		parts := []string{opts.Regexp}
		if strings.Contains(opts.Regexp, " | ") {
			parts = strings.Split(opts.Regexp, " | ")
		} else if strings.Contains(opts.Regexp, "|") {
			parts = strings.Split(opts.Regexp, "|")
		}
		patterns := make([]*regexp.Regexp, 0, len(parts))
		for _, part := range parts {
			patterns = append(patterns, regexp.MustCompile(part))
		}
		gadgets = slices.DeleteFunc(gadgets, func(g Gadget) bool {
			insts := strings.Split(g.Text, " ; ")
			for _, pattern := range patterns {
				matched := false
				for _, inst := range insts {
					if pattern.MatchString(inst) {
						matched = true
						break
					}
				}
				if !matched {
					return true
				}
			}
			return false
		})
	}

	if opts.BadBytes != "" {
		bad, err := parseBadBytes(opts.BadBytes)
		if err != nil {
			return nil, nil, err
		}
		addrBuf := make([]byte, 8)
		gadgets = slices.DeleteFunc(gadgets, func(g Gadget) bool {
			if bin.Mode == capstone.Mode32 {
				binary.LittleEndian.PutUint32(addrBuf[:4], uint32(g.Vaddr))
				return bytes.IndexByte(bad, addrBuf[0]) >= 0 ||
					bytes.IndexByte(bad, addrBuf[1]) >= 0 ||
					bytes.IndexByte(bad, addrBuf[2]) >= 0 ||
					bytes.IndexByte(bad, addrBuf[3]) >= 0
			}
			binary.LittleEndian.PutUint64(addrBuf, g.Vaddr)
			for _, b := range addrBuf {
				if bytes.IndexByte(bad, b) >= 0 {
					return true
				}
			}
			return false
		})
	}

	messages := []string{}
	if opts.CallPreceded {
		if bin.Arch != capstone.ArchX86 {
			messages = append(messages, "Options().removeNonCallPreceded(): Unsupported architecture.")
		} else {
			before := len(gadgets)
			patterns := []*regexp.Regexp{
				regexp.MustCompile(`\xe8[\x00-\xff]{4}$`),
				regexp.MustCompile(`\xe8[\x00-\xff]{8}$`),
				regexp.MustCompile(`\xff[\x00-\xff]$`),
				regexp.MustCompile(`\xff[\x00-\xff]{2}$`),
				regexp.MustCompile(`\xff[\x00-\xff]{4}$`),
				regexp.MustCompile(`\xff[\x00-\xff]{8}$`),
			}
			gadgets = slices.DeleteFunc(gadgets, func(g Gadget) bool {
				for _, pattern := range patterns {
					if pattern.Match(g.Prev) {
						return false
					}
				}
				return true
			})
			messages = append(messages, fmt.Sprintf("Options().removeNonCallPreceded(): Filtered out %d gadgets.", before-len(gadgets)))
		}
	}

	return gadgets, messages, nil
}

func parseBadBytes(value string) ([]byte, error) {
	out := make([]byte, 0, 32)
	for _, rawPart := range strings.Split(value, "|") {
		part := strings.TrimSpace(rawPart)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid badbytes range %q", part)
			}
			low, err := strconv.ParseUint(rangeParts[0], 16, 8)
			if err != nil {
				return nil, err
			}
			high, err := strconv.ParseUint(rangeParts[1], 16, 8)
			if err != nil {
				return nil, err
			}
			for b := low; b <= high; b++ {
				out = append(out, byte(b))
			}
			continue
		}
		decoded, err := hex.DecodeString(part)
		if err != nil {
			return nil, err
		}
		out = append(out, decoded...)
	}
	return out, nil
}

func dedupeAndSort(opts Options, gadgets []Gadget) []Gadget {
	if !opts.All && !opts.NoInstr {
		seen := make(map[string]struct{}, len(gadgets))
		deduped := make([]Gadget, 0, len(gadgets))
		for _, gadget := range gadgets {
			if _, ok := seen[gadget.Text]; ok {
				continue
			}
			seen[gadget.Text] = struct{}{}
			deduped = append(deduped, gadget)
		}
		gadgets = deduped
	}
	if !opts.NoInstr {
		sort.Slice(gadgets, func(i, j int) bool {
			return gadgets[i].Text < gadgets[j].Text
		})
	}
	return gadgets
}
