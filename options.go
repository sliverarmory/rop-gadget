package ropgadget

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Options struct {
	Binary       string
	Opcode       string
	String       string
	MemStr       string
	Depth        int
	Only         string
	Filter       string
	Range        string
	BadBytes     string
	RawArch      string
	RawMode      string
	RawEndian    string
	Regexp       string
	Offset       string
	ROPChain     bool
	Thumb        bool
	Console      bool
	NoROP        bool
	NoJOP        bool
	CallPreceded bool
	NoSYS        bool
	MultiBr      bool
	All          bool
	NoInstr      bool
	Dump         bool
	Silent       bool
	Align        int
	MIPSROP      string
}

func DefaultOptions() Options {
	return Options{
		Depth: 10,
		Range: "0x0-0x0",
	}
}

func (o Options) SearchMode() string {
	switch {
	case o.String != "":
		return "string"
	case o.Opcode != "":
		return "opcode"
	case o.MemStr != "":
		return "memstr"
	case o.MIPSROP != "":
		return "mipsrop"
	default:
		return "gadgets"
	}
}

func (o *Options) Normalize() {
	o.RawArch = strings.TrimSpace(strings.ToLower(o.RawArch))
	o.RawMode = strings.TrimSpace(strings.ToLower(o.RawMode))
	o.RawEndian = strings.TrimSpace(strings.ToLower(o.RawEndian))
}

func (o Options) Validate() error {
	if o.NoInstr && o.Only != "" {
		return errors.New("[Error] --noinstr and --only=<key> can't be used together")
	}
	if o.NoInstr && o.Regexp != "" {
		return errors.New("[Error] --noinstr and --re=<re> can't be used together")
	}
	if o.Thumb && o.RawMode != "" && strings.TrimSpace(strings.ToLower(o.RawMode)) != "thumb" {
		return errors.New("[Error] --rawMode is conflicting with --thumb")
	}
	if o.RawArch == "" && o.RawMode != "" {
		return errors.New("[Error] Specify --rawArch")
	}
	if o.RawArch == "" && o.RawEndian != "" {
		return errors.New("[Error] Specify --rawArch")
	}
	rawMode := o.RawMode
	if o.Thumb {
		rawMode = "thumb"
	}
	if o.RawArch != "" && rawMode == "" {
		return errors.New("[Error] Specify --rawMode")
	}
	if o.RawArch != "" && o.RawEndian == "" && o.RawArch != "x86" {
		return errors.New("[Error] Specify --rawEndian")
	}
	if o.Depth < 2 {
		return errors.New("[Error] The depth must be >= 2")
	}
	if !o.Console && o.Binary == "" {
		return errors.New("[Error] Need a binary filename (--binary/--console or --help)")
	}
	if _, _, err := ParseRange(o.Range); err != nil {
		return err
	}
	return nil
}

func ParseRange(value string) (uint64, uint64, error) {
	if value == "" {
		value = "0x0-0x0"
	}
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return 0, 0, errors.New("[Error] A range must be set in hexadecimal. Ex: 0x08041000-0x08042000")
	}
	start, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 0, 64)
	if err != nil {
		return 0, 0, errors.New("[Error] A range must be set in hexadecimal. Ex: 0x08041000-0x08042000")
	}
	end, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 0, 64)
	if err != nil {
		return 0, 0, errors.New("[Error] A range must be set in hexadecimal. Ex: 0x08041000-0x08042000")
	}
	if start > end {
		return 0, 0, errors.New("[Error] The start value must be greater than end value")
	}
	return start, end, nil
}

func ParseOffset(value string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 0, 64)
	if err != nil {
		return 0, fmt.Errorf("[Error] The offset must be in hexadecimal")
	}
	return parsed, nil
}
