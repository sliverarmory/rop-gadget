package ropgadget

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
)

func RunConsole(ctx context.Context, opts *Options, in io.Reader, out io.Writer) error {
	console := &Console{
		ctx:    ctx,
		opts:   opts,
		writer: out,
	}
	if opts.Binary != "" {
		if err := console.loadBinary(opts.Binary, true); err != nil {
			return err
		}
	}

	scanner := bufio.NewScanner(in)
	for {
		if _, err := fmt.Fprint(out, "(ROPgadget)> "); err != nil {
			return err
		}
		if !scanner.Scan() {
			return nil
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		command := strings.ToLower(parts[0])
		arg := ""
		if len(parts) > 1 {
			arg = strings.TrimSpace(line[len(parts[0]):])
		}
		switch command {
		case "quit", "exit":
			return nil
		case "binary":
			if err := console.loadBinary(strings.TrimSpace(arg), false); err != nil {
				fmt.Fprintln(out, err)
			}
		case "load":
			if err := console.loadGadgets(false); err != nil {
				fmt.Fprintln(out, err)
			}
		case "display":
			fmt.Fprint(out, FormatResult(*opts, &Result{Mode: "gadgets", Binary: console.bin, Gadgets: console.gadgets}))
		case "depth":
			fmt.Sscanf(arg, "%d", &opts.Depth)
			fmt.Fprintln(out, "[+] Depth updated. You have to reload gadgets")
		case "filter":
			opts.Filter = strings.TrimSpace(arg)
			fmt.Fprintln(out, "[+] Filter setted. You have to reload gadgets")
		case "only":
			arg = strings.TrimSpace(arg)
			if strings.EqualFold(arg, "none") {
				opts.Only = ""
			} else {
				opts.Only = arg
			}
			fmt.Fprintln(out, "[+] Only setted. You have to reload gadgets")
		case "range":
			opts.Range = strings.TrimSpace(arg)
			fmt.Fprintln(out, "[+] Range setted. You have to reload gadgets")
		case "badbytes":
			opts.BadBytes = strings.TrimSpace(arg)
			fmt.Fprintln(out, "[+] Bad bytes updated. You have to reload gadgets")
		case "count":
			fmt.Fprintf(out, "[+] %d loaded gadgets.\n", len(console.gadgets))
		case "search":
			console.search(arg)
		case "settings":
			console.settings()
		case "nojop":
			opts.NoJOP = strings.TrimSpace(arg) == "enable"
			fmt.Fprintln(out, "[+] NoJOP set. You have to reload gadgets")
		case "norop":
			opts.NoROP = strings.TrimSpace(arg) == "enable"
			fmt.Fprintln(out, "[+] NoROP set. You have to reload gadgets")
		case "nosys":
			opts.NoSYS = strings.TrimSpace(arg) == "enable"
			fmt.Fprintln(out, "[+] NoSYS set. You have to reload gadgets")
		case "thumb":
			opts.Thumb = strings.TrimSpace(arg) == "enable"
			fmt.Fprintln(out, "[+] Thumb set. You have to reload gadgets")
		case "all":
			opts.All = strings.TrimSpace(arg) == "enable"
			fmt.Fprintln(out, "[+] Showing all gadgets updated. You have to reload gadgets")
		case "multibr":
			opts.MultiBr = strings.TrimSpace(arg) == "enable"
			fmt.Fprintln(out, "[+] Multiple branch gadgets updated. You have to reload gadgets")
		case "re":
			if strings.EqualFold(strings.TrimSpace(arg), "none") {
				opts.Regexp = ""
			} else {
				opts.Regexp = arg
			}
			fmt.Fprintln(out, "[+] Re setted. You have to reload gadgets")
		default:
			fmt.Fprintf(out, "Unknown command: %s\n", command)
		}
	}
}

func (c *Console) loadBinary(path string, silent bool) error {
	c.opts.Binary = path
	bin, err := LoadBinary(*c.opts)
	if err != nil {
		return err
	}
	c.bin = bin
	offset, err := ParseOffset(c.opts.Offset)
	if err != nil {
		return err
	}
	c.offset = offset
	if !silent {
		fmt.Fprintln(c.writer, "[+] Binary loaded")
	}
	return nil
}

func (c *Console) loadGadgets(silent bool) error {
	if c.bin == nil {
		fmt.Fprintln(c.writer, "[-] No binary loaded.")
		return nil
	}
	if !silent {
		fmt.Fprintln(c.writer, "[+] Loading gadgets, please wait...")
	}
	result, err := analyzeGadgets(c.ctx, c.bin, *c.opts, c.offset)
	if err != nil {
		return err
	}
	c.gadgets = result.Gadgets
	if !silent {
		fmt.Fprintln(c.writer, "[+] Gadgets loaded !")
	}
	return nil
}

func (c *Console) search(arg string) {
	withK := []string{}
	withoutK := []string{}
	for _, token := range strings.Fields(arg) {
		if strings.HasPrefix(token, "!") {
			withoutK = append(withoutK, token[1:])
		} else {
			withK = append(withK, token)
		}
	}
	for _, gadget := range c.gadgets {
		ok := true
		for _, token := range withK {
			if !strings.Contains(gadget.Text, token) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		for _, token := range withoutK {
			if strings.Contains(gadget.Text, token) {
				ok = false
				break
			}
		}
		if ok {
			fmt.Fprintf(c.writer, "%s : %s\n", formatAddress(c.bin.AddressDigits(), gadget.Vaddr), gadget.Text)
		}
	}
}

func (c *Console) settings() {
	fmt.Fprintf(c.writer, "All:         %v\n", c.opts.All)
	fmt.Fprintf(c.writer, "Badbytes:    %s\n", c.opts.BadBytes)
	fmt.Fprintf(c.writer, "Binary:      %s\n", c.opts.Binary)
	fmt.Fprintf(c.writer, "Depth:       %d\n", c.opts.Depth)
	fmt.Fprintf(c.writer, "Filter:      %s\n", c.opts.Filter)
	fmt.Fprintf(c.writer, "Memstr:      %s\n", c.opts.MemStr)
	fmt.Fprintf(c.writer, "MultiBr:     %v\n", c.opts.MultiBr)
	fmt.Fprintf(c.writer, "NoJOP:       %v\n", c.opts.NoJOP)
	fmt.Fprintf(c.writer, "NoROP:       %v\n", c.opts.NoROP)
	fmt.Fprintf(c.writer, "NoSYS:       %v\n", c.opts.NoSYS)
	fmt.Fprintf(c.writer, "Offset:      %s\n", c.opts.Offset)
	fmt.Fprintf(c.writer, "Only:        %s\n", c.opts.Only)
	fmt.Fprintf(c.writer, "Opcode:      %s\n", c.opts.Opcode)
	fmt.Fprintf(c.writer, "ROPchain:    %v\n", c.opts.ROPChain)
	fmt.Fprintf(c.writer, "Range:       %s\n", c.opts.Range)
	fmt.Fprintf(c.writer, "RawArch:     %s\n", c.opts.RawArch)
	fmt.Fprintf(c.writer, "RawMode:     %s\n", c.opts.RawMode)
	fmt.Fprintf(c.writer, "RawEndian:   %s\n", c.opts.RawEndian)
	fmt.Fprintf(c.writer, "Re:          %s\n", c.opts.Regexp)
	fmt.Fprintf(c.writer, "String:      %s\n", c.opts.String)
	fmt.Fprintf(c.writer, "Thumb:       %v\n", c.opts.Thumb)
	fmt.Fprintf(c.writer, "Mipsrop:     %s\n", c.opts.MIPSROP)
}
