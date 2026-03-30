package ropgadget

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	opts := DefaultOptions()
	var versionFlag bool
	var checkUpdateFlag bool

	cmd := &cobra.Command{
		Use:   "ROPgadget",
		Short: "Search gadgets in binaries",
		Long: `description:
  ROPgadget lets you search your gadgets on a binary. It supports several
  file formats and architectures and uses the Capstone disassembler for
  the search engine.

formats supported:
  - ELF
  - PE
  - Mach-O
  - Raw

architectures supported:
  - x86
  - x86-64
  - ARM
  - ARM64
  - MIPS
  - PowerPC
  - Sparc
  - RISC-V 64
  - RISC-V Compressed
`,
		Example: strings.Join([]string{
			"ROPgadget --binary ./test-suite-binaries/elf-Linux-x86",
			"ROPgadget --binary ./test-suite-binaries/elf-Linux-x86 --ropchain",
			"ROPgadget --binary ./test-suite-binaries/elf-Linux-x86 --depth 3",
			"ROPgadget --binary ./test-suite-binaries/elf-Linux-x86 --string \"main\"",
			"ROPgadget --binary ./test-suite-binaries/elf-Linux-x86 --string \"m..n\"",
			"ROPgadget --binary ./test-suite-binaries/elf-Linux-x86 --opcode c9c3",
			"ROPgadget --binary ./test-suite-binaries/elf-Linux-x86 --only \"mov|ret\"",
			"ROPgadget --binary ./test-suite-binaries/elf-Linux-x86 --filter \"xchg|add|sub|cmov.*\"",
			"ROPgadget --binary ./test-suite-binaries/elf-Linux-x86 --norop --nosys",
			"ROPgadget --binary ./test-suite-binaries/raw-x86.raw --rawArch=x86 --rawMode=32",
		}, "\n"),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if versionFlag {
				_, err := io.WriteString(cmd.OutOrStdout(), FormatVersion())
				return err
			}
			if checkUpdateFlag {
				_, err := io.WriteString(cmd.OutOrStdout(), CheckUpdate(context.Background()))
				return err
			}
			if opts.Console {
				return RunConsole(context.Background(), &opts, cmd.InOrStdin(), cmd.OutOrStdout())
			}
			result, err := Analyze(context.Background(), opts)
			if err != nil {
				return err
			}
			_, err = io.WriteString(cmd.OutOrStdout(), FormatResult(opts, result))
			return err
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&versionFlag, "version", "v", false, "Display the ROPgadget's version")
	flags.BoolVarP(&checkUpdateFlag, "checkUpdate", "c", false, "Checks if a new version is available")
	flags.StringVar(&opts.Binary, "binary", "", "Specify a binary filename to analyze")
	flags.StringVar(&opts.Opcode, "opcode", "", "Search opcode in executable segment")
	flags.StringVar(&opts.String, "string", "", "Search string in readable segment")
	flags.StringVar(&opts.MemStr, "memstr", "", "Search each byte in all readable segment")
	flags.IntVar(&opts.Depth, "depth", opts.Depth, "Depth for search engine (default 10)")
	flags.StringVar(&opts.Only, "only", "", "Only show specific instructions")
	flags.StringVar(&opts.Filter, "filter", "", "Suppress specific mnemonics")
	flags.StringVar(&opts.Range, "range", opts.Range, "Search between two addresses (0x...-0x...)")
	flags.StringVar(&opts.BadBytes, "badbytes", "", "Rejects specific bytes in the gadget's address")
	flags.StringVar(&opts.RawArch, "rawArch", "", "Specify an arch for a raw file x86|arm|arm64|sparc|mips|ppc|riscv")
	flags.StringVar(&opts.RawMode, "rawMode", "", "Specify a mode for a raw file 32|64|arm|thumb")
	flags.StringVar(&opts.RawEndian, "rawEndian", "", "Specify an endianness for a raw file little|big")
	flags.StringVar(&opts.Regexp, "re", "", "Regular expression")
	flags.StringVar(&opts.Offset, "offset", "", "Specify an offset for gadget addresses")
	flags.BoolVar(&opts.ROPChain, "ropchain", false, "Enable the ROP chain generation")
	flags.BoolVar(&opts.Thumb, "thumb", false, "Use the thumb mode for the search engine (ARM only)")
	flags.BoolVar(&opts.Console, "console", false, "Use an interactive console for search engine")
	flags.BoolVar(&opts.NoROP, "norop", false, "Disable ROP search engine")
	flags.BoolVar(&opts.NoJOP, "nojop", false, "Disable JOP search engine")
	flags.BoolVar(&opts.CallPreceded, "callPreceded", false, "Only show gadgets which are call-preceded")
	flags.BoolVar(&opts.NoSYS, "nosys", false, "Disable SYS search engine")
	flags.BoolVar(&opts.MultiBr, "multibr", false, "Enable multiple branch gadgets")
	flags.BoolVar(&opts.All, "all", false, "Disables the removal of duplicate gadgets")
	flags.BoolVar(&opts.NoInstr, "noinstr", false, "Disable the gadget instructions console printing")
	flags.BoolVar(&opts.Dump, "dump", false, "Outputs the gadget bytes")
	flags.BoolVar(&opts.Silent, "silent", false, "Disables printing of gadgets during analysis")
	flags.IntVar(&opts.Align, "align", 0, "Align gadgets addresses (in bytes)")
	flags.StringVar(&opts.MIPSROP, "mipsrop", "", "MIPS useful gadgets finder stackfinder|system|tails|lia0|registers")

	return cmd
}

func Execute() error {
	cmd := NewCommand()
	cmd.SetIn(os.Stdin)
	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)
	return cmd.Execute()
}

func CheckUpdate(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://raw.githubusercontent.com/JonathanSalwan/ROPgadget/master/ropgadget/version.py", nil)
	if err != nil {
		return "Can't connect to raw.githubusercontent.com\n"
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "Can't connect to raw.githubusercontent.com\n"
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Can't connect to raw.githubusercontent.com\n"
	}
	content := string(body)
	major := regexp.MustCompile(`MAJOR_VERSION.+(?P<value>[\d]+)`).FindStringSubmatch(content)
	minor := regexp.MustCompile(`MINOR_VERSION.+(?P<value>[\d]+)`).FindStringSubmatch(content)
	if len(major) < 2 || len(minor) < 2 {
		return "Can't connect to raw.githubusercontent.com\n"
	}
	webVersion := major[1] + minor[1]
	curVersion := fmt.Sprintf("%d%d", MajorVersion, MinorVersion)
	if webVersion > curVersion {
		return fmt.Sprintf("The version %s.%s is available. Currently, you use the version %d.%d.\n", major[1], minor[1], MajorVersion, MinorVersion)
	}
	return "Your version is up-to-date.\n"
}
