# rop-gadget

This repository is a Go port of the Python [`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget) project, built as a Go library first and then exposed through a CLI in [`./cli`](./cli/main.go).

## Features

- Library-first API for loading binaries, analyzing gadgets, formatting output, and generating x86/x64 ELF ROP chains
- Cobra CLI with the same primary flag surface as the Python tool
- Binary format support for ELF, PE, Mach-O, Universal Mach-O, and raw blobs
- Architecture support for x86, x86-64, ARM, ARM64, MIPS, PowerPC, SPARC, and RISC-V
- Disassembly through [`github.com/moloch--/go-capstone`](https://github.com/moloch--/go-capstone)
- Synthetic test assembly through [`github.com/moloch--/go-keystone`](https://github.com/moloch--/go-keystone)
- Interoperability tests that compare the Go output against archived Python reference output and, when available, a live Python run

## Layout

- [`analyze.go`](./analyze.go): top-level analysis entrypoint
- [`binary.go`](./binary.go): binary loading and section extraction
- [`gadgetfinder.go`](./gadgetfinder.go): gadget discovery and validation
- [`ropchain.go`](./ropchain.go): x86/x64 ELF ROP-chain generation
- [`command.go`](./command.go): Cobra command wiring
- [`cli/main.go`](./cli/main.go): CLI entrypoint
- [`analyze_test.go`](./analyze_test.go): fixture, synthetic, and interoperability tests

## Dependencies

The module depends on the following packages:

- `github.com/moloch--/go-capstone`
- `github.com/moloch--/go-keystone`

These dependencies are resolved through standard Go module configuration.

## Build

Build the CLI binary:

```bash
go build -trimpath -o ./bin/rop-gadget ./cli
```

## CLI Usage

Basic gadget search:

```bash
rop-gadget --binary ./testdata/test-suite-binaries/elf-Linux-x86
```

Search a raw x86 blob:

```bash
rop-gadget --binary ./testdata/test-suite-binaries/raw-x86.raw --rawArch=x86 --rawMode=32
```

Generate an x86 ELF ROP chain:

```bash
rop-gadget --binary ./testdata/test-suite-binaries/elf-Linux-x86 --ropchain
```

String and opcode searches:

```bash
rop-gadget --binary ./testdata/test-suite-binaries/elf-Linux-x86 --string main

rop-gadget --binary ./testdata/test-suite-binaries/elf-Linux-x86 --opcode c9c3
```

## Library Usage

```go
package main

import (
	"context"
	"fmt"

	ropgadget "github.com/sliverarmory/rop-gadget"
)

func main() {
	opts := ropgadget.DefaultOptions()
	opts.Binary = "./testdata/test-suite-binaries/elf-Linux-x86"
	opts.Depth = 3

	result, err := ropgadget.Analyze(context.Background(), opts)
	if err != nil {
		panic(err)
	}

	fmt.Print(ropgadget.FormatResult(opts, result))
}
```

## Testing

Run the full Go test suite:

```bash
env GOCACHE=/tmp/rop-gadget-gocache GOSUMDB=off go test ./...
```

The suite includes:

- synthetic x86 gadget tests assembled on the fly with `go-keystone`
- copied binary fixture smoke tests across multiple architectures
- archived Python reference-output similarity checks
- an optional live Python interoperability test

The live Python interoperability test is skipped automatically if `python3` does not have the `capstone` module installed.

## Notes

- The goal is compatibility with Python `ROPgadget`, not byte-for-byte identical output.
- `--checkUpdate` performs a network request to GitHub.
- The current x86/x64 ELF ROP-chain generator follows the same general strategy as the Python implementation.
