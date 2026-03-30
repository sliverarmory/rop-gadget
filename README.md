# rop-gadget

This repository is a Go port of the Python `ROPgadget` project, built as a library first and then exposed through a Cobra-based CLI in [`./cli`](/Users/moloch/git/rop-gadget/cli/main.go).

The Python tree in [`./ROPgadget`](/Users/moloch/git/rop-gadget/ROPgadget) is kept only as a reference implementation during the port. The Go code does not import that Python code. The copied fixture corpus used by the Go tests lives under [`./testdata/test-suite-binaries`](/Users/moloch/git/rop-gadget/testdata/test-suite-binaries).

## Features

- Library-first API for loading binaries, analyzing gadgets, formatting output, and generating x86/x64 ELF ROP chains
- Cobra CLI with the same primary flag surface as the Python tool
- Binary format support for ELF, PE, Mach-O, Universal Mach-O, and raw blobs
- Architecture support for x86, x86-64, ARM, ARM64, MIPS, PowerPC, SPARC, and RISC-V
- Disassembly through [`github.com/moloch--/go-capstone`](https://github.com/moloch--/go-capstone)
- Synthetic test assembly through [`github.com/moloch--/go-keystone`](https://github.com/moloch--/go-keystone)
- Interoperability tests that compare the Go output against archived Python reference output and, when available, a live Python run

## Layout

- [`analyze.go`](/Users/moloch/git/rop-gadget/analyze.go): top-level analysis entrypoint
- [`binary.go`](/Users/moloch/git/rop-gadget/binary.go): binary loading and section extraction
- [`gadgetfinder.go`](/Users/moloch/git/rop-gadget/gadgetfinder.go): gadget discovery and validation
- [`ropchain.go`](/Users/moloch/git/rop-gadget/ropchain.go): x86/x64 ELF ROP-chain generation
- [`command.go`](/Users/moloch/git/rop-gadget/command.go): Cobra command wiring
- [`cli/main.go`](/Users/moloch/git/rop-gadget/cli/main.go): CLI entrypoint
- [`analyze_test.go`](/Users/moloch/git/rop-gadget/analyze_test.go): fixture, synthetic, and interoperability tests

## Dependencies

The module currently uses local `replace` directives in [`go.mod`](/Users/moloch/git/rop-gadget/go.mod) for:

- `github.com/moloch--/go-capstone`
- `github.com/moloch--/go-keystone`

If you move this repository to another machine, update those `replace` paths or remove them and depend on published module versions instead.

## Build

Show CLI help:

```bash
env GOCACHE=/tmp/rop-gadget-gocache GOSUMDB=off go run ./cli --help
```

Build the CLI binary:

```bash
env GOCACHE=/tmp/rop-gadget-gocache GOSUMDB=off go build -o ./bin/ROPgadget ./cli
```

## CLI Usage

Basic gadget search:

```bash
env GOCACHE=/tmp/rop-gadget-gocache GOSUMDB=off \
  go run ./cli --binary ./testdata/test-suite-binaries/elf-Linux-x86
```

Search a raw x86 blob:

```bash
env GOCACHE=/tmp/rop-gadget-gocache GOSUMDB=off \
  go run ./cli --binary ./testdata/test-suite-binaries/raw-x86.raw --rawArch=x86 --rawMode=32
```

Generate an x86 ELF ROP chain:

```bash
env GOCACHE=/tmp/rop-gadget-gocache GOSUMDB=off \
  go run ./cli --binary ./testdata/test-suite-binaries/elf-Linux-x86 --ropchain
```

String and opcode searches:

```bash
env GOCACHE=/tmp/rop-gadget-gocache GOSUMDB=off \
  go run ./cli --binary ./testdata/test-suite-binaries/elf-Linux-x86 --string main

env GOCACHE=/tmp/rop-gadget-gocache GOSUMDB=off \
  go run ./cli --binary ./testdata/test-suite-binaries/elf-Linux-x86 --opcode c9c3
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
