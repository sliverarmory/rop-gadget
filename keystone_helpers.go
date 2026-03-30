package ropgadget

import (
	"sync"

	keystone "github.com/moloch--/go-keystone"
)

var (
	x86StarterOnce sync.Once
	x86StarterSet  map[byte]struct{}
)

func x86CandidateStarterSet() map[byte]struct{} {
	x86StarterOnce.Do(func() {
		x86StarterSet = map[byte]struct{}{
			0x0f: {}, 0x26: {}, 0x2e: {}, 0x36: {}, 0x3e: {}, 0x48: {}, 0x64: {},
			0x65: {}, 0xc2: {}, 0xc3: {}, 0xca: {}, 0xcb: {}, 0xcd: {}, 0xcf: {},
			0xe8: {}, 0xe9: {}, 0xeb: {}, 0xf2: {}, 0xff: {},
		}

		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
		if err != nil {
			return
		}
		defer func() { _ = engine.Close() }()
		_ = engine.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)

		templates := []string{
			".code64\nret\n",
			".code64\nret 0x1337\n",
			".code64\nretf\n",
			".code64\nretf 0x1337\n",
			".code64\njmp rax\n",
			".code64\ncall rax\n",
			".code64\njmp 0x11223344\n",
			".code64\ncall 0x11223344\n",
			".code64\nsyscall\n",
			".code64\nsysret\n",
			".code64\nint3\n",
			".code32\nint 0x80\n",
			".code32\nsysenter\n",
			".code32\niret\n",
		}
		for _, template := range templates {
			buf, err := engine.Assemble(template, 0)
			if err != nil || len(buf) == 0 {
				continue
			}
			x86StarterSet[buf[0]] = struct{}{}
		}
	})
	return x86StarterSet
}
