# BinWeaver

Static structure inspector for PE and ELF files: a C++20 core library, a command-line tool, and a Qt 6 desktop
workbench. BinWeaver maps files read-only and never executes or loads them. It reports what the headers and tables
say, where they are in the file, and exactly which structures are malformed. It is not a disassembler, an unpacker
or a malware classifier.

## What it does

| Area | Implemented | Not implemented (see [docs/LIMITATIONS.md](docs/LIMITATIONS.md)) |
|---|---|---|
| PE/COFF | DOS/COFF/optional headers (PE32, PE32+), sections incl. COFF long names, RVA↔offset mapping with loader rounding, data-directory validation, imports, delay imports, exports incl. forwarders, resource tree (type/name/language, loop-safe), RT_STRING string tables, icon extraction to .ico, VERSIONINFO (fixed info + string table), manifest execution level, load config (/GS cookie, SafeSEH, CFG guard flags and table size), x64 exception table (.pdata function ranges with decoded UNWIND_INFO: prolog, unwind codes, frame register, handlers, chaining), full debug directory (CodeView, Repro hash, POGO, VC feature counters, Ex-DllCharacteristics incl. CET shadow stack), .NET metadata (CLR header, streams, all table row counts, Module/Assembly/AssemblyRef/ModuleRef, public-key tokens), Rich header with checksum verification, pefile-compatible imphash, Authenticode signer metadata and image-digest check (SHA-256/SHA-1), certificate-table entries, CodeView/PDB info, base-relocation block counts, TLS callbacks, checksum, overlay | Dialogs, menus, message tables, .NET IL/signatures/custom attributes, ARM64 unwind data, exception tables, Authenticode **signature/chain** verification, nested signatures, Rich product-id names, ROM images |
| ELF | ELF32/ELF64, both byte orders, extended numbering (`e_shnum`/`e_shstrndx`/`e_phnum` via section 0), sections, segments, symbols incl. `SHN_XINDEX`, GNU symbol versioning (verdef/verneed/versym), RELR relocation expansion, dynamic entries with string resolution, REL/RELA relocations with type names (x86, x86-64, AArch64), notes (build-id, ABI tag, GNU properties, Go, FDO), layout validation | Dynamic symbols in files without section headers, DWARF, relocation names for other architectures |
| Diff | Raw positional byte diff with changed runs; structural diff of headers, properties, sections, segments, directories, imports, exports, symbols (incl. versions), needed libraries, notes, resources, Rich header and certificates, each with a confidence level and explicit caveats | Insertion/deletion alignment, code-level (instruction) diff |
| Heuristics | 11 `heur.*` observations (W+X sections/segments, packer section names, high-entropy code, code with no file data, entry in writable section, dynamic import resolution, high-entropy overlay, TLS callbacks, executable stack, ELF without section headers), each with its reason; calibrated on all of System32 (see docs/TESTING.md) | Signatures, YARA, emulation; no malware verdicts |
| Other | Multi-threaded directory scan to CSV, SHA-256 (x86 SHA extensions when available), SHA-1, MD5, entropy windows, byte search with wildcards (chunked, cancellable, find-all), printable ASCII/UTF-16 string extraction | — |
| Inspection aids | Header field map (every header byte named, with value), extraction of sections/segments/resources/overlay/ranges to files, self-contained HTML report | — |
| Rules | A small rule language (hex/text/wide patterns, imports, properties; scopes; any/all/N conditions) for `binweaver-cli match` and the GUI; see [docs/RULES.md](docs/RULES.md) | Boolean expressions, regexes, YARA compatibility |
| Diagnostics | 173 stable codes (4 retired) with severities, documented in [docs/DIAGNOSTICS.md](docs/DIAGNOSTICS.md) | — |

## Build

Requires CMake 3.20+ and a C++20 compiler (tested: Clang 17 and 22 / llvm-mingw on Windows; GCC, Clang and MSVC are
configured in CI). The GUI needs Qt 6.4+ Widgets and Concurrent; Qt 6.8.3 was used for development.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Options: `-DBINWEAVER_BUILD_GUI=ON` (Qt UI and GUI tests), `-DBINWEAVER_BUILD_BENCH=ON` (benchmark tool),
`-DBINWEAVER_SANITIZE="address;undefined"` (GCC/Clang), `-DBINWEAVER_FUZZ=ON` (libFuzzer harness, Clang on Linux/macOS),
`-DBINWEAVER_WERROR=ON`.

## Command line

```sh
binweaver-cli inspect app.exe            # text report; exit 1 if structural errors were found
binweaver-cli inspect libfoo.so --json   # JSON, schema_version 2
binweaver-cli compare old.dll new.dll    # structural + raw diff, with caveats
binweaver-cli map app.exe 0x2104         # RVA / virtual address -> file offset
binweaver-cli locate app.exe 0x1a00      # which headers/sections/directories contain an offset
binweaver-cli find app.exe "e8 ?? ?? ?? ?? 48"   # byte search with wildcards
binweaver-cli entropy app.exe --window 4096
binweaver-cli strings app.exe --min 8 --utf16 # printable strings with offsets
binweaver-cli scan C:\Windows\System32 --csv out.csv --recursive  # parallel batch summary
binweaver-cli icon app.exe app.ico            # extract the application icon
binweaver-cli fields app.exe                  # every header field with offset and value
binweaver-cli extract app.exe section:.text text.bin   # dump a section (also segment:/resource:/overlay/range:)
binweaver-cli inspect app.exe --html > report.html     # shareable HTML report
binweaver-cli match examples/rules/example.rules C:\Windows\System32   # run rules
binweaver-cli diagnostics                # list all diagnostic codes
```

`examples/` contains two small programs built against the library: `binweaver-hardening-check` (ASLR/DEP/CFG for PE;
PIE/NX stack/RELRO for ELF; usable as a CI gate) and `binweaver-deps` (dependency listing).

## Desktop workbench

`binweaver [file] [other-file]` opens a file, or a comparison when two files are given (or dropped).

- **Navigation:** a category list (Overview, Diagnostics, Sections, Segments, Structures, Directories, Imports, Exports,
  Header fields, Symbols, Dynamic, Relocations, Notes, Debug, Functions, .NET, Resource strings, Resources, Rich header, Strings,
  Signatures, Certificates, Bookmarks, Rule matches, Search results). The file's icon is shown above the list.
- **Bookmarks with notes** (Ctrl+D to add, F2/Shift+F2 to jump, Ctrl+Shift+D to remove) are saved per file content
  (SHA-256) and restored when the same file is opened again. **File → Run Rules…** lists rule hits as navigable rows.
  Each is a sortable table with a filter box; Ctrl+Shift+E exports the table as shown (filter, sort, column order) to
  CSV.
- **Hex view:** paints only the visible rows straight from the memory mapping, so large files open instantly (a 256 MiB
  file loads and analyzes in about 1.1 s in the GUI test on the machine below). It supports cursor and selection, go to
  offset (Ctrl+G), address (Ctrl+Shift+G) or the entry point (Ctrl+Shift+P), with Back/Forward history
  (Alt+←/Alt+→), and Ctrl+C copies the selection as hex. Byte or text search supports `??`
  wildcards (Ctrl+F, F3, Shift+F3). It runs on a worker thread with progress and Esc to cancel; **Find All** lists every
  match, with its enclosing structure and address, in a results table.
- **Synchronization:** selecting a table row selects its bytes, and import, export, symbol and relocation rows are
  translated through the address mapping. Moving the hex cursor updates the structural tables and the **Inspector**:
  offset, RVA/VA, every enclosing structure, integers decoded in both byte orders, and the selection's length,
  entropy and SHA-256.
- **Entropy dock:** entropy per window across the file, with section boundaries; click to navigate.
- **Compare window:** structural changes with confidence, a list of what could not be compared reliably, and two
  hex views kept in step with changed bytes highlighted (F3/Shift+F3 jump between changed runs).
- Panels are resizable docks and splitters, and the layout is restored on start. F1 lists every shortcut; the list is
  generated from the live actions.

## Correctness checks against other tools

`tools/crosscheck_pefile.py` compares BinWeaver's JSON with [pefile](https://github.com/erocarrera/pefile) for
sections, imports, exports, imphash, Rich entries, resources, RT_STRING tables, x64 exception tables, file versions
and load-config fields (UNWIND_INFO and debug-directory entries were added later and checked on 1,500 files). On the 4,000
PE files of `C:\Windows\System32` + `SysWOW64` on the development machine it reports **no differences**. The only
skipped comparisons are three documented pefile limitations (see the script header). Authenticode signer subjects
and serials were compared with Windows' `Get-AuthenticodeSignature` on third-party signed executables, and image
digests match on all 987 embedded signatures in System32. `tools/crosscheck_dnfile.py` compares the .NET metadata with
[dnfile](https://github.com/malwarefrank/dnfile): 0 differences on 1,369 .NET Framework and GAC assemblies.
Extracted icons were decoded by Pillow: all 369 icon groups of `imageres.dll.mun` decode.

For ELF, `tools/crosscheck_pyelftools.py` compares with [pyelftools](https://github.com/eliben/pyelftools) on real
Linux binaries taken from manylinux wheels (x86-64 and AArch64). On 113 such shared objects it reports 0 differences
across 287,854 symbols (including GNU versions), 198,639 relocations, 3,193 sections and 1,019 segments.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): layers, data model, threading, design decisions
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md): what is not supported and known inaccuracies
- [docs/DIAGNOSTICS.md](docs/DIAGNOSTICS.md): stable diagnostic codes
- [docs/RULES.md](docs/RULES.md): the rule language
- [docs/TESTING.md](docs/TESTING.md): test suites, corpus, sanitizers, fuzzing, and what was verified where
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md): measured performance with hardware and compiler
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): handling of hostile input
- [CHANGELOG.md](CHANGELOG.md): changes, including defects found in the previous version

## Security

Treat every input as hostile. Parsers bounds-check every read with overflow-checked arithmetic, and the test suite
fuzzes them under AddressSanitizer and UndefinedBehaviorSanitizer. That is evidence, not proof. Analyze untrusted
samples in a disposable VM.

## License

MIT; see `LICENSE`.
