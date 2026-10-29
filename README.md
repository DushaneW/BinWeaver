# BinWeaver

![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg?style=flat-square&logo=c%2B%2B)
![Qt 6](https://img.shields.io/badge/Qt-6.4%2B-41CD52.svg?style=flat-square&logo=qt)
![CMake](https://img.shields.io/badge/CMake-3.20%2B-064F8C.svg?style=flat-square&logo=cmake)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg?style=flat-square)

Static structure inspector for PE and ELF binaries. Includes a zero-dependency C++20 core library, a fast CLI tool, and a Qt 6 desktop workbench.

BinWeaver memory-maps files strictly read-only and never executes or loads them. It reports exact header and table contents, file offsets, and structural anomalies. It is built for reverse engineers, malware analysts, and low-level developers who need raw structural ground truth rather than disassembly or opaque heuristic scores.

---

## Key Highlights

- **Hostile-Input Safe:** Every parser read is bounds-checked with overflow-safe arithmetic. Continuously fuzzed with libFuzzer under ASan and UBSan.
- **Instant Large-File Loading:** Zero-copy architecture renders hex views and parses structures directly from memory-mapped pages (loads and analyzes 256 MiB binaries in ~1.1s).
- **Battle-Tested Accuracy:** Cross-checked with **0 differences** against `pefile`, `dnfile`, and `pyelftools` across 5,500+ real-world system binaries (`System32`, `SysWOW64`, GAC, and `manylinux` wheels).
- **CI/CD Ready:** Structured JSON output (`schema_version 2`), deterministic exit codes, custom rule matching, and standalone HTML reports.

---

## Features

### PE / COFF
* **Headers & Layout:** DOS, COFF, and Optional headers (PE32/PE32+), section tables (including COFF long names), RVA-to-offset mapping with loader rounding, data-directory validation, checksums, and overlays.
* **Imports & Exports:** Standard and delay-load imports, `pefile`-compatible `imphash`, exports, and forwarders.
* **Resources:** Loop-safe resource trees (type/name/language), `RT_STRING` tables, `VERSIONINFO` (fixed + string tables), manifest execution levels, and `.ico` extraction.
* **Internals & Mitigations:** Load Config (`/GS` cookie, SafeSEH, CFG guard flags and table sizes), x64 `.pdata` exception tables with decoded `UNWIND_INFO` (prolog, unwind codes, frame registers, handlers, chaining), TLS callbacks, and base-relocation block counts.
* **Debug & Metadata:** Full debug directory (`CodeView`/PDB, Repro hash, POGO, VC feature counters, `Ex-DllCharacteristics` including CET shadow stack), Rich header with XOR key and checksum verification, and .NET metadata (CLR header, streams, table row counts, `Module`/`Assembly`/`AssemblyRef`/`ModuleRef`, public-key tokens).
* **Signatures:** Certificate table entries, Authenticode signer metadata, and SHA-256/SHA-1 image-digest verification.

### ELF
* **Core & Layout:** ELF32/ELF64, little and big-endian, extended numbering (`e_shnum`, `e_shstrndx`, `e_phnum` via section 0), sections, segments, and structural layout validation.
* **Symbols & Linking:** Symbol tables (including `SHN_XINDEX`), GNU symbol versioning (`verdef`, `verneed`, `versym`), dynamic entries with string resolution, `RELR` relocation expansion, and `REL`/`RELA` relocations with type names for x86, x86-64, and AArch64.
* **Notes:** `NT_GNU_BUILD_ID`, ABI tags, GNU properties, Go build info, and FDO packaging notes.

### Analysis, Diff & Tooling
* **Structural & Byte Diff:** Raw positional byte diff with changed runs alongside structural comparison (headers, sections, segments, imports, exports, versioned symbols, needed libraries, notes, resources, Rich headers, certificates) with confidence levels and explicit caveats.
* **Heuristics:** 11 transparent structural observations (`heur.*`), including W+X mappings, known packer section names, high-entropy code/overlays, code without file backing, writable entry points, dynamic import resolution, TLS callbacks, executable stacks, and sectionless ELF files.
* **Diagnostics:** 173 stable diagnostic codes with severity levels pinpointing malformed or non-standard structures.
* **Search & Extraction:** Byte-accurate header field maps, section/segment/resource/overlay dumping, chunked wildcard byte search (`??`), ASCII/UTF-16 string extraction, sliding-window entropy, SHA-256 (hardware-accelerated via x86 SHA extensions), SHA-1, MD5, and multi-threaded directory scanning to CSV.

### Out of Scope / Not Implemented
* Disassembly, decompilation, unpacking, or emulation.
* PE dialogs, menus, message tables, ROM images, ARM64 unwind data, .NET IL/signatures/custom attributes, Authenticode chain/root validation, nested signatures, and Rich product-ID name lookups.
* ELF dynamic symbol recovery without section headers, DWARF debugging info, and relocation names outside x86/x86-64/AArch64.

---

## Quick Start & Build

Requires **CMake 3.20+** and a **C++20 compiler** (GCC, Clang, or MSVC). The desktop GUI requires **Qt 6.4+** (`Widgets` and `Concurrent`).

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBINWEAVER_BUILD_GUI=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

### CMake Options

| Option | Default | Description |
| :--- | :--- | :--- |
| `-DBINWEAVER_BUILD_GUI` | `OFF` | Build Qt 6 desktop workbench and GUI test suite |
| `-DBINWEAVER_BUILD_BENCH` | `OFF` | Build performance benchmark tool |
| `-DBINWEAVER_SANITIZE` | `""` | Enable sanitizers on GCC/Clang (e.g., `"address;undefined"`) |
| `-DBINWEAVER_FUZZ` | `OFF` | Build libFuzzer harnesses (Clang on Linux/macOS) |
| `-DBINWEAVER_WERROR` | `OFF` | Treat compiler warnings as errors |

---

## CLI Usage

```bash
# Inspection & Reporting
binweaver-cli inspect app.exe                         # Text report (exits 1 on structural errors)
binweaver-cli inspect libfoo.so --json                # JSON output (schema v2)
binweaver-cli inspect app.exe --html > report.html    # Self-contained HTML report
binweaver-cli fields app.exe                          # Dump every header field with offset and value
binweaver-cli diagnostics                             # List all 173 diagnostic codes

# Addressing & Search
binweaver-cli map app.exe 0x2104                      # Convert RVA / VA to file offset
binweaver-cli locate app.exe 0x1a00                   # Show structures enclosing a file offset
binweaver-cli find app.exe "e8 ?? ?? ?? ?? 48"        # Wildcard byte search
binweaver-cli strings app.exe --min 8 --utf16         # Extract printable ASCII/UTF-16 strings
binweaver-cli entropy app.exe --window 4096           # Sliding-window entropy calculation

# Diffing, Extraction & Batch Processing
binweaver-cli compare old.dll new.dll                 # Structural + raw positional byte diff
binweaver-cli icon app.exe app.ico                    # Extract application icon to .ico
binweaver-cli extract app.exe section:.text text.bin  # Dump section:, segment:, resource:, overlay, or range:
binweaver-cli scan C:\Windows\System32 --csv out.csv --recursive
binweaver-cli match examples/rules/example.rules C:\Windows\System32
```

### Example Rule (`examples/rules/example.rules`)

BinWeaver includes a lightweight rule engine for matching patterns, imports, and structural properties across directories or inside the GUI:

```text
rule SuspiciousPackerLayout {
    meta:
        description = "Writable executable section with high-entropy overlay"
    properties:
        format == "PE"
        has_wx_section == true
        overlay_entropy > 7.2
    strings:
        $mz = { 4D 5A ?? ?? 50 45 00 00 }
        $api = "VirtualAlloc" ascii wide
    condition:
        all of properties and any of strings
}
```

### Standalone Library Examples (`examples/`)
* `binweaver-hardening-check` — Verifies binary mitigations (ASLR, DEP, CFG for PE; PIE, NX stack, RELRO for ELF). Designed as a drop-in CI/CD security gate.
* `binweaver-deps` — Fast recursive dependency tree lister.

---

## Desktop Workbench

Launch `binweaver [file] [other-file]` to inspect a single binary or open a side-by-side comparison (supports drag-and-drop).

* **Bi-Directional Synchronization:** Selecting any table row (Imports, Exports, Symbols, Relocations, Sections, Functions, etc.) highlights the exact bytes in the hex view. Moving the hex cursor updates the **Inspector** with file offset, RVA/VA, all enclosing structures, decoded integer values (little/big-endian), selection length, entropy, and SHA-256.
* **High-Performance Hex View:** Renders visible rows directly from the memory map. Supports background wildcard search (`??`) with an interactive **Find All** results table, navigation history, and instant jumps to offsets, addresses, or the entry point.
* **Entropy Dock:** Visualizes sliding-window entropy across the file with section boundary overlays; click anywhere on the graph to jump to that offset.
* **Compare Mode:** Displays structural changes with confidence ratings alongside dual synchronized hex views with highlighted byte differences.
* **Persistent Bookmarks:** Add notes to specific offsets; bookmarks are automatically indexed and restored by file SHA-256.

### Keyboard Shortcuts

| Shortcut | Action |
| :--- | :--- |
| `Ctrl+G` / `Ctrl+Shift+G` | Go to File Offset / Go to RVA or Virtual Address |
| `Ctrl+Shift+P` | Jump to Entry Point |
| `Alt+Left` / `Alt+Right` | Navigate Back / Forward in jump history |
| `Ctrl+F` / `F3` / `Shift+F3` | Search bytes or text (with `??` wildcards) / Next / Previous match (or diff run) |
| `Ctrl+D` / `Ctrl+Shift+D` | Add Bookmark with note / Remove Bookmark |
| `F2` / `Shift+F2` | Jump to Next / Previous Bookmark |
| `Ctrl+C` | Copy selected bytes as hex string |
| `Ctrl+Shift+E` | Export current table view (respecting active filter, sort, and column order) to CSV |
| `F1` | Show complete live shortcut reference |

---

## Validation & Correctness

BinWeaver's parsers are continuously verified against industry-standard libraries across large real-world corpora:

* **PE (`tools/crosscheck_pefile.py`):** Compared against `pefile` across **4,000 PE files** in `C:\Windows\System32` and `SysWOW64`. Reports **0 differences** across sections, imports, exports, `imphash`, Rich entries, resources, `RT_STRING` tables, `.pdata` exception tables, `UNWIND_INFO`, debug directories, version info, and Load Config. Authenticode signer metadata matches `Get-AuthenticodeSignature`, and image digests match across all 987 embedded signatures in `System32`. All 369 icon groups extracted from `imageres.dll.mun` decode cleanly via Pillow.
* **.NET (`tools/crosscheck_dnfile.py`):** Compared against `dnfile` across **1,369 .NET Framework and GAC assemblies** with **0 differences**.
* **ELF (`tools/crosscheck_pyelftools.py`):** Compared against `pyelftools` across **113 Linux shared objects** (x86-64 and AArch64 `manylinux` wheels). Reports **0 differences** across 287,854 symbols (including GNU versions), 198,639 relocations, 3,193 sections, and 1,019 segments.

---

## Security Notice

Always treat inspected binaries as hostile. While BinWeaver never executes code, uses strict bounds-checked arithmetic, and undergoes continuous fuzzing with ASan/UBSan, parsing untrusted or potentially malicious samples should always be performed inside an isolated virtual machine.
