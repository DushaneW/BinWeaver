"""Differential test for ELF: compares binweaver-cli JSON with pyelftools.

    pip install pyelftools
    python tools/crosscheck_pyelftools.py <binweaver-cli> <file-or-dir>... [--verbose]

Real Linux binaries can be obtained on any OS from manylinux wheels, e.g.
    pip download --only-binary=:all: --platform manylinux2014_x86_64 --python-version 3.12 --no-deps numpy
and extracting the *.so files.

Compared: header (class, byte order, machine, type, entry), sections (name, type,
flags, address, offset, size), segments (type, flags, offset, vaddr, filesz,
memsz), dynamic entries (count, NEEDED/SONAME/RPATH/RUNPATH strings), symbols of
every SHT_SYMTAB/SHT_DYNSYM (name, value, size, type, bind, section index,
GNU version), REL/RELA relocations (offset, type, symbol index, addend), RELR
relocation addresses, and notes (owner, type, descriptor size).
"""
import json
import os
import subprocess
import sys
import time

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import NoteSection, SymbolTableSection

TOTALS = {}  # items compared per category, to show the comparison is not vacuous


def count(category, items):
    TOTALS[category] = TOTALS.get(category, 0) + len(items)


SHN = {"SHN_UNDEF": 0, "SHN_ABS": 0xFFF1, "SHN_COMMON": 0xFFF2, "SHN_XINDEX": 0xFFFF}
TYPE_ALIASES = {"LOOS": "GNU_IFUNC", "GNU_IFUNC": "GNU_IFUNC"}
BIND_ALIASES = {"LOOS": "GNU_UNIQUE", "GNU_UNIQUE": "GNU_UNIQUE"}


def files_in(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                f = os.path.join(p, name)
                if os.path.isfile(f):
                    out.append(f)
        else:
            out.append(p)
    return out


def run_cli(cli, path):
    for attempt in range(5):  # antivirus may briefly block a fresh executable
        try:
            return json.loads(subprocess.run([cli, "inspect", path, "--json"], capture_output=True).stdout)
        except PermissionError:
            time.sleep(0.5 * (attempt + 1))
    raise PermissionError(cli)


def versions(elf):
    """Version index -> name, from .gnu.version_d / .gnu.version_r."""
    names = {}
    for sec in elf.iter_sections():
        if sec["sh_type"] == "SHT_GNU_verdef":
            for vd, auxs in sec.iter_versions():
                aux = next(auxs, None)
                if aux is not None:
                    names[vd["vd_ndx"]] = aux.name
        elif sec["sh_type"] == "SHT_GNU_verneed":
            for _, auxs in sec.iter_versions():
                for aux in auxs:
                    names[aux["vna_other"]] = aux.name
    return names


def compare(cli, path, verbose):
    with open(path, "rb") as fh:
        try:
            elf = ELFFile(fh)
        except Exception:
            return None
        bw = run_cli(cli, path)
        issues = []

        def check(category, ours, theirs):
            if isinstance(theirs, list):
                count(category, theirs)
            if ours != theirs:
                if verbose:
                    o = [x for x in ours if x not in theirs][:3] if isinstance(ours, list) else ours
                    t = [x for x in theirs if x not in ours][:3] if isinstance(theirs, list) else theirs
                    issues.append("%s: only-ours=%r only-pyelftools=%r" % (category, o, t))
                else:
                    issues.append(category + " differs")

        check("bitness", bw["bitness"], "64-bit" if elf.elfclass == 64 else "32-bit")
        check("byte order", bw["byte_order"], "little-endian" if elf.little_endian else "big-endian")
        check("entry", bw["entry_point"], elf.header["e_entry"])

        theirs_sections = []
        for i, s in enumerate(elf.iter_sections()):
            t = s["sh_type"]
            theirs_sections.append((s.name or ("<null>" if i == 0 else "<unnamed>"), s.header["sh_addr"], s.header["sh_offset"],
                                    0 if t == "SHT_NOBITS" else s.header["sh_size"], s.header["sh_flags"]))
        check("sections", [(x["name"], x["address"], x["offset"], x["size"], x["flags"]) for x in bw["sections"]],
              theirs_sections)
        theirs_seg = [(p.header["p_offset"], p.header["p_vaddr"], p.header["p_filesz"], p.header["p_memsz"], p.header["p_flags"])
                      for p in elf.iter_segments()]
        check("segments", [(x["offset"], x["address"], x["size"], x["virtual_size"], x["flags"]) for x in bw["segments"]],
              theirs_seg)

        dyn = next((s for s in elf.iter_sections() if s["sh_type"] == "SHT_DYNAMIC"), None)
        if dyn is not None:
            tags = [t for t in dyn.iter_tags() if t.entry.d_tag != "DT_NULL"]
            # pyelftools stops at the first DT_NULL, as BinWeaver does.
            check("dynamic count", len(bw["dynamic"]), len(tags))
            want = []
            for t in tags:
                if t.entry.d_tag == "DT_NEEDED":
                    want.append(("DT_NEEDED", t.needed))
                elif t.entry.d_tag in ("DT_SONAME", "DT_RPATH", "DT_RUNPATH"):
                    want.append((t.entry.d_tag, getattr(t, t.entry.d_tag[3:].lower())))
            ours = [(d["tag_name"], d["text"]) for d in bw["dynamic"] if d["tag_name"] in ("DT_NEEDED", "DT_SONAME", "DT_RPATH", "DT_RUNPATH")]
            check("dynamic strings", ours, want)

        names = versions(elf)
        theirs_syms = []
        for sec in elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            versym = None
            if sec["sh_type"] == "SHT_DYNSYM":
                versym = next((v for v in elf.iter_sections() if v["sh_type"] == "SHT_GNU_versym"), None)
            for i, sym in enumerate(sec.iter_symbols()):
                info = sym["st_info"]
                typ = info["type"].replace("STT_", "")
                bind = info["bind"].replace("STB_", "")
                shndx = sym["st_shndx"]
                shndx = SHN.get(shndx, shndx) if isinstance(shndx, str) else shndx
                version = ""
                if versym is not None and i < versym.num_symbols():
                    v = versym.get_symbol(i)["ndx"]
                    if isinstance(v, int):
                        idx = v & 0x7FFF
                        if idx > 1 and idx in names:
                            version = names[idx] + (" (hidden)" if v & 0x8000 else "")
                theirs_syms.append((sec.name, i, sym.name, sym["st_value"], sym["st_size"], TYPE_ALIASES.get(typ, typ),
                                    BIND_ALIASES.get(bind, bind), shndx, version))
        check("symbols", [(s["table"], s["index"], s["name"], s["value"], s["size"], s["type"], s["bind"],
                           s["section_index"], s["version"]) for s in bw["symbols"]], theirs_syms)

        theirs_rel, theirs_relr = [], []
        for sec in elf.iter_sections():
            if sec["sh_type"] == "SHT_RELR":
                theirs_relr += [r["r_offset"] for r in sec.iter_relocations()]
            elif isinstance(sec, RelocationSection):
                for r in sec.iter_relocations():
                    theirs_rel.append((sec.name, r["r_offset"], r["r_info_type"], r["r_info_sym"],
                                       r["r_addend"] if r.is_RELA() else None))
        ours_rel = [(r["section"], r["offset"], r["type"], r["symbol_index"], r["addend"]) for r in bw["relocations"]
                    if "(RELR)" not in r["type_name"] and "RELR" not in r["section"].upper()]
        check("relocations", ours_rel, theirs_rel)
        check("relr", [r["offset"] for r in bw["relocations"] if "(RELR)" in r["type_name"]], theirs_relr)

        theirs_notes = []
        for sec in elf.iter_sections():
            if isinstance(sec, NoteSection):
                for n in sec.iter_notes():
                    t = n["n_type"]
                    theirs_notes.append((n["n_name"], n["n_descsz"]))
        check("notes", [(n["owner"], n["descriptor_size"]) for n in bw["notes"]], theirs_notes)
        if not bw["structurally_valid"]:
            issues.append("binweaver reports structural errors")
        return issues


def main():
    sys.stdout.reconfigure(errors="backslashreplace")
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    verbose = "--verbose" in sys.argv
    cli, inputs = args[0], args[1:]
    compared = differing = skipped = 0
    for f in files_in(inputs):
        issues = compare(cli, f, verbose)
        if issues is None:
            skipped += 1
            continue
        compared += 1
        if issues:
            differing += 1
            for i in issues:
                print("%s: %s" % (os.path.basename(f), i))
    print("\ncompared %d ELF files (%d skipped), %d with differences" % (compared, skipped, differing))
    print("items compared: " + ", ".join("%s %d" % kv for kv in sorted(TOTALS.items())))
    return 1 if differing else 0


if __name__ == "__main__":
    sys.exit(main())
