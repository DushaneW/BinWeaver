"""Regenerates docs/DIAGNOSTICS.md from the catalog compiled into the CLI.

    binweaver-cli diagnostics > catalog.txt
    python tools/gen_diagnostics_doc.py catalog.txt docs/DIAGNOSTICS.md
"""
import sys

HEADER = """# Diagnostic codes

Every diagnostic BinWeaver emits has a stable code. Codes are the contract for scripts and CI checks; the
human-readable message may change between releases, the code will not. A code is never renamed or reused;
retired codes stay listed here (marked *retired*) and are never emitted.

The test suite (`robust.diagnostic_catalog`) enforces this file: every code used in `src/` must be in the
catalog in `src/diagnostics.cpp`, every non-retired catalogued code must be used, and every catalogued code must
appear below. Regenerate with `tools/gen_diagnostics_doc.py`; `binweaver-cli diagnostics` prints the catalog.

## Severity policy

| Severity | Meaning | Effect |
|---|---|---|
| `error` | A structure is inconsistent with the file or the format, so some metadata could not be interpreted. | `structurally_valid` becomes `false`; `binweaver-cli inspect` exits with status 1. |
| `warning` | Interpretable but unusual, suspicious, or relevant to how a loader would treat the file. | None. |
| `info` | A noteworthy fact, or a feature BinWeaver explicitly does not decode. | None. |

Codes starting with `heur.` are **heuristics**: structural traits common in packed, self-modifying or
tampered binaries, each stated with its reason. They are observations, not verdicts; legitimate software
(installers with appended archives, JIT runtimes, DRM) triggers them too. `AnalyzeOptions::heuristics = false`
disables them.

Every diagnostic carries a file `offset` pointing at the field or structure involved, or `0` when no single
location applies. Repeated per-entry problems (for example thousands of broken symbol names) are reported 16
times per code; the rest are counted in one `diag.suppressed` entry.
"""

GROUPS = [("General", ("file.", "format.", "diag.")), ("PE / COFF", ("pe.",)), ("ELF", ("elf.",)),
          ("Heuristics", ("heur.",))]


def main(src, dst):
    rows = []
    for line in open(src, encoding="utf-8"):
        parts = line.rstrip("\n").split(None, 2)
        if len(parts) == 3:
            rows.append(parts)
    out = [HEADER]
    for title, prefixes in GROUPS:
        out += ["## " + title, "", "| Code | Severity | Meaning |", "|---|---|---|"]
        for severity, code, summary in rows:
            if code.startswith(prefixes):
                if summary.startswith("Retired"):
                    severity = "*retired*"
                out.append("| `%s` | %s | %s |" % (code, severity, summary.replace("|", "\\|")))
        out.append("")
    open(dst, "w", encoding="utf-8", newline="\n").write("\n".join(out))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
