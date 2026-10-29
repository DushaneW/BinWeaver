"""Differential test for .NET metadata: compares binweaver-cli JSON with dnfile.

    pip install dnfile
    python tools/crosscheck_dnfile.py <binweaver-cli> <file-or-dir>... [--limit N] [--verbose]

Compared: metadata version string, CLR flags, stream names and sizes, row counts
of every table, Module name, Assembly name/version/culture, AssemblyRef
name/version/culture/public-key token (when stored as a token), and ModuleRef
names. Files dnfile cannot parse, or that have no CLR header, are skipped.
"""
import json
import os
import subprocess
import sys
import time

import logging

import dnfile

logging.disable(logging.WARNING)  # dnfile logs malformed #US/#Blob entries


def text(v):
    if v is None:
        return ""
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    value = getattr(v, "value", v)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def files_in(paths, limit):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for dirpath, _, names in os.walk(p):
                for name in sorted(names):
                    if name.lower().endswith((".dll", ".exe")):
                        out.append(os.path.join(dirpath, name))
        else:
            out.append(p)
    return out[:limit] if limit else out


def run_cli(cli, path):
    for attempt in range(5):  # antivirus may briefly block a fresh executable
        try:
            return subprocess.run([cli, "inspect", path, "--json"], capture_output=True)
        except PermissionError:
            time.sleep(0.5 * (attempt + 1))
    raise PermissionError(cli)


def compare(cli, path, verbose):
    try:
        pe = dnfile.dnPE(path)
    except Exception:
        return None
    net = pe.net
    if net is None or net.metadata is None:
        return None
    bw = json.loads(run_cli(cli, path).stdout.decode("utf-8", "replace"))
    ours = bw.get("dotnet")
    issues = []

    def check(category, mine, theirs):
        if mine != theirs:
            issues.append(category + (": ours=%r dnfile=%r" % (mine, theirs) if verbose else " differs"))

    if ours is None:
        return ["binweaver found no .NET metadata"]
    check("metadata version", ours["metadata_version"], text(net.metadata.struct.Version).rstrip("\0"))
    check("flags", ours["flags"], int(net.struct.Flags))
    check("streams", [(s["name"], s["size"]) for s in ours["streams"]],
          [(text(s.struct.Name).rstrip("\0"), s.struct.Size) for s in net.metadata.streams_list])
    # dnfile spells FieldRVA as "FieldRva"; compare names case-insensitively.
    tables = {t.name.lower(): t.num_rows for t in (net.mdtables.tables_list if net.mdtables else []) if t.num_rows}
    check("table rows", {k.lower(): v for k, v in ours["tables"].items()}, tables)
    md = net.mdtables
    if md and md.Module and md.Module.rows:
        check("module", ours["module"], text(md.Module.rows[0].Name))
    if md and md.Assembly and md.Assembly.rows:
        r = md.Assembly.rows[0]
        check("assembly", (ours["assembly"], ours["version"], ours["culture"]),
              (text(r.Name), "%d.%d.%d.%d" % (r.MajorVersion, r.MinorVersion, r.BuildNumber, r.RevisionNumber), text(r.Culture)))
    theirs_refs = []
    for r in (md.AssemblyRef.rows if md and md.AssemblyRef else []):
        key = getattr(r.PublicKey, "value", None) or b""
        token = key.hex() if (key and not r.Flags.afPublicKey) else None
        theirs_refs.append((text(r.Name), "%d.%d.%d.%d" % (r.MajorVersion, r.MinorVersion, r.BuildNumber, r.RevisionNumber),
                            text(r.Culture), token))
    ours_refs = [(x["name"], x["version"], x["culture"], x["public_key_token"]) for x in ours["references"]]
    # Full public keys in AssemblyRef are hashed by BinWeaver; compare tokens only where stored as tokens.
    ours_refs = [o if t[3] is not None else o[:3] + (None,) for o, t in zip(ours_refs, theirs_refs)] + ours_refs[len(theirs_refs):]
    check("assembly refs", ours_refs, theirs_refs)
    check("module refs", ours["module_references"], [text(m.Name) for m in (md.ModuleRef.rows if md and md.ModuleRef else [])])
    return issues


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    limit = 0
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])
        args.remove(str(limit))
    verbose = "--verbose" in sys.argv
    cli, inputs = args[0], args[1:]
    compared = differing = skipped = 0
    for f in files_in(inputs, limit):
        issues = compare(cli, f, verbose)
        if issues is None:
            skipped += 1
            continue
        compared += 1
        if issues:
            differing += 1
            for i in issues:
                print("%s: %s" % (f, i))
    print("\ncompared %d .NET files (%d skipped: not .NET or not parsable by dnfile), %d with differences"
          % (compared, skipped, differing))
    return 1 if differing else 0


if __name__ == "__main__":
    sys.exit(main())
