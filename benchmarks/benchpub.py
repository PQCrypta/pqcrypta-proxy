"""What export-bench.py and export-study.py share: reading the rig, and making a
configuration file fit to publish."""
import re
import subprocess


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()


def lib(var):
    """A setting from benchlib.sh, as the harness itself sees it."""
    return sh(f"bash -c 'source /root/bench/benchlib.sh >/dev/null 2>&1; echo ${var}'")


def publishable(text):
    """The file as run, less any comment paragraph naming a public domain.

    The rig is a production host, and its files carry operators' notes about
    what else it serves. Those are comments, so dropping them changes nothing
    the software reads; the directives are published untouched.
    """
    out_lines, para = [], []
    domain = re.compile(r"\b[a-z0-9-]+\.(?:com|org|net|io|dev)\b", re.I)

    def flush():
        if not any(domain.search(l) for l in para):
            out_lines.extend(para)
        para.clear()

    for line in text.splitlines(keepends=True):
        if line.strip() == "#":
            # A bare "#" separates paragraphs within one comment block.
            flush()
            out_lines.append(line)
        elif line.lstrip().startswith("#"):
            para.append(line)
        else:
            flush()
            out_lines.append(line)
    flush()
    return "".join(out_lines)


def conf_as_run(name, run_dir, started_epoch):
    """A configuration as the run used it.

    The run directory's own snapshot (RUN/conf/NAME) when it has one; otherwise
    the rig's current file, but only if it has not changed since the run
    started -- a configuration edited afterwards is not the one that ran, and
    publishing it under the run would be a false record.
    """
    import os, sys
    snap = f"{run_dir.rstrip('/')}/conf/{name}"
    if os.path.exists(snap):
        return open(snap).read()
    cur = f"/root/bench/conf/{name}"
    if os.stat(cur).st_mtime > started_epoch:
        sys.exit(f"{cur} changed after {run_dir} started; put the file as run at {snap}")
    return open(cur).read()


def binary_commit(binary, given):
    """The commit a proxy binary was built from.

    Builds since 2026-09-25 name it in `--version` ("0.2.2 (701e003)"); that
    wins, and a different commit given by hand is refused -- a typed commit
    once published a binary-hash prefix no repository had. Older builds report
    none, and the given one is used. A "-dirty" build matches no commit and is
    refused unless ALLOW_DIRTY=1.
    """
    import os, sys
    m = re.search(r"\(([0-9a-f]{7,40})(-dirty)?\)", sh(f"{binary} --version 2>/dev/null | tail -1"))
    if not m:
        return given
    if m.group(2) and os.environ.get("ALLOW_DIRTY") != "1":
        sys.exit(f"{binary} was built from uncommitted changes on {m.group(1)}")
    built = m.group(1) + (m.group(2) or "")
    if given and not (built.startswith(given) or given.startswith(m.group(1))):
        sys.exit(f"{binary} reports commit {built}, not {given}")
    return built
