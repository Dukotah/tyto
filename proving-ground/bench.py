#!/usr/bin/env python3
"""tyto capability benchmark.

Runs tyto against the local vulnerable lab (lab-vulnapp.py), scores the findings
against the planted answer key (answer-key.json), and writes a scorecard. This is
the fitness function for the capability loop: every loop iteration must move a
number here (or be measurement/infra that enables one) to count.

Deterministic by default: `--planner scripted` drives a fixed recon->scan->exploit
sweep with NO model, so the score is reproducible anywhere. `--planner ollama`
(needs a local model) adds the autonomous-recall dimension. A matcher credits a
class on the finding's CONTENT (title/description/evidence), never the tool name.

RUNNER: on Windows, Smart App Control blocks freshly-built unsigned .exe files
(WinError 4551), which would block the benchmark binary. SAC governs Windows PEs
only, so the default runner cross-compiles a Linux ELF and runs the lab + tyto
inside WSL, out of SAC's reach. Force with --runner native|wsl.

SAFETY: the lab binds 127.0.0.1:8080 only and the engagement is self-attested and
scoped to localhost. This harness must never be pointed at a real or external host.

Usage:
  python bench.py                      # auto runner (WSL on Windows), scripted planner
  python bench.py --runner native      # force native exe (non-SAC machines)
  python bench.py --planner ollama --model llama3.1
Exit codes: 0 = ran and scored; 2 = infrastructure failure (build/lab/run).
"""
import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent          # proving-ground/
REPO = ROOT.parent                              # repo root
BENCH = ROOT / ".bench"                          # gitignored work dir
LAB = ROOT / "lab-vulnapp.py"
ENG = ROOT / "lab-northwind.engagement.yaml"
KEY = ROOT / "answer-key.json"
HOST, PORT = "127.0.0.1", 8080
WSL_DISTRO = os.environ.get("TYTO_BENCH_WSL_DISTRO", "Ubuntu")


def die(msg):
    print(f"[bench] INFRA FAILURE: {msg}", file=sys.stderr)
    sys.exit(2)


def win_to_wsl(p: Path) -> str:
    """C:\\Users\\x -> /mnt/c/Users/x (for paths handed to a WSL process)."""
    s = str(Path(p).resolve())
    drive, rest = s[0], s[2:].replace("\\", "/")
    return f"/mnt/{drive.lower()}{rest}"


def wait_port(host, port, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), 0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def resolve_runner(choice):
    if choice != "auto":
        return choice
    return "wsl" if platform.system() == "Windows" else "native"


def build(runner):
    BENCH.mkdir(exist_ok=True)
    if runner == "wsl":
        binp = BENCH / "tyto-linux"
        env = dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0")
        r = subprocess.run(["go", "build", "-o", str(binp), "./cmd/tyto"],
                           cwd=REPO, capture_output=True, text=True, env=env)
    else:
        binp = BENCH / ("tyto.exe" if platform.system() == "Windows" else "tyto")
        r = subprocess.run(["go", "build", "-o", str(binp), "./cmd/tyto"],
                           cwd=REPO, capture_output=True, text=True)
    if r.returncode != 0:
        die("go build failed:\n" + r.stderr)
    return binp


def tyto_run(runner, binp, report, planner, model, timeout):
    """Run one engagement, writing the JSON report. Returns the run result."""
    if runner == "wsl":
        cmd = ["wsl", "-d", WSL_DISTRO, "--", win_to_wsl(binp), "run",
               "--engagement", win_to_wsl(ENG), "--planner", planner,
               "--report-format", "json", "--report-out", win_to_wsl(report),
               "--audit", win_to_wsl(BENCH / "audit.jsonl"),
               "--state", win_to_wsl(BENCH / "state.json")]
        if model:
            cmd += ["--model", model]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    cmd = [str(binp), "run", "--engagement", str(ENG), "--planner", planner,
           "--report-format", "json", "--report-out", str(report),
           "--audit", str(BENCH / "audit.jsonl"), "--state", str(BENCH / "state.json")]
    if model:
        cmd += ["--model", model]
    env = dict(os.environ, TYTO_EXEC=os.environ.get("TYTO_EXEC", ""))
    return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True,
                          timeout=timeout, env=env)


def start_lab(runner):
    if runner == "wsl":
        return subprocess.Popen(["wsl", "-d", WSL_DISTRO, "--", "python3", win_to_wsl(LAB)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.Popen([sys.executable, str(LAB)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop_lab(runner, proc):
    proc.terminate()
    try:
        proc.wait(5)
    except Exception:
        proc.kill()
    if runner == "wsl":
        # the real server is a child of the wsl launcher; reap it by name.
        subprocess.run(["wsl", "-d", WSL_DISTRO, "--", "pkill", "-f", "lab-vulnapp.py"],
                       capture_output=True)


def finding_text(f):
    # Match on the finding's SEMANTIC content, never the tool name — otherwise a
    # class is credited just because a tool ran (e.g. "sqli" matching the tool
    # "sqliexploit" even when it found nothing).
    return " ".join(str(f.get(k, "")) for k in
                    ("title", "description", "evidence", "repro", "impact", "remediation")).lower()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--planner", default="scripted",
                    help="tyto planner backend: scripted|ollama|openai|mock")
    ap.add_argument("--model", default="", help="model name (for ollama/openai)")
    ap.add_argument("--runner", default="auto", choices=["auto", "native", "wsl"],
                    help="auto (WSL on Windows to dodge Smart App Control) | native | wsl")
    ap.add_argument("--timeout", type=int, default=900, help="run timeout (s)")
    args = ap.parse_args()

    if not LAB.exists() or not ENG.exists() or not KEY.exists():
        die("missing lab app, engagement, or answer key")
    key = json.loads(KEY.read_text(encoding="utf-8"))
    classes = key["classes"]

    runner = resolve_runner(args.runner)
    binp = build(runner)

    lab = start_lab(runner)
    report = BENCH / "report.json"
    try:
        if not wait_port(HOST, PORT):
            die(f"lab app did not bind {HOST}:{PORT} (runner={runner})")
        if report.exists():
            report.unlink()
        run = tyto_run(runner, binp, report, args.planner, args.model, args.timeout)
        if not report.exists():
            die(f"tyto run produced no report (runner={runner}). stderr tail:\n"
                + (run.stderr or "")[-2000:])
        data = json.loads(report.read_text(encoding="utf-8"))
    finally:
        stop_lab(runner, lab)

    findings = data.get("findings", [])
    texts = [(finding_text(f), bool(f.get("validated"))) for f in findings]

    results, matched = [], set()
    found = validated = 0
    for c in classes:
        hit = val = False
        for i, (t, v) in enumerate(texts):
            if any(m.lower() in t for m in c["match"]):
                hit = True
                matched.add(i)
                if v:
                    val = True
        results.append({"id": c["id"], "name": c["name"], "severity": c["severity"],
                        "found": hit, "validated": val})
        found += hit
        validated += val

    total = len(classes)
    unmatched = len(findings) - len(matched)
    depth = 0
    if found:
        depth = 1
    if validated:
        depth = 2
    if any(r["validated"] and r["severity"] in ("high", "critical") for r in results):
        depth = 3

    scorecard = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "planner": args.planner,
        "runner": runner,
        "target": "lab-vulnapp (Northwind), 127.0.0.1:8080",
        "totals": {
            "classes": total, "found": found, "validated": validated,
            "coverage_pct": round(100 * found / total, 1),
            "validated_pct": round(100 * validated / total, 1),
            "raw_findings": len(findings), "unmatched_findings": unmatched,
        },
        "chain_depth": depth,
        "classes": results,
    }
    (ROOT / "scorecard.json").write_text(json.dumps(scorecard, indent=2) + "\n", encoding="utf-8")

    t = scorecard["totals"]
    print(f"\n=== tyto capability scorecard (planner={args.planner}, runner={runner}) ===")
    print(f"coverage   : {found}/{total} classes  ({t['coverage_pct']}%)")
    print(f"validated  : {validated}/{total}  ({t['validated_pct']}%)")
    print(f"chain depth: {depth}/3")
    print(f"findings   : {len(findings)} raw  ({unmatched} unmatched to a class)")
    misses = [r["id"] for r in results if not r["found"]]
    print("misses     : " + (", ".join(misses) if misses else "none"))
    print(f"\nscorecard -> {ROOT / 'scorecard.json'}")
    sys.exit(0)


if __name__ == "__main__":
    main()
