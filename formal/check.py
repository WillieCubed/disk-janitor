#!/usr/bin/env python3
"""Run this script *inside* the installed disk-janitor guard; no installation."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
DIGEST = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
CASES = {
    "safety": ("JobsSafety.cfg", None),
    "liveness": ("JobsLiveness.cfg", None),
    "public": ("JobsPublic.cfg", None),
    "public-four": ("JobsPublicFour.cfg", None),
    "bad-admission": ("JobsBadAdmission.cfg", "ResourceSafe"),
    "bad-replay": ("JobsBadReplay.cfg", "NoUnknownReplay"),
    "bad-release": ("JobsBadRelease.cfg", "ResourceSafe"),
    "bad-proof": ("JobsBadProof.cfg", "SuccessHasProof"),
    "no-executor": ("JobsNoExecutor.cfg", "temporal"),
    "no-capacity": ("JobsNoCapacity.cfg", "temporal"),
    "no-fairness": ("JobsNoFairness.cfg", "temporal"),
    "concurrent-witness": ("JobsConcurrentWitness.cfg", "NeverThreeConcurrent"),
    "late-receipt-witness": ("JobsLateReceiptWitness.cfg", "NeverLateResolved"),
    "pressure-linux": ("PressureLinux.cfg", None),
    "pressure-darwin": ("PressureDarwin.cfg", None),
    "pressure-orphan": ("PressureOrphan.cfg", "temporal"),
    "pressure-overshoot": ("PressureOvershoot.cfg", "HardReserve"),
    "pressure-replay": ("PressureReplay.cfg", "NoReplay"),
    "pressure-signal-other": ("PressureSignalOther.cfg", "NoUnrelatedSignal"),
}


def state_counts(text):
    # Progress lines use comma separators. Select the final standalone summary,
    # never a suffix of a formatted progress count such as the "140" in "2,140".
    matches = re.findall(r"^(\d+) states generated, (\d+) distinct states found, "
                         r"(\d+) states left on queue\.", text, re.MULTILINE)
    return dict(zip(("generated", "distinct", "remaining"), map(int, matches[-1]))) if matches else {}


def main():
    if hashlib.sha256((ROOT / "tla2tools.jar").read_bytes()).hexdigest() != DIGEST:
        raise SystemExit("Unexpected TLC tool digest")
    java = os.environ.get("JANITOR_FORMAL_JAVA")
    if not java:
        raise SystemExit("Set JANITOR_FORMAL_JAVA to the Java 21 executable")
    results = ROOT / "results"
    results.mkdir(exist_ok=True)
    requested = sys.argv[1:] or list(CASES)
    summary = {}
    for name in requested:
        config, violation = CASES[name]
        model = "Pressure.tla" if config.startswith("Pressure") else "Jobs.tla"
        with tempfile.TemporaryDirectory(prefix="janitor-tlc-") as meta:
            command = [java, "-Dtlc2.tool.fp.FPSet.impl=tlc2.tool.fp.MemFPSet",
                       "-XX:+UseSerialGC", "-Xmx640m", "-cp",
                       str(ROOT / "tla2tools.jar"), "tlc2.TLC", "-workers", "2",
                       "-metadir", meta, "-config", config, model]
            log = results / (name + ".log")
            print("Checking " + name, flush=True)
            with log.open("w") as output:
                output.write("COMMAND " + json.dumps(command) + "\n")
                output.flush()
                completed = subprocess.run(command, cwd=ROOT, stdout=output,
                                           stderr=subprocess.STDOUT, check=False)
            text = log.read_text()
            if violation:
                marker = ("Temporal properties were violated" if violation == "temporal"
                          else "Invariant " + violation + " is violated")
                trace = ("The following behavior constitutes a counter-example" if
                         violation == "temporal" else "The behavior up to this point is")
                passed = (completed.returncode != 0 and marker in text and
                          trace in text)
            else:
                passed = (completed.returncode == 0 and
                          "Model checking completed. No error has been found." in text)
            summary[name] = {"exit_code": completed.returncode,
                             "expected_violation": violation, "passed": passed,
                             "config": config,
                             "model": model,
                             "model_sha256": hashlib.sha256((ROOT / model).read_bytes()).hexdigest(),
                             "config_sha256": hashlib.sha256((ROOT / config).read_bytes()).hexdigest()}
            summary[name].update(state_counts(text))
            print(json.dumps({name: summary[name]}), flush=True)
            if not passed:
                print(text, flush=True)
                break
    (results / "last-run.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if all(x["passed"] for x in summary.values()) and len(summary) == len(requested) else 1


if __name__ == "__main__":
    raise SystemExit(main())
