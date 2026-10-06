#!/usr/bin/env python3
"""Build committed source and check the isolated Node test reports."""
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

if not __debug__:
    raise RuntimeError("Run verification without Python optimization")

root = Path(__file__).resolve().parents[2]
output = Path(sys.argv[1]).resolve()
output.mkdir(parents=True, exist_ok=False)
report = {"commands": [], "scope": "Node suite and bounded encoding controls"}
expected_pending = sorted(
    "rsa should generate same 512 bit key pair " + mode for mode in [
        "(prng+sync,prng+sync+purejs)", "(prng+sync,prng+async)",
        "(prng+async,prng+sync)", "(prng+async,prng+async)"
    ]
)


def run(args, data=None, timeout=300):
    cidfile = None
    if args[:2] == ["docker", "run"]:
        cidfile = output / ("container-" + str(len(report["commands"])) + ".cid")
        args = args[:2] + ["--cidfile", str(cidfile)] + args[2:]
    record = {"argv": args, "exit_code": None}
    report["commands"].append(record)
    command_error = None
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            result = subprocess.run(args, cwd=root, input=data, stdout=stdout,
                                    stderr=stderr, timeout=timeout)
            stdout.seek(0)
            stderr.seek(0)
            out = stdout.read(16 * 1024 * 1024 + 1)
            err = stderr.read(1024 * 1024 + 1)
        record.update({
            "exit_code": result.returncode,
            "stdout_sha256": hashlib.sha256(out).hexdigest(),
            "stderr_sha256": hashlib.sha256(err).hexdigest(),
        })
        assert len(out) <= 16 * 1024 * 1024 and len(err) <= 1024 * 1024, "Output limit exceeded"
        if err:
            print(err.decode("utf-8", errors="replace"), file=sys.stderr)
        assert result.returncode == 0, "Command failed: " + args[0]
        return out
    except Exception as error:
        command_error = error
        record["error_type"] = type(error).__name__
        raise
    finally:
        if cidfile is not None:
            cleanup = {"cidfile": str(cidfile), "result": "FAIL"}
            record["cleanup"] = cleanup
            try:
                # Only the exact ID emitted by this invocation may be removed.
                cid = cidfile.read_text().strip()
                assert re.fullmatch("[0-9a-f]{64}", cid), "Invalid owned container ID"
                cleanup["container_id"] = cid
                result = subprocess.run(["docker", "rm", "--force", cid],
                                        capture_output=True, timeout=30)
                cleanup["exit_code"] = result.returncode
                assert result.returncode == 0, "Owned container cleanup failed"
                cleanup["result"] = "REMOVED"
            except Exception as error:
                cleanup["error_type"] = type(error).__name__
                print("Owned container cleanup failed: " + type(error).__name__,
                      file=sys.stderr)
                if command_error is None:
                    raise


try:
    assert not run(["git", "status", "--porcelain"]).strip(), "Commit changes before testing"
    commit = run(["git", "rev-parse", "HEAD"]).decode().strip()
    report["commit"] = commit
    archive = run(["git", "archive", "--format=tar", "HEAD"])
    run(["docker", "build", "--no-cache", "--progress=plain",
         "--file", ".github/ci/Dockerfile", "--iidfile", str(output / "image.id"),
         "--label", "org.opencontainers.image.revision=" + commit, "-"], archive)
    image = (output / "image.id").read_text().strip()
    report["image"] = image
    container = ["docker", "run", "--network=none", "--read-only",
                 "--user", "10001:10001", "--cap-drop=ALL",
                 "--security-opt=no-new-privileges", "--memory=1g", "--cpus=2",
                 "--pids-limit=128", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m", image]
    paths = run(["git", "ls-files", "-z"]).decode().split("\0")
    expected = {p: hashlib.sha256((root / p).read_bytes()).hexdigest()
                for p in paths if p == "package.json"
                or p.startswith(("lib/", "tests/", ".github/ci/"))}
    script = ("const fs=require('fs'),c=require('crypto');"
              "console.log(JSON.stringify(Object.fromEntries(process.argv.slice(1)"
              ".map(p=>[p,c.createHash('sha256').update(fs.readFileSync(p)).digest('hex')]))));")
    actual = json.loads(run(container + ["node", "-e", script] + list(expected)))
    assert actual == expected, "Baked source differs from checkout"
    report["sources"] = actual
    suite = json.loads(run(container + [
        "node", "/tooling/node_modules/mocha/bin/mocha.js",
        "--timeout", "30000", "--reporter", "json", "tests/unit/index.js"]))
    stats = suite["stats"]
    report["suite"] = {"stats": stats, "pending": [t["fullTitle"] for t in suite["pending"]]}
    assert stats["tests"] == len(suite["tests"]) == 880, "Missing or changed test inventory"
    assert stats["passes"] == len(suite["passes"]) >= 876, "Missing passing tests"
    assert stats["failures"] == len(suite["failures"]) == 0, "Upstream suite failed"
    assert stats["pending"] == len(suite["pending"]) == 4, "Unexpected pending count"
    assert sorted(report["suite"]["pending"]) == expected_pending, "Unexpected skipped tests"
    controls = json.loads(run(container + ["node", ".github/ci/security-controls.js"]))
    report["security_controls"] = controls
    assert controls["tests"] == controls["passed"] == len(controls["observations"]) == 25
    assert controls["failed"] == 0 and all(t["pass"] for t in controls["observations"])
    report["result"] = "PASS_WITH_FOUR_DISCLOSED_UPSTREAM_SKIPS"
except Exception as error:
    report["result"] = "FAIL"
    report["error_type"] = type(error).__name__
    raise
finally:
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
