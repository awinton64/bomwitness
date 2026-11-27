"""Assemble the full report and render it as Markdown."""
from __future__ import annotations

import datetime as dt

from . import __version__

AUTOMATIC_PASS = ("verified_A", "verified_B")
AUTOMATIC_FAIL = ("wrong_version", "wrong_component", "absent")
NEEDS_REVIEW = ("bytes_differ", "label_unconfirmed")
VERDICT_TEXT = {
    "verified_A": "verified, byte-identical to the publisher's build",
    "verified_B": "verified by a version marker in the bytes",
    "wrong_version": "wrong version",
    "wrong_component": "wrong component",
    "absent": "absent from the firmware",
    "bytes_differ": "bytes differ from the publisher's build (review)",
    "label_unconfirmed": "bytes match, version label not confirmed (review)",
    "unverifiable": "unverifiable",
}


def triage(sbom: dict) -> dict:
    v = sbom["summary"]["verdicts"]
    image_level = sum(1 for f in sbom["findings"] if f["class"] in ("undeclared_component", "undeclared_file"))
    return {"automatic_pass": sum(v.get(k, 0) for k in AUTOMATIC_PASS),
            "automatic_fail": sum(v.get(k, 0) for k in AUTOMATIC_FAIL) + image_level,
            "needs_review": sum(v.get(k, 0) for k in NEEDS_REVIEW),
            "unverifiable": v.get("unverifiable", 0)}


def build(subject: dict, reference: dict, sbom: dict, device_db: dict | None = None, cbom: dict | None = None,
          aibom: dict | None = None, inputs: dict | None = None) -> dict:
    return {"tool": {"name": "bomwitness", "version": __version__},
            "generated": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "subject": subject, "reference": reference, "inputs": inputs or {}, "triage": triage(sbom),
            "sbom": sbom, "device_db": device_db, "cbom": cbom, "aibom": aibom}


def markdown(rep: dict) -> str:
    s, t = rep["sbom"], rep["triage"]
    out = [f"# BOMwitness report: {rep['subject'].get('name', 'firmware')}", ""]
    ref = rep["reference"]
    out += [f"Reference: OpenWrt {ref.get('release')} {ref.get('target')} ({ref.get('arch')}), "
            f"sha256sums signed by usign key {ref.get('sha256sums_signed_by')}.",
            f"Evidence used: byte hashes {'on' if s['options']['use_hashes'] else 'off'}, version markers "
            f"{'on' if s['options']['use_markers'] else 'off'}, release manifest {'yes' if s['options']['release_manifest'] else 'no'}, "
            f"sibling-image snapshots {len(s['options'].get('snapshots', []))}, file-path index {'yes' if s['options']['path_index'] else 'no'}.", ""]
    out += ["## Triage", "", "| Outcome | Count | Meaning |", "|---|---|---|",
            f"| Automatic pass | {t['automatic_pass']} | claim supported by grade A or B evidence |",
            f"| Automatic fail | {t['automatic_fail']} | claim contradicted by the bytes, or undeclared content found |",
            f"| Needs review | {t['needs_review']} | bytes or label differ from the reference and a person must decide |",
            f"| Unverifiable | {t['unverifiable']} | nothing to compare against |", "",
            f"Files in the image: {s['summary']['rootfs_files']}, accounted for by a declared component or reference package: "
            f"{s['summary']['files_accounted']}. Executable files not accounted for: {s['summary']['orphan_code_files']}.", ""]
    hard = [f for f in s["findings"] if f["class"] not in ("stale", "label_unconfirmed")]
    out += ["## SBOM findings", ""]
    if hard:
        out += ["| Class | Component | Grade | Detail |", "|---|---|---|---|"]
        out += [f"| {f['class']} | {f['component']} | {f['grade']} | {f['detail']} |" for f in hard]
    else:
        out += ["None."]
    info = [f for f in s["findings"] if f["class"] in ("stale", "label_unconfirmed")]
    if info:
        out += ["", "### Notes (not failures)", "", "| Class | Component | Detail |", "|---|---|---|"]
        out += [f"| {f['class']} | {f['component']} | {f['detail']} |" for f in info]
    db = rep.get("device_db")
    out += ["", "## Device package database (grade C, self-reported)", ""]
    if not db:
        out += ["Not consulted."]
    elif not db["present"]:
        out += ["The firmware has no package database. Nothing above depended on one."]
    elif db["findings"]:
        out += [f"{db['packages']} packages listed. Disagreements:", "", "| Class | Component | Detail |", "|---|---|---|"]
        out += [f"| {f['class']} | {f['component']} | {f['detail']} |" for f in db["findings"]]
    else:
        out += [f"{db['packages']} packages listed. It agrees with the BOM and is not contradicted by the bytes."]
    cb = rep.get("cbom")
    if cb:
        out += ["", "## CBOM findings", "",
                f"Found in the bytes: {cb['assets']['certificates']} certificates, {cb['assets']['keys']} keys, "
                f"{cb['assets']['algorithm_pairs']} (component, algorithm) pairs.", ""]
        if cb["findings"]:
            out += ["| Class | Asset | Grade | Detail |", "|---|---|---|---|"]
            out += [f"| {f['class']} | {f['asset']} | {f['grade']} | {f['detail']} |" for f in cb["findings"]]
        else:
            out += ["None."]
    ai = rep.get("aibom")
    if ai:
        out += ["", "## AI-BOM", "", f"Model files found by magic bytes: {ai['models_found']}.", ""]
        out += ([f"- {f['class']}: {f['asset']}. {f['detail']}" for f in ai["findings"]] or ["No findings."])
    out += ["", "## Declared components", "", "| Component | Declared version | Verdict | Evidence |", "|---|---|---|---|"]
    for c in s["components"]:
        out.append(f"| {c['name']} | {c['declared_version']} | {VERDICT_TEXT.get(c['verdict'], c['verdict'])} | {c.get('reason', '')} |")
    out += ["", "## What this report does not establish", "",
            "- That any component is free of vulnerabilities or is used at run time.",
            "- Anything about files outside the root filesystem (boot loader, kernel image, radio calibration data).",
            "- That an `unverifiable` or `needs review` component is wrong. Those need a person or more reference data.",
            "- Algorithm findings are string-level evidence (grade B), not proof of an implementation.", ""]
    return "\n".join(out)
