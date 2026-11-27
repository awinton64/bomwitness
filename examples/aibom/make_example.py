"""Build the synthetic AI-BOM example: two placeholder "model" files and the declarations for them.

The files are a format header followed by padding. They are not models. They exist so that the presence
check in bomwitness/aibom.py has something to find, and so that the repository ships an AI-BOM example.
Run from the repository root: python examples/aibom/make_example.py
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from bomwitness import aibom  # noqa: E402

rootfs = HERE / "rootfs"
models = rootfs / "usr/share/models"
models.mkdir(parents=True, exist_ok=True)
pad = b"synthetic fixture for the BOMwitness AI-BOM example; not a model\n" * 4
(models / "keyword-spotter.gguf").write_bytes(b"GGUF" + (3).to_bytes(4, "little") + pad)
(models / "anomaly-detector.tflite").write_bytes((28).to_bytes(4, "little") + b"TFL3" + pad)

found = aibom.discover(rootfs)
correct = aibom.to_aibom(found, "synthetic-edge-device")
(HERE / "aibom-correct.cdx.json").write_text(json.dumps(correct, indent=1) + "\n")

wrong = json.loads(json.dumps(correct))
wrong["components"] = [c for c in wrong["components"] if not c["name"].endswith(".tflite")]      # one model left out
wrong["components"].append({"type": "machine-learning-model", "bom-ref": "model:phantom", "name": "usr/share/models/face-id.onnx",
                            "hashes": [{"alg": "SHA-256", "content": "0" * 64}],
                            "properties": [{"name": "bomwitness:format", "value": "ONNX"}]})     # one model that is not there
(HERE / "aibom-with-errors.cdx.json").write_text(json.dumps(wrong, indent=1) + "\n")
(HERE / "expected-findings.json").write_text(json.dumps(
    [["absent_model", "usr/share/models/face-id.onnx"], ["undeclared_model", "usr/share/models/anomaly-detector.tflite"]], indent=1) + "\n")
print("models found:", [m["path"] for m in found])
