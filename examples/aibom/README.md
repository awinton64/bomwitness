# AI-BOM example (synthetic)

The router images in the benchmark contain no models, so this example is synthetic and says so: the two
"model" files under `rootfs/usr/share/models/` are a format header followed by padding text. They are not
models, and nothing here measures accuracy.

What it shows is the AI-BOM presence check (`bomwitness/aibom.py`): model files are recognised by file
header (GGUF, TensorFlow Lite, HDF5) or by a generic header plus the file extension (safetensors, PyTorch
archives, ONNX) and matched to declared `machine-learning-model` components by SHA-256.

| File | Contents |
|---|---|
| `aibom-correct.cdx.json` | a CycloneDX 1.6 AI-BOM that lists both files |
| `aibom-with-errors.cdx.json` | the same with one model left out and one listed that is not in the tree |
| `expected-findings.json` | the two findings the second document must produce |
| `make_example.py` | regenerates all of the above |

```sh
python examples/aibom/run.py
```

prints the findings for both documents and ends with `PASS` (`undeclared_model` for the file that was left
out, `absent_model` for the listed model that is not there). `bomwitness verify --aibom <file>` runs the same
check next to the SBOM and CBOM checks.

## All three BOM types in one run

```sh
sh examples/aibom/unified.sh
```

copies the unpacked root filesystem of the pipeline example's official OpenWrt image, adds the two placeholder
model files, and runs one `bomwitness verify` with the declared SBOM and CBOM (seeded errors) and
`aibom-with-errors.cdx.json`. It prints the four SBOM findings, the four CBOM and cross-BOM findings and the
two AI-BOM findings, checks them against the expected lists (`check_unified.py`) and ends with `PASS`. The
subject is synthetic: an official image's files plus two files that are not models. The report title says
so. This demonstrates that the three checks run in one workflow; it measures nothing about models.

Examples of the other two BOM types are in `pipeline/1_analysis_object/bomwitness/`: one CycloneDX 1.6
document per case that holds the SBOM (150 software components) and the CBOM (194 cryptographic assets).
