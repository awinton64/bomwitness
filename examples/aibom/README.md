# AI-BOM example (synthetic)

The router images in the benchmark contain no models, so this example is synthetic and says so: the two
"model" files under `rootfs/usr/share/models/` are a format header followed by padding text. They are not
models, and nothing here measures accuracy.

What it shows is the AI-BOM presence check (`bomwitness/aibom.py`): model files are found by magic bytes and
matched to declared `machine-learning-model` components by SHA-256.

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

Examples of the other two BOM types are in `pipeline/1_analysis_object/bomwitness/`: one CycloneDX 1.6
document per case that holds the SBOM (150 software components) and the CBOM (194 cryptographic assets).
