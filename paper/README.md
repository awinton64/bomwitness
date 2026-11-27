# Paper

`bomwitness.tex` is the SafeIoT Hackathon 2026 Track 2 paper (ACM `acmart`, `sigconf`), and `bomwitness.pdf` is the built copy.

No result number is typed into the text. `gen_numbers.py` derives every number, table body and plot coordinate from
the committed result files (`results/r2/`, the pipeline example report, the algorithm table in `bomwitness/crypto.py`) and
writes `numbers.tex`, `numbers.json` (each fact with its source file and computation), `tab-*.tex` and `fig-drift.tex`.

`check_numbers.py` then fails unless:

1. the generated files on disk equal what the result files produce now;
2. the paper source contains no literal number other than the listed identifiers (release names, tool versions, class ids);
3. every token with a digit in the built PDF is a generated fact, a listed identifier, bibliography text or structural numbering;
4. the body ends on page 5 or earlier and the PDF has at most 7 pages.

```sh
PYTHON=.venv/bin/python sh paper/build.sh     # needs tectonic and pdftotext
```

The last run's report is `number-check.json`.
