# Checklist generator

`build_checklist.py` rebuilds `ASVS-checklist-en.xlsx` and `ASVS-checklist-en.ods` from the
official OWASP ASVS release data, so a new ASVS version is a rerun rather than a manual re-type.

## Usage

```bash
pip install openpyxl
python3 tools/build_checklist.py            # build both artifacts
python3 tools/build_checklist.py --verify   # build, then re-read and check the output
python3 tools/build_checklist.py --no-ods   # skip the LibreOffice conversion
python3 tools/build_checklist.py --refresh  # re-download the ASVS sources
```

## Requirements

- Python 3.9+ with [`openpyxl`](https://pypi.org/project/openpyxl/) (the only dependency).
- [LibreOffice](https://www.libreoffice.org/) for the `.ods` output, which is converted from the
  generated `.xlsx` with `soffice --headless --convert-to ods`. Without it the script still writes
  the `.xlsx` and just skips the conversion. On macOS `/Applications/LibreOffice.app` is found
  automatically; elsewhere `soffice` needs to be on `PATH`.

## Sources

Everything is pinned to the ASVS release tag and cached under `tools/.cache/` (gitignored):

| File | Used for |
| --- | --- |
| `..._en.flat.json` (release asset) | chapters, sections, requirement ids, text and levels |
| `5.0/mappings/v5.0.be_cwe_mapping.json` | CWE column |
| `5.0/mappings/nist.md` | NIST column |
| `5.0/mappings/mapping_v5.0.be_to_v5.0.0.yml` | joins the two mappings above onto released ids |

The CWE and NIST mappings are published against 5.0.be (bleeding edge) ids, so they **must** be
joined through the renumbering table — a direct id-to-id join silently mislabels requirements.

## Upgrading to a new ASVS version

Change `ASVS_VERSION` and `ASVS_TAG` at the top of the script, run it with `--verify`, and check
the rendered result before committing. `--verify` re-reads the generated workbook and asserts sheet
names and order, per-chapter row counts, requirement ids, levels and their colour coding, CWE/NIST
placement, the `Valid` dropdown ranges, and the merged section ranges.
