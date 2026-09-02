#!/usr/bin/env python3
"""Generate the OWASP ASVS audit checklist artifacts from the official ASVS release data.

Outputs ``ASVS-checklist-en.xlsx`` (built with openpyxl) and, when LibreOffice is
available, ``ASVS-checklist-en.ods`` (converted from the xlsx).

Usage::

    python3 tools/build_checklist.py            # build both artifacts
    python3 tools/build_checklist.py --verify   # build, then re-read and check the output
    python3 tools/build_checklist.py --no-ods   # skip the LibreOffice conversion

Upgrading to a newer ASVS release is normally a matter of changing ASVS_VERSION
and ASVS_TAG below.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import urllib.request
from collections import OrderedDict
from pathlib import Path

from openpyxl import Workbook, load_workbook
from openpyxl.chart import RadarChart, Reference
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.worksheet.datavalidation import DataValidation

# --------------------------------------------------------------------------------------
# Sources (pinned to the ASVS release tag)
# --------------------------------------------------------------------------------------

ASVS_VERSION = "5.0.0"
ASVS_TAG = "v5.0.0_release"

RELEASE_URL = f"https://github.com/OWASP/ASVS/releases/download/{ASVS_TAG}"
RAW_URL = f"https://raw.githubusercontent.com/OWASP/ASVS/{ASVS_TAG}/5.0"

SOURCES = {
    # The requirements themselves.
    "requirements.json": f"{RELEASE_URL}/OWASP_Application_Security_Verification_Standard_{ASVS_VERSION}_en.flat.json",
    # ASVS 5.0.0 dropped the CWE/NIST columns from the requirement exports; the only
    # mappings published with the release are keyed by 5.0.be (bleeding edge) ids, so
    # they have to be joined through the official be -> 5.0.0 renumbering table.
    "cwe.json": f"{RAW_URL}/mappings/v5.0.be_cwe_mapping.json",
    "be_to_release.yml": f"{RAW_URL}/mappings/mapping_v5.0.be_to_v{ASVS_VERSION}.yml",
    "nist.md": f"{RAW_URL}/mappings/nist.md",
}

REPO_ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = Path(__file__).resolve().parent / ".cache"
XLSX_PATH = REPO_ROOT / "ASVS-checklist-en.xlsx"
ODS_PATH = REPO_ROOT / "ASVS-checklist-en.ods"

# Excel caps sheet names at 31 characters; only one chapter name is too long.
SHEET_NAME_OVERRIDES = {"Security Logging and Error Handling": "Logging and Error Handling"}

RESULTS_SHEET = "ASVS Results"
VALID_CHOICES = "Valid,Non-valid,Not Applicable"

# --------------------------------------------------------------------------------------
# Styling (values mirror the 4.0.3 workbook so the look and feel is unchanged)
# --------------------------------------------------------------------------------------

INK = "FF102A43"
WHITE = "FFFFFFFF"
HEADER_FILL = PatternFill("solid", fgColor="FF486581")
AREA_FILL = PatternFill("solid", fgColor="FF9FB3C8")
RESULT_HEADER_FILL = PatternFill("solid", fgColor="FF9FB3C8")
RESULT_CATEGORY_FILL = PatternFill("solid", fgColor="FF486581")
RESULT_DATA_FILL = PatternFill("solid", fgColor="FFF0F4F8")

LEVEL_FILLS = {
    1: PatternFill("solid", fgColor="FFFAFA6A"),
    2: PatternFill("solid", fgColor="FFC7EA8F"),
    3: PatternFill("solid", fgColor="FF87EAF2"),
}

HEADER_FONT = Font(name="Calibri", size=16, color=WHITE)
AREA_FONT = Font(name="Calibri", size=16, color=INK)
BODY_FONT = Font(name="Calibri", size=12, color=INK)
RESULT_TITLE_FONT = Font(name="Calibri", size=16, color="FFE12D39", bold=True)
RESULT_HEADER_FONT = Font(name="Calibri", size=16, color=INK)
RESULT_CATEGORY_FONT = Font(name="Calibri", size=16, color=WHITE)

THIN = Side(style="thin", color="FFBCCCDC")
MEDIUM = Side(style="medium", color="FF334E68")
BODY_BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
HEADER_BORDER = Border(left=MEDIUM, right=MEDIUM, top=MEDIUM, bottom=MEDIUM)

CENTER = Alignment(horizontal="center", vertical="center", wrap_text=True)
LEFT_WRAP = Alignment(horizontal="left", vertical="center", wrap_text=True)
AREA_ALIGN = Alignment(horizontal="left", vertical="center", wrap_text=True)

PERCENT_FORMAT = "#,##0.00;(#,##0.00)"

HEADERS = [
    "Area",
    "#",
    "ASVS Level",
    "CWE",
    "NIST",
    "Verification Requirement",
    "Valid",
    "Source Code Reference",
    "Comment",
    "Tool Used",
]
COLUMN_WIDTHS = {
    "A": 19.85546875,
    "B": 8.85546875,
    "C": 8.85546875,
    "D": 8.85546875,
    "E": 8.85546875,
    "F": 60.85546875,
    "G": 19.140625,
    "H": 30.85546875,
    "I": 31.7109375,
    "J": 41.7109375,
}
RESULT_HEADERS = [
    "Security Category",
    "Valid criteria",
    "Total criteria",
    "Validity Percentage",
    "ASVS Level Acquired",
]
RESULT_COLUMN_WIDTHS = {"A": 55.0, "B": 18.0, "C": 18.0, "D": 22.0, "E": 24.0}

VALID_COL = "G"
LEVEL_COL = "C"


# --------------------------------------------------------------------------------------
# Source data
# --------------------------------------------------------------------------------------


def fetch(name: str, refresh: bool = False) -> Path:
    """Download a pinned source file, caching it under tools/.cache/."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / name
    if refresh or not path.exists():
        url = SOURCES[name]
        print(f"  fetching {url}")
        with urllib.request.urlopen(url) as response:
            path.write_bytes(response.read())
    return path


def load_be_to_release(path: Path) -> dict[str, str]:
    """Parse the flat 'v5.0.be-X: v5.0.0-Y' renumbering table."""
    mapping = {}
    pattern = re.compile(r"^(v5\.0\.be-[\d.]+):\s*(v[\d.]+-[\d.]+)\s*$")
    for line in path.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line.strip())
        if match:
            mapping[match.group(1)] = match.group(2)
    return mapping


def load_cwe(path: Path, be_to_release: dict[str, str]) -> dict[str, str]:
    """CWE ids keyed by release requirement id (e.g. '1.1.1')."""
    prefix = f"v{ASVS_VERSION}-"
    result = {}
    for be_id, cwe in json.loads(path.read_text(encoding="utf-8")).items():
        target = be_to_release.get(be_id, "")
        if target.startswith(prefix) and cwe:
            result[target[len(prefix):]] = str(cwe)
    return result


def load_nist(path: Path, be_to_release: dict[str, str]) -> dict[str, str]:
    """NIST SP 800-63B sections keyed by release requirement id."""
    prefix = f"v{ASVS_VERSION}-"
    row = re.compile(r"^\|\s*\*\*([\d.]+)\*\*\s*\|\s*(.*?)\s*\|\s*$")
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = row.match(line.strip())
        if not match or not match.group(2):
            continue
        target = be_to_release.get(f"v5.0.be-{match.group(1)}", "")
        if target.startswith(prefix):
            result[target[len(prefix):]] = match.group(2)
    return result


def load_chapters(path: Path) -> "OrderedDict[str, dict]":
    """Group the flat requirement list into chapters, preserving document order."""
    chapters: "OrderedDict[str, dict]" = OrderedDict()
    for req in json.loads(path.read_text(encoding="utf-8"))["requirements"]:
        chapter = chapters.setdefault(
            req["chapter_id"],
            {"id": req["chapter_id"], "name": req["chapter_name"], "requirements": []},
        )
        chapter["requirements"].append(req)
    return chapters


def sheet_name_for(chapter_name: str) -> str:
    return SHEET_NAME_OVERRIDES.get(chapter_name, chapter_name)


# --------------------------------------------------------------------------------------
# Workbook construction
# --------------------------------------------------------------------------------------


def build_chapter_sheet(workbook: Workbook, chapter: dict, cwe: dict, nist: dict) -> None:
    sheet = workbook.create_sheet(sheet_name_for(chapter["name"]))
    sheet.sheet_view.zoomScale = 85
    sheet.sheet_view.zoomScaleNormal = 85

    for column, width in COLUMN_WIDTHS.items():
        sheet.column_dimensions[column].width = width

    for index, title in enumerate(HEADERS, start=1):
        cell = sheet.cell(row=1, column=index, value=title)
        cell.font = HEADER_FONT
        cell.fill = HEADER_FILL
        cell.border = HEADER_BORDER
        cell.alignment = CENTER
    sheet.row_dimensions[1].height = 30

    section_spans: list[tuple[int, int]] = []
    current_section = None

    for offset, req in enumerate(chapter["requirements"]):
        row = offset + 2
        req_id = req["req_id"].lstrip("V")
        level = int(req["L"])

        if req["section_id"] != current_section:
            current_section = req["section_id"]
            section_spans.append((row, row))
            area = sheet.cell(row=row, column=1, value=req["section_name"])
            area.font = AREA_FONT
            area.fill = AREA_FILL
            area.alignment = AREA_ALIGN
            area.border = BODY_BORDER
        else:
            start, _ = section_spans[-1]
            section_spans[-1] = (start, row)
            area = sheet.cell(row=row, column=1)
            area.fill = AREA_FILL
            area.border = BODY_BORDER

        values = {
            2: req_id,
            3: level,
            4: cwe.get(req_id, ""),
            5: nist.get(req_id, ""),
            6: req["req_description"],
        }
        for column, value in values.items():
            cell = sheet.cell(row=row, column=column, value=value)
            cell.font = BODY_FONT
            cell.border = BODY_BORDER
            cell.alignment = LEFT_WRAP if column == 6 else CENTER
        sheet.cell(row=row, column=3).fill = LEVEL_FILLS[level]

        for column in range(7, 11):
            cell = sheet.cell(row=row, column=column)
            cell.font = BODY_FONT
            cell.border = BODY_BORDER
            cell.alignment = LEFT_WRAP

    for start, end in section_spans:
        if end > start:
            sheet.merge_cells(start_row=start, start_column=1, end_row=end, end_column=1)

    last_row = len(chapter["requirements"]) + 1
    validation = DataValidation(
        type="list", formula1=f'"{VALID_CHOICES}"', allow_blank=True, showErrorMessage=True
    )
    sheet.add_data_validation(validation)
    validation.add(f"{VALID_COL}2:{VALID_COL}{last_row}")

    # Keep the header visible while scrolling; no autofilter, as filtering would break
    # the vertically merged Area column.
    sheet.freeze_panes = "A2"


def level_acquired_formula(sheet_ref: str, last_row: int) -> str:
    """Highest ASVS level whose requirements are all marked Valid (ignoring N/A).

    A level also needs at least one requirement actually marked Valid, so that an
    untouched sheet - or a chapter that happens to have no requirement at that level -
    reports "-" instead of a level nobody verified.
    """
    levels = f"{sheet_ref}!$C$2:$C${last_row}"
    valid = f"{sheet_ref}!$G$2:$G${last_row}"

    def unmet(level: int) -> str:
        return (
            f'COUNTIFS({levels},"<={level}",{valid},"<>Valid",{valid},"<>Not Applicable")'
        )

    def met(level: int) -> str:
        return f'COUNTIFS({levels},"<={level}",{valid},"Valid")'

    def acquired(level: int) -> str:
        return f"AND({unmet(level)}=0,{met(level)}>0)"

    return (
        f"=IF({acquired(3)},3,IF({acquired(2)},2,IF({acquired(1)},1,\"-\")))"
    )


def build_results_sheet(workbook: Workbook, chapters: "OrderedDict[str, dict]") -> None:
    sheet = workbook[RESULTS_SHEET]
    sheet.sheet_view.zoomScale = 70
    sheet.sheet_view.zoomScaleNormal = 70

    for column, width in RESULT_COLUMN_WIDTHS.items():
        sheet.column_dimensions[column].width = width

    for index, title in enumerate(RESULT_HEADERS, start=1):
        cell = sheet.cell(row=1, column=index, value=title)
        cell.font = RESULT_TITLE_FONT if index == 1 else RESULT_HEADER_FONT
        cell.fill = RESULT_HEADER_FILL
        cell.border = BODY_BORDER
        cell.alignment = CENTER
    sheet.row_dimensions[1].height = 30

    first_row = 2
    for offset, chapter in enumerate(chapters.values()):
        row = first_row + offset
        name = sheet_name_for(chapter["name"])
        ref = f"'{name}'" if " " in name else name
        last = len(chapter["requirements"]) + 1

        label = sheet.cell(row=row, column=1, value=f"{chapter['id']} {chapter['name']}")
        label.font = RESULT_CATEGORY_FONT
        label.fill = RESULT_CATEGORY_FILL
        label.border = BODY_BORDER
        label.alignment = Alignment(horizontal="left", vertical="center")

        formulas = {
            2: f'=COUNTIF({ref}!G2:G{last},"Valid")',
            3: f'=COUNTIF({ref}!G2:G{last},"<>Not Applicable")',
            4: f"=IFERROR(B{row}/C{row}*100,0)",
            5: level_acquired_formula(ref, last),
        }
        for column, formula in formulas.items():
            cell = sheet.cell(row=row, column=column, value=formula)
            cell.font = BODY_FONT
            cell.fill = RESULT_DATA_FILL
            cell.border = BODY_BORDER
            cell.alignment = CENTER
            if column == 4:
                cell.number_format = PERCENT_FORMAT

    total_row = first_row + len(chapters)
    last_category_row = total_row - 1
    total_label = sheet.cell(row=total_row, column=1, value="Total")
    total_label.font = RESULT_CATEGORY_FONT
    total_label.fill = RESULT_CATEGORY_FILL
    total_label.border = BODY_BORDER
    total_label.alignment = Alignment(horizontal="left", vertical="center")

    totals = {
        2: f"=SUM(B{first_row}:B{last_category_row})",
        3: f"=SUM(C{first_row}:C{last_category_row})",
        4: f"=IFERROR(B{total_row}/C{total_row}*100,0)",
        5: (
            f'=IF(COUNTIF(E{first_row}:E{last_category_row},"-")>0,"-",'
            f"MIN(E{first_row}:E{last_category_row}))"
        ),
    }
    for column, formula in totals.items():
        cell = sheet.cell(row=total_row, column=column, value=formula)
        cell.font = BODY_FONT
        cell.fill = RESULT_DATA_FILL
        cell.border = BODY_BORDER
        cell.alignment = CENTER
        if column == 4:
            cell.number_format = PERCENT_FORMAT

    chart = RadarChart()
    chart.type = "filled"
    chart.style = 26
    chart.title = "Validity Percentage"
    chart.y_axis.scaling.min = 0
    chart.y_axis.scaling.max = 100
    chart.height = 17
    chart.width = 24
    data = Reference(sheet, min_col=4, min_row=1, max_row=total_row)
    categories = Reference(sheet, min_col=1, min_row=first_row, max_row=total_row)
    chart.add_data(data, titles_from_data=True)
    chart.set_categories(categories)
    sheet.add_chart(chart, f"A{total_row + 2}")


def build_workbook(chapters, cwe, nist) -> Workbook:
    workbook = Workbook()
    workbook.active.title = RESULTS_SHEET
    for chapter in chapters.values():
        build_chapter_sheet(workbook, chapter, cwe, nist)
    build_results_sheet(workbook, chapters)

    workbook.properties.title = (
        f"OWASP Application Security Verification Standard {ASVS_VERSION} Checklist"
    )
    workbook.properties.subject = f"OWASP ASVS {ASVS_VERSION}"
    workbook.properties.keywords = "OWASP ASVS Checklist Spreadsheet"
    workbook.properties.description = (
        "Spreadsheet to help performing security audits and code reviews with the "
        f"OWASP ASVS {ASVS_VERSION} method and criteria"
    )
    workbook.properties.creator = "Batard Florent"
    workbook.properties.language = "en-US"
    return workbook


# --------------------------------------------------------------------------------------
# ODS conversion
# --------------------------------------------------------------------------------------


def find_soffice() -> str | None:
    found = shutil.which("soffice")
    if found:
        return found
    bundled = Path("/Applications/LibreOffice.app/Contents/MacOS/soffice")
    return str(bundled) if bundled.exists() else None


def convert_to_ods(xlsx_path: Path, ods_path: Path) -> bool:
    soffice = find_soffice()
    if not soffice:
        print("! LibreOffice not found - skipping the .ods conversion")
        return False
    outdir = xlsx_path.parent
    subprocess.run(
        [soffice, "--headless", "--convert-to", "ods", "--outdir", str(outdir), str(xlsx_path)],
        check=True,
        capture_output=True,
    )
    produced = outdir / (xlsx_path.stem + ".ods")
    if produced != ods_path:
        produced.replace(ods_path)
    return True


# --------------------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------------------


def verify(chapters, cwe, nist) -> int:
    failures = []

    def check(condition, message):
        if not condition:
            failures.append(message)

    workbook = load_workbook(XLSX_PATH)
    expected_sheets = [RESULTS_SHEET] + [sheet_name_for(c["name"]) for c in chapters.values()]
    check(
        workbook.sheetnames == expected_sheets,
        f"sheet names/order mismatch: {workbook.sheetnames}",
    )

    total_requirements = 0
    cwe_filled = 0
    nist_filled = 0
    for chapter in chapters.values():
        sheet = workbook[sheet_name_for(chapter["name"])]
        expected_rows = len(chapter["requirements"])
        total_requirements += expected_rows
        check(
            sheet.max_row == expected_rows + 1,
            f"{sheet.title}: {sheet.max_row - 1} rows, expected {expected_rows}",
        )

        ranges = {str(dv.sqref) for dv in sheet.data_validations.dataValidation}
        check(
            ranges == {f"G2:G{expected_rows + 1}"},
            f"{sheet.title}: unexpected validation ranges {ranges}",
        )

        expected_sections = []
        for offset, req in enumerate(chapter["requirements"]):
            row = offset + 2
            if not expected_sections or expected_sections[-1][0] != req["section_id"]:
                expected_sections.append([req["section_id"], row, row])
            else:
                expected_sections[-1][2] = row
        expected_merges = {
            f"A{start}:A{end}" for _, start, end in expected_sections if end > start
        }
        check(
            {str(r) for r in sheet.merged_cells.ranges} == expected_merges,
            f"{sheet.title}: merged section ranges do not match the source data",
        )

        for offset, req in enumerate(chapter["requirements"]):
            row = offset + 2
            req_id = req["req_id"].lstrip("V")
            level = int(req["L"])
            check(
                sheet.cell(row=row, column=2).value == req_id,
                f"{sheet.title}!B{row}: expected id {req_id}",
            )
            check(
                sheet.cell(row=row, column=3).value == level,
                f"{sheet.title}!C{row}: expected level {level}",
            )
            colour = sheet.cell(row=row, column=3).fill.fgColor.rgb
            check(
                colour == LEVEL_FILLS[level].fgColor.rgb,
                f"{sheet.title}!C{row}: level {level} coloured {colour}",
            )
            check(
                sheet.cell(row=row, column=4).value == (cwe.get(req_id) or None),
                f"{sheet.title}!D{row}: CWE mismatch",
            )
            check(
                sheet.cell(row=row, column=5).value == (nist.get(req_id) or None),
                f"{sheet.title}!E{row}: NIST mismatch",
            )
            cwe_filled += 1 if sheet.cell(row=row, column=4).value else 0
            nist_filled += 1 if sheet.cell(row=row, column=5).value else 0

    check(total_requirements == 345, f"expected 345 requirements, found {total_requirements}")
    check(cwe_filled == len(cwe), f"CWE cells filled: {cwe_filled}, mapping has {len(cwe)}")
    check(nist_filled == len(nist), f"NIST cells filled: {nist_filled}, mapping has {len(nist)}")

    results = workbook[RESULTS_SHEET]
    check(
        results.max_row == len(chapters) + 2,
        f"results sheet has {results.max_row} rows, expected {len(chapters) + 2}",
    )
    check(len(results._charts) == 1, "results sheet should carry exactly one radar chart")

    print(f"  {total_requirements} requirements, {cwe_filled} CWE, {nist_filled} NIST references")
    if failures:
        print(f"\n{len(failures)} verification failure(s):")
        for failure in failures[:25]:
            print(f"  - {failure}")
        return 1
    print("  verification passed")
    return 0


# --------------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="check the generated workbook")
    parser.add_argument("--no-ods", action="store_true", help="skip the LibreOffice conversion")
    parser.add_argument("--refresh", action="store_true", help="re-download the ASVS sources")
    args = parser.parse_args()

    print(f"OWASP ASVS {ASVS_VERSION} ({ASVS_TAG})")
    paths = {name: fetch(name, args.refresh) for name in SOURCES}

    chapters = load_chapters(paths["requirements.json"])
    be_to_release = load_be_to_release(paths["be_to_release.yml"])
    cwe = load_cwe(paths["cwe.json"], be_to_release)
    nist = load_nist(paths["nist.md"], be_to_release)

    workbook = build_workbook(chapters, cwe, nist)
    workbook.save(XLSX_PATH)
    print(f"  wrote {XLSX_PATH.relative_to(REPO_ROOT)}")

    if not args.no_ods and convert_to_ods(XLSX_PATH, ODS_PATH):
        print(f"  wrote {ODS_PATH.relative_to(REPO_ROOT)}")

    if args.verify:
        return verify(chapters, cwe, nist)
    return 0


if __name__ == "__main__":
    sys.exit(main())
