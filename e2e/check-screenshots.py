#!/usr/bin/env python3
"""Reject screenshots that would look wrong in the README.

`capture.mjs` checks the page as it captured it; this checks the file that
landed on disk, which is the thing a reader actually sees. The two catch
different failures: a screenshot can be written correctly and still be a
blank rectangle because the page painted after the capture, or be so tall and
sparse that it reads as broken.

Run through `just screenshot-check`. Exits non-zero if any image fails, so it
can gate a documentation change.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    from PIL import Image, ImageChops
except ImportError:  # pragma: no cover - the message is the point
    print(
        "check-screenshots needs Pillow: `pip install pillow`",
        file=sys.stderr,
    )
    raise SystemExit(1)

SHOTS = Path(__file__).resolve().parents[1] / "docs" / "screenshots"

# A page has to have something on it. These are deliberately loose: the point
# is to catch a blank or all-white rectangle, not to police a design.
MIN_DISTINCT_COLOURS = 40
MIN_BYTES = 12_000


def inspect(path: Path) -> list[str]:
    problems: list[str] = []
    if path.stat().st_size < MIN_BYTES:
        problems.append("tiny")

    with Image.open(path) as im:
        im = im.convert("RGB")
        width, height = im.size
        if width < 600 or height < 300:
            problems.append(f"small({width}x{height})")

        # The background is whatever colour the top-left pixel is. Pixels that
        # differ from it are content, and their bounding box describes the
        # layout without assuming where on the page it sits — a 404 is a few
        # lines near the top, a login form is a card in the middle, and both
        # are correct.
        background = im.getpixel((0, 0))
        mask = ImageChops.difference(im, Image.new("RGB", im.size, background)).convert("L")
        box = mask.point(lambda v: 255 if v > 18 else 0).getbbox()

        if box is None:
            problems.append("blank")
        else:
            box_w, box_h = box[2] - box[0], box[3] - box[1]
            # Below this, the page rendered a stray pixel or a rule and not a
            # layout. The units are real pixels of the capture.
            if box_w < 120 or box_h < 40:
                problems.append(f"no-layout({box_w}x{box_h})")

        small = im.resize((width // 4 or 1, height // 4 or 1))
        colours = len(set(small.get_flattened_data()))
        if colours < MIN_DISTINCT_COLOURS:
            problems.append(f"flat({colours})")
        if _is_all_white(im):
            problems.append("white")

    return problems


def _is_all_white(im: Image.Image) -> bool:
    small = im.resize((64, 64)).convert("RGB")
    return all(min(p) > 250 for p in small.get_flattened_data())


def main() -> int:
    report_path = SHOTS / "report.json"
    if not report_path.exists():
        print(f"no {report_path}; run `just screenshots` first", file=sys.stderr)
        return 1

    try:
        entries = json.loads(report_path.read_text())
    except json.JSONDecodeError as error:
        print(f"{report_path} is not valid JSON: {error}", file=sys.stderr)
        return 1

    captured = {entry["name"] for entry in entries}
    images = sorted(p for p in SHOTS.glob("*.png"))
    names_on_disk = {p.stem for p in images}
    if not images:
        print(f"no PNGs in {SHOTS}", file=sys.stderr)
        return 1

    failures = 0
    for path in images:
        problems = inspect(path)
        # A PNG with no entry in the report was not produced by this run, so it
        # is either stale or added by hand. Both are worth knowing about.
        if path.stem not in captured:
            problems.append("not-in-report")
        status = "FAIL" if problems else "ok  "
        failures += bool(problems)
        print(f"{status} {path.name:32} {', '.join(problems) or 'looks fine'}")

    # The other direction: the report is the record of what the capture saw,
    # and it is committed alongside the images. An entry that recorded a
    # problem, answered with the wrong status, or names a file with no PNG is
    # the same failure as a blank image — the capture said so and the report
    # was committed anyway. Checking only PNG-against-name would let an entry
    # with `problems` ride through unnoticed.
    for entry in entries:
        name = entry.get("name", "<unnamed>")
        problems = list(entry.get("problems") or [])
        expected = entry.get("expectedStatus")
        actual = entry.get("status")
        if expected is not None and actual != expected:
            problems.append(f"status({actual} != {expected})")
        if entry.get("settleError"):
            problems.append("state-not-reached")
        if name not in names_on_disk:
            problems.append("no-image")
        if problems:
            print(f"FAIL report entry {name}: {', '.join(problems)}")
            failures += 1

    referenced = _readme_references(SHOTS)
    orphans = sorted({p.name for p in images} - referenced)
    missing = sorted(referenced - {p.name for p in images})
    if orphans:
        print(f"FAIL not referenced by README: {', '.join(orphans)}")
        failures += 1
    if missing:
        print(f"FAIL referenced by README but absent: {', '.join(missing)}")
        failures += 1

    print(
        f"\n{len(images)} images, {len(entries)} report entries, "
        f"{len(referenced)} shown in README, {failures} with problems"
    )
    return 1 if failures else 0


def _readme_references(shots: Path) -> set[str]:
    """The screenshot files README.md links to, by name.

    A screenshot nobody shows is dead weight, and one the README points at but
    that does not exist is a broken image — both are documentation bugs that
    nothing else here would catch.
    """
    readme = shots.parent.parent / "README.md"
    if not readme.exists():
        return set()
    return {
        Path(match).name
        for match in re.findall(r"docs/screenshots/([\w.-]+\.png)", readme.read_text())
    }


if __name__ == "__main__":
    sys.exit(main())
