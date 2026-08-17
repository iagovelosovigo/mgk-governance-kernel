"""Browser acceptance for the MGK v0.3.0 runtime web UI (playwright, headless).

Captures screenshots and verifies each page renders. Run with the framework
Python that has playwright + chromium installed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8812"
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/tmp/mgk-browser-shots")
OUT.mkdir(parents=True, exist_ok=True)

PAGES = [
    ("index", "/", "MGK Governance Runtime"),
    ("propose", "/propose", "Submit a proposal"),
    ("human_gate", "/human-gate", None),
    ("flight_recorder", "/flight-recorder", "Flight recorder"),
    ("evidence", "/evidence", "Evidence"),
]

results = []


def main() -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 1000})
        for name, path, expected in PAGES:
            page.goto(f"{BASE}{path}")
            page.wait_for_load_state("networkidle")
            title = page.title()
            shot = OUT / f"{name}.png"
            page.screenshot(path=str(shot), full_page=True)
            ok = expected is None or expected in page.content()
            results.append({"page": name, "path": path, "title": title, "ok": ok, "shot": str(shot)})
            print(f"{name}: ok={ok} title={title!r} -> {shot}")

        # interactive: submit a write proposal, confirm REQUIRE_HUMAN result, approve
        page.goto(f"{BASE}/propose")
        page.wait_for_load_state("networkidle")
        page.select_option("select[name='action']", "sandbox.write_file")
        page.fill("input[name='request_id']", "browser-write")
        page.fill("input[name='resource']", "files/browser.txt")
        page.fill("textarea[name='parameters']", '{"content_b64": "YnJvd3Nlci1oZWxsbw"}')
        page.click("button[type='submit']")
        page.wait_for_timeout(800)
        result_text = page.inner_text("#result")
        shot = OUT / "propose_result_require_human.png"
        page.screenshot(path=str(shot), full_page=True)
        print("propose-result:", result_text[:200])
        ok = '"REQUIRE_HUMAN"' in result_text
        results.append({"page": "propose_result", "ok": ok, "shot": str(shot), "result": result_text})

        page.goto(f"{BASE}/human-gate")
        page.wait_for_load_state("networkidle")
        shot = OUT / "human_gate_pending.png"
        page.screenshot(path=str(shot), full_page=True)
        has_pending = "browser-write" in page.content()
        results.append({"page": "human_gate_pending", "ok": has_pending, "shot": str(shot)})
        print("human-gate has pending:", has_pending)

        browser.close()

    (OUT / "browser_acceptance.json").write_text(json.dumps(results, indent=2))
    all_ok = all(r["ok"] for r in results)
    print("all ok:", all_ok)
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())