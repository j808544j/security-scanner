import os

from playwright.sync_api import expect, sync_playwright


def main():
    with sync_playwright() as playwright:
        options = {}
        if executable := os.environ.get("BROWSER_EXECUTABLE"):
            options["executable_path"] = executable
        browser = playwright.chromium.launch(**options)
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        page.goto(os.environ.get("DASHBOARD_URL", "http://localhost:3000"))
        page.get_by_role("button", name="Run scan").click()
        latest = page.get_by_role("region", name="Latest scan")
        expect(latest.get_by_text("RUNNING", exact=True)).to_be_visible()
        expect(latest.get_by_text("COMPLETED", exact=True)).to_be_visible(timeout=12_000)
        expect(latest.get_by_text("64.7", exact=True)).to_be_visible()
        for status, count in (("PASS", "11"), ("FAIL", "6"), ("CANNOT_SCAN", "2")):
            summary = latest.locator("dl > div").filter(has=page.get_by_text(status, exact=True))
            expect(summary.get_by_text(count, exact=True)).to_be_visible()
        latest.get_by_role("link", name="View findings").click()
        expect(page.get_by_role("heading", name="Findings", exact=True)).to_be_visible()
        resource = page.get_by_role("cell", name="example-corp-public-downloads")
        expect(resource).to_be_visible()
        for check_id in ("AWS-IAM-01", "AWS-IAM-02"):
            expect(page.get_by_text(check_id, exact=True).first).to_be_visible()
        expect(page.get_by_role("navigation", name="Findings pages")
               .get_by_text("19 findings")).to_be_visible()
        browser.close()


if __name__ == "__main__":
    main()
