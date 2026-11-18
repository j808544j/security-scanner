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
        expect(latest.get_by_text("40.0", exact=True)).to_be_visible()
        expect(latest.locator("dl > div").filter(has=page.get_by_text("PASS", exact=True))
               .get_by_text("2", exact=True)).to_be_visible()
        expect(latest.locator("dl > div").filter(has=page.get_by_text("FAIL", exact=True))
               .get_by_text("3", exact=True)).to_be_visible()
        latest.get_by_role("link", name="View findings").click()
        expect(page.get_by_role("heading", name="Findings", exact=True)).to_be_visible()
        expect(page.get_by_text("example-corp-public-downloads", exact=True)).to_be_visible()
        browser.close()


if __name__ == "__main__":
    main()
