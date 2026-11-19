import os

from playwright.sync_api import expect, sync_playwright

STATUS_COUNTS = {"PASS": 27, "FAIL": 18, "CANNOT_SCAN": 4}
FAILURES_BY_SEVERITY = {"CRITICAL": 7, "HIGH": 8, "MEDIUM": 2, "LOW": 1}
ACCOUNT_RESULTS = {
    "123456789012": (14, 10, 0, "58.3"),
    "210987654321": (2, 1, 4, "66.7"),
    "8f14e45f-ceea-4e7a-9d3b-2f6c1a0b7d21": (4, 3, 0, "57.1"),
    "example-corp-gcp": (7, 4, 0, "63.6"),
}


def verify_summary(container):
    expect(container.get_by_text("60.0", exact=True)).to_be_visible()
    for status, count in STATUS_COUNTS.items():
        summary = container.locator("dl > div").filter(
            has=container.page.get_by_text(status, exact=True)
        )
        expect(summary.get_by_text(str(count), exact=True)).to_be_visible()


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
        verify_summary(latest)
        latest.get_by_role("link", name="View findings").click()
        scan_id = page.url.rsplit("/", 1)[-1]
        base_url = page.url.split("#", 1)[0].rstrip("/")
        response = page.request.get(f"{base_url}/api/scans/{scan_id}")
        assert response.ok
        scan = response.json()
        assert scan["counts"] == STATUS_COUNTS
        assert scan["score"] == 60.0
        assert scan["fail_counts_by_severity"] == FAILURES_BY_SEVERITY
        verify_summary(page.locator("section").filter(
            has=page.get_by_role("heading", name="Scan results", exact=True)
        ))
        severities = page.get_by_label("Failures by severity")
        for severity, count in FAILURES_BY_SEVERITY.items():
            row = severities.locator("div").filter(has_text=severity)
            expect(row.get_by_text(f"{count} failed", exact=True)).to_be_visible()
        accounts = {account["account_id"]: account for account in scan["accounts"]}
        assert accounts.keys() == ACCOUNT_RESULTS.keys()
        for account_id, (passed, failed, unreadable, score) in ACCOUNT_RESULTS.items():
            assert accounts[account_id]["counts"] == {
                "PASS": passed, "FAIL": failed, "CANNOT_SCAN": unreadable,
            }
            assert accounts[account_id]["score"] == float(score)
            row = page.get_by_role("row").filter(has=page.get_by_role(
                "cell", name=account_id, exact=True
            ))
            account_summary = page.locator("section").filter(
                has=page.get_by_role("heading", name="Account scores", exact=True)
            )
            expect(account_summary.locator(row).get_by_role("cell")).to_have_text(
                [account_id, str(passed), str(failed), str(unreadable), score]
            )
        expect(page.get_by_role("heading", name="Findings", exact=True)).to_be_visible()
        resource = page.get_by_role("cell", name="example-corp-public-downloads")
        expect(resource).to_be_visible()
        for check_id in ("AWS-IAM-01", "AWS-IAM-02"):
            expect(page.get_by_text(check_id, exact=True).first).to_be_visible()
        pages = page.get_by_role("navigation", name="Findings pages")
        expect(pages.get_by_text("Page 1 of 2 · 49 findings")).to_be_visible()
        pages.get_by_role("button", name="Next").click()
        expect(pages.get_by_text("Page 2 of 2 · 49 findings")).to_be_visible()
        page.get_by_label("Status").select_option("FAIL", timeout=5000)
        page.get_by_label("Provider").select_option("gcp", timeout=5000)
        expect(pages.get_by_text("Page 1 of 1 · 4 findings")).to_be_visible()
        expect(page.get_by_role("cell", name="allow-rdp-anywhere global", exact=True)).to_be_visible()
        browser.close()


if __name__ == "__main__":
    main()
