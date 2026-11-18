import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, StrictStr

from .checks import CHECKS
from .scanner import InventorySnapshot, Scanner
from .store import ScanStore

logger = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[2]


class ScanRequest(BaseModel):
    account_ids: Annotated[list[StrictStr], Field(min_length=1)] | None = None


def create_app(
    inventory_path: Path | None = None,
    db_path: Path | None = None,
    account_workers: int | None = None,
) -> FastAPI:
    inventory_path = inventory_path or Path(
        os.environ.get("INVENTORY_PATH", ROOT / "data" / "inventory.json")
    )
    store = ScanStore(db_path or Path(
        os.environ.get("DB_PATH", ROOT / "var" / "scanner.sqlite3")
    ))
    if account_workers is None:
        account_workers = int(os.environ.get("ACCOUNT_WORKERS", "4"))
    if account_workers < 1:
        raise ValueError("ACCOUNT_WORKERS must be positive.")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store.initialize()
        app.state.scanner = Scanner(account_workers)
        app.state.tasks = set()
        try:
            yield
        finally:
            pending = tuple(app.state.tasks)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    app = FastAPI(title="Mini Gauntlet", lifespan=lifespan)

    async def execute(scan: dict, snapshot: InventorySnapshot | None):
        try:
            if snapshot is None:
                store.fail(scan["id"], "Inventory snapshot could not be read.")
                return
            findings = await app.state.scanner.scan(snapshot, scan["account_ids"])
            store.complete(scan, findings)
        except Exception:
            logger.exception("Scan %s failed", scan["id"])
            store.fail(scan["id"], "Scan execution failed.")

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/checks")
    def checks():
        return [check.catalog_entry() for check in CHECKS]

    @app.post("/api/scans", status_code=202)
    async def start_scan(request: ScanRequest | None = None):
        selected = request.account_ids if request else None
        try:
            snapshot = await asyncio.to_thread(InventorySnapshot.read, inventory_path)
        except (OSError, ValueError):
            logger.exception("Inventory snapshot could not be read")
            if selected is not None:
                raise HTTPException(503, "Inventory snapshot could not be read.") from None
            snapshot = None
        account_ids = list(snapshot.accounts) if snapshot else []
        if selected is not None:
            if any(account_id not in account_ids for account_id in selected):
                raise HTTPException(422, "Unknown account ID.")
            account_ids = list(dict.fromkeys(selected))
        scan = store.start(account_ids)
        task = asyncio.create_task(execute(scan, snapshot))
        app.state.tasks.add(task)
        task.add_done_callback(app.state.tasks.discard)
        return scan

    @app.get("/api/scans")
    def list_scans():
        return store.list_scans()

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str):
        scan = store.get_scan(scan_id)
        if scan is None:
            raise HTTPException(404, "Scan not found.")
        return scan

    @app.get("/api/scans/{scan_id}/findings")
    def findings(
        scan_id: str,
        status: str | None = None,
        severity: str | None = None,
        provider: str | None = None,
        account_id: str | None = None,
        check_id: str | None = None,
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    ):
        result = store.findings(scan_id, {
            "status": status, "severity": severity, "provider": provider,
            "account_id": account_id, "check_id": check_id,
        }, page, page_size)
        if result is None:
            raise HTTPException(404, "Scan not found.")
        return result

    return app


app = create_app()
