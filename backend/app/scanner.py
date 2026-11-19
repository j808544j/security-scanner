import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .checks import CHECKS, required_string

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class InventorySnapshot:
    taken_at: str
    accounts: dict[str, dict]

    @classmethod
    def read(cls, path: Path) -> "InventorySnapshot":
        snapshot = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("accounts"), list):
            raise ValueError("Inventory snapshot must include an accounts list.")
        taken_at = snapshot.get("snapshot_taken_at")
        if not isinstance(taken_at, str) or datetime.fromisoformat(
            taken_at.replace("Z", "+00:00")
        ).tzinfo is None:
            raise ValueError("Inventory snapshot must include a timestamp with a time zone.")
        accounts = {}
        for account in snapshot["accounts"]:
            if not isinstance(account, dict):
                raise ValueError("Account must be an object.")
            account_id = account.get("account_id")
            if not isinstance(account_id, str) or not account_id or account_id in accounts:
                raise ValueError("Each account must have a unique, nonempty account_id.")
            if account.get("provider") not in ("aws", "azure", "gcp"):
                raise ValueError("Account provider is invalid.")
            latency = account.get("simulated_latency_ms")
            if type(latency) is not int or latency < 0:
                raise ValueError("Account simulated_latency_ms must be a nonnegative integer.")
            accounts[account_id] = account
        return cls(taken_at, accounts)


class Scanner:
    def __init__(self, account_workers: int):
        self.slots = asyncio.Semaphore(account_workers)

    async def scan(self, snapshot: InventorySnapshot, account_ids: list[str]) -> list[dict]:
        results = await asyncio.gather(*(
            self.scan_account(snapshot.accounts[account_id], snapshot.taken_at)
            for account_id in account_ids
        ))
        return [finding for account_findings in results for finding in account_findings]

    async def scan_account(self, account: dict, taken_at: str) -> list[dict]:
        async with self.slots:
            await asyncio.sleep(account["simulated_latency_ms"] / 1000)
            findings = []
            for check in CHECKS:
                if check.provider != account["provider"]:
                    continue
                errors = account.get("errors", {})
                resources = account.get("resources", {})
                if isinstance(errors, dict) and check.collection in errors:
                    try:
                        error = required_string(
                            errors[check.collection], f"{check.collection} collection error code"
                        )
                    except ValueError as exc:
                        error = str(exc)
                        logger.warning("Malformed collection error for check %s: %s", check.id, error)
                    results = [check.finding("CANNOT_SCAN", f"Collection read failed: {error}")]
                elif not isinstance(errors, dict) or not isinstance(resources, dict):
                    logger.warning("Malformed collection maps for check %s", check.id)
                    results = [check.finding("CANNOT_SCAN", "Invalid account collection maps.")]
                elif isinstance(records := resources.get(check.collection, []), list):
                    results = [check.evaluate(record, taken_at) for record in records]
                else:
                    logger.warning("Malformed collection for check %s", check.id)
                    results = [check.finding("CANNOT_SCAN", "Collection must be a list.")]
                findings.extend(
                    {**finding, "account_id": account["account_id"]} for finding in results
                )
            return findings
