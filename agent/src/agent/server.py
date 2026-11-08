"""Official MCP stdio server: six reads and one capability-gated local write."""
import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .config import Settings
from .data import DataTools, validate_cve
from .store import Store


def make_server(settings=None):
    settings = settings or Settings()
    server = FastMCP("fix-first-triage", instructions="Read-only investigation tools. Call get_cve first to establish the snapshot. Ticket creation requires a backend-issued approval capability.")
    data = None

    def source():
        nonlocal data
        if data is None:
            data = DataTools(settings)
        return data

    read = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)

    @server.tool(annotations=read)
    def get_cve(cve_id: str, fixture: str | None = None) -> dict:
        """Read description, CVSS parts, CWE names and month-end signals. Establish this session's snapshot for vendor_history."""
        row = source().get_cve(cve_id)
        fixture = fixture or os.getenv("TRIAGE_FIXTURE")
        if fixture:
            fixtures = json.loads((Path(__file__).resolve().parents[2] / "evals/injections.json").read_text())
            attack = next((f for f in fixtures if f["id"] == fixture), None)
            if attack is None:
                raise ValueError("unknown injection fixture")
            row["description"] = attack["description"]
            row["fixture"] = attack["id"]
        return row

    @server.tool(annotations=read)
    def explain_score(cve_id: str) -> dict:
        """Read ranking and unmodified reasons from the ranking pipeline's score file; flag invalid seed probabilities."""
        return source().explain_score(cve_id)

    @server.tool(annotations=read)
    def vendor_history(vendor: str) -> dict:
        """Read KEV counts through the active CVE snapshot, capped at 2025-12-31. Exact normalized vendor matching."""
        return source().vendor_history(vendor)

    @server.tool(annotations=read)
    def similar_exploited(cve_id: str, k: int = 3) -> dict:
        """Read nearest earlier KEV descriptions using IBM Granite embeddings. Similarity is not evidence of exploitation."""
        return source().similar_exploited(cve_id, k)

    @server.tool(annotations=read)
    def signal_timeline(cve_id: str) -> dict:
        """Read available EPSS and exploit flags up to the snapshot; preserve missing months and the March 2025 EPSS break."""
        return source().signal_timeline(cve_id)

    @server.tool(annotations=read)
    def queue(n: int = 15, filters: dict | None = None) -> dict:
        """Read up to 100 ranked candidates. Filters: snapshot_month, any_exploit, min_epss."""
        return source().queue(n, filters)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False))
    def file_fix_ticket(cve_id: str, briefing_hash: str, approval_token: str) -> dict:
        """Append a local ticket only with an unexpired backend-issued capability for this exact CVE and immutable briefing hash."""
        validate_cve(cve_id)
        store = Store(settings.state, settings.tickets)
        try:
            ticket = store.file_ticket(cve_id, briefing_hash, approval_token)
            return {"allowed": True, "ticket_id": ticket["ticket_id"], "idempotency_key": ticket["idempotency_key"], "destination": ticket["destination"]}
        except PermissionError as exc:
            return {"allowed": False, "reason": str(exc)}

    if os.getenv('TRIAGE_PREPARE_LIVE') == '1':
        from .embeddings import EmbeddingIndex
        EmbeddingIndex.build(settings, source())
        source().index = EmbeddingIndex(settings, source())
        source().index._model = EmbeddingIndex.encoder()
    return server


def main():
    make_server().run(transport="stdio")


if __name__ == "__main__":
    main()
