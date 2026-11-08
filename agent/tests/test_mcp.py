import pytest
from test_data import corpus


@pytest.mark.asyncio
async def test_official_mcp_lists_tools_reads_and_refuses_write(corpus):
    from agent.client import ToolClient
    async with ToolClient(corpus) as client:
        tools = {t.name: t for t in client.tools}
        assert set(tools) == {'get_cve', 'explain_score', 'vendor_history', 'similar_exploited', 'signal_timeline', 'queue', 'file_fix_ticket', 'search_ranked', 'compare_cves', 'summarize_ranked'}
        assert all(t.annotations.readOnlyHint for n, t in tools.items() if n != 'file_fix_ticket')
        assert not tools['file_fix_ticket'].annotations.readOnlyHint
        row = await client.call('get_cve', {'cve_id': 'CVE-2025-1000'})
        assert row['signals']['epss'] == .1
        history = await client.call('vendor_history', {'vendor': 'Acme'})
        assert history['prior_kev'] == 1
        result = await client.call('file_fix_ticket', {'cve_id': 'CVE-2025-1000', 'briefing_hash': 'invented', 'approval_token': 'invented'})
        assert result['allowed'] is False
        assert not corpus.tickets.exists()
