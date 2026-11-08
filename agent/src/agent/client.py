from contextlib import AsyncExitStack
from datetime import timedelta
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import Settings


class ToolClient:
    def __init__(self, settings=None, fixture=None, prepare_live=False):
        self.settings = settings or Settings()
        self.fixture = fixture
        self.prepare_live = prepare_live
        self.stack = AsyncExitStack()

    async def __aenter__(self):
        env = dict(os.environ)
        env.update({"TRIAGE_ROOT": str(self.settings.root), "TRIAGE_STATE_DB": str(self.settings.state), "TRIAGE_TICKETS": str(self.settings.tickets), "TOKENIZERS_PARALLELISM": "false"})
        env["TRIAGE_SCORES"] = str(self.settings.scores)
        if self.prepare_live:
            env['TRIAGE_PREPARE_LIVE']='1'
        else:
            env.pop('TRIAGE_PREPARE_LIVE',None)
        if self.settings.snapshot_month:
            env["TRIAGE_SNAPSHOT_MONTH"] = self.settings.snapshot_month
        else:
            env.pop("TRIAGE_SNAPSHOT_MONTH", None)
        if self.fixture:
            env["TRIAGE_FIXTURE"] = self.fixture
        else:
            env.pop("TRIAGE_FIXTURE", None)
        transport = await self.stack.enter_async_context(stdio_client(StdioServerParameters(command=sys.executable, args=["-m", "agent.server"], env=env)))
        self.session = await self.stack.enter_async_context(ClientSession(*transport, read_timeout_seconds=timedelta(seconds=25)))
        await self.session.initialize()
        self.tools = (await self.session.list_tools()).tools
        return self

    async def __aexit__(self, *args):
        return await self.stack.__aexit__(*args)

    async def call(self, name, arguments):
        result = await self.session.call_tool(name, arguments)
        if result.isError:
            raise RuntimeError("; ".join(c.text for c in result.content if c.type == "text"))
        if result.structuredContent is not None:
            return result.structuredContent
        return json.loads(next(c.text for c in result.content if c.type == "text"))
