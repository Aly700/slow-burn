"""Drain cancelled native generation before another job may use the model."""
import asyncio
import threading
import time


class GenerationCancelled(Exception):
    pass


def check_cancel(event):
    if event.is_set():
        raise GenerationCancelled('client disconnected or request cancelled')


async def complete(model, messages, max_tokens, deadline, cancel_event):
    check_cancel(cancel_event)
    args = (messages, max_tokens, deadline)
    if getattr(model, 'supports_cancellation', False):
        args += (cancel_event,)
    task = asyncio.create_task(asyncio.to_thread(model.complete, *args))
    try:
        result = await asyncio.wait_for(asyncio.shield(task), max(.01, deadline-time.monotonic()))
        check_cancel(cancel_event)
        return result
    except (asyncio.CancelledError, TimeoutError):
        cancel_event.set()
        # Cancellation cannot free the worker while a native kernel still owns it.
        await asyncio.shield(asyncio.gather(task, return_exceptions=True))
        raise
