from dataclasses import dataclass
import threading
import time

from .config import IBM_MODEL, MODEL, MODEL_REVISION


@dataclass
class Completion:
    text: str
    metrics: dict


class Granite:
    backend = 'mlx'
    supports_cancellation = True
    def __init__(self, name=MODEL):
        self.name = name
        self.source_name = IBM_MODEL if name == MODEL else name
        self.revision = MODEL_REVISION if name == MODEL else None
        self._model = None
        self._lock = threading.Lock()
        self.load_seconds = None
        self._lease = None

    def warmup(self):
        with self._lock:
            if self._model is None:
                from mlx_lm import load
                from huggingface_hub import snapshot_download
                from pathlib import Path
                import fcntl
                import tempfile
                self._lease = open(Path(tempfile.gettempdir())/'before-the-breach-granite.lock','a')
                try:
                    fcntl.flock(self._lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:
                    self._lease.close()
                    self._lease = None
                    raise RuntimeError('Granite is already loaded by another local process; stop it before starting a second copy.') from None
                start = time.monotonic()
                try:
                    path = self.name if Path(self.name).exists() else snapshot_download(self.name, revision=self.revision, local_files_only=True)
                    self._model, self._tokenizer = load(path)
                except BaseException:
                    self._lease.close()
                    self._lease = None
                    raise
                self.load_seconds = time.monotonic() - start

    def complete(self, messages, max_tokens, deadline, cancel_event=None):
        from mlx_lm import stream_generate
        from mlx_lm.sample_utils import make_sampler
        self.warmup()
        with self._lock:
            from .inference import check_cancel
            if cancel_event is not None: check_cancel(cancel_event)
            if time.monotonic() >= deadline:
                raise TimeoutError("model deadline exceeded")
            prompt = self._tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            parts, last = [], None
            for token in stream_generate(self._model, self._tokenizer, prompt=prompt, max_tokens=max_tokens,
                                         sampler=make_sampler(temp=0), prefill_step_size=512):
                if time.monotonic() >= deadline:
                    raise TimeoutError("model deadline exceeded")
                if cancel_event is not None: check_cancel(cancel_event)
                parts.append(token.text)
                last = token
            metrics = {"prompt_tokens": last.prompt_tokens, "generation_tokens": last.generation_tokens,
                       "prompt_tps": round(last.prompt_tps, 2), "generation_tps": round(last.generation_tps, 2),
                       "peak_memory_gb": round(last.peak_memory, 3)} if last else {}
            return Completion("".join(parts), metrics)


def create_model(settings):
    if settings.backend == 'mlx':
        return Granite(settings.model)
    if settings.backend == 'watsonx':
        import os
        from .budget import TokenBudget
        from .watsonx import Watsonx
        model = Watsonx()
        if os.getenv('SLOWBURN_BUDGET_COS_URL'):
            from .cos_budget import CosBudget
            model.budget = CosBudget(os.environ['SLOWBURN_BUDGET_COS_URL'], settings.daily_tokens,
                                     lambda: model._bearer(time.monotonic()+10))
        else:
            if settings.public and (os.getenv('CE_APP') or os.getenv('K_SERVICE')):
                raise ValueError('Code Engine public mode requires a durable COS token budget')
            model.budget = TokenBudget(settings.budget_path, settings.daily_tokens)
        return model
    raise ValueError('SLOWBURN_MODEL_BACKEND must be mlx or watsonx')
