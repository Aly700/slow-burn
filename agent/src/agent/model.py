from dataclasses import dataclass
import threading
import time

from .config import IBM_MODEL, MODEL, MODEL_REVISION


@dataclass
class Completion:
    text: str
    metrics: dict


class Granite:
    def __init__(self, name=MODEL):
        self.name = name
        self.source_name = IBM_MODEL if name == MODEL else name
        self.revision = MODEL_REVISION if name == MODEL else None
        self._model = None
        self._lock = threading.Lock()
        self.load_seconds = None

    def warmup(self):
        with self._lock:
            if self._model is None:
                from mlx_lm import load
                start = time.monotonic()
                self._model, self._tokenizer = load(self.name, revision=self.revision)
                self.load_seconds = time.monotonic() - start

    def complete(self, messages, max_tokens, deadline):
        from mlx_lm import stream_generate
        from mlx_lm.sample_utils import make_sampler
        self.warmup()
        with self._lock:
            if time.monotonic() >= deadline:
                raise TimeoutError("model deadline exceeded")
            prompt = self._tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            parts, last = [], None
            for token in stream_generate(self._model, self._tokenizer, prompt=prompt, max_tokens=max_tokens,
                                         sampler=make_sampler(temp=0), prefill_step_size=512):
                if time.monotonic() >= deadline:
                    raise TimeoutError("model deadline exceeded")
                parts.append(token.text)
                last = token
            metrics = {"prompt_tokens": last.prompt_tokens, "generation_tokens": last.generation_tokens,
                       "prompt_tps": round(last.prompt_tps, 2), "generation_tps": round(last.generation_tps, 2),
                       "peak_memory_gb": round(last.peak_memory, 3)} if last else {}
            return Completion("".join(parts), metrics)
