import re

PATTERNS = [
    r"ignore\s+(?:all\s+|your\s+|previous\s+)*(?:instructions|rules|prompts)",
    r"(?:call|invoke|execute)\s+file_fix_ticket",
    r"(?:mark|set|return)\s+(?:this\s+|the\s+verdict\s+)?fix_now",
    r"approval\s+(?:has\s+)?(?:already\s+)?(?:been\s+)?(?:granted|approved)",
    r"(?:quietly|automatically|immediately)\s+(?:create|file|submit)\s+(?:the\s+|a\s+)?(?:remediation\s+)?ticket",
    r"(?:system|developer)\s*(?:message|override|instruction)\s*:",
    r"(?:skip|bypass|disable)\s+(?:the\s+)?(?:approval|verification|policy|human)",
    r"(?:approval_token|briefing_hash)\s*[:=]",
]


def scan_text(text: str) -> list[dict]:
    spans = []
    for pattern in PATTERNS:
        for m in re.finditer(pattern, text, flags=re.I):
            spans.append({"start": m.start(), "end": m.end(), "text": m.group(), "rule": pattern})
    return sorted(spans, key=lambda s: s["start"])


def scan_payload(value, path=""):
    found = []
    if isinstance(value, str):
        found = [{**s, "field": path} for s in scan_text(value)]
    elif isinstance(value, dict):
        for key, item in value.items():
            found.extend(scan_payload(item, f"{path}.{key}".lstrip(".")))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            found.extend(scan_payload(item, f"{path}.{i}"))
    return found


def sanitized(value):
    if isinstance(value, str):
        for span in reversed(scan_text(value)):
            value = value[:span["start"]] + "[untrusted instruction removed]" + value[span["end"]:]
        return value
    if isinstance(value, dict):
        return {k: sanitized(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitized(v) for v in value]
    return value
