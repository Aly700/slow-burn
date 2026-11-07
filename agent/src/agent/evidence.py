import json
from copy import deepcopy


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def resolve(output, field):
    node = output
    for part in field.split("."):
        if isinstance(node, list):
            if not part.isdigit():
                raise KeyError(field)
            node = node[int(part)]
        elif isinstance(node, dict):
            node = node[part]
        else:
            raise KeyError(field)
    return node


def verify(claims, calls):
    kept, dropped = [], []
    for claim in claims:
        valid = bool(claim.get("evidence"))
        for ref in claim.get("evidence", []):
            match = False
            for call in calls:
                if call["tool"] != ref.get("tool") or (ref.get("call_id") and call.get("call_id") != ref["call_id"]):
                    continue
                try:
                    actual = resolve(call["output"], ref["field"])
                    match |= canonical(actual) == canonical(ref["value"])
                except (KeyError, IndexError, ValueError, TypeError):
                    pass
            valid &= match
        if valid:
            kept.append({**claim, "verified": True})
        else:
            dropped.append({"id": claim.get("id", "unknown"), "why": "evidence does not resolve to the same tool, field, type and value in this run"})
    return kept, {"claims_total": len(claims), "claims_verified": len(kept), "dropped": dropped}


def render_selection(ids, cards):
    by_id = {c["id"]: c for c in cards}
    selected, dropped, seen = [], [], set()
    for key in ids:
        if key not in by_id or key in seen:
            dropped.append({"id": key, "why": "unknown or repeated evidence card"})
            continue
        seen.add(key)
        selected.append(deepcopy(by_id[key]))
    return selected, dropped
