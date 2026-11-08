"""A tiny JSON Schema checker (just the keywords spec/report.schema.json uses), stdlib only."""
import re

def _types(t):
    return t if isinstance(t, list) else [t]

def _is(v, t):
    if t == "null": return v is None
    if t == "boolean": return isinstance(v, bool)
    if t == "integer": return isinstance(v, int) and not isinstance(v, bool)
    if t == "string": return isinstance(v, str)
    if t == "array": return isinstance(v, list)
    if t == "object": return isinstance(v, dict)
    raise ValueError(t)

def validate(v, s, path="$"):
    """Return a list of error strings (empty = valid)."""
    errs = []
    if "const" in s and v != s["const"]: errs.append(f"{path}: not const {s['const']!r}")
    if "enum" in s and v not in s["enum"]: errs.append(f"{path}: {v!r} not in enum")
    if "oneOf" in s:
        ok = [not validate(v, sub, path) for sub in s["oneOf"]]
        if sum(ok) != 1: errs.append(f"{path}: matches {sum(ok)} of oneOf")
        return errs
    if "type" in s and not any(_is(v, t) for t in _types(s["type"])):
        return errs + [f"{path}: type {type(v).__name__} not {s['type']}"]
    if isinstance(v, str) and "pattern" in s and not re.search(s["pattern"], v): errs.append(f"{path}: {v!r} !~ {s['pattern']}")
    if isinstance(v, int) and not isinstance(v, bool) and "minimum" in s and v < s["minimum"]: errs.append(f"{path}: {v} < min")
    if isinstance(v, dict):
        for k in s.get("required", []):
            if k not in v: errs.append(f"{path}: missing {k}")
        props = s.get("properties", {})
        if s.get("additionalProperties") is False:
            for k in v:
                if k not in props: errs.append(f"{path}: unexpected {k}")
        for k, sub in props.items():
            if k in v: errs += validate(v[k], sub, f"{path}.{k}")
    if isinstance(v, list):
        if "minItems" in s and len(v) < s["minItems"]: errs.append(f"{path}: too short")
        if "maxItems" in s and len(v) > s["maxItems"]: errs.append(f"{path}: too long")
        if "items" in s:
            for i, x in enumerate(v): errs += validate(x, s["items"], f"{path}[{i}]")
    return errs
