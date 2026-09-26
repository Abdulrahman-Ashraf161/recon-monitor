"""Snapshot / diff engine (TASK-009).

Compare normalized snapshots target-safely:
    Current Scan -> Normalized Snapshot -> Previous Snapshot -> Diff
    -> Added / Removed / Changed / Unchanged (with old+new state).
"""
import hashlib
import json


def _canon(obj):
    return json.dumps(obj, sort_keys=True, default=str)


def state_hash(state: dict) -> str:
    return hashlib.sha256(_canon(state or {}).encode()).hexdigest()[:16]


def normalize_snapshot(items, key_fn, state_fn):
    """items: iterable; key_fn(item)->str key; state_fn(item)->dict state."""
    snap = {}
    for it in items:
        k = key_fn(it)
        snap[k] = {"state": state_fn(it), "hash": state_hash(state_fn(it))}
    return snap


def diff_snapshots(previous: dict, current: dict):
    """Both: {key: {state, hash}}. Returns dict with added/removed/changed/unchanged.

    changed entries include old_state/new_state/old_hash/new_hash.
    """
    added, removed, changed, unchanged = {}, {}, {}, {}
    for k, cur in current.items():
        prev = previous.get(k)
        if prev is None:
            added[k] = cur
        elif prev["hash"] != cur["hash"]:
            changed[k] = {
                "old_state": prev["state"], "new_state": cur["state"],
                "old_hash": prev["hash"], "new_hash": cur["hash"],
            }
        else:
            unchanged[k] = cur
    for k, prev in previous.items():
        if k not in current:
            removed[k] = prev
    return {"added": added, "removed": removed, "changed": changed, "unchanged": unchanged}
