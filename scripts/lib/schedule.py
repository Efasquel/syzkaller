#!/usr/bin/env python3
"""The scheduler, extracted as a pure function of (plan, state, observations).

Scheduling used to be the ~250-line `while True` in `cmd_run`, interleaved with
supervision, triage and halting, so the only way to test "what runs next" was to
drive the whole loop against a real box. That is why every scheduling decision
lives here instead, as small functions that take plain data and return a Step or
a string: they can be table-tested exhaustively, and the runner is left to
*execute* steps rather than choose them.

The split is deliberate:

  - `next_step` chooses what to do between items: run the one that is running,
    start or skip the first pending one, halt, or declare the campaign done.
  - `stop_reason` answers, for the item that is running, whether it should end
    now and why -- the question the supervisor asks on every poll.

There is no I/O in this module and it never mutates its inputs. The runner owns
`state.json` (one writer per file), so everything here reads the state the
runner passes and hands back a decision for the runner to apply and persist.
"""

from collections import namedtuple
from os.path import basename, splitext

# A scheduling decision. `kind` is one of "run", "end", "done", "halt"; `item`
# is the item id the decision concerns, or None when it concerns none ("done",
# "halt"); `reason` records why, so the runner can log it and map it to a status.
Step = namedtuple("Step", "kind item reason")


def _stem(config_path):
    """The config's bare name, which an item id is built from.

    'config/AppleFDEKeyStore_gram.cfg' -> 'AppleFDEKeyStore_gram'. Only the
    directory and the extension are stripped; '-' and '_' inside the stem are
    part of the name and are left alone, so the id splits unambiguously later at
    its one trailing '-<n>'.
    """
    return splitext(basename(config_path))[0]


def item_ids(configs):
    """Derive stable item ids from an ordered list of config paths.

    Each distinct config stem is numbered in the order it appears: the first
    time a stem is seen it is '<stem>-1', the next '<stem>-2', and so on. The
    suffix is always present, even for a stem listed once, so a single run of a
    config is 'AppleFDEKeyStore_gram-1' and the first sample's folder never
    repeats the bare config name. Running a config three times is listing it
    three times; this turns that list into three ids.

    Pure function of the list: the same list always yields the same ids.
    """
    seen = {}
    ids = []
    for config in configs:
        stem = _stem(config)
        seen[stem] = seen.get(stem, 0) + 1
        ids.append("{}-{}".format(stem, seen[stem]))
    return ids


def stop_reason(obs, requests, item_id):
    """Why the running item should end now, or None if it should keep running.

    Called by the supervisor on every poll, with `obs` a plain dict it fills
    from the item's live accounting. The conditions are checked in a fixed order
    so the reason recorded is the one that actually governs:

      1. an operator request outranks any budget, because the operator is
         reacting to something the budget cannot see. A pending {"verb": "next"}
         ends whatever is running ("next"); a {"verb": "skip", "item": item_id}
         that targets this item is the same as next, recorded as "skip".
      2. budget spent: obs["spent"] >= obs["budget"] -> "max_hours". Equality
         counts as exhausted -- the budget is a ceiling, not a strict bound.
      3. too many incidents: obs["incidents"] >= obs["max_incidents"] ->
         "max_crashes".
      4. a plateau, only when the plan opted in: obs["since_new_block"] has
         reached obs["plateau_seconds"] -> "plateau".

    `obs` carries whatever the caller measured. The plateau keys are optional --
    absent (or None) means the plan did not enable the plateau rule, so the
    check does not apply rather than firing on a missing value.
    """
    # An operator request wins over everything a budget could detect.
    for request in requests:
        verb = request.get("verb")
        if verb == "next":
            return "next"
        if verb == "skip" and request.get("item") == item_id:
            return "skip"

    if obs["spent"] >= obs["budget"]:
        return "max_hours"

    if obs["incidents"] >= obs["max_incidents"]:
        return "max_crashes"

    # Opt-in: both keys must be present and set for the plateau rule to apply.
    plateau = obs.get("plateau_seconds")
    since = obs.get("since_new_block")
    if plateau is not None and since is not None and since >= plateau:
        return "plateau"

    return None


def next_step(item_order, items, requests):
    """Choose what the runner does next, as a Step. Never mutates its inputs.

    `item_order` is the list of item ids in plan order; `items` maps each id to
    its state dict (with a "status" of pending/running/done/abandoned/skipped);
    `requests` is the ordered list of pending operator requests.

    The order of the checks is the policy:

      - a halt request stops this campaign regardless of what else is pending,
        so the box can move to the next campaign in the queue.
      - otherwise, if an item is already running, keep running it: the caller
        then asks stop_reason with that item's observations.
      - otherwise start the first pending item -- unless a skip request targets
        it, in which case end it as "skipped" without ever starting it.
      - with nothing pending, the campaign is done.
    """
    if any(request.get("verb") == "halt" for request in requests):
        return Step("halt", None, "halt by operator")

    for item_id in item_order:
        if items.get(item_id, {}).get("status") == "running":
            return Step("run", item_id, None)

    for item_id in item_order:
        if items.get(item_id, {}).get("status") == "pending":
            for request in requests:
                if request.get("verb") == "skip" and request.get("item") == item_id:
                    return Step("end", item_id, "skip")
            return Step("run", item_id, None)

    return Step("done", None, None)


def end_status(reason):
    """The item status an end reason maps to.

    A skip never ran as a sample, so it is 'skipped'. An item taken off the air
    for crashing too much is 'abandoned'. Everything else -- a spent budget, a
    plateau, an operator 'next' -- still produced a usable sample, so it is
    'done'; cutting a run short with 'next' does not make it a non-sample, and
    the reason stays visible in state.
    """
    if reason == "skip":
        return "skipped"
    if reason == "max_crashes":
        return "abandoned"
    return "done"


def requests_for(requests, item_id):
    """The subset of requests that concern one item.

    A request concerns the item when its "item" is that id, or when its verb is
    one that carries no item and so applies to whatever is running: "next" and
    "halt". The caller uses this to decide which pending requests to show or
    apply against a given item.
    """
    return [
        request
        for request in requests
        if request.get("verb") in ("next", "halt")
        or request.get("item") == item_id
    ]
