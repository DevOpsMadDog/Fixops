"""Agent prompt wrapper — auto-prepend persistent memory to specialist prompts.

When the CTO (Claude Code) dispatches a specialist agent (backend-hardener,
frontend-craftsman, qa-engineer, ...) we want the agent's prompt to start with
the top-K most semantically similar past tasks they completed, so the agent
doesn't redo analysis it already finished in a previous session.

This is the thin pure-Python helper that does that wrapping.

Usage
-----

    from tools.agent_memory_prompt_wrapper import (
        wrap_prompt,
        record_agent_outcome,
    )

    # Before dispatching:
    augmented = wrap_prompt(
        agent_id="backend-hardener",
        prompt="Fix IDOR in /admin/users endpoint, scope to org_id...",
    )
    # `augmented` now starts with a "## Persistent memory — past similar tasks"
    # block listing top-5 prior tasks, then the original prompt.

    # After the agent finishes (in the dispatcher / hook):
    record_agent_outcome(
        agent_id="backend-hardener",
        task_brief="Fix IDOR in /admin/users endpoint, scope to org_id...",
        outcome="success",
        summary="Added tenant scoping; tests pass.",
        findings=["IDOR via /admin/users?org_id=", "Missing role guard"],
        commit_sha="abc1234",
        files_touched=["suite-api/apps/api/admin_router.py"],
    )

Design principles
-----------------
- **Best effort, never blocks.** Memory failure → original prompt is returned
  unchanged. Specialist invocation is never harder because of this wrapper.
- **Bounded budget.** Hard cap on prompt-prefix length (~3 KB) so we don't
  blow the context window on retrieval.
- **Idempotent.** Calling ``wrap_prompt`` twice with the same prompt+agent
  produces the same output (modulo new memories landing between calls).
- **Token-conscious.** When recall returns 0 hits we add NO prefix at all
  (no "no past tasks" filler).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import List, Mapping, Optional, Sequence

# Make sure suite-core is on sys.path so this script works whether invoked from
# the repo root or imported as a package.
_ROOT = Path(__file__).resolve().parent.parent
for _sub in ("suite-core",):
    _p = _ROOT / _sub
    if _p.exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from core.agent_memory_bridge import (  # noqa: E402
    AgentTaskMemory,
    recall_for_agent,
    remember_for_agent,
)

logger = logging.getLogger(__name__)

__all__ = [
    "wrap_prompt",
    "record_agent_outcome",
    "format_memory_block",
    "DEFAULT_PREFIX_BUDGET_CHARS",
]

# ~3 KB ≈ 750 tokens for the memory prefix. Big enough for 5 high-quality past
# tasks; small enough not to crowd the actual prompt.
DEFAULT_PREFIX_BUDGET_CHARS = 3_000

# Top-K we ask for from AgentDB. Even if budget cuts to 3, we still want the
# best 5 candidates ranked by similarity in case the top picks are too long.
_DEFAULT_K = 5


def format_memory_block(
    memories: Sequence[AgentTaskMemory],
    *,
    budget_chars: int = DEFAULT_PREFIX_BUDGET_CHARS,
) -> str:
    """Render past memories as a bounded markdown prompt prefix.

    Returns an empty string when ``memories`` is empty so we don't pollute the
    prompt with a "no past tasks" stub.

    Args:
        memories: ranked list (descending similarity) from ``recall_for_agent``.
        budget_chars: hard cap on the rendered length. Past tasks are appended
            in order until adding the next one would exceed the budget.

    Returns:
        Markdown string starting with a ``## Persistent memory`` header, or
        empty string if there's nothing to render.
    """
    if not memories:
        return ""

    header = (
        "## Persistent memory — past similar tasks for this specialist\n"
        "(retrieved from AgentDB / .swarm/memory.db; "
        "use these to avoid re-doing analysis)\n\n"
    )
    parts: List[str] = [header]
    used = len(header)
    rendered = 0
    for i, mem in enumerate(memories, start=1):
        block = mem.render_for_prompt(index=i)
        block_with_sep = block + "\n\n"
        if used + len(block_with_sep) > budget_chars:
            # Cap reached — stop adding more, but keep what we already have.
            break
        parts.append(block_with_sep)
        used += len(block_with_sep)
        rendered += 1

    if rendered == 0:
        # First entry alone exceeded the budget — drop the header rather than
        # emit a header with nothing under it.
        return ""

    parts.append(
        f"--- end persistent memory ({rendered} of {len(memories)} past task(s)) ---\n\n"
    )
    return "".join(parts)


def wrap_prompt(
    *,
    agent_id: str,
    prompt: str,
    k: int = _DEFAULT_K,
    min_similarity: float = 0.15,
    budget_chars: int = DEFAULT_PREFIX_BUDGET_CHARS,
    cross_agent: bool = False,
) -> str:
    """Return ``prompt`` prefixed with the agent's top-K past similar tasks.

    On any failure (memory unavailable, recall errors, etc.) the original prompt
    is returned unchanged. This function MUST never raise.

    Args:
        agent_id: stable specialist id (e.g. ``"backend-hardener"``).
        prompt: the new task prompt that's about to be dispatched.
        k: how many past tasks to recall (default 5).
        min_similarity: cosine cutoff (default 0.15, weakly related and up).
        budget_chars: max length of the memory prefix block.
        cross_agent: if True, search across all specialist namespaces.

    Returns:
        Either ``prompt`` unchanged (no past tasks / memory disabled) or
        a string of the form::

            ## Persistent memory — past similar tasks for this specialist
            ...top-K snippets...
            --- end persistent memory ---

            <original prompt>
    """
    if not agent_id or not prompt:
        return prompt or ""

    try:
        past = recall_for_agent(
            agent_id=agent_id,
            task_brief=prompt,
            k=k,
            min_similarity=min_similarity,
            cross_agent=cross_agent,
        )
    except Exception as exc:  # noqa: BLE001 - safety net; recall is already wrapped
        logger.debug("wrap_prompt: recall failed (%s) — returning prompt as-is", exc)
        return prompt

    if not past:
        return prompt

    prefix = format_memory_block(past, budget_chars=budget_chars)
    if not prefix:
        return prompt
    return prefix + prompt


def record_agent_outcome(
    *,
    agent_id: str,
    task_brief: str,
    outcome: str,
    summary: str,
    findings: Optional[Sequence[str]] = None,
    commit_sha: Optional[str] = None,
    files_touched: Optional[Sequence[str]] = None,
    extra: Optional[Mapping[str, object]] = None,
) -> bool:
    """Persist a completed-task memory. Convenience wrapper around remember_for_agent.

    Returns True iff the memory landed in AgentDB.
    """
    try:
        return remember_for_agent(
            agent_id=agent_id,
            task_brief=task_brief,
            outcome=outcome,
            summary=summary,
            findings=findings,
            commit_sha=commit_sha,
            files_touched=files_touched,
            extra=extra,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_agent_outcome failed: %s", exc)
        return False
