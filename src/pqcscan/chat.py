"""Answer plain-language questions from a scan already on the dashboard.

Replies are assembled from that inventory. This is not a live model, and it
does not decide that a system is quantum-safe.
"""

from __future__ import annotations


def answer_question(analysis: dict | None, question: str) -> str:
    if not analysis:
        return "Scan a folder first. Then ask about the colors, a practice, or what to update."
    text = " ".join(question.lower().split())
    if not text:
        return "Type a question about this scan."

    parts: list[str] = []
    if _safety_question(text):
        parts.append(_safety_answer())
    named = _mentioned(analysis, text)
    files = _mentioned_files(analysis, text)
    if named:
        parts.append(_explain_named(named, analysis))
        if "safe" in text and not _safety_question(text):
            parts.append("That note is not a quantum-safety result.")
    elif files and not _safety_question(text):
        parts.append(_explain_files(files))
    elif _color_question(text) or (not named and "safe" in text and not _safety_question(text)):
        if "safe" in text and not _color_question(text):
            parts.append(_safety_answer())
        else:
            parts.append(_color_answer())
    elif _first_question(text):
        parts.append(_first_answer(analysis))
    elif _hidden_question(text):
        parts.append(_hidden_answer(analysis))
    elif _risk_question(text):
        parts.append(_risk_answer(analysis))
    elif _limit_question(text):
        parts.append(_limit_answer(analysis))
    elif _summary_question(text) or _greeting(text):
        parts.append(_summary_answer(analysis))
    if not parts:
        parts.append(_fallback(analysis))
    reply = " ".join(parts)
    if "quantum-safe" in reply.lower() and "not" not in reply.lower():
        reply += " This reply does not prove the system is quantum-safe."
    return reply


def _safety_question(text: str) -> bool:
    markers = ("quantum", "certified", "compliant", "attest", "proof", "prove")
    return any(marker in text for marker in markers)


def _safety_answer() -> str:
    return (
        "No. This scan does not prove the system is quantum-safe, and a clean result is not a quantum-safety attestation. "
        "It only lists cryptography the files still use. "
        "Red items are already obsolete on ordinary computers. "
        "Orange items, especially RSA and elliptic curves, need a migration plan because they rely on public-key math a future quantum computer would threaten."
    )


def _color_question(text: str) -> bool:
    return any(word in text for word in ("color", "colour", "legend", "what is red", "what is orange", "what is green", "what is blue", "what is purple")) or (
        any(word in text.split() for word in ("red", "orange", "green", "blue", "purple")) and "mean" in text
    )


def _color_answer() -> str:
    return (
        "Red means retire it now. Orange means plan a migration. "
        "Green means keep it and give it an owner. "
        "Blue means the scan only saw a library or a name, not a working post-quantum deployment. "
        "Purple means a comment, not confirmed use. Do not schedule work from a purple row."
    )


def _first_question(text: str) -> bool:
    return any(word in text for word in ("first", "retire", "urgent", "fix", "update", "priority", "start", "obsolete", "behind"))


def _first_answer(analysis: dict) -> str:
    urgent = _group_items(analysis, "urgent")
    if not urgent:
        return "No obsolete practice was confirmed in this folder. Still give each remaining item an owner. That is not a quantum-safety result."
    names = ", ".join(item["name"] for item in urgent[:6])
    extra = len(urgent) - min(len(urgent), 6)
    more = f", plus {extra} more" if extra else ""
    step = ""
    for update in analysis.get("updates", []):
        if update.get("concern") == "urgent":
            step = f" The first suggested change is {update['title']}: {update['action']}"
            break
    return (
        f"Retire the red group first. This folder has {len(urgent)} of those practices, including {names}{more}. "
        f"Replacing them does not make the system post-quantum.{step}"
    )


def _hidden_question(text: str) -> bool:
    return any(word in text for word in ("hidden", "wrapper", "easy to miss", "indirect", "calls"))


def _hidden_answer(analysis: dict) -> str:
    hidden = analysis.get("hidden") or []
    if not hidden:
        return "No wrapper-only use was found. Every confirmed practice is named in the file that uses it."
    sample = hidden[0]
    return (
        f"Some files never name the algorithm. They call a file that does. "
        f"For example, {sample['caller']} reaches {sample['mechanism']} through {sample['origin']}. "
        f"There are {len(hidden)} of these links on the Easy to miss list."
    )


def _risk_question(text: str) -> bool:
    return any(word in text for word in ("break", "risk", "compat", "peer", "downgrade"))


def _risk_answer(analysis: dict) -> str:
    risks = analysis.get("risks") or []
    if not risks:
        return "The scan did not attach a compatibility note. Still test the oldest client you support before changing a protocol or a token format."
    return "Changing an algorithm can break peers. " + " ".join(risks[:3])


def _limit_question(text: str) -> bool:
    return any(word in text for word in ("limit", "cannot", "can't", "hsm", "runtime", "out of scope"))


def _limit_answer(analysis: dict) -> str:
    limits = analysis.get("limitations") or []
    if not limits:
        return "The scan reads files. It does not run the program, and it does not see HSMs or cloud consoles."
    return " ".join(limits[:3])


def _summary_question(text: str) -> bool:
    return any(word in text for word in ("summary", "overview", "what did", "what is this", "how many", "headline", "explain"))


def _greeting(text: str) -> bool:
    return text.strip(" ?.!") in {"hi", "hello", "hey", "help"}


def _summary_answer(analysis: dict) -> str:
    counts = analysis.get("counts") or {}
    return (
        f"{analysis.get('headline', 'The scan finished.')} "
        f"It read {analysis.get('files_scanned', 0)} files. "
        f"Red practices: {counts.get('retire', 0)}. Orange practices: {counts.get('plan', 0)}. "
        f"Green practices: {counts.get('keep', 0)}. Purple comments: {counts.get('uncertain', 0)}. "
        "Ask about a name, such as MD5 or RSA, if you want the files and the suggested change."
    )


def _group_items(analysis: dict, key: str) -> list[dict]:
    for group in analysis.get("standards") or []:
        if group.get("key") == key:
            return list(group.get("items") or [])
    return []


def _catalog(analysis: dict) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for group in analysis.get("standards") or []:
        for item in group.get("items") or []:
            name = str(item.get("name", ""))
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            rows.append(
                {
                    "name": name,
                    "plain": item.get("plain", ""),
                    "where": item.get("where", ""),
                    "locations": item.get("locations") or [],
                    "key": group.get("key", ""),
                    "title": group.get("title", ""),
                }
            )
    for finding in analysis.get("findings") or []:
        if finding.get("confidence") == "confirmed":
            continue
        name = str(finding.get("name", ""))
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        rows.append(
            {
                "name": name,
                "plain": finding.get("plain", ""),
                "where": finding.get("where", ""),
                "key": "uncertain",
                "title": "Comment, not confirmed",
            }
        )
    return rows


def _mentioned(analysis: dict, question: str) -> list[dict]:
    ranked = sorted(_catalog(analysis), key=lambda item: len(item["name"]), reverse=True)
    kept: list[dict] = []
    spans: list[tuple[int, int]] = []
    for item in ranked:
        name = item["name"].lower()
        if len(name) < 2:
            continue
        start = question.find(name)
        if start < 0:
            continue
        span = (start, start + len(name))
        if any(span[0] >= begin and span[1] <= end for begin, end in spans):
            continue
        spans.append(span)
        kept.append(item)
        if len(kept) == 3:
            break
    return kept


def _explain_named(named: list[dict], analysis: dict) -> str:
    sentences = []
    updates = {str(item.get("title", "")).lower(): item for item in analysis.get("updates") or []}
    for item in named:
        where = item["where"] or "the inventory"
        line = ""
        locations = item.get("locations") or []
        if locations and locations[0].get("snippet"):
            spot = locations[0]
            place = f"{spot['path']}:{spot['line']}" if spot.get("line") else spot.get("path", where)
            line = f" One line is {place}: {spot['snippet']}"
        sentences.append(f"{item['name']} is in the {item['title'].lower()} group. {item['plain']} It showed up at {where}.{line}")
        update = updates.get(item["name"].lower())
        if update and update.get("action"):
            sentences.append(f"Suggested change: {update['action']}")
    return " ".join(sentences)


def _mentioned_files(analysis: dict, question: str) -> list[dict]:
    hits = []
    seen: set[str] = set()
    for finding in analysis.get("findings") or []:
        where = str(finding.get("where", ""))
        base = where.split(":")[0].replace("\\", "/").split("/")[-1].lower()
        if len(base) < 3 or base not in question or base in seen:
            continue
        seen.add(base)
        hits.append(finding)
        if len(hits) == 4:
            break
    return hits


def _explain_files(findings: list[dict]) -> str:
    lines = []
    for finding in findings:
        lines.append(f"{finding['where']} shows {finding['name']}. {finding['plain']}")
    return " ".join(lines)


def _fallback(analysis: dict) -> str:
    headline = analysis.get("headline") or "The scan finished."
    return (
        f"{headline} I can explain the colors, what to retire first, a practice by name, a file name, or what this scan does not prove. "
        "This reply does not prove the system is quantum-safe."
    )
