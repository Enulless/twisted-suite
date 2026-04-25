"""Convert the three procedure .docx manuals into per-step markdown
lessons under ``src/twisted/training/lessons/``.

Strategy: rather than relying on the docx heading hierarchy (which
varies per document and shifts as the manual gets edited), we walk
each docx into a flat list of *sections* keyed by heading text, then
for every step in the procedure YAML we find the best-matching docx
section by name similarity. The matched section's body becomes the
lesson; un-matched steps still get a placeholder lesson with the
procedure-level intro so the dashboard never shows a blank page.

Output layout::

    src/twisted/training/lessons/<procedure>/<stage>/<step_slug>.md

Each file gets YAML frontmatter (step_id / procedure / stage / title)
and ``## What`` / ``## Why`` / ``## How`` sections derived from any
H3 children of the matched section, plus the section body if no H3
breakdown is present.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path

try:
    from docx import Document
except ImportError as e:  # pragma: no cover - hard dep, just clearer error
    raise ImportError(
        "python-docx is required for the lesson extractor. "
        "Run: pip install -e '.[dev]'"
    ) from e

from ..core.procedures import ProcedureLoader, Step

# ──────────────────────────── Generic docx parsing ────────────────────────────


@dataclass
class DocxSection:
    """One heading + all paragraphs below it until the next heading of
    the same level or shallower. Children are deeper-level headings
    that also fall under this section."""
    level: int
    title: str
    body_paragraphs: list[str] = field(default_factory=list)
    children: list[DocxSection] = field(default_factory=list)
    parent: DocxSection | None = None

    @property
    def body_md(self) -> str:
        return "\n\n".join(p for p in self.body_paragraphs if p.strip()).strip()

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()


_HEADING_STYLE_RE = re.compile(r"^Heading (\d+)$")


def parse_docx(path: Path | str) -> DocxSection:
    """Parse a .docx into a tree of ``DocxSection``s.

    The root section has ``level=0`` and ``title=document title``.
    Body paragraphs that appear before any heading are attached to
    the root.
    """
    doc = Document(str(path))
    root = DocxSection(level=0, title=Path(path).stem)
    stack: list[DocxSection] = [root]
    for p in doc.paragraphs:
        text = p.text.strip()
        style = (p.style.name if p.style else "") or ""
        m = _HEADING_STYLE_RE.match(style)
        if m and text:
            level = int(m.group(1))
            while stack and stack[-1].level >= level:
                stack.pop()
            parent = stack[-1] if stack else root
            section = DocxSection(level=level, title=text, parent=parent)
            parent.children.append(section)
            stack.append(section)
        elif text:
            target = stack[-1] if stack else root
            target.body_paragraphs.append(text)
    return root


# ──────────────────────────── Name matching ────────────────────────────


_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "for", "to", "in", "on",
    "by", "with", "from", "via", "as", "at", "is", "are", "be",
    "this", "that", "their", "its",
    "stage", "phase", "step", "procedure",
    "walkthrough", "module",
}


def _tokens(text: str) -> set[str]:
    raw = re.findall(r"[a-z0-9]+", text.lower())
    return {t for t in raw if t and t not in _STOPWORDS and len(t) > 1}


def _similarity(name_a: str, name_b: str) -> float:
    """Compose a similarity score in [0, 1] from token-overlap +
    SequenceMatcher ratio. Token overlap dominates for short strings;
    SequenceMatcher catches near-identical phrasing."""
    ta, tb = _tokens(name_a), _tokens(name_b)
    if not ta or not tb:
        return 0.0
    overlap = len(ta & tb) / max(1, len(ta | tb))
    seq = SequenceMatcher(None, name_a.lower(), name_b.lower()).ratio()
    return 0.7 * overlap + 0.3 * seq


def best_match(step: Step, candidates: list[DocxSection],
               *, min_score: float = 0.30) -> tuple[DocxSection | None, float]:
    """Return the candidate section whose title is closest to the step's
    name, plus the score. Returns (None, score) if best score < min_score.

    Manual aliases per step id can override automatic matching.
    """
    target = STEP_NAME_OVERRIDES.get(step.id, step.name)
    best: tuple[DocxSection | None, float] = (None, 0.0)
    for cand in candidates:
        score = _similarity(target, cand.title)
        if score > best[1]:
            best = (cand, score)
    if best[1] < min_score:
        return (None, best[1])
    return best


# Manual overrides for steps whose YAML name differs significantly from
# the docx section heading. Empty by default — populate as needed.
STEP_NAME_OVERRIDES: dict[str, str] = {
    "bb.stage1.crtsh": "Certificate Transparency Log Harvesting",
    "bb.stage1.censys_walkthrough": "Censys Certificate Search",
    "bb.stage1.dns_enum": "DNS Record Enumeration",
    "bb.stage1.whois": "Passive WHOIS",
    "bb.stage1.email_security": "SPF DKIM DMARC",
    "bb.stage2.subfinder": "Subdomain Enumeration via Multi-Source Aggregators",
    "bb.stage2.assetfinder": "Subdomain Enumeration via Multi-Source Aggregators",
    "bb.stage2.amass": "Subdomain Enumeration via Multi-Source Aggregators",
    "bb.stage2.fofa_walkthrough": "Fofa Service Enumeration",
    "bb.stage2.virustotal_walkthrough": "VirusTotal Historical DNS",
    "bb.stage2.google_dorking_walkthrough": "Google Dorking",
    "bb.stage3.http_probe": "HTTP Header Analysis",
    "bb.stage3.headers_audit": "HTTP Header Analysis",
    "bb.stage3.tls_audit": "TLS Certificate Inspection",
    "bb.stage3.wappalyzer_walkthrough": "Wappalyzer Technology Fingerprinting",
    "bb.stage3.cve_lookup": "CVE Lookup",
    "bb.stage3.risk_score": "Risk Scoring",
    "bb.stage4.nmap_top": "Nmap Port Scan",
    "bb.stage4.nmap_full": "Nmap Full Port Scan",
    "bb.stage4.nikto": "Nikto Web Server Scan",
    "wp_stress.phase1.scope_confirm": "Pre-Engagement Setup",
    "wp_stress.phase1.backup": "Pre-Engagement Setup",
    "wp_stress.phase1.baseline_ab": "Pre-Engagement Setup",
    "wp_stress.phase1.headers_baseline": "Pre-Engagement Setup",
    "wp_stress.phase2.warmup": "Stress Testing Load DoS Simulation",
    "wp_stress.phase2.escalating": "Stress Testing Load DoS Simulation",
    "wp_stress.phase2.endpoint_stress": "Stress Testing Load DoS Simulation",
    "wp_stress.phase2.locust_walkthrough": "Stress Testing Load DoS Simulation",
    "wp_stress.phase3.headers_diff": "Automated Vulnerability Scanning",
    "wp_stress.phase3.exposed_files": "Automated Vulnerability Scanning",
    "wp_stress.phase3.wpscan": "Automated Vulnerability Scanning",
    "wp_stress.phase3.nikto": "Automated Vulnerability Scanning",
    "wp_stress.phase3.zap_walkthrough": "Automated Vulnerability Scanning",
    "wp_stress.phase4.remediation_matrix": "Analysis Remediation and Hardening",
    "wp_stress.phase4.retest_baseline": "Analysis Remediation and Hardening",
    "wp_stress.phase4.report": "Analysis Remediation and Hardening",
    "wifi.phase0.authorisation": "Pre-Engagement Checklist",
    "wifi.phase0.preflight": "Pre-Engagement Checklist",
    "wifi.phase1.monitor_mode": "Enable Monitor Mode",
    "wifi.phase1.airodump_scan": "Passive Network Enumeration",
    "wifi.phase2.handshake_capture": "WPA Handshake Capture",
    "wifi.phase2.hashcat_crack": "Offline Password Cracking",
    "wifi.phase2.wps_attack": "WPS Attacks",
    "wifi.phase3.eviltwin_walkthrough": "Evil Twin",
    "wifi.phase4.responder_walkthrough": "Post Exploitation Responder",
    "wifi.phase4.crackmapexec_walkthrough": "Post Exploitation CrackMapExec",
    "wifi.phase4.enum4linux_walkthrough": "Post Exploitation Enumeration",
}


# ──────────────────────────── Section → lesson body ────────────────────────────


_SECTION_ALIASES: dict[str, str] = {
    "what we are doing": "what",
    "what": "what",
    "objective": "what",
    "step-by-step execution": "how",
    "steps": "how",
    "procedure": "how",
    "why": "why",
    "rationale": "why",
    "why we do this": "why",
    "how this data will be used": "how",
    "how to use it": "how",
    "what to collect": "what_to_collect",
    "tools used": "tools",
    "tools required": "tools",
    "tools used in this phase": "tools",
}


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "section"


def section_to_lesson_body(section: DocxSection) -> dict[str, str]:
    """Convert a DocxSection's nested children (and lead body) into a
    canonical-keyed lesson body. Recurses through any deeper heading
    levels so a matched H1 picks up its H2 children, and so on."""
    sections: dict[str, str] = {}
    if section.body_md:
        sections["what"] = section.body_md
    _harvest_children(section, sections)
    return sections


def _harvest_children(parent: DocxSection, sections: dict[str, str]) -> None:
    for child in parent.children:
        body = child.body_md
        if body:
            title_lower = child.title.strip().lower()
            # Strip leading numeric prefixes like "1.1 " / "2.3  " so
            # "1.1 Why We Do This" canonicalises to "why".
            normalised = re.sub(r"^\d+(\.\d+)*\s+", "", title_lower).strip()
            key = _SECTION_ALIASES.get(normalised)
            if key is None:
                if normalised.startswith("why "):
                    key = "why"
                elif normalised.startswith("how "):
                    key = "how"
                else:
                    key = _slugify(child.title)
            if key in sections:
                sections[key] = sections[key] + "\n\n" + body
            else:
                sections[key] = body
        _harvest_children(child, sections)


# ──────────────────────────── Output ────────────────────────────


@dataclass
class StepLesson:
    step_id: str
    procedure: str
    stage: str | None
    title: str
    sections: dict[str, str]
    matched: bool
    match_score: float
    estimated_minutes: int = 8


_PRETTY = {
    "what": "What We Are Doing",
    "why": "Why",
    "how": "How",
    "what_to_collect": "What to Collect",
    "tools": "Tools",
}


def _pretty_section(key: str) -> str:
    return _PRETTY.get(key, " ".join(w.capitalize() for w in key.split("_")))


def _yaml_scalar(text: str) -> str:
    if any(c in text for c in ":#&*!,[]{}|>"):
        escaped = text.replace('"', '\\"')
        return f'"{escaped}"'
    return text


def render_markdown(lesson: StepLesson) -> str:
    fm = (
        "---\n"
        f"step_id: {lesson.step_id}\n"
        f"procedure: {lesson.procedure}\n"
        f"stage: {lesson.stage or ''}\n"
        f"title: {_yaml_scalar(lesson.title)}\n"
        f"estimated_minutes: {lesson.estimated_minutes}\n"
        "---\n\n"
    )
    body_parts: list[str] = []
    if not lesson.matched:
        body_parts.append(
            "_This lesson is a placeholder. The matching procedure-manual "
            "section couldn't be auto-extracted; populate it by hand or "
            "rerun the extractor against an updated docx._"
        )
    for key in ("what", "why", "how", "what_to_collect", "tools"):
        if lesson.sections.get(key):
            body_parts.append(f"## {_pretty_section(key)}\n\n{lesson.sections[key].strip()}")
    for key, val in lesson.sections.items():
        if key in ("what", "why", "how", "what_to_collect", "tools"):
            continue
        body_parts.append(f"## {_pretty_section(key)}\n\n{val.strip()}")
    return fm + "\n\n".join(body_parts) + "\n"


def write_lessons(lessons: list[StepLesson], dest_root: Path) -> list[Path]:
    written: list[Path] = []
    for lsn in lessons:
        slug = lsn.step_id.split(".")[-1]
        relpath = Path(lsn.procedure) / (lsn.stage or "_misc") / f"{slug}.md"
        target = dest_root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render_markdown(lsn), encoding="utf-8")
        written.append(target)
    return written


# ──────────────────────────── Orchestrator ────────────────────────────


@dataclass
class ExtractReport:
    procedure: str
    docx_source: Path
    lessons_written: list[Path] = field(default_factory=list)
    matched: int = 0
    placeholder: int = 0
    matches_by_step: dict[str, float] = field(default_factory=dict)


def extract_one(procedure_id: str, docx_path: Path, dest_root: Path,
                procedures: ProcedureLoader,
                *, min_score: float = 0.30) -> ExtractReport:
    """Extract lessons for every step of ``procedure_id`` from
    ``docx_path``, writing them under
    ``dest_root/<procedure>/<stage>/<slug>.md``.
    """
    proc = procedures.get(procedure_id)
    root = parse_docx(docx_path)
    candidate_sections = [s for s in root.walk() if s.level >= 1 and s.title]

    lessons: list[StepLesson] = []
    for step in proc.all_steps():
        match, score = best_match(step, candidate_sections, min_score=min_score)
        if match is not None:
            sections = section_to_lesson_body(match)
            matched = True
        else:
            sections = {}
            matched = False
        lessons.append(StepLesson(
            step_id=step.id, procedure=procedure_id, stage=step.stage,
            title=step.name, sections=sections,
            matched=matched, match_score=score,
        ))
    written = write_lessons(lessons, dest_root)
    return ExtractReport(
        procedure=procedure_id, docx_source=docx_path,
        lessons_written=written,
        matched=sum(1 for lsn in lessons if lsn.matched),
        placeholder=sum(1 for lsn in lessons if not lsn.matched),
        matches_by_step={lsn.step_id: lsn.match_score for lsn in lessons},
    )


def extract_all(docx_paths: dict[str, Path], dest_root: Path,
                procedures: ProcedureLoader,
                *, min_score: float = 0.30) -> list[ExtractReport]:
    """Extract lessons from every procedure docx provided."""
    reports: list[ExtractReport] = []
    for procedure, path in docx_paths.items():
        if procedure not in {p.id for p in procedures.all().values()}:
            continue
        reports.append(extract_one(procedure, path, dest_root, procedures,
                                    min_score=min_score))
    return reports
