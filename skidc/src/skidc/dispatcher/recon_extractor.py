"""RECON phase gate and potential-target extraction for real-website mode.

When bootstrap_enabled=False the scheduler uses this module to:
1. Check whether the categories required by the project's ReconProfile have
   been executed before moving from recon to explore.
2. Parse RECON facts and extract potential sub-targets (subdomains, open
   services, URLs) written as facts with goal_type='potential_target'.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from skidc.server.models import Fact, ReconProfile

LOG = logging.getLogger(__name__)

# Keywords that indicate a fact belongs to a particular RECON category.
_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "port_scan": ("port", "nmap", "naabu", "open port", "tcp", "service"),
    "subdomain": ("subdomain", "subfinder", "amass", "dns", "cname"),
    "directory": ("directory", "ffuf", "gobuster", "dirsearch", "path", "endpoint"),
    "asset": ("asset", "katana", "crawl", "url", "endpoint", "javascript", "js file"),
    "android_app": ("android", "package", "apk", "manifest", "activity"),
    "android_ui": ("screen", "ui", "activity", "button", "login screen"),
    "mobile_api": ("mobile api", "api call", "network history", "endpoint"),
    "android_storage": ("storage", "shared preferences", "sqlite", "keystore"),
}

_DEFAULT_REQUIRED_CATEGORIES = ("port_scan", "subdomain", "directory", "asset")


@dataclass(slots=True)
class ReconCategoryStatus:
    """Execution status for a single RECON category."""

    executed: bool = False
    found_results: bool = False


@dataclass(slots=True)
class ReconExecutionStatus:
    """Tracks execution status for the categories selected by a ReconProfile."""

    required_categories: list[str] = field(default_factory=lambda: list(_DEFAULT_REQUIRED_CATEGORIES))
    optional_categories: list[str] = field(default_factory=list)
    disabled_categories: list[str] = field(default_factory=list)
    categories: dict[str, ReconCategoryStatus] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for category in self.required_categories + self.optional_categories:
            self.category(category)

    @property
    def port_scan(self) -> ReconCategoryStatus:
        return self.category("port_scan")

    @property
    def subdomain(self) -> ReconCategoryStatus:
        return self.category("subdomain")

    @property
    def directory(self) -> ReconCategoryStatus:
        return self.category("directory")

    @property
    def asset(self) -> ReconCategoryStatus:
        return self.category("asset")

    @property
    def all_executed(self) -> bool:
        return all(self.category(category).executed for category in self.required_categories)

    @property
    def missing_executions(self) -> list[str]:
        return [
            category
            for category in self.required_categories
            if not self.category(category).executed
        ]

    @property
    def ordered_categories(self) -> list[str]:
        ordered: list[str] = []
        for category in self.required_categories + self.optional_categories + sorted(self.categories):
            if category in self.disabled_categories or category in ordered:
                continue
            ordered.append(category)
        return ordered

    def category(self, name: str) -> ReconCategoryStatus:
        return self.categories.setdefault(name, ReconCategoryStatus())


@dataclass(slots=True)
class PotentialTarget:
    description: str
    source: str  # which fact produced this target


def check_recon_executed(
    facts: list[Fact],
    profile: ReconProfile | dict | None = None,
) -> ReconExecutionStatus:
    """Scan facts and return execution status for the configured RECON profile.

    Structured recon metadata is canonical. Keyword matching is kept only as a
    compatibility fallback for older description-only facts.
    """
    profile_model = _profile_from_input(profile)
    required, optional, disabled = _profile_category_sets(profile_model)
    status = ReconExecutionStatus(
        required_categories=required,
        optional_categories=optional,
        disabled_categories=disabled,
    )
    positive_indicators = ("found", "discovered", "open", "detected")

    for fact in facts:
        structured_category = _clean_category(fact.recon_category)
        if structured_category is not None and fact.recon_executed is not None:
            if structured_category not in disabled:
                category_status = status.category(structured_category)
                category_status.executed = category_status.executed or bool(fact.recon_executed)
                if fact.recon_found_results is not None:
                    category_status.found_results = category_status.found_results or bool(fact.recon_found_results)
            continue

        desc_lower = fact.description.lower()
        for category, keywords in _CATEGORY_KEYWORDS.items():
            if category in disabled:
                continue
            if any(kw in desc_lower for kw in keywords):
                category_status = status.category(category)
                category_status.executed = True
                if any(indicator in desc_lower for indicator in positive_indicators):
                    category_status.found_results = True

    return status


# Backward compatibility alias
check_recon_status = check_recon_executed


def format_recon_status(status: ReconExecutionStatus) -> str:
    lines = []
    required = set(status.required_categories)
    optional = set(status.optional_categories)
    for category in status.ordered_categories:
        category_status = status.category(category)
        role = "required" if category in required else "optional" if category in optional else "observed"
        lines.append(
            f"- {category}: role={role}, executed={category_status.executed}, "
            f"found_results={category_status.found_results}"
        )
    if status.disabled_categories:
        lines.append(f"- disabled: {', '.join(status.disabled_categories)}")
    return "\n".join(lines) if lines else "(none)"


def _profile_from_input(profile: ReconProfile | dict | None) -> ReconProfile:
    if profile is None:
        return ReconProfile()
    if isinstance(profile, ReconProfile):
        return profile
    if isinstance(profile, dict):
        return ReconProfile.model_validate(profile)
    return ReconProfile()


def _profile_category_sets(profile: ReconProfile) -> tuple[list[str], list[str], list[str]]:
    disabled = _dedupe_categories(profile.disabled_categories)
    disabled_set = set(disabled)
    required = [
        category
        for category in _dedupe_categories(profile.required_categories)
        if category not in disabled_set
    ]
    optional = [
        category
        for category in _dedupe_categories(profile.optional_categories)
        if category not in disabled_set and category not in required
    ]
    return required, optional, disabled


def _dedupe_categories(categories: list[str]) -> list[str]:
    cleaned: list[str] = []
    for category in categories:
        value = _clean_category(category)
        if value is not None and value not in cleaned:
            cleaned.append(value)
    return cleaned


def _clean_category(category: str | None) -> str | None:
    if not isinstance(category, str):
        return None
    value = category.strip()
    return value or None


def extract_potential_targets(facts: list[Fact]) -> list[PotentialTarget]:
    """Parse RECON facts and extract potential sub-targets.

    Looks for:
    - Subdomains (e.g. ``admin.example.com``)
    - Open ports/services (e.g. ``80/tcp http``, ``443/tcp https``)
    - Interesting URLs/paths (e.g. ``/api/v1/admin``)
    """
    targets: list[PotentialTarget] = []
    seen: set[str] = set()

    for fact in facts:
        desc = fact.description

        # Subdomains: word.word.tld patterns (at least 3 parts)
        for match in re.finditer(r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})\b", desc):
            domain = match.group(1)
            if domain not in seen:
                seen.add(domain)
                targets.append(PotentialTarget(
                    description=f"Subdomain discovered: {domain}",
                    source=fact.id,
                ))

        # Open ports/services: patterns like "80/tcp", "443/tcp https", "22/ssh"
        for match in re.finditer(r"\b(\d{1,5})/(tcp|udp)\s*(\w+)?", desc):
            port = match.group(1)
            proto = match.group(2)
            service = match.group(3) or ""
            label = f"{port}/{proto}"
            if service:
                label += f" ({service})"
            if label not in seen:
                seen.add(label)
                targets.append(PotentialTarget(
                    description=f"Open port/service: {label}",
                    source=fact.id,
                ))

        # Interesting paths: /api/..., /admin, /login, etc.
        for match in re.finditer(r"(/(?:api|admin|login|dashboard|upload|backup|config|\.env|\.git|wp-|phpmyadmin)[^\s]*)", desc, re.IGNORECASE):
            path = match.group(1)
            if path not in seen:
                seen.add(path)
                targets.append(PotentialTarget(
                    description=f"Interesting path: {path}",
                    source=fact.id,
                ))

    return targets
