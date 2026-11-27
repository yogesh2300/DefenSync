"""Analytics environment (source family) classification.

Linux, cloud, HPC, and behavioral analytics are environment-specific: an event
belongs to exactly one family, and no family is ever substituted for another.
Unrecognised source types are UNKNOWN (never Linux) so they cannot reach the
Linux model, baselines, or correlation.
"""

from __future__ import annotations

LINUX = "LINUX"
CLOUD = "CLOUD"
HPC = "HPC"
BEHAVIORAL = "BEHAVIORAL"
UNKNOWN = "UNKNOWN"

SOURCE_FAMILIES = (LINUX, CLOUD, HPC, BEHAVIORAL)
ENVIRONMENT_PATTERN = "^(LINUX|CLOUD|HPC|BEHAVIORAL)$"

# CLOUD_DATASET and AZURE are legacy cloud source_type values.
_SOURCE_TYPE_FAMILY = {
    "LINUX": LINUX,
    "CLOUD": CLOUD,
    "CLOUD_DATASET": CLOUD,
    "AZURE": CLOUD,
    "HPC": HPC,
    "BEHAVIORAL": BEHAVIORAL,
}


def source_family(source_type: str | None) -> str:
    """Map a stored source_type to its analytics family. A missing value is historical Linux data."""
    value = (source_type or "").strip().upper()
    if not value:
        return LINUX
    return _SOURCE_TYPE_FAMILY.get(value, UNKNOWN)


def source_types_for_family(family: str) -> tuple[str, ...]:
    """All stored source_type values (canonical and legacy) that belong to one family."""
    return tuple(sorted(value for value, mapped in _SOURCE_TYPE_FAMILY.items() if mapped == family))


def normalize_environment(environment: str | None, default: str = LINUX) -> str:
    """Validate a requested aggregate environment; UNKNOWN is never a requestable environment."""
    value = (environment or default).strip().upper()
    if value not in SOURCE_FAMILIES:
        raise ValueError(f"Unsupported environment: {environment!r}")
    return value
