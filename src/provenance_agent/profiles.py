from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


DEFAULT_POLICY_PROFILE = "enterprise-linux-default@1.0.0"


class RiskBands(BaseModel):
    model_config = ConfigDict(extra="forbid")

    low: int = Field(ge=1, le=100)
    medium: int = Field(ge=1, le=100)
    high: int = Field(ge=1, le=100)
    critical: int = Field(ge=1, le=100)

    @model_validator(mode="after")
    def validate_order(self) -> RiskBands:
        if not (self.low <= self.medium <= self.high <= self.critical):
            raise ValueError("risk band thresholds must be monotonic")
        return self


class DecisionThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow_min_confidence: int = Field(ge=0, le=100)
    unknown_below_completeness: int = Field(ge=0, le=100)
    unknown_below_confidence: int = Field(ge=0, le=100)
    policy_review_risk_score: int = Field(ge=0, le=100)
    automatic_deny_score: int | None = Field(default=None, ge=0, le=100)


class BlastRadiusCalibration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    high_count: int = Field(ge=1)
    high_weight: int = Field(ge=0, le=100)


class PolicyProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_id: Literal["provenance-risk-agent.policy-profile.v1"] = Field(
        alias="schema",
        serialization_alias="schema",
    )
    profile_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]+$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    title: str
    description: str
    finding_weights: dict[str, int]
    vulnerability_weights: dict[str, int]
    blast_radius: BlastRadiusCalibration
    risk_bands: RiskBands
    decision: DecisionThresholds
    advisory_max_age_seconds: int = Field(gt=0)
    calibration_dataset: str

    @property
    def identifier(self) -> str:
        return f"{self.profile_id}@{self.version}"

    @model_validator(mode="after")
    def validate_weights(self) -> PolicyProfile:
        if any(weight < 0 or weight > 100 for weight in self.finding_weights.values()):
            raise ValueError("finding weights must be between 0 and 100")
        if any(weight < 0 or weight > 100 for weight in self.vulnerability_weights.values()):
            raise ValueError("vulnerability weights must be between 0 and 100")
        required = {"unknown", "none", "low", "medium", "high", "critical"}
        if set(self.vulnerability_weights) != required:
            raise ValueError("vulnerability weights must define every severity")
        return self

    def weight_for(self, evidence: dict[str, Any]) -> int:
        code = str(evidence.get("code") or "")
        if code in {
            "UNFIXED_VULNERABILITY",
            "EDGP_ADVISORY_AFFECTS_ARTIFACT",
        }:
            severity = str(evidence.get("severity") or "unknown").lower()
            return self.vulnerability_weights.get(
                severity,
                self.vulnerability_weights["unknown"],
            )
        if code == "EDGP_LARGE_BLAST_RADIUS":
            count = int((evidence.get("attributes") or {}).get("dependent_count") or 0)
            if count >= self.blast_radius.high_count:
                return self.blast_radius.high_weight
        return self.finding_weights.get(code, int(evidence.get("weight") or 0))


_PROFILE_FILES = {
    "enterprise-linux-default@1.0.0": "enterprise-linux-default-v1.json",
    "enterprise-linux-strict@1.0.0": "enterprise-linux-strict-v1.json",
}


@lru_cache(maxsize=None)
def load_policy_profile(identifier: str = DEFAULT_POLICY_PROFILE) -> PolicyProfile:
    try:
        filename = _PROFILE_FILES[identifier]
    except KeyError as exc:
        supported = ", ".join(sorted(_PROFILE_FILES))
        raise ValueError(
            f"Unknown policy profile {identifier!r}. Supported profiles: {supported}."
        ) from exc
    resource = files("provenance_agent").joinpath("policy_profiles", filename)
    return PolicyProfile.model_validate_json(resource.read_text(encoding="utf-8"))


def list_policy_profiles() -> list[PolicyProfile]:
    return [load_policy_profile(identifier) for identifier in sorted(_PROFILE_FILES)]
