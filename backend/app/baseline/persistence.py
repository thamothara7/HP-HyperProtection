"""Persistence helpers for trusted personal and peer behavioral baselines."""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.baseline.personal import PersonalBaseline
from app.baseline.poisoning_guard import learning_weight
from app.baseline.robust_stats import robust_z_score
from app.db.models import BaselineProfileRecord, IdentityRecord, PeerBaselineRecord
from app.features.extractor import SessionFeatures

_PROFILE_LIMIT = 180
_PEER_LIMIT = 500


def feature_values(features: SessionFeatures) -> dict[str, float]:
    return {
        "target_count": float(features.unique_target_count),
        "sensitive_reads": float(features.sensitive_resource_reads),
        "after_hours": features.after_hours_score,
    }


def load_personal_baseline(db: Session, identity_id: str) -> tuple[PersonalBaseline, BaselineProfileRecord | None]:
    record = db.scalar(select(BaselineProfileRecord).where(BaselineProfileRecord.identity_id == identity_id))
    if record is None:
        return PersonalBaseline(), None
    profile = record.profile or {}
    return PersonalBaseline(
        known_devices=set(profile.get("known_devices", [])),
        known_targets=set(profile.get("known_targets", [])),
        target_counts=[float(value) for value in profile.get("target_counts", [])],
        sensitive_reads=[float(value) for value in profile.get("sensitive_reads", [])],
        after_hours=[float(value) for value in profile.get("after_hours", [])],
        max_observations=_PROFILE_LIMIT,
    ), record


def trusted_vectors(record: BaselineProfileRecord | None) -> list[list[float]]:
    if record is None:
        return []
    return [list(map(float, vector)) for vector in (record.profile or {}).get("trusted_vectors", [])]


def save_personal_baseline(
    db: Session,
    *,
    identity_id: str,
    baseline: PersonalBaseline,
    record: BaselineProfileRecord | None,
    features: SessionFeatures,
    risk_score: int,
) -> BaselineProfileRecord:
    """Persist a profile only after risk evaluation has decided learning is safe."""
    profile = dict(record.profile) if record is not None else {}
    weight = learning_weight(risk_score)
    vectors = [list(map(float, vector)) for vector in profile.get("trusted_vectors", [])]
    if weight == 1:
        vectors.append(features.vector())
        del vectors[:-_PROFILE_LIMIT]
    profile.update(
        {
            "known_devices": sorted(baseline.known_devices),
            "known_targets": sorted(baseline.known_targets),
            "target_counts": baseline.target_counts,
            "sensitive_reads": baseline.sensitive_reads,
            "after_hours": baseline.after_hours,
            "trusted_vectors": vectors,
        }
    )
    if record is None:
        record = BaselineProfileRecord(identity_id=identity_id, profile=profile, trusted_observations=1 if weight == 1 else 0)
        db.add(record)
    else:
        record.profile = profile
        if weight == 1:
            record.trusted_observations += 1
    return record


@dataclass
class PeerProfile:
    department: str
    role: str
    observations: dict[str, list[float]] = field(default_factory=lambda: {"target_count": [], "sensitive_reads": [], "after_hours": []})

    def deviation(self, features: SessionFeatures) -> float:
        scores = [robust_z_score(value, self.observations.get(name, [])) for name, value in feature_values(features).items()]
        return min(100.0, max(scores, default=0.0) * 20.0)

    def update(self, features: SessionFeatures, risk_score: int) -> None:
        # Peer learning follows the same anti-poisoning decision as personal learning.
        if learning_weight(risk_score) == 0:
            return
        for name, value in feature_values(features).items():
            values = self.observations.setdefault(name, [])
            if learning_weight(risk_score) == 1 or not values:
                values.append(value)
            else:
                values.append(sum(values[-min(10, len(values)):]) / min(10, len(values)))
            del values[:-_PEER_LIMIT]


def load_peer_profile(db: Session, identity_id: str) -> tuple[PeerProfile, PeerBaselineRecord | None]:
    identity = db.get(IdentityRecord, identity_id)
    department = (identity.department if identity and identity.department else "Unassigned")
    role = (identity.role if identity and identity.role else "Unassigned")
    record = db.scalar(
        select(PeerBaselineRecord).where(PeerBaselineRecord.department == department, PeerBaselineRecord.role == role)
    )
    if record is None:
        return PeerProfile(department=department, role=role), None
    profile = record.profile or {}
    observations = {
        name: [float(value) for value in profile.get(name, [])]
        for name in ("target_count", "sensitive_reads", "after_hours")
    }
    return PeerProfile(department=department, role=role, observations=observations), record


def save_peer_profile(db: Session, profile: PeerProfile, record: PeerBaselineRecord | None) -> PeerBaselineRecord:
    payload = {name: values[-_PEER_LIMIT:] for name, values in profile.observations.items()}
    if record is None:
        record = PeerBaselineRecord(department=profile.department, role=profile.role, profile=payload)
        db.add(record)
    else:
        record.profile = payload
    return record
