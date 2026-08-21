from app.features.extractor import SessionFeatures


def within_session_drift(earlier: SessionFeatures, current: SessionFeatures) -> float:
    """Compare current behavior with an earlier slice of the *same* context."""
    previous = earlier.vector()
    now = current.vector()
    deltas = [abs(new - old) / max(1.0, old + 1.0) for old, new in zip(previous, now, strict=True)]
    return min(100.0, sum(deltas) / len(deltas) * 35.0)
