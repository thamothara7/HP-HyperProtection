from app.collector.service import CollectorState


def test_collector_state_is_bounded_and_survives_restart(tmp_path) -> None:
    path = tmp_path / "collector-state.json"
    state = CollectorState.load(path)
    state.record("win-MGR-PC-1")
    state.save()
    restored = CollectorState.load(path)
    assert restored.contains("win-MGR-PC-1")
