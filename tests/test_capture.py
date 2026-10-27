from app.services.capture import CaptureManager


def test_capture_manager_status():
    manager = CaptureManager()
    status = manager.status()

    assert "running" in status
    assert "packet_count" in status
    assert isinstance(status["packet_count"], int)


def test_capture_manager_requires_interface():
    manager = CaptureManager()

    try:
        manager.start(interface="")
        assert False, "Expected ValueError for empty interface"
    except ValueError:
        pass


def test_capture_manager_validates_capture_limits():
    manager = CaptureManager()

    for options in (
        {"packet_limit": 0},
        {"duration": 0},
    ):
        try:
            manager.start(interface="lo", **options)
            assert False, "Expected ValueError for invalid capture settings"
        except ValueError:
            pass


def test_capture_manager_clear_and_snapshot():
    manager = CaptureManager()
    manager.packets.append({"protocol": "TCP"})

    snapshot = manager.snapshot()
    manager.clear()

    assert snapshot == [{"protocol": "TCP"}]
    assert manager.packets == []
