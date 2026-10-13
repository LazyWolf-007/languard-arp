from fastapi.testclient import TestClient
import pytest
from app.main import app
from app.state import state


@pytest.fixture(autouse=True)
def reset_state():
    state.reset()
    yield
    state.reset()


def test_rest_websocket_and_reset_share_the_same_authoritative_state():
    with TestClient(app) as client:
        with client.websocket_connect("/api/ws") as socket:
            initial = socket.receive_json()
            assert initial == client.get("/api/state").json()

            demo_response = client.post("/api/simulation/demo")
            assert demo_response.status_code == 200
            demo_state = demo_response.json()
            assert demo_state == socket.receive_json() == client.get("/api/state").json()
            assert len(demo_state["alerts"]) == 1
            assert demo_state["evaluation"]["tp"] == 1

            mode_response = client.post("/api/mode/enforcement")
            assert mode_response.status_code == 200
            assert mode_response.json() == socket.receive_json()

            spoof_response = client.post("/api/simulation/spoof")
            assert spoof_response.status_code == 200
            spoof_state = spoof_response.json()["snapshot"]
            assert spoof_state == socket.receive_json() == client.get("/api/state").json()
            gateway = next(m for m in spoof_state["mappings"] if m["ip"] == "192.168.1.1")
            assert gateway["mac"] == gateway["trusted_mac"]
            assert spoof_state["decisions"][0]["action"] == "rejected"

            reset_response = client.post("/api/reset")
            assert reset_response.status_code == 200
            reset_state = reset_response.json()
            assert reset_state == socket.receive_json() == client.get("/api/state").json()
            assert not reset_state["alerts"] and not reset_state["events"] and not reset_state["decisions"]
