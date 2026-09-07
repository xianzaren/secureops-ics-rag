from unittest.mock import patch

from fastapi.testclient import TestClient

from src.api import app


client = TestClient(app)


def test_health_and_status():
    assert client.get("/health").json() == {"status": "ok"}
    response = client.get("/api/status")
    assert response.status_code == 200
    assert "index_ready" in response.json()


def test_ask_rejects_blank_query():
    assert client.post("/api/ask", json={"query": " "}).status_code == 422


def test_upload_rejects_unsupported_extension():
    response = client.post("/api/upload", files=[("files", ("payload.exe", b"x", "application/octet-stream"))])
    assert response.status_code == 400


@patch("src.api.build_index")
def test_text_upload_is_passed_to_indexer(mock_build_index, tmp_path, monkeypatch):
    import src.api as api
    monkeypatch.setattr(api, "UPLOAD_DIR", tmp_path)
    mock_build_index.return_value = (1, 1)

    response = client.post("/api/upload", files=[("files", ("notes.txt", b"OT firewall", "text/plain"))])

    assert response.status_code == 200
    assert (tmp_path / "notes.txt").read_text() == "OT firewall"
    assert mock_build_index.call_args.kwargs["upload_dir"] == str(tmp_path)
