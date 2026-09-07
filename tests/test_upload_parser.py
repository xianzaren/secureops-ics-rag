from src.ingestion.upload_parser import parse_text_to_chunks


def test_parse_text_to_chunks(tmp_path):
    document = tmp_path / "operator-guide.txt"
    document.write_text("PLC segmentation and firewall guidance " * 300, encoding="utf-8")

    chunks = parse_text_to_chunks(str(document), max_words=100)

    assert len(chunks) > 1
    assert all(chunk["metadata"]["source"] == "USER_UPLOAD" for chunk in chunks)
    assert all(chunk["metadata"]["filename"] == "operator-guide.txt" for chunk in chunks)
    assert "PLC segmentation" in chunks[0]["text"]

