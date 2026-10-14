"""REST API: valid input, invalid input, unknown ids, export, bulk upload."""
import csv
import io

from tests.conftest import OK_CHAT, SCAM_BILL, SCAM_KYC


def test_health_and_meta(client):
    h = client.get("/api/health").json()
    assert h["status"] == "ok" and set(h["models"]) == {"text_model", "url_model", "metrics"}
    m = client.get("/api/meta").json()
    assert [l["name"] for l in m["levels"]] == ["Safe", "Low", "Medium", "High", "Critical"]
    assert len(m["samples"]) >= 10 and m["problem_statement"] == "SKIT025"


def test_pages_are_served(client):
    for path in ("/", "/go", "/static/app.js", "/static/styles.css", "/static/go.js", "/static/vendor/chart.umd.min.js"):
        assert client.get(path).status_code == 200, path
    assert "<title>" in client.get("/").text


def test_analyze_saves_a_case(client):
    r = client.post("/api/analyze", json={"text": SCAM_KYC, "sender": "9876501234"})
    assert r.status_code == 200
    body = r.json()
    assert body["level"] in ("High", "Critical") and body["case_id"] >= 1
    assert {"score", "level", "category", "factors", "urls", "entities", "highlights", "advice", "notes"} <= set(body)
    assert client.get(f"/api/cases/{body['case_id']}").json()["text"] == SCAM_KYC


def test_analyze_without_saving(client):
    r = client.post("/api/analyze", json={"text": OK_CHAT, "save": False}).json()
    assert r["case_id"] is None
    assert client.get("/api/cases").json()["total"] == 0


def test_analyze_rejects_bad_input(client):
    assert client.post("/api/analyze", json={"text": ""}).status_code == 422
    assert client.post("/api/analyze", json={"text": "   \n  "}).status_code == 422
    assert client.post("/api/analyze", json={}).status_code == 422
    assert client.post("/api/analyze", json={"text": 12345}).status_code == 422
    assert client.post("/api/analyze", json={"text": "hi", "channel": "fax"}).status_code == 422
    assert client.post("/api/analyze", json={"text": "hi", "unknown_field": 1}).status_code == 422
    assert client.post("/api/analyze", json={"text": "x" * 20001}).status_code == 422
    assert client.post("/api/analyze", content=b"not json", headers={"Content-Type": "application/json"}).status_code == 422
    assert client.post("/api/analyze", json={"text": "hi", "sender": "s" * 400}).status_code == 422


def test_analyze_accepts_the_maximum_length(client):
    r = client.post("/api/analyze", json={"text": "word " * 4000, "save": False})
    assert r.status_code == 200 and len(r.json()["text"]) == 20000


def test_check_url(client):
    r = client.get("/api/check-url", params={"u": "http://sbi-kyc-update.xyz/login"}).json()
    assert r["level"] in ("High", "Critical") and r["needs_warning"] is True
    assert r["display"] == "hxxp://sbi-kyc-update[.]xyz/login"
    ok = client.get("/api/check-url", params={"u": "https://www.onlinesbi.sbi/"}).json()
    assert ok["level"] == "Safe" and ok["needs_warning"] is False and ok["trusted"] is True
    assert client.get("/api/check-url", params={"u": "paypa1.com/login"}).json()["url"] == "http://paypa1.com/login"


def test_check_url_rejects_other_schemes(client):
    for bad in ("javascript:alert(1)", "data:text/html,<script>alert(1)</script>", "file:///etc/passwd", "ftp://example.com/x"):
        r = client.get("/api/check-url", params={"u": bad})
        assert r.status_code == 400 or r.json()["valid"] is False, bad
    assert client.get("/api/check-url").status_code == 422
    assert client.get("/api/check-url", params={"u": "x" * 3000}).status_code == 422


def test_case_endpoints(client):
    cid = client.post("/api/analyze", json={"text": SCAM_KYC}).json()["case_id"]
    r = client.patch(f"/api/cases/{cid}", json={"status": "confirmed_scam", "notes": "seen twice"})
    assert r.status_code == 200 and r.json()["status"] == "confirmed_scam" and r.json()["notes"] == "seen twice"
    assert client.patch(f"/api/cases/{cid}", json={"status": "nonsense"}).status_code == 422
    assert client.patch(f"/api/cases/{cid}", json={"score": 0}).status_code == 422       # score cannot be edited
    assert client.delete(f"/api/cases/{cid}").json() == {"deleted": cid}
    assert client.get(f"/api/cases/{cid}").status_code == 404
    assert client.delete(f"/api/cases/{cid}").status_code == 404
    assert client.patch("/api/cases/999", json={"status": "reviewed"}).status_code == 404
    assert client.get("/api/cases/abc").status_code == 422
    assert client.get("/api/cases/-1").status_code == 404


def test_case_list_query_validation(client):
    assert client.get("/api/cases", params={"page": 0}).status_code == 422
    assert client.get("/api/cases", params={"page_size": 1000}).status_code == 422
    assert client.get("/api/cases", params={"date_from": "yesterday"}).status_code == 422
    assert client.get("/api/cases", params={"sort": "random"}).status_code == 422
    assert client.get("/api/cases", params={"min_score": 500}).status_code == 422
    assert client.get("/api/stats", params={"days": 0}).status_code == 422
    ok = client.get("/api/cases", params={"q": "anything", "level": "High", "date_from": "2026-01-01"})
    assert ok.status_code == 200 and ok.json()["total"] == 0


def test_stats_and_model_card(client):
    client.post("/api/analyze", json={"text": SCAM_KYC})
    s = client.get("/api/stats", params={"days": 7}).json()
    assert s["kpis"]["total"] == 1 and len(s["trend"]["days"]) == 7
    card = client.get("/api/model-card").json()
    assert len(card["rules"]) >= 15 and card["brands"] >= 30 and "formula" in card["scoring"]


def test_export_csv(client):
    client.post("/api/analyze", json={"text": SCAM_KYC})
    client.post("/api/analyze", json={"text": OK_CHAT})
    r = client.get("/api/cases/export.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text.lstrip("﻿"))))
    assert len(rows) == 1 and rows[0]["level"] in ("High", "Critical")   # the safe message was not saved
    only = list(csv.DictReader(io.StringIO(client.get("/api/cases/export.csv", params={"q": "kyc"}).text.lstrip("﻿"))))
    assert len(only) == 1 and "KYC" in only[0]["text"]


def test_bulk_upload_csv_and_txt(client):
    data = "text,sender\n" + f'"{SCAM_KYC}",9876501234\n' + f'"{OK_CHAT}",\n' + '"",\n'
    r = client.post("/api/bulk", files={"file": ("msgs.csv", data.encode(), "text/csv")})
    assert r.status_code == 200
    body = r.json()
    assert body["analysed"] == 2 and body["by_level"]["Safe"] == 1 and body["saved"] == 1
    assert client.get("/api/cases", params={"source": "bulk"}).json()["total"] == 1
    txt = (SCAM_BILL + "\n\n" + OK_CHAT + "\n").encode()
    assert client.post("/api/bulk", files={"file": ("m.txt", txt, "text/plain")}).json()["analysed"] == 2


def test_bulk_upload_rejects_bad_files(client):
    assert client.post("/api/bulk", files={"file": ("a.csv", b"foo,bar\n1,2\n", "text/csv")}).status_code == 400
    assert client.post("/api/bulk", files={"file": ("a.txt", b"", "text/plain")}).status_code == 400
    assert client.post("/api/bulk", files={"file": ("a.txt", b"\xff\xfe\x00bad", "text/plain")}).status_code == 400
    big = b"hello world message\n" * 120000
    assert client.post("/api/bulk", files={"file": ("big.txt", big, "text/plain")}).status_code == 413
    assert client.post("/api/bulk").status_code == 422


def test_bulk_upload_row_limit(client):
    many = "\n".join(f"lunch message number {i}" for i in range(520)).encode()
    body = client.post("/api/bulk", files={"file": ("many.txt", many, "text/plain")}).json()
    assert body["analysed"] == 500 and body["truncated"] is True


def test_unknown_route_is_json_404(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and "detail" in r.json()
