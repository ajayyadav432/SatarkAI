"""History store: save, full-text search, filters, pagination, status, delete."""
from app import db
from app.analysis.pipeline import analyze
from tests.conftest import OK_CHAT, OK_OTP, SCAM_BILL, SCAM_HINDI, SCAM_KYC, SCAM_LOTTERY


def seed(*texts, **kw):
    return [db.save_case(analyze(t), **kw) for t in texts]


def test_save_and_get(fresh_db):
    (case_id,) = seed(SCAM_KYC)
    case = db.get_case(case_id)
    assert case["text"] == SCAM_KYC and case["status"] == "new" and case["source"] == "user"
    assert case["result"]["score"] == case["score"] and case["level"] in ("High", "Critical")
    assert db.get_case(99999) is None


def test_search_text_domain_phone_upi(fresh_db):
    kyc, bill, lottery, chat = seed(SCAM_KYC, SCAM_BILL, SCAM_LOTTERY, OK_CHAT)
    find = lambda q: {c["id"] for c in db.list_cases(q=q)["items"]}
    assert find("kyc") == {kyc}
    assert find("electricity officer") == {bill}
    assert find("sbi-kyc-update.xyz") == {kyc}          # domain
    assert find("sbi-kyc") == {kyc}                      # part of a domain
    assert find("9876543210") == {bill}                  # phone number
    assert find("kbcoffice@ybl") == {lottery}            # UPI ID
    assert find("elec") == {bill}                        # prefix
    assert find("lunch tomorrow") == {chat}
    assert find("nothingmatchesthis") == set()


def test_search_in_hindi(fresh_db):
    (hindi,) = seed(SCAM_HINDI)
    assert {c["id"] for c in db.list_cases(q="केवाईसी")["items"]} == {hindi}
    assert {c["id"] for c in db.list_cases(q="खाता")["items"]} == {hindi}


def test_search_is_all_words(fresh_db):
    kyc, bill = seed(SCAM_KYC, SCAM_BILL)
    assert {c["id"] for c in db.list_cases(q="dear")["items"]} == {kyc, bill}
    assert {c["id"] for c in db.list_cases(q="dear electricity")["items"]} == {bill}


def test_filters(fresh_db):
    kyc, otp, chat = seed(SCAM_KYC, OK_OTP, OK_CHAT)
    assert {c["id"] for c in db.list_cases(level="Safe")["items"]} == {otp, chat}
    assert {c["id"] for c in db.list_cases(level="High,Critical")["items"]} == {kyc}
    assert {c["id"] for c in db.list_cases(category="KYC / account update")["items"]} == {kyc}
    assert {c["id"] for c in db.list_cases(min_score=60)["items"]} == {kyc}
    assert db.list_cases(level="NotALevel")["total"] == 0
    assert db.list_cases(date_from="2099-01-01")["total"] == 0
    assert db.list_cases(date_to="2099-01-01")["total"] == 3


def test_pagination_and_sort(fresh_db):
    ids = seed(*[f"Message number {i} about lunch" for i in range(23)])
    page1 = db.list_cases(page=1, page_size=10)
    page3 = db.list_cases(page=3, page_size=10)
    assert page1["total"] == 23 and page1["pages"] == 3
    assert len(page1["items"]) == 10 and len(page3["items"]) == 3
    assert page1["items"][0]["id"] == ids[-1]                       # newest first
    assert db.list_cases(sort="oldest", page_size=1)["items"][0]["id"] == ids[0]
    assert db.list_cases(page=99, page_size=10)["items"] == []


def test_sort_by_score(fresh_db):
    kyc, chat = seed(SCAM_KYC, OK_CHAT)
    assert db.list_cases(sort="score_desc")["items"][0]["id"] == kyc
    assert db.list_cases(sort="score_asc")["items"][0]["id"] == chat
    assert db.list_cases(sort="; DROP TABLE cases")["total"] == 2   # unknown sort falls back safely


def test_status_notes_and_search_in_notes(fresh_db):
    (kyc,) = seed(SCAM_KYC)
    assert db.update_case(kyc, status="confirmed_scam", notes="reported to bank helpdesk")
    case = db.get_case(kyc)
    assert case["status"] == "confirmed_scam" and case["notes"] == "reported to bank helpdesk"
    assert {c["id"] for c in db.list_cases(q="helpdesk")["items"]} == {kyc}
    assert {c["id"] for c in db.list_cases(status="confirmed_scam")["items"]} == {kyc}
    assert db.update_case(424242, status="reviewed") is False


def test_delete_removes_case_and_search_entry(fresh_db):
    kyc, bill = seed(SCAM_KYC, SCAM_BILL)
    assert db.delete_case(kyc) is True
    assert db.get_case(kyc) is None
    assert db.list_cases(q="kyc")["total"] == 0
    assert db.list_cases()["total"] == 1
    assert db.delete_case(kyc) is False


def test_demo_cases_are_tagged_and_removable(fresh_db):
    seed(SCAM_KYC, source="demo-seed")
    seed(SCAM_BILL)
    assert db.list_cases(source="demo-seed")["total"] == 1
    assert db.stats()["kpis"]["demo"] == 1
    assert db.delete_by_source("demo-seed") == 1
    assert db.list_cases()["total"] == 1


def test_stats(fresh_db):
    seed(SCAM_KYC, SCAM_KYC, SCAM_LOTTERY, OK_CHAT, OK_OTP)
    s = db.stats(30)
    assert s["kpis"]["total"] == 5 and s["kpis"]["high_risk"] == 3 and s["kpis"]["today"] == 5
    assert s["kpis"]["needs_review"] == 3
    assert sum(l["n"] for l in s["levels"]) == 5
    assert len(s["trend"]["days"]) == 30 and sum(sum(v) for v in s["trend"]["series"].values()) == 5
    assert s["categories"][0] == {"category": "KYC / account update", "n": 2, "avg_score": s["categories"][0]["avg_score"]}
    assert any(b["brand"] == "State Bank of India" for b in s["brands"])
    assert any(d["domain"] == "sbi-kyc-update.xyz" and d["n"] == 2 for d in s["domains"])
    assert s["factors"] and all(f["n"] >= 1 for f in s["factors"])


def test_stats_on_empty_database(fresh_db):
    s = db.stats(7)
    assert s["kpis"]["total"] == 0 and s["kpis"]["high_risk_share"] == 0
    assert s["categories"] == [] and len(s["trend"]["days"]) == 7


def test_fts_query_quotes_user_input():
    assert db.fts_query('kyc "update') == '"kyc"* """update"*'
    assert db.fts_query("a AND b OR NOT c") == '"a"* "AND"* "b"* "OR"* "NOT"* "c"*'
    assert db.fts_query("*** --- ((( ") is None
