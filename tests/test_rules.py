"""Each rule group fires on a scam example and stays silent on a normal one."""
import pytest

from app.analysis import rules


def groups(text):
    return {h["group"] for h in rules.apply_rules(text)}


FIRES = [
    ("urgency", "Reply within 24 hours or lose access"),
    ("urgency", "Turant call karein"),
    ("urgency", "तुरंत संपर्क करें"),
    ("threat", "Your account will be blocked today"),
    ("threat", "aapka khata band ho jayega"),
    ("threat", "आपका खाता बंद हो जाएगा"),
    ("credential_request", "Please share your OTP to complete verification"),
    ("credential_request", "apna OTP batao"),
    ("credential_request", "अपना ओटीपी बताएं"),
    ("reward", "Congratulations! You have won a cash prize"),
    ("reward", "Badhai ho, aapne inaam jeeta"),
    ("reward", "बधाई हो! आपने लॉटरी जीती है"),
    ("payment_request", "Pay Rs 5,000 processing fee to release the amount"),
    ("kyc", "Your KYC is pending"),
    ("kyc", "केवाईसी अपडेट करें"),
    ("link_action", "Click on the link below to continue"),
    ("link_action", "नीचे दिए गए लिंक पर क्लिक करें"),
    ("courier", "Your parcel could not be delivered due to incomplete address"),
    ("job", "Part time job, work from home, earn Rs 3000 per day"),
    ("bill", "Your electricity connection will be disconnected tonight at 9.30 pm"),
    ("bill", "aapka bijli connection kat jayega"),
    ("authority", "You are under digital arrest by the CBI"),
    ("refund", "You are eligible for a tax refund of Rs 15,490"),
    ("investment", "Guaranteed returns of 30% every week, double your money"),
    ("remote_access", "Install AnyDesk so that our engineer can help"),
    ("family_emergency", "Hi mum, this is my new number, my phone is broken"),
    ("loan", "Pre-approved loan of Rs 5,00,000, no CIBIL check"),
    ("extortion", "I have recorded you and will leak the video to your contacts"),
    ("generic_greeting", "Dear customer, greetings"),
    ("callback", "Call 9876543210 for help"),
]


@pytest.mark.parametrize("group,text", FIRES)
def test_rule_fires(group, text):
    assert group in groups(text)


NORMAL = [
    "Hey are we still meeting for lunch tomorrow at 1? Let me know",
    "Happy birthday! Party at my place on Saturday evening, bring your guitar.",
    "Notes for unit 3 are uploaded on the class drive. Exam is on Monday, all the best.",
    "bhai kal college aa raha hai kya, assignment submit karna hai mujhe bhi bata dena",
    "कल सुबह दस बजे कॉलेज में मिलते हैं",
    "The meeting is moved to 3 pm in the seminar hall. Please bring your laptops.",
]


@pytest.mark.parametrize("text", NORMAL)
def test_normal_messages_trigger_nothing(text):
    assert rules.apply_rules(text) == []
    assert rules.obfuscation(text) == []


@pytest.mark.parametrize("text", [
    "482913 is your OTP. Do not share it with anyone.",
    "Never share your OTP or PIN with anyone. The bank will never ask you to share your password.",
    "OTP kisi ko na batayein",
    "अपना ओटीपी किसी को न बताएं",
])
def test_warning_not_to_share_is_not_a_request(text):
    assert "credential_request" not in groups(text)


def test_evidence_text_and_spans_point_into_the_message():
    text = "Hello. Your account will be blocked today."
    hit = next(h for h in rules.apply_rules(text) if h["group"] == "threat")
    s, e = hit["spans"][0]
    assert text[s:e].lower() == hit["evidence"][0].lower()


def test_more_matching_patterns_raise_the_weight_up_to_a_cap():
    one = next(h for h in rules.apply_rules("urgent") if h["group"] == "urgency")
    many = next(h for h in rules.apply_rules("urgent, act now, last chance, within 2 hours, hurry, final warning, asap")
                if h["group"] == "urgency")
    assert one["weight"] == 0.25 and one["weight"] < many["weight"] <= 0.4


def test_obfuscation_detection():
    assert {h["id"] for h in rules.obfuscation("Get fr33 c@sh, just l0gin")} == {"obf_leet"}
    assert {h["id"] for h in rules.obfuscation("Cl​ick he​re")} == {"obf_zero_width"}
    assert {h["id"] for h in rules.obfuscation("Your pаypal account")} == {"obf_mixed_script"}   # Cyrillic 'а'
    assert {h["id"] for h in rules.obfuscation("WIN A FREE PHONE NOW CLAIM YOUR PRIZE TODAY")} == {"obf_caps"}


def test_standard_alert_shapes():
    assert rules.looks_like_standard_alert("482913 is your OTP for transaction of INR 2,499.00") == "otp"
    assert rules.looks_like_standard_alert("Rs 5,000.00 debited from A/c XX1234 on 12-Oct. Avl Bal Rs 12,340.55") == "transaction"
    assert rules.looks_like_standard_alert("Hey, lunch tomorrow?") is None


def test_every_rule_group_is_described():
    info = rules.group_info()
    assert len(info) >= 15
    for g in info:
        assert g["title"] and g["explain"] and 0 < g["weight"] <= g["max_weight"] <= 1
