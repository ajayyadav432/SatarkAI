"""Fill the history with demo cases so the dashboard has something to show.

The messages below were written by hand for the demo. They are NOT real reports and
are NOT used for training or for accuracy numbers. Every case is stored with
source = 'demo-seed' and is shown with a "demo-seed" badge in the app.

Run:  python scripts/seed_demo.py            add the demo cases
      python scripts/seed_demo.py --remove   delete them again
"""
from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import db  # noqa: E402
from app.analysis.pipeline import analyze  # noqa: E402

SOURCE = "demo-seed"

# (channel, sender, text)
SCAMS = [
    ("sms", "9876501234", "Dear customer, your SBI account will be blocked today. Update your KYC immediately: http://sbi-kyc-update.xyz/login"),
    ("sms", "", "Your HDFC Bank NetBanking will be suspended. Re-KYC pending. Click here to update: https://hdfcbank-rekyc.top/verify"),
    ("sms", "8899776655", "ICICI Bank: your PAN card is not updated. Your account will be blocked within 24 hours. Update PAN now https://icici-pan-update.in/kyc"),
    ("sms", "", "Dear Consumer, your electricity power will be disconnected tonight at 9.30 pm because your previous month bill was not updated. Please contact our electricity officer 9876543210 immediately."),
    ("sms", "", "Bijli vibhag: aapka bijli connection aaj raat kat jayega. Bill jama karne ke liye turant call karein 9123456701"),
    ("social", "", "This is Inspector Sharma from CBI. Your Aadhaar is linked to a money laundering case. You are under digital arrest. Join the video call now and do not tell anyone. Transfer Rs 2,00,000 for verification."),
    ("social", "", "Mumbai Cyber Crime Branch: a parcel in your name containing illegal items was seized by customs. Your Aadhaar was misused in a criminal case. Stay on video call for investigation and keep this confidential."),
    ("sms", "", "Congratulations! You have won Rs 25,00,000 in KBC lucky draw. To claim your prize pay processing fee Rs 5,000 to kbcoffice@ybl. Call 8765432109"),
    ("sms", "", "Badhai ho! Aapne lucky draw me iPhone jeeta hai. Inaam claim karne ke liye link par click karein: http://free-gift-winner.click/claim"),
    ("sms", "", "India Post: Your parcel could not be delivered due to incomplete address. Update your address within 12 hours: https://indiapost-redelivery.top/track"),
    ("sms", "", "FedEx: your shipment is on hold at customs. Pay customs clearance fee Rs 149 to release: https://fedex-customs-pay.shop/in"),
    ("sms", "", "Blue Dart: delivery attempt failed. Reschedule your delivery here bit.ly/3bdRedeliv and pay redelivery fee Rs 25"),
    ("social", "", "Hi, I am HR from Amazon. Part time job, work from home. Earn Rs 3000-8000 per day by liking YouTube videos. No experience needed. Contact on WhatsApp: wa.me/919812345678"),
    ("social", "", "We are hiring! Simple tasks on Telegram, daily income Rs 5000. No investment required. Join our Telegram channel t.me/dailytask_earn"),
    ("sms", "", "Your traffic e-challan of Rs 500 is pending. Download the app to pay: http://echallan-parivahan.in/mParivahan.apk"),
    ("sms", "", "Priya grahak, aapka HDFC khata band ho jayega. Turant KYC update karein, link par click karein: hdfc-kyc.co.in/verify"),
    ("sms", "", "प्रिय ग्राहक, आपका एसबीआई खाता आज बंद हो जाएगा। तुरंत केवाईसी अपडेट करने के लिए नीचे दिए गए लिंक पर क्लिक करें: https://sbi-kyc.in/update"),
    ("sms", "", "बधाई हो! आपने 10 लाख रुपये की लॉटरी जीती है। इनाम पाने के लिए अभी कॉल करें 9988776601"),
    ("email", "PayPal Support <service@paypa1-secure.com>", "Subject: Your account has been limited\n\nDear customer,\n\nWe noticed unusual activity in your PayPal account. Your account has been limited. Please log in to verify your identity within 24 hours or your account will be suspended.\n\nhttps://paypa1.com/signin?country=IN\n\nThank you,\nPayPal Security Team"),
    ("email", "Microsoft Account Team <security@rnicrosoft-support.com>", "Subject: Unusual sign-in activity\n\nDear user,\n\nWe detected a suspicious login to your Microsoft account. Verify your identity immediately to avoid your account being locked.\n\nhttps://rnicrosoft.com/login/verify\n\nMicrosoft account team"),
    ("email", "Netflix <billing@netflix-renew.info>", "Subject: Payment declined\n\nDear member,\n\nYour Netflix membership has been suspended because your payment failed. Update your payment details within 48 hours to keep watching.\n\nhttp://netflix-billing.support/account/update\n\nNetflix"),
    ("social", "9123456780", "Hi mum, this is my new number. My phone is broken. Can you send me 15000 urgently? I will return it tomorrow."),
    ("social", "", "Your Netflix payment failed. Update billing at hxxps://netflix-billing[.]support/account to avoid suspension."),
    ("sms", "", "Income Tax Department: you are eligible for a tax refund of Rs 15,490. Submit your bank details to claim your refund: https://incometax-refund.co.in/claim"),
    ("social", "", "Join our VIP group for stock tips. Guaranteed returns of 30% every week. Invest Rs 10,000 and get Rs 50,000 in 7 days. Join our WhatsApp group now: chat.whatsapp.com/Gh3kLmN"),
    ("sms", "", "Your Airtel SIM will be deactivated in 24 hours due to pending verification. Call customer care 9876012345 immediately to avoid disconnection."),
    ("social", "", "Microsoft support: virus detected on your computer. Your PC has been blocked. Install AnyDesk and call tech support on 18005551234 now."),
    ("sms", "", "Pre-approved loan of Rs 5,00,000 is ready. No documents, no CIBIL check. Pay processing fee Rs 999 and get instant loan: instant-loan-approve.online/apply"),
    ("sms", "", "Dear customer, you have received Rs 2,000 cashback. Enter your UPI PIN to receive the amount. Click paytm-cashback-offer.xyz"),
    ("url", "", "https://secure-login.paypal.com.account-verify.top/signin"),
    ("url", "", "http://192.168.45.12:8080/sbi/netbanking/login.php"),
    ("url", "", "https://amaz0n-offers.in/great-indian-sale/claim"),
]

GENUINE = [
    ("sms", "AD-HDFCBK", "482913 is your OTP for transaction of INR 2,499.00 at AMAZON. Do not share it with anyone. -HDFC Bank"),
    ("sms", "VM-SBIBNK", "Rs 5,000.00 debited from A/c XX1234 on 12-Oct-26. Avl Bal Rs 12,340.55. If not you, call 18001234567 -SBI"),
    ("sms", "AX-AMAZON", "Your Amazon order #402-1234567 has been shipped and will arrive tomorrow. Track: https://www.amazon.in/gp/your-account/order-details"),
    ("social", "", "Hey are we still meeting for lunch tomorrow at 1? Let me know"),
    ("social", "", "bhai kal college aa raha hai kya, assignment submit karna hai mujhe bhi bata dena"),
    ("sms", "JM-IRCTCi", "PNR 2345678901, Train 12951, 14-Oct, JP-BCT, B2 34. Chart prepared. Check status at https://www.irctc.co.in"),
    ("email", "rahul.sharma@skit.ac.in", "Subject: Project review meeting\n\nHi team,\n\nPlease find attached the agenda for tomorrow's project review. We will meet at 10 am in the seminar hall. Let me know if you have any questions.\n\nThanks,\nRahul"),
    ("social", "", "Check this article https://www.thehindu.com/sci-tech/technology/ and https://en.wikipedia.org/wiki/Phishing"),
    ("sms", "AD-ICICIB", "Rs 1,250.00 credited to A/c XX9087 on 10-Oct-26 by UPI. Avl Bal Rs 8,412.10 -ICICI Bank"),
    ("social", "", "Happy birthday! Party at my place on Saturday evening, bring your guitar."),
    ("url", "", "https://github.com/scikit-learn/scikit-learn"),
    ("social", "", "Notes for unit 3 are uploaded on the class drive. Exam is on Monday, all the best."),
]


def remove() -> int:
    db.init_db()
    return db.delete_by_source(SOURCE)


def seed() -> int:
    db.init_db()
    removed = db.delete_by_source(SOURCE)
    rng = random.Random(42)
    now = datetime.now(timezone.utc)
    cases = []
    # Each scam appears one to three times, genuine messages once or twice, spread over 30 days.
    for item in SCAMS:
        cases += [item] * rng.choice([1, 1, 2, 3])
    for item in GENUINE:
        cases += [item] * rng.choice([1, 2])
    rng.shuffle(cases)
    count = 0
    for channel, sender, text in cases:
        days_ago = min(29, int(rng.triangular(0, 30, 3)))   # more cases in recent days
        when = now - timedelta(days=days_ago, hours=rng.randint(0, 9), minutes=rng.randint(0, 59))
        result = analyze(text, channel=channel, sender=sender)
        db.save_case(result, source=SOURCE, created_at=when.strftime("%Y-%m-%dT%H:%M:%SZ"))
        count += 1
    print(f"removed {removed} old demo cases, added {count} demo cases (source = '{SOURCE}')")
    return count


if __name__ == "__main__":
    if "--remove" in sys.argv:
        print(f"removed {remove()} demo cases")
    else:
        seed()
