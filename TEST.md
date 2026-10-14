# SatarkAI test messages

Paste these into the app (http://localhost:8000) to check the detector. Each case gives the message type and
sender to choose, what a person would call it, and what the app actually returned.

All messages were written by hand for testing. Phone numbers, UPI IDs and scam domains are made up.
Do not open the links.

## How the results were measured

- Run on 14 Oct 2026 against the current models and rules, with *Live domain lookup* off and *Save to history* off.
- A case counts as **correct** when a scam scores 40 or more (Medium, High or Critical) and a genuine
  message scores below 40 (Safe or Low).
- Result: **33 of 39 correct**. The 6 misses are listed at the end with the reason the app gave.

If you change the rules (`app/data/patterns.json`) or retrain the models, the scores can change.

## A. Bank and KYC scams

**A1.** Type: SMS · Sender: `VM-ALERTS` · Expected: **scam** · Got: **Critical 99** (Credential phishing) ✅

```text
Dear customer, your SBI YONO account will be suspended today. Update your PAN card immediately: http://sbi-yono-pan-update.top/verify
```

**A2.** Type: SMS · Sender: `9812345670` · Expected: **scam** · Got: **Critical 97** (KYC / account update) ✅

```text
HDFC Bank: Your KYC has expired. Your account will be blocked in 24 hours. Complete KYC here https://hdfc-kyc-online.xyz/login
```

**A3.** Type: SMS · Expected: **scam** · Got: **Critical 96** (Credential phishing) ✅

```text
ICICI: Your net banking is locked due to suspicious activity. Verify your details now at http://icici-secure-verify.click to avoid permanent block.
```

**A4.** Type: E-mail · Sender: `support@paytm-verify-team.com` · Expected: **scam** · Got: **Critical 96** (Credential phishing) ✅

```text
Dear user, your Paytm wallet KYC is pending. Share the OTP sent to your mobile with our executive to complete verification, otherwise your wallet will be closed.
```

## B. Hindi and Hinglish scams

**B1.** Type: SMS · Sender: `9876501234` · Expected: **scam** · Got: **Critical 91** (KYC / account update) ✅

```text
प्रिय ग्राहक, आपका बैंक खाता आज बंद कर दिया जाएगा। तुरंत KYC अपडेट करें: http://bank-kyc-hindi.xyz
```

**B2.** Type: Chat / social · Expected: **scam** · Got: **Critical 97** (KYC / account update) ✅

```text
Aapka SBI account aaj band ho jayega. Turant KYC update karo is link par: http://sbi-kyc-update.online warna paisa nahi nikal paoge
```

**B3.** Type: Chat / social · Expected: **scam** · Got: **High 77** (Lottery / prize scam) ✅

```text
Congratulations! Aapne KBC lucky draw me 25 lakh jeete hain. Prize lene ke liye 12,500 processing fee bhejo is UPI par: kbcwinner@ybl
```

**B4.** Type: SMS · Expected: **scam** · Got: **Critical 86** (Utility bill scam) ✅

```text
आपका बिजली कनेक्शन आज रात 9:30 बजे काट दिया जाएगा क्योंकि पिछले महीने का बिल अपडेट नहीं हुआ है। तुरंत इस नंबर पर कॉल करें 9123456780
```

## C. Digital arrest and authority impersonation

**C1.** Type: Chat / social · Expected: **scam** · Got: **High 71** (Authority impersonation / digital arrest) ✅

```text
This is Inspector Verma from Mumbai Cyber Crime. A parcel with drugs was booked on your Aadhaar. You are under digital arrest. Stay on the video call and transfer Rs 1,50,000 to the RBI verification account or you will be arrested.
```

**C2.** Type: SMS · Expected: **scam** · Got: **Critical 98** (Credential phishing) ✅

```text
Income Tax Department: You are eligible for a refund of Rs 15,490. Submit your bank details at http://incometax-refund-gov.co.in.claim-now.xyz within 24 hours.
```

**C3.** Type: SMS · Expected: **scam** · Got: **High 68** (Authority impersonation / digital arrest) ✅

```text
TRAI notice: Your mobile number will be disconnected in 2 hours due to illegal activity. Press 9 to speak to the officer.
```

## D. Delivery, bills and challans

**D1.** Type: SMS · Expected: **scam** · Got: **Critical 90** (Courier / delivery scam) ✅

```text
India Post: Your parcel is held at our warehouse due to incomplete address. Update within 12 hours: https://indiapost-redelivery.top/track
```

**D2.** Type: SMS · Expected: **scam** · Got: **Critical 92** (Utility bill scam) ✅

```text
Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please immediately contact our electricity officer 9087654321.
```

**D3.** Type: SMS · Expected: **scam** · Got: **Critical 91** (Brand impersonation) ✅

```text
Your vehicle has an unpaid traffic challan of Rs 500. Download the e-Challan app to pay: http://echallan-parivahan.apk-download.xyz/eChallan.apk
```

## E. Jobs, loans, investment

**E1.** Type: Chat / social · Expected: **scam** · Got: **Medium 45** (Job / task scam) ✅

```text
Hello! We are hiring part-time workers. Earn Rs 3000-8000 daily by liking YouTube videos. No experience needed. Contact our HR on Telegram @easyjob_hr
```

**E2.** Type: SMS · Expected: **scam** · Got: **Critical 80** (Loan scam) ✅

```text
Instant loan of Rs 5,00,000 approved without documents! No CIBIL check. Pay only Rs 999 processing fee to get money in 10 minutes: http://instant-loan-approve.online
```

**E3.** Type: Chat / social · Expected: **scam** · Got: **Low 35** (Investment / crypto scam) ❌

```text
Join our VIP stock market WhatsApp group. Guaranteed 300% returns in 30 days. Invest via our trading app, minimum Rs 10,000.
```

## F. Phishing e-mails and fake links

**F1.** Type: E-mail · Sender: `no-reply@netflix-billing.support` · Expected: **scam** · Got: **Critical 99** (Credential phishing) ✅

```text
Your Netflix payment failed. Update your billing information within 24 hours or your membership will be cancelled: https://netflix-billing.support/update
```

**F2.** Type: E-mail · Sender: `security@micros0ft-account.com` · Expected: **scam** · Got: **Critical 99** (Credential phishing) ✅

```text
Microsoft account alert: unusual sign-in activity detected. Verify your password now at https://login.microsoftonline.com.verify-user.xyz/secure
```

**F3.** Type: Link · Expected: **scam** · Got: **Critical 92** (Brand impersonation) ✅

```text
http://paypa1.com/signin?account=verify
```

**F4.** Type: Link · Expected: **scam** · Got: **Critical 93** (Suspicious link) ✅

```text
http://192.168.45.12:8080/sbi/netbanking/login.php
```

**F5.** Type: Link · Expected: **scam** · Got: **Medium 48** (Suspicious link) ✅

```text
https://bit.ly/3xYzKyc
```

**F6.** Type: SMS · Expected: **scam** · Got: **Critical 91** (Brand impersonation) ✅

```text
Your Amazon order is on hold. Confirm payment at hxxp://amazon-order-confirm[.]xyz/pay
```

## G. Family and friend impersonation

**G1.** Type: Chat / social · Expected: **scam** · Got: **Critical 83** (Impersonation of a known person) ✅

```text
Hi Mum, this is my new number, my phone broke. I need to pay a bill urgently, can you send Rs 20,000 to this UPI? I'll return it tomorrow. rahul.help@okaxis
```

**G2.** Type: Chat / social · Expected: **scam** · Got: **High 71** (Impersonation of a known person) ✅

```text
Hello uncle, I am stuck at the airport, my wallet got stolen. Please send 8000 urgently on GPay to this number 9988776655. Don't tell papa.
```

## H. Genuine messages (should stay Safe or Low)

**H1.** Type: SMS · Sender: `AD-HDFCBK` · Expected: **genuine** · Got: **Low 25** (Suspicious message) ✅

```text
123456 is your OTP for transaction of Rs 1,250.00 at AMAZON. Valid for 10 minutes. Do not share this OTP with anyone. -HDFC Bank
```

**H2.** Type: SMS · Sender: `VM-SBIINB` · Expected: **genuine** · Got: **Low 21** (Suspicious message) ✅

```text
Dear Customer, your a/c XX1234 is debited by Rs 500.00 on 14-10-26 by UPI ref 628712345678. If not done by you, call 1800 1234.
```

**H3.** Type: SMS · Sender: `AX-AMAZON` · Expected: **genuine** · Got: **Safe 15** ✅

```text
Your Amazon order #402-1234567 has been shipped and will arrive by Thursday. Track at https://www.amazon.in/your-orders
```

**H4.** Type: Chat / social · Expected: **genuine** · Got: **Safe 0** ✅

```text
Hey, are we still meeting at 6 for dinner? I'll book the table near the station.
```

**H5.** Type: E-mail · Sender: `priya@company.com` · Expected: **genuine** · Got: **Safe 0** ✅

```text
Hi team, please find attached the minutes of today's meeting. The next review is on Monday at 11 AM. Thanks, Priya
```

**H6.** Type: Link · Expected: **genuine** · Got: **Safe 0** ✅

```text
https://www.onlinesbi.sbi
```

**H7.** Type: Link · Expected: **genuine** · Got: **Safe 0** ✅

```text
https://www.irctc.co.in/nget/train-search
```

**H8.** Type: Chat / social · Expected: **genuine** · Got: **Safe 0** ✅

```text
Mummy main ghar 8 baje tak aa jaunga, khana bana ke rakhna.
```

**H9.** Type: SMS · Sender: `JD-AIRTEL` · Expected: **genuine** · Got: **High 60** (Spam / unsolicited message) ❌

```text
Your Airtel bill of Rs 499 is generated. Pay via Airtel Thanks app or https://www.airtel.in before 20 Oct to avoid late fee.
```

## I. Tricky cases (borderline, good for testing limits)

**I1.** Type: SMS · Expected: **scam** · Got: **Low 35** (Suspicious message) ❌

```text
Your account will be blocked. Call customer care now.
```

**I2.** Type: SMS · Expected: **genuine** · Got: **Medium 40** (Utility bill scam) ❌

```text
Reminder: your electricity bill of Rs 1,240 is due on 20 Oct. Pay on the official app or website. Ignore if already paid.
```

**I3.** Type: Chat / social · Expected: **scam** · Got: **Low 25** (Suspicious message) ❌

```text
Bhai urgent hai, 5000 bhej de abhi, kal wapas kar dunga. Ye naya number hai mera.
```

**I4.** Type: SMS · Expected: **genuine** · Got: **Safe 0** ✅

```text
Your OTP for login is 482910. Do not share it with anyone, including bank staff.
```

**I5.** Type: E-mail · Expected: **scam** · Got: **Low 21** (Spam / unsolicited message) ❌

```text
Dear Sir, kindly find the attached invoice for payment. Please process the payment of USD 4,800 to the new bank account mentioned, as our old account is under audit.
```

## Misses and why

| Case | Expected | Got | Reason the app gave |
|---|---|---|---|
| E3 | scam | Low 35 | Only one rule matched (*Promises guaranteed profit*, +35). No link, and the text model did not flag it. |
| H9 | genuine | High 60 | False alarm. The text model (89% scam, +38) and the *Asks you to pay* rule (+35) fired on a normal bill reminder, even though the only link is the official airtel.in. |
| I1 | scam | Low 35 | Very short message with no link. Only *Threatens a loss* (+35) matched. |
| I2 | genuine | Medium 40 | False alarm on the edge: *Utility disconnection threat* (+40) matched the word pattern although the message is polite and gives no number to call. |
| I3 | scam | Low 25 | Only *Creates time pressure* (+25). The text model was skipped (Hinglish words are unknown to it) and no rule covers the 'new number, send money' pattern in Hinglish. |
| I5 | scam | Low 21 | Business e-mail fraud (change of bank account). No rule covers it; only the text model fired weakly (59%, +21). |

These match the known limits in the README: the text models were trained on English SMS and e-mail
from 2006-2012, and Hinglish and India-specific scams depend on hand-written rules.

## Quick checks to try

- Same scam in three languages: A1, B5 and B6 (all KYC).
- Add or remove the sender: paste A2 with sender `9812345670`, then with `AD-HDFCBK`, and compare.
- Ask the assistant (bottom right) after a scan: *Why is this rated Critical?*
- Tick *Live domain lookup* on a link case to see domain age (needs internet; the link itself is not opened).
