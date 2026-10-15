"""Case report as a PDF, built from an analysis result (a saved case, a feed post or a fresh scan).

Noto Sans with Noto Sans Devanagari as fallback, and HarfBuzz text shaping, so Hindi messages print
correctly. Links are written in their safe form (hxxp://bad[.]site) so a PDF viewer cannot make them
clickable.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from app import config

LEVEL_RGB = {"Safe": (22, 163, 74), "Low": (107, 114, 128), "Medium": (217, 140, 10),
             "High": (230, 100, 50), "Critical": (220, 53, 69)}
INK, MUTED, ACCENT = (11, 31, 24), (98, 122, 112), (5, 150, 105)
CHANNEL = {"sms": "SMS", "email": "E-mail", "social": "Chat / social", "url": "Link"}


def _defang(text: str, urls: list[dict]) -> str:
    for u in urls:
        if u.get("raw") and u.get("display"):
            text = text.replace(u["raw"], u["display"])
    for u in urls:
        if u.get("registered_domain"):
            text = text.replace(u["registered_domain"], u["registered_domain"].replace(".", "[.]"))
    # Anything still looking like a web address is broken up too.
    return text.replace("http://", "hxxp://").replace("https://", "hxxps://").replace("www.", "www[.]")


class _Report(FPDF):
    def footer(self):
        self.set_y(-14)
        self.set_font("Noto", size=8)
        self.set_text_color(*MUTED)
        self.cell(0, 6, f"{config.APP_NAME} · automated offline analysis, not legal evidence · "
                        f"page {self.page_no()}/{{nb}}", align="C")


def build(result: dict, title: str, subtitle: str = "") -> bytes:
    pdf = _Report(format="A4")
    pdf.set_margins(16, 16, 16)
    pdf.set_auto_page_break(True, margin=18)
    for style, f in (("", "NotoSans-Regular.ttf"), ("B", "NotoSans-Bold.ttf")):
        pdf.add_font("Noto", style, str(config.FONTS_DIR / f))
    for style, f in (("", "NotoSansDevanagari-Regular.ttf"), ("B", "NotoSansDevanagari-Bold.ttf")):
        pdf.add_font("NotoDeva", style, str(config.FONTS_DIR / f))
    pdf.set_fallback_fonts(["NotoDeva"])
    pdf.set_text_shaping(True)
    pdf.set_title(f"{config.APP_NAME} {title}")
    pdf.set_author(config.APP_NAME)
    pdf.add_page()
    w = pdf.epw

    def text(s, size=10, style="", color=INK, h=5.2):
        pdf.set_font("Noto", style, size)
        pdf.set_text_color(*color)
        pdf.multi_cell(w, h, s, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def heading(s):
        pdf.ln(3)
        text(s.upper(), 9, "B", MUTED)
        pdf.ln(0.5)

    # Title
    text(f"{config.APP_NAME} case report", 18, "B", ACCENT, 8)
    generated = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    text(" · ".join(x for x in (title, subtitle, f"generated {generated}") if x), 9, color=MUTED)
    pdf.ln(3)

    # Verdict box
    rgb = LEVEL_RGB.get(result["level"], INK)
    top = pdf.get_y()
    pdf.set_fill_color(*rgb)
    pdf.rect(pdf.l_margin, top, w, 24, style="F")
    pdf.set_xy(pdf.l_margin + 5, top + 3)
    pdf.set_font("Noto", "B", 20)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(w - 10, 9, f"{result['level']}  {result['score']}/100", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_x(pdf.l_margin + 5)
    pdf.set_font("Noto", "", 10)
    category = result.get("category")
    pdf.multi_cell(w - 10, 5, (f"{category} · " if category and category != "None" else "") + result.get("summary", ""))
    pdf.set_y(top + 27)
    if result.get("history_raised"):
        text(f"This message alone: {result['own_level']} {result['own_score']}. The score is higher because of this "
             "sender's earlier risky messages.", 9, color=MUTED)

    urls = result.get("urls") or []
    heading("Message")
    meta = [f"Received as: {CHANNEL.get(result.get('channel'), result.get('channel', ''))}"]
    if result.get("sender"):
        meta.insert(0, f"Sender: {result['sender']}")
    text("   ".join(meta), 9, color=MUTED)
    pdf.ln(1)
    pdf.set_fill_color(238, 244, 241)
    pdf.set_font("Noto", "", 10)
    pdf.set_text_color(*INK)
    pdf.multi_cell(w, 5.4, _defang(result.get("text", ""), urls), fill=True, padding=3,
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    factors = result.get("factors") or []
    if factors:
        heading("Why this level")
        for f in factors:
            pts = f.get("points")
            text(f"+{pts}  {f['title']}" if pts is not None else f["title"], 10, "B")
            if f.get("detail"):
                text(_defang(f["detail"], urls), 9, color=MUTED, h=4.6)
            pdf.ln(1)
        text("Score = 100 × [1 − (1 − w1)(1 − w2)…], each weight w between 0 and 1.", 8, color=MUTED)

    if urls:
        heading("Links found (safe form, do not open)")
        for u in urls:
            text(f"{u['display']}   {u['level']} {u['score']}", 10)

    ent = result.get("entities") or {}
    rows = [("Phone numbers", ent.get("phones")), ("UPI IDs", ent.get("upi_ids")), ("E-mail addresses", ent.get("emails")),
            ("Amounts", ent.get("amounts")), ("Organisations named", result.get("brands"))]
    rows = [(k, v) for k, v in rows if v]
    if rows:
        heading("Indicators")
        for k, v in rows:
            text(f"{k}: {', '.join(v)}", 10)

    if result.get("advice"):
        heading("What to do")
        for a in result["advice"]:
            text(f"•  {a}", 10)

    heading("Report a scam in India")
    text("National Cyber Crime Reporting Portal: cybercrime.gov.in   ·   Helpline: 1930 (call at once if money was lost)", 10)
    return bytes(pdf.output())
