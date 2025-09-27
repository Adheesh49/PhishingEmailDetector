import re, json, os, datetime
from urllib.parse import urlparse
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import joblib
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Optional spellchecker
try:
    from spellchecker import SpellChecker
    SPELL_OK = True
    sp = SpellChecker()
except:
    SPELL_OK = False
    sp = None

# Load keywords
BASE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE, "keywords.json"), "r", encoding="utf-8") as f:
    KW = json.load(f)

# Load ML model if available
try:
    ML_MODEL = joblib.load("phish_model.pkl")
    VECTORIZER = joblib.load("vectorizer.pkl")
except:
    ML_MODEL, VECTORIZER = None, None

# ---------------- Helpers ----------------
def extract_urls(text):
    regex = re.compile(r'(https?://[^\s"\']+|www\.[^\s"\']+)', re.I)
    return list(set(regex.findall(text)))

def get_domain(url):
    if not url.lower().startswith("http"):
        url = "http://" + url
    return urlparse(url).netloc.split(":")[0].lower()

def parse_headers(text):
    from_h, subject = "", ""
    for line in text.splitlines():
        if line.lower().startswith("from:"):
            from_h = line.partition(":")[2].strip()
        if line.lower().startswith("subject:"):
            subject = line.partition(":")[2].strip()
    return from_h, subject

def check_spelling(text):
    if not SPELL_OK: return None
    words = re.findall(r"\b[a-zA-Z']{2,}\b", text)
    miss = sp.unknown([w.lower() for w in words[:2000]])
    return {"count": len(miss), "samples": list(miss)[:10]}

# ---------------- Heuristics ----------------
def analyze(text):
    low = text.lower()
    from_h, subject = parse_headers(text)
    urls = extract_urls(text)

    keywords = [kw for kw in KW["phishing_keywords"] if kw in low]

    risky_attach = any(ext in low for ext in KW["risky_extensions"])
    shorteners = [u for u in urls if any(s in u for s in KW["url_shorteners"])]
    non_https = [u for u in urls if u.startswith("http://")]

    mismatches = []
    if "@" in from_h:
        sender_domain = from_h.split("@")[-1].lower()
        for u in urls:
            d = get_domain(u)
            if sender_domain not in d:
                mismatches.append((u, d))

    grammar = 0
    if re.search(r'!{2,}|\?{2,}', text): grammar += 1
    if re.search(r'\b[A-Z]{3,}\b', text): grammar += 1

    score = 0; reasons = []
    if urls: score += 10; reasons.append("Links present")
    if mismatches: score += 25; reasons.append("Domain mismatch")
    if keywords: score += 15; reasons.append("Suspicious keywords found")
    if risky_attach: score += 25; reasons.append("Risky attachment mention")
    if shorteners: score += 15; reasons.append("Shortened URL used")
    if non_https: score += 5; reasons.append("Non-HTTPS links")
    if grammar: score += 8; reasons.append("Grammar anomalies")
    if score > 100: score = 100

    label = "Safe" if score <= 40 else "Suspicious" if score <= 70 else "Likely Phishing"
    return {"label": label, "score": score, "reasons": reasons, "urls": urls,
            "from": from_h, "subject": subject, "keywords": keywords,
            "mismatches": mismatches, "risky_attach": risky_attach,
            "shorteners": shorteners, "non_https": non_https, "grammar": grammar}

# ---------------- ML ----------------
def ml_classify(text):
    if not ML_MODEL: return None, None
    X = VECTORIZER.transform([text])
    pred = ML_MODEL.predict(X)[0]
    conf = round(max(ML_MODEL.predict_proba(X)[0]) * 100, 2)
    label = "Phishing (ML)" if pred == 1 else "Safe (ML)"
    return label, conf

# ---------------- Report ----------------
def build_report(text, heur, ml, spell):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    rep = []
    rep.append(f"Phishing Detector Report — {now}")
    rep.append("="*60)
    rep.append(f"From: {heur['from']}")
    rep.append(f"Subject: {heur['subject']}")
    rep.append(f"Heuristics Result: {heur['label']} (score {heur['score']})")
    if ml[0]:
        rep.append(f"ML Result: {ml[0]} (confidence {ml[1]}%)")

    rep.append("\nReasons:")
    for r in heur['reasons']:
        rep.append(f"- {r}")

    rep.append("\nKeywords: " + (", ".join(heur['keywords']) if heur['keywords'] else "None"))
    rep.append("Links: " + (", ".join(heur['urls']) if heur['urls'] else "None"))

    if heur['mismatches']:
        rep.append("Domain mismatches:")
        for u, d in heur['mismatches']:
            rep.append(f"- {u} vs {d}")

    if spell:
        rep.append(f"\nSpelling mistakes: {spell['count']}, samples: {', '.join(spell['samples'])}")
    else:
        rep.append("\nSpelling check not available.")

    rep.append("\nEducational insights:")
    for r in heur['reasons']:
        if "domain" in r.lower():
            rep.append("- Domain mismatch: sender and link domains differ, a strong phishing sign.")
        if "short" in r.lower():
            rep.append("- Shortened URLs hide the true destination.")
        if "keyword" in r.lower():
            rep.append("- Urgent keywords are designed to pressure victims.")
        if "attach" in r.lower():
            rep.append("- Attachments with risky extensions may carry malware.")
        if "grammar" in r.lower():
            rep.append("- Poor grammar is common in phishing emails.")

    rep.append("\nSuggested action:")
    if heur['label'] == "Safe": rep.append("Likely safe, but stay cautious.")
    elif heur['label'] == "Suspicious": rep.append("Be cautious: verify sender, don’t click unknown links.")
    else: rep.append("Likely phishing: do not click links or open attachments.")

    return "\n".join(rep)

# Save PDF report
def save_report_as_pdf(report_text):
    filename = filedialog.asksaveasfilename(defaultextension=".pdf",
                                            filetypes=[("PDF Files", "*.pdf")])
    if not filename: return
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    y = height - 50
    for line in report_text.splitlines():
        c.drawString(50, y, line)
        y -= 15
        if y < 50:
            c.showPage()
            y = height - 50
    c.save()
    messagebox.showinfo("Saved", f"Report saved as {filename}")

# ---------------- GUI ----------------
class App:
    def __init__(self, root):
        self.root = root
        root.title("Phishing Detector — Heuristics + ML")
        root.geometry("1000x700")
        self.dark_mode = False

        top = tk.Frame(root); top.pack(fill=tk.X, padx=5, pady=5)
        tk.Button(top, text="Open File", command=self.open_file).pack(side=tk.LEFT)
        tk.Button(top, text="Scan", command=self.scan).pack(side=tk.LEFT)
        tk.Button(top, text="Clear", command=self.clear).pack(side=tk.LEFT)
        tk.Button(top, text="Save Report", command=self.save_report).pack(side=tk.LEFT)
        tk.Button(top, text="Toggle Dark Mode", command=self.toggle_dark).pack(side=tk.LEFT)

        pan = tk.Frame(root); pan.pack(fill=tk.BOTH, expand=True)
        self.input = scrolledtext.ScrolledText(pan, width=70, height=30)
        self.input.grid(row=0, column=0, sticky="nsew")
        self.out = scrolledtext.ScrolledText(pan, width=40, height=30, state=tk.DISABLED)
        self.out.grid(row=0, column=1, sticky="nsew")
        pan.grid_columnconfigure(0, weight=3); pan.grid_columnconfigure(1, weight=2)

    def open_file(self):
        p = filedialog.askopenfilename(filetypes=[("Email files", "*.txt *.eml")])
        if not p: return
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            self.input.delete("1.0", tk.END)
            self.input.insert(tk.END, f.read())

    def scan(self):
        text = self.input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("Empty", "No email text provided.")
            return
        heur = analyze(text)
        ml = ml_classify(text)
        spell = check_spelling(text)
        report = build_report(text, heur, ml, spell)

        self.out.configure(state=tk.NORMAL)
        self.out.delete("1.0", tk.END)
        self.out.insert(tk.END, report)
        self.out.configure(state=tk.DISABLED)

    def clear(self):
        self.input.delete("1.0", tk.END)
        self.out.configure(state=tk.NORMAL)
        self.out.delete("1.0", tk.END)
        self.out.configure(state=tk.DISABLED)

    def save_report(self):
        report = self.out.get("1.0", tk.END).strip()
        if not report:
            messagebox.showinfo("Empty", "No report to save.")
            return
        save_report_as_pdf(report)

    def toggle_dark(self):
        self.dark_mode = not self.dark_mode
        bg, fg = ("#2e2e2e", "#ffffff") if self.dark_mode else ("#ffffff", "#000000")
        self.input.configure(bg=bg, fg=fg, insertbackground=fg)
        self.out.configure(state=tk.NORMAL, bg=bg, fg=fg, insertbackground=fg)
        self.out.configure(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
