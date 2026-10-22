import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import reporting

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
original = json.loads(source.read_text(encoding="utf-8-sig"))
reviewed = reporting.review_state(original)
labels = {"updated": "آپدیت موفق بر اساس شواهد گزارش", "failed": "ناموفق", "php-not-detected": "PHP شناسایی نشد؛ آپدیت اجرا نشد", "updated-needs-verification": "نیازمند تأیید نسخه", "needs-configuration": "نیازمند تنظیم مسیر نصب"}
lines = ["# بررسی گزارش Patch Desk — ۲۲ اکتبر ۲۰۲۶", "", f"منبع: `{source.name}`. این تحلیل فقط بر اساس شواهد ثبت‌شده است؛ اتصال یا آپدیت جدیدی اجرا نشده و وضعیت فعلی شبکه را تأیید نمی‌کند.", "", "دو برچسب اشتباه ابزار اصلاح شده‌اند: بسته عمومی php-common نسخه PHP نیست؛ نبود PHP قابل‌شناسایی هم به معنی نیاز قطعی به آپدیت نیست. برچسب اولیه در داده بررسی‌شده با reported_status حفظ می‌شود.", ""]
for job in reviewed.get("jobs", []):
    counts = collections.Counter(e["status"] for e in job["servers"].values())
    lines += ["نتیجه بازخوانی: " + "؛ ".join(f"{count} مورد {labels.get(status, status)}" for status, count in counts.items()), "", "| سرور | پورت‌های امتحان‌شده در گزارش | نتیجه / علت | قدم بعدی |", "|---|---|---|---|"]
    for entry in job["servers"].values():
        diagnosis = entry.get("diagnosis") or {}
        ports = ", ".join(map(str, entry["endpoint"].get("ports", [])))
        title = diagnosis.get("title") or labels.get(entry["status"], entry["status"])
        next_step = diagnosis.get("advice") or ("طبق نسخه‌ها و مراحل موفق ثبت‌شده، تکرار آپدیت PHP لازم نیست؛ سلامت فعلی سرویس جداگانه بررسی شود." if entry["status"] == "updated" else "اگر انتظار PHP دارید، نصب سفارشی یا کانتینرهای متوقف باید بررسی شوند؛ نبود PHP در همه مسیرها اثبات نشده است.")
        lines.append(f"| {entry['name']} | {ports} | {title} | {next_step} |")
    print(json.dumps({"reviewed_counts": dict(counts), "failure_kinds": dict(collections.Counter((e.get('diagnosis') or {}).get('kind') for e in job['servers'].values() if e['status']=='failed'))}))
destination.write_text("\n".join(lines)+"\n", encoding="utf-8")
