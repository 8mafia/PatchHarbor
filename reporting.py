"""Re-evaluate saved evidence; never connect to servers or execute commands."""
import copy
import engine


def review_entry(server, original):
    entry = copy.deepcopy(original)
    entry.setdefault("endpoint", {"host": server.get("host", entry.get("name", "")), "port": server.get("port", 22), "ports": server.get("ports") or [server.get("port", 22)]})
    assessment = entry.get("assessment")
    if assessment:
        assessment["summary"] = engine.assessment_summary(assessment)
        summary = assessment["summary"]
        replacement = None
        if entry.get("status") == "updated-needs-verification" and summary["update_required"] is False:
            replacement = "updated"
        if entry.get("status") == "needs-configuration" and summary["update_required"] is None:
            replacement = "php-not-detected"
        if replacement:
            entry.setdefault("reported_status", entry["status"])
            entry["status"] = replacement
            entry["review_note"] = "برچسب نتیجه بر اساس شواهد ثبت‌شده اصلاح شد؛ اتصال یا دستور جدیدی اجرا نشده است."
    if entry.get("status") == "failed":
        errors = [e for e in entry.get("events", []) if e.get("code")]
        output = "\n".join(e.get("output", "") for e in errors)
        phase = entry.get("phase") or ("connection" if not assessment else errors[0].get("name", "operation") if errors else "operation")
        diagnosis = engine.classify(output, phase)
        if diagnosis["kind"] != "unknown" or not entry.get("diagnosis"):
            entry["diagnosis"] = diagnosis
        entry["failure"] = entry.get("failure") or {"stage": phase, "message": output[-3000:], "changes_started": any("-y " in s.get("command", "") for s in (entry.get("plan") or {}).get("steps", []) if any(e.get("name") == s.get("name") for e in errors))}
    return entry


def review_state(state):
    result = copy.deepcopy(state)
    servers = {s["id"]: s for s in result.get("servers", [])}
    for server in servers.values():
        if server.get("assessment"):
            server["assessment"]["summary"] = engine.assessment_summary(server["assessment"])
    for job in result.get("jobs", []):
        if job.get("status") == "finished":
            job["servers"] = {sid: review_entry(servers.get(sid, {}), entry) for sid, entry in job.get("servers", {}).items()}
    return result
