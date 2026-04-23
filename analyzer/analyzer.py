import json
import os
import re
from datetime import datetime
from analyzer.patterns import FAILED_LOGIN_KEYWORDS, WARNING_KEYWORDS, ERROR_KEYWORDS

IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"

def extract_ip(line):
    match = re.search(IP_REGEX, line)
    return match.group(0) if match else None

def detect_severity(failed_count):
    if failed_count >= 5:
        return "HIGH"
    if failed_count >= 3:
        return "MEDIUM"
    if failed_count >= 1:
        return "LOW"
    return "NONE"

def analyze_log_file(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    failed_login_count = 0
    warning_count = 0
    error_count = 0
    ip_failures = {}
    suspicious_entries = []

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            lower_line = line.lower()

            if any(keyword in lower_line for keyword in FAILED_LOGIN_KEYWORDS):
                failed_login_count += 1
                ip = extract_ip(line)

                if ip:
                    ip_failures[ip] = ip_failures.get(ip, 0) + 1

                suspicious_entries.append({
                    "type": "failed_login",
                    "line": line.strip(),
                    "ip": ip
                })

            elif any(keyword in lower_line for keyword in WARNING_KEYWORDS):
                warning_count += 1
                suspicious_entries.append({
                    "type": "warning",
                    "line": line.strip(),
                    "ip": extract_ip(line)
                })

            elif any(keyword in lower_line for keyword in ERROR_KEYWORDS):
                error_count += 1
                suspicious_entries.append({
                    "type": "error",
                    "line": line.strip(),
                    "ip": extract_ip(line)
                })

    flagged_ips = []
    for ip, count in ip_failures.items():
        flagged_ips.append({
            "ip": ip,
            "failed_attempts": count,
            "severity": detect_severity(count)
        })

    flagged_ips.sort(key=lambda x: x["failed_attempts"], reverse=True)

    summary = {
        "failed_login_count": failed_login_count,
        "warning_count": warning_count,
        "error_count": error_count,
        "unique_suspicious_ips": len(ip_failures)
    }

    return {
        "summary": summary,
        "flagged_ips": flagged_ips,
        "suspicious_entries": suspicious_entries
    }

def save_report(data):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"results/log_report_{timestamp}.json"

    with open(filename, "w", encoding="utf-8") as report_file:
        json.dump(data, report_file, indent=4)

    print(f"\nReport saved to: {filename}")

def print_report(data):
    print("\nSecurity Log Analysis Report")
    print("=" * 40)

    print("\nSummary")
    print("-" * 20)
    for key, value in data["summary"].items():
        print(f"{key.replace('_', ' ').title()}: {value}")

    print("\nFlagged IPs")
    print("-" * 20)
    if data["flagged_ips"]:
        for item in data["flagged_ips"]:
            print(
                f"IP: {item['ip']} | Failed Attempts: {item['failed_attempts']} | Severity: {item['severity']}"
            )
    else:
        print("No suspicious IPs found.")

def main():
    print("Log Analyzer / Security Alert Tool")
    print("=" * 40)

    log_path = input("Enter log file path (example logs/sample_auth.log): ").strip()

    results = analyze_log_file(log_path)
    print_report(results)
    save_report(results)

if __name__ == "__main__":
    main()