#!/usr/bin/env python3
import subprocess
import json
import sys
import csv
from collections import defaultdict

# Ensure tabulate is installed
try:
    from tabulate import tabulate
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "tabulate"])
    from tabulate import tabulate

def get_unique_images():
    cmd = [
        "kubectl", "get", "pods", "--all-namespaces",
        "-o", "jsonpath={range .items[*]}{range .spec.containers[*]}{.image}{\"\\n\"}{end}{end}"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return sorted(set(filter(None, result.stdout.splitlines())))

def scan_image(image):
    try:
        proc = subprocess.run(
            ["grype", image, "-o", "json"],
            capture_output=True, text=True, check=True
        )
        data = json.loads(proc.stdout)
        return data.get("matches", [])
    except subprocess.CalledProcessError:
        print(f"[!] Warning: failed to scan {image}", file=sys.stderr)
        return []

def summarize(matches):
    cnt = defaultdict(int)
    for m in matches:
        sev = m.get("vulnerability", {}).get("severity", "").capitalize()
        if sev in ("Critical", "High", "Medium", "Low"):
            cnt[sev] += 1
    return cnt

def main():
    images = get_unique_images()
    if not images:
        print("No images found.", file=sys.stderr)
        sys.exit(1)

    total = defaultdict(int)
    per_image = []

    # scan each image, show progress, accumulate totals and prepare CSV rows
    for img in images:
        print(f"🚀 Scanning: {img}")
        matches = scan_image(img)
        s = summarize(matches)
        for sev in ("Critical", "High", "Medium", "Low"):
            total[sev] += s.get(sev, 0)
        per_image.append({
            "Image": img,
            "Critical": s.get("Critical", 0),
            "High":     s.get("High", 0),
            "Medium":   s.get("Medium", 0),
            "Low":      s.get("Low", 0),
        })

    # print only the cumulative summary
    summary = [[
        total.get("Critical", 0),
        total.get("High",     0),
        total.get("Medium",   0),
        total.get("Low",      0),
    ]]
    print("\n📊 Total Vulnerability Summary:")
    print(tabulate(summary,
                   headers=["Critical", "High", "Medium", "Low"],
                   tablefmt="grid"))

    # write per-image CSV
    csv_file = "grype-per-image-report.csv"
    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["Image", "Critical", "High", "Medium", "Low"])
        writer.writeheader()
        writer.writerows(per_image)

    print(f"\n✅ Per-image details written to: {csv_file}")

if __name__ == "__main__":
    main()