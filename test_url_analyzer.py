
from analyzer.url_analyzer import (
    analyze_website,
    analyze_play_store_url,
    URLAnalysisError,
)

website = input("Enter a public website URL: ").strip()

try:
    result = analyze_website(website)
    print("\nWebsite analysis:")
    print("Hostname:", result["hostname"])
    print("HTTP status:", result["http_status"])
    print("Risk score:", result["risk_score"])
    print("Verdict:", result["verdict"])

    for finding in result["findings"]:
        print(
            finding["name"],
            "-",
            finding["status"],
            "-",
            finding["risk"],
        )

except URLAnalysisError as exc:
    print("Analysis error:", exc)
