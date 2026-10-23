
import ipaddress
import json
import os
import re
import socket
import tempfile
import time
from html import unescape
from urllib.parse import parse_qs, urljoin, urlparse

import requests


MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_HTML_BYTES = 2 * 1024 * 1024  # 2 MB
REQUEST_TIMEOUT = (5, 15)
MAX_REDIRECTS = 5

USER_AGENT = "AppRiskAnalyzer/1.0 (security assessment)"


class URLAnalysisError(Exception):
    """Raised when a URL cannot be analyzed safely."""


# ---------------------------------------------------------
# 1. URL VALIDATION
# ---------------------------------------------------------

def _validate_public_url(url):
    """Validate HTTP(S) URLs and reject private destinations."""

    if not isinstance(url, str) or not url.strip():
        raise URLAnalysisError("Please enter a valid URL.")

    url = url.strip()

    if len(url) > 2048:
        raise URLAnalysisError("The URL is too long.")

    if any(ord(char) < 32 for char in url):
        raise URLAnalysisError("The URL contains invalid characters.")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise URLAnalysisError("The URL contains an invalid host or port.") from exc

    if parsed.scheme not in ("http", "https"):
        raise URLAnalysisError("Only HTTP and HTTPS URLs are supported.")

    if not hostname:
        raise URLAnalysisError("The URL does not contain a valid hostname.")

    if parsed.username or parsed.password:
        raise URLAnalysisError("URLs containing credentials are not allowed.")

    if port is not None and not (1 <= port <= 65535):
        raise URLAnalysisError("The URL contains an invalid port.")

    hostname = hostname.rstrip(".").lower()

    if (
        hostname == "localhost"
        or hostname.endswith(".localhost")
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
    ):
        raise URLAnalysisError(
            "Local or internal hostnames are not allowed."
        )

    try:
        literal_ip = ipaddress.ip_address(hostname)

        if not literal_ip.is_global:
            raise URLAnalysisError(
                "Private, local, and reserved IP addresses are not allowed."
            )

    except ValueError:
        # The hostname is not a literal IP address.
        pass

    try:
        addresses = socket.getaddrinfo(
            hostname,
            port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise URLAnalysisError(
            "The hostname could not be resolved."
        ) from exc

    if not addresses:
        raise URLAnalysisError("The hostname could not be resolved.")

    for address in addresses:
        try:
            resolved_ip = ipaddress.ip_address(address[4][0])
        except ValueError as exc:
            raise URLAnalysisError(
                "The hostname resolved to an invalid IP address."
            ) from exc

        if not resolved_ip.is_global:
            raise URLAnalysisError(
                "The URL resolves to a private or non-public IP address."
            )

    return url


# ---------------------------------------------------------
# 2. SAFE HTTP REQUESTS AND REDIRECTS
# ---------------------------------------------------------

def _safe_get(url, stream=False):
    """
    Follow redirects manually and validate every destination.

    TLS certificate verification remains enabled.
    """

    current_url = _validate_public_url(url)

    for _ in range(MAX_REDIRECTS + 1):
        try:
            response = requests.get(
                current_url,
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                stream=stream,
                verify=True,
            )
        except requests.RequestException as exc:
            raise URLAnalysisError(
                f"Could not retrieve the URL: {exc}"
            ) from exc

        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location")
            response.close()

            if not location:
                raise URLAnalysisError(
                    "The server returned a redirect without a destination."
                )

            current_url = _validate_public_url(
                urljoin(current_url, location)
            )
            continue

        return response

    raise URLAnalysisError("The URL exceeded the redirect limit.")


# ---------------------------------------------------------
# 3. GOOGLE PLAY STORE URL PARSING
# ---------------------------------------------------------

def _get_play_store_id(url):
    """Extract the package ID from a Google Play listing URL."""

    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise URLAnalysisError("Invalid Google Play URL.") from exc

    hostname = (parsed.hostname or "").lower()

    if hostname not in ("play.google.com", "www.play.google.com"):
        return None

    if parsed.path.rstrip("/") != "/store/apps/details":
        return None

    package_id = parse_qs(parsed.query).get("id", [None])[0]

    if not package_id:
        raise URLAnalysisError(
            "The Google Play URL does not contain an app package ID."
        )

    if (
        len(package_id) > 255
        or not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_id)
    ):
        raise URLAnalysisError(
            "The Google Play URL contains an invalid package ID."
        )

    return package_id


# ---------------------------------------------------------
# 4. WEBSITE SECURITY ANALYSIS
# ---------------------------------------------------------

def analyze_website(url):
    """Inspect basic, publicly observable website security signals."""

    url = _validate_public_url(url)
    started = time.perf_counter()

    response = _safe_get(url)

    try:
        parsed = urlparse(response.url)
        headers = response.headers
        is_https = parsed.scheme == "https"

        security_headers = {
            "Strict-Transport-Security": (
                "strict-transport-security",
                "Recommended for HTTPS sites.",
            ),
            "Content-Security-Policy": (
                "content-security-policy",
                "Helps restrict content and script sources.",
            ),
            "X-Content-Type-Options": (
                "x-content-type-options",
                "Helps prevent MIME-type sniffing.",
            ),
            "X-Frame-Options": (
                "x-frame-options",
                "Helps mitigate clickjacking.",
            ),
            "Referrer-Policy": (
                "referrer-policy",
                "Controls referrer information.",
            ),
            "Permissions-Policy": (
                "permissions-policy",
                "Restricts selected browser features.",
            ),
        }

        findings = []

        findings.append({
            "name": "HTTPS",
            "status": "Present" if is_https else "Missing",
            "risk": "Low" if is_https else "High",
            "details": (
                "The final URL uses HTTPS."
                if is_https
                else (
                    "The final URL uses HTTP. Data may be transmitted "
                    "without transport encryption."
                )
            ),
        })

        if response.status_code >= 500:
            http_risk = "Medium"
            http_details = "The server returned a 5xx response."
        elif response.status_code >= 400:
            http_risk = "Medium"
            http_details = "The server returned a 4xx response."
        else:
            http_risk = "Low"
            http_details = "HTTP status observed during inspection."

        findings.append({
            "name": "HTTP response",
            "status": str(response.status_code),
            "risk": http_risk,
            "details": http_details,
        })

        for label, (header_name, description) in security_headers.items():
            present = bool(headers.get(header_name))

            # HSTS is meaningful only when delivered over HTTPS.
            if label == "Strict-Transport-Security" and not is_https:
                present = False

            findings.append({
                "name": label,
                "status": "Present" if present else "Missing",
                "risk": "Low" if present else "Medium",
                "details": (
                    f"{description} Header found."
                    if present
                    else f"{description} Header not found in this response."
                ),
            })

        score = 0

        for finding in findings:
            if finding["risk"] == "High":
                score += 25
            elif finding["risk"] == "Medium":
                score += 8

        score = min(score, 100)

        if score >= 70:
            verdict = "High Risk"
        elif score >= 40:
            verdict = "Medium Risk"
        else:
            verdict = "Low Risk"

        return {
            "analysis_type": "website",
            "url": url,
            "final_url": response.url,
            "hostname": parsed.hostname,
            "http_status": response.status_code,
            "is_https": is_https,
            "risk_score": score,
            "verdict": verdict,
            "findings": findings,
            "duration_seconds": round(
                time.perf_counter() - started, 2
            ),
            "limitations": (
                "This is a basic response-header and transport inspection. "
                "It does not perform a penetration test, audit website source "
                "code, or prove that a website is safe or malicious. "
                "A missing header alone does not prove a vulnerability."
            ),
        }

    finally:
        response.close()


# ---------------------------------------------------------
# 5. GOOGLE PLAY STORE METADATA EXTRACTION
# ---------------------------------------------------------

def analyze_play_store_url(url):
    """
    Inspect publicly available Google Play listing metadata.

    This does not download or analyze the app's APK.
    """

    url = _validate_public_url(url)
    package_id = _get_play_store_id(url)

    if not package_id:
        raise URLAnalysisError(
            "This is not a supported Google Play Store app listing URL."
        )

    started = time.perf_counter()
    response = _safe_get(url)

    try:
        if response.status_code >= 400:
            raise URLAnalysisError(
                f"The app listing returned HTTP {response.status_code}."
            )

        # Read a bounded amount of HTML instead of loading an unlimited page.
        html_parts = []
        total_bytes = 0

        for chunk in response.iter_content(chunk_size=16 * 1024):
            if not chunk:
                continue

            remaining = MAX_HTML_BYTES - total_bytes

            if remaining <= 0:
                break

            chunk = chunk[:remaining]
            html_parts.append(chunk)
            total_bytes += len(chunk)

            if total_bytes >= MAX_HTML_BYTES:
                break

        html = b"".join(html_parts).decode(
            response.encoding or "utf-8",
            errors="replace",
        )

        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "html.parser")

        def clean_text(value):
            if not isinstance(value, str):
                return ""

            value = unescape(value)
            return re.sub(r"\s+", " ", value).strip()

        def find_meta(*selectors):
            for selector in selectors:
                tag = soup.select_one(selector)

                if tag:
                    content = clean_text(
                        tag.get("content", "")
                        or tag.get_text(" ", strip=True)
                    )

                    if content:
                        return content

            return ""

        # First attempt: standard HTML metadata.
        app_name = find_meta(
            'meta[itemprop="name"]',
            'meta[property="og:title"]',
            'meta[name="twitter:title"]',
        )

        description = find_meta(
            'meta[name="description"]',
            'meta[property="og:description"]',
            'meta[name="twitter:description"]',
        )

        developer = find_meta(
            'meta[name="author"]',
            'meta[property="og:site_name"]',
        )

        # Second attempt: structured JSON-LD metadata.
        for script in soup.find_all(
            "script",
            attrs={"type": "application/ld+json"},
        ):
            try:
                raw_json = script.string or script.get_text()
                data = json.loads(raw_json)
            except (json.JSONDecodeError, TypeError):
                continue

            objects = data if isinstance(data, list) else [data]

            for item in objects:
                if not isinstance(item, dict):
                    continue

                if not app_name:
                    candidate = item.get("name")

                    if isinstance(candidate, str):
                        app_name = clean_text(candidate)

                if not description:
                    candidate = item.get("description")

                    if isinstance(candidate, str):
                        description = clean_text(candidate)

                if not developer:
                    author = item.get("author")

                    if isinstance(author, dict):
                        developer = clean_text(author.get("name", ""))
                    elif isinstance(author, str):
                        developer = clean_text(author)

        # Third attempt: page title, but reject generic Google Play titles.
        if not app_name and soup.title:
            page_title = clean_text(
                soup.title.get_text(" ", strip=True)
            )

            generic_titles = {
                "google play",
                "google play store",
                "apps on google play",
            }

            if (
                page_title
                and page_title.lower() not in generic_titles
                and package_id.lower() not in page_title.lower()
            ):
                app_name = page_title

        app_name = app_name or (
            "Not available from public listing HTML"
        )

        description = description or (
            "No description was available in the returned HTML."
        )

        developer = developer or "Not available"

        findings = [
            {
                "name": "Listing accessibility",
                "status": "Accessible",
                "risk": "Informational",
                "details": "The listing page was reachable.",
            },
            {
                "name": "Package ID",
                "status": package_id,
                "risk": "Informational",
                "details": "Package identifier extracted from the URL.",
            },
            {
                "name": "App name extraction",
                "status": (
                    "Extracted"
                    if app_name != (
                        "Not available from public listing HTML"
                    )
                    else "Unavailable"
                ),
                "risk": "Informational",
                "details": app_name,
            },
            {
                "name": "Developer extraction",
                "status": (
                    "Extracted"
                    if developer != "Not available"
                    else "Unavailable"
                ),
                "risk": "Informational",
                "details": developer,
            },
            {
                "name": "Description extraction",
                "status": (
                    "Extracted"
                    if description != (
                        "No description was available in the returned HTML."
                    )
                    else "Unavailable"
                ),
                "risk": "Informational",
                "details": description[:300],
            },
            {
                "name": "Internal app analysis",
                "status": "Not performed",
                "risk": "Informational",
                "details": (
                    "Listing metadata does not expose the APK's internal "
                    "code and cannot verify the application's security."
                ),
            },
        ]

        return {
            "analysis_type": "play_store",
            "url": url,
            "final_url": response.url,
            "package_id": package_id,
            "app_name": app_name,
            "developer": developer,
            "description": description[:1000],
            "http_status": response.status_code,
            "risk_score": None,
            "verdict": "Listing inspected — app security not verified",
            "findings": findings,
            "duration_seconds": round(
                time.perf_counter() - started, 2
            ),
            "limitations": (
                "Metadata extraction depends on the HTML returned by "
                "Google Play. Dynamic rendering or access restrictions "
                "may cause some fields to be unavailable. This inspection "
                "does not analyze the APK or verify app security."
            ),
        }

    finally:
        response.close()


# ---------------------------------------------------------
# 6. DIRECT APK DOWNLOAD
# ---------------------------------------------------------

def download_apk_from_url(url, destination_dir=None):
    """
    Download a direct APK URL to a temporary file.

    The caller must analyze the resulting file and remove it afterward.
    """

    url = _validate_public_url(url)
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise URLAnalysisError(
            "Direct APK downloads must use HTTPS."
        )

    if destination_dir is not None:
        os.makedirs(destination_dir, exist_ok=True)

    response = _safe_get(url, stream=True)
    temp_path = None

    try:
        if response.status_code != 200:
            raise URLAnalysisError(
                f"APK download returned HTTP {response.status_code}."
            )

        content_type = response.headers.get(
            "Content-Type", ""
        ).lower()

        if "text/html" in content_type:
            raise URLAnalysisError(
                "This URL returned a web page, not a direct APK download."
            )

        content_length = response.headers.get("Content-Length")

        if content_length:
            try:
                if int(content_length) > MAX_DOWNLOAD_BYTES:
                    raise URLAnalysisError(
                        "The APK exceeds the 100 MB download limit."
                    )
            except ValueError:
                pass

        file_descriptor, temp_path = tempfile.mkstemp(
            suffix=".apk",
            dir=destination_dir,
        )

        total_bytes = 0

        with os.fdopen(file_descriptor, "wb") as output:
            for chunk in response.iter_content(
                chunk_size=64 * 1024
            ):
                if not chunk:
                    continue

                total_bytes += len(chunk)

                if total_bytes > MAX_DOWNLOAD_BYTES:
                    raise URLAnalysisError(
                        "The APK exceeds the 100 MB download limit."
                    )

                output.write(chunk)

        if total_bytes == 0:
            raise URLAnalysisError(
                "The downloaded file is empty."
            )

        with open(temp_path, "rb") as downloaded_file:
            signature = downloaded_file.read(4)

        if signature != b"PK\x03\x04":
            raise URLAnalysisError(
                "The downloaded file does not look like a ZIP-based APK."
            )

        return temp_path

    except Exception:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        raise

    finally:
        response.close()
