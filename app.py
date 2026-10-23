
import os
import time

from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

from analyzer.apk_parser import analyze_apk
from analyzer.risk_score import calculate_risk
from analyzer.groq_ai import analyze_permissions
from analyzer.pdf_report import generate_pdf
from analyzer.url_analyzer import (
    URLAnalysisError,
    analyze_website,
    analyze_play_store_url,
    download_apk_from_url,
)

from database import (
    init_db,
    save_analysis,
    get_all_analysis,
    get_statistics,
)


app = Flask(__name__)

# Initialize the database
init_db()

# Upload configuration
UPLOAD_FOLDER = os.path.abspath("uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/")
def home():
    return render_template(
        "index.html",
        app_name="App Risk Analyzer"
    )


def process_apk(filepath):
    """Run the existing APK analysis pipeline and display its results."""

    total_start = time.perf_counter()

    # Step 1: Analyze APK
    start = time.perf_counter()
    app_info = analyze_apk(filepath)

    print(
        f"[TIMING] APK parsing: "
        f"{time.perf_counter() - start:.2f}s"
    )

    # Step 2: Calculate risk score
    start = time.perf_counter()
    risk = calculate_risk(app_info["permissions"])

    print(
        f"[TIMING] Risk calculation: "
        f"{time.perf_counter() - start:.2f}s"
    )

    # Step 3: Generate AI security report
    start = time.perf_counter()

    try:
        ai_report = analyze_permissions(
            app_info["app_name"],
            app_info["permissions"],
            risk["score"]
        )
    except Exception:
        app.logger.exception("AI analysis failed")
        ai_report = (
            "AI analysis could not be generated.\n\n"
            "Please try again later. The APK analysis "
            "and risk score may still be available."
        )

    print(
        f"[TIMING] AI report: "
        f"{time.perf_counter() - start:.2f}s"
    )

    # Step 4: Save analysis to database
    start = time.perf_counter()
    save_analysis(app_info, risk)

    print(
        f"[TIMING] Database save: "
        f"{time.perf_counter() - start:.2f}s"
    )

    # Step 5: Generate PDF report
    start = time.perf_counter()
    pdf_file = generate_pdf(app_info, risk, ai_report)

    print(
        f"[TIMING] PDF generation: "
        f"{time.perf_counter() - start:.2f}s"
    )

    print(
        f"[TIMING] TOTAL: "
        f"{time.perf_counter() - total_start:.2f}s"
    )

    # Step 6: Display results
    return render_template(
        "result.html",
        app=app_info,
        risk=risk,
        ai_report=ai_report,
        pdf_file=pdf_file
    )


@app.route("/upload", methods=["POST"])
def upload():
    # Validate uploaded file
    if "apkfile" not in request.files:
        return "No file selected.", 400

    file = request.files["apkfile"]

    if file.filename == "":
        return "Please choose an APK.", 400

    if not file.filename.lower().endswith(".apk"):
        return "Only APK files are allowed.", 400

    filename = secure_filename(file.filename)

    if not filename:
        return "Invalid filename.", 400

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    try:
        start = time.perf_counter()
        file.save(filepath)

        print(
            f"[TIMING] Save APK: "
            f"{time.perf_counter() - start:.2f}s"
        )

        return process_apk(filepath)

    except Exception:
        app.logger.exception("APK analysis failed")
        return (
            "An error occurred while analyzing the APK. "
            "Please check the Flask terminal for details."
        ), 500


@app.route("/analyze-url", methods=["POST"])
def analyze_url():
    analysis_type = request.form.get("analysis_type", "").strip()
    url = request.form.get("url", "").strip()

    if analysis_type not in ("website", "play_store", "apk_url"):
        return (
            "Invalid analysis type. Please select a valid option.",
            400
        )

    if not url:
        return render_template(
            "url_result.html",
            result=None,
            error="Please enter a URL.",
            analysis_type=analysis_type
        ), 400

    # Website security-header analysis
    if analysis_type == "website":
        try:
            result = analyze_website(url)

            return render_template(
                "url_result.html",
                result=result,
                error=None,
                analysis_type=analysis_type
            )

        except URLAnalysisError as exc:
            return render_template(
                "url_result.html",
                result=None,
                error=str(exc),
                analysis_type=analysis_type
            ), 400

        except Exception:
            app.logger.exception("Website analysis failed")
            return render_template(
                "url_result.html",
                result=None,
                error="Website analysis failed. Check the Flask terminal for details.",
                analysis_type=analysis_type
            ), 500

    # Google Play Store listing inspection
    if analysis_type == "play_store":
        try:
            result = analyze_play_store_url(url)

            return render_template(
                "url_result.html",
                result=result,
                error=None,
                analysis_type=analysis_type
            )

        except URLAnalysisError as exc:
            return render_template(
                "url_result.html",
                result=None,
                error=str(exc),
                analysis_type=analysis_type
            ), 400

        except Exception:
            app.logger.exception("Play Store analysis failed")
            return render_template(
                "url_result.html",
                result=None,
                error="Play Store inspection failed. Check the Flask terminal for details.",
                analysis_type=analysis_type
            ), 500

    # Direct APK URL: download temporarily and reuse the APK pipeline
    temporary_apk = None

    try:
        temporary_apk = download_apk_from_url(
            url,
            app.config["UPLOAD_FOLDER"]
        )

        return process_apk(temporary_apk)

    except URLAnalysisError as exc:
        return render_template(
            "url_result.html",
            result=None,
            error=str(exc),
            analysis_type=analysis_type
        ), 400

    except Exception:
        app.logger.exception("APK URL analysis failed")
        return render_template(
            "url_result.html",
            result=None,
            error="The APK URL could not be analyzed. Check the Flask terminal for details.",
            analysis_type=analysis_type
        ), 500

    finally:
        # Remove only the temporary download. Keep generated PDF reports.
        if temporary_apk and os.path.isfile(temporary_apk):
            try:
                os.remove(temporary_apk)
            except OSError:
                app.logger.exception(
                    "Could not remove temporary APK file"
                )


@app.route("/dashboard")
def dashboard():
    stats = get_statistics()

    return render_template(
        "dashboard.html",
        stats=stats
    )


@app.route("/download")
def download():
    file = request.args.get("file", "")

    if not file:
        return "PDF filename is missing.", 400

    upload_dir = os.path.realpath(
        app.config["UPLOAD_FOLDER"]
    )
    requested_file = os.path.realpath(file)

    try:
        if os.path.commonpath(
            [upload_dir, requested_file]
        ) != upload_dir:
            return "Invalid file path.", 400
    except ValueError:
        return "Invalid file path.", 400

    if not os.path.isfile(requested_file):
        return "PDF file not found.", 404

    return send_file(
        requested_file,
        as_attachment=True
    )


@app.route("/history")
def history():
    history_records = get_all_analysis()

    return render_template(
        "history.html",
        history=history_records
    )


if __name__ == "__main__":
    app.run(debug=True)
