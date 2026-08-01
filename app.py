from analyzer.apk_parser import analyze_apk
from analyzer.risk_score import calculate_risk
from analyzer.groq_ai import analyze_permissions
from analyzer.pdf_report import generate_pdf
from database import init_db, save_analysis
from database import get_all_analysis
from flask import Flask, render_template, request, send_file
from database import get_statistics

import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/")
def home():
    return render_template("index.html", app_name="App Risk Analyzer")


@app.route("/upload", methods=["POST"])
def upload():

    if "apkfile" not in request.files:
        return "No file selected."

    file = request.files["apkfile"]

    if file.filename == "":
        return "Please choose an APK."

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)

    # Analyze APK
    app_info = analyze_apk(filepath)

    # Calculate Risk
    risk = calculate_risk(app_info["permissions"])

    # AI Analysis
    try:
        ai_report = analyze_permissions(
            app_info["app_name"],
            app_info["permissions"],
            risk["score"]
        )
    except Exception as e:
        ai_report = (
            "AI analysis could not be generated.\n\n"
            f"Reason: {str(e)}"
        )
    save_analysis(app_info, risk)
    # Generate PDF
    pdf_file = generate_pdf(
        app_info,
        risk,
        ai_report
    )

    # Show Result Page
    return render_template(
        "result.html",
        app=app_info,
        risk=risk,
        ai_report=ai_report,
        pdf_file=pdf_file
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

    file = request.args.get("file")

    if not os.path.exists(file):
        return "PDF file not found."

    return send_file(file, as_attachment=True)

@app.route("/history")
def history():

    history = get_all_analysis()
    
    return render_template(
        "history.html",
        history=history
    )

if __name__ == "__main__":
    init_db()
    app.run(debug=True)