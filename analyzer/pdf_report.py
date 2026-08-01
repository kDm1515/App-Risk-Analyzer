from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import os

styles = getSampleStyleSheet()


def generate_pdf(app_info, risk, ai_report):

    os.makedirs("reports", exist_ok=True)

    filename = f"reports/{app_info['app_name']}_Report.pdf"

    doc = SimpleDocTemplate(filename)

    story = []

    story.append(Paragraph("<b>App Risk Analyzer Report</b>", styles["Heading1"]))

    story.append(Paragraph(f"<b>App Name:</b> {app_info['app_name']}", styles["BodyText"]))
    story.append(Paragraph(f"<b>Package:</b> {app_info['package_name']}", styles["BodyText"]))
    story.append(Paragraph(f"<b>Version:</b> {app_info['version_name']}", styles["BodyText"]))

    story.append(Paragraph("<br/>", styles["BodyText"]))

    story.append(Paragraph(f"<b>Risk Score:</b> {risk['score']}/100", styles["BodyText"]))
    story.append(Paragraph(f"<b>Verdict:</b> {risk['verdict']}", styles["BodyText"]))

    story.append(Paragraph("<br/>", styles["BodyText"]))
    story.append(Paragraph("<b>Permissions</b>", styles["Heading2"]))

    for permission in risk["permissions"]:
        story.append(
            Paragraph(
                f"{permission['permission']} - {permission['risk']}",
                styles["BodyText"]
            )
        )

    story.append(Paragraph("<br/>", styles["BodyText"]))

    story.append(Paragraph("<b>AI Security Analysis</b>", styles["Heading2"]))
    story.append(Paragraph(ai_report.replace("\n", "<br/>"), styles["BodyText"]))

    doc.build(story)

    return filename