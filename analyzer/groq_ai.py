import os
from dotenv import load_dotenv
from groq import Groq

# Load .env file
load_dotenv()

# Get API Key
client = Groq(
    api_key=os.getenv("GROQ_API_KEY")
)


def analyze_permissions(app_name, permissions, score):

    prompt = f"""
You are a Senior Android Cybersecurity Analyst.

Analyze the following Android application.

App Name:
{app_name}

Permissions:
{permissions}

Risk Score:
{score}/100

Generate a professional security report.

Use the following headings exactly:

🔒 Overall Security Analysis

⚠ Dangerous Permissions

🔐 Privacy Concerns

💡 Security Recommendations

✅ Final Verdict

Instructions:
- Use simple English.
- Explain why permissions are risky.
- Mention whether the app is Safe, Moderate Risk, or High Risk.
- Keep the report between 200–300 words.
- Use bullet points wherever possible.
"""

    try:
        response = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            max_tokens=600,
        )

        return response.choices[0].message.content

    except Exception as e:
        print("Groq Error:", e)
        return f"AI Report Error: {e}"