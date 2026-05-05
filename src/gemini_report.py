import os
from dotenv import load_dotenv
from google import genai
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / "config.env"

load_dotenv(ENV_PATH, override=True)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


def get_gemini_client():
    if not GEMINI_API_KEY:
        return None

    return genai.Client(api_key=GEMINI_API_KEY)


def generate_soc_report(log_type, events_df, alerts_df):
    client = get_gemini_client()

    if client is None:
        return "Gemini API key not found. Check your config.env file."

    events_sample = events_df.head(30).to_string(index=False) if not events_df.empty else "No parsed events."
    alerts_sample = alerts_df.to_string(index=False) if not alerts_df.empty else "No alerts detected."

    prompt = f"""
You are a SOC Level 2 analyst.

Generate a professional SOC investigation report based on parsed security logs and detected alerts.

Log type: {log_type}

Parsed events sample:
{events_sample}

Detected alerts:
{alerts_sample}

The report must include:
1. Executive Summary
2. Technical Analysis
3. Key Indicators of Compromise
4. Severity Assessment
5. Timeline Summary
6. Recommended Actions
7. Conclusion

Rules:
- Do not invent data.
- Use only the information provided.
- Keep the report realistic and professional.
- Write in clear English.
"""

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )

        return response.text

    except Exception as e:
        return f"Error while generating Gemini report: {e}"