import sys
from pathlib import Path

import pandas as pd
import streamlit as st

try:
    CURRENT_DIR = Path(__file__).resolve().parent
except NameError:
    CURRENT_DIR = Path.cwd()

PROJECT_ROOT = CURRENT_DIR.parent

sys.path.append(str(CURRENT_DIR))

from parsers import detect_log_type, parse_logs
from detectors import detect_alerts
from gemini_report import generate_soc_report

def build_executive_summary(events_df, alerts_df, log_type):
    total_events = len(events_df)
    total_alerts = len(alerts_df)

    if not alerts_df.empty:
        highest_risk = alerts_df["risk_score"].max()
        top_alert = alerts_df.sort_values("risk_score", ascending=False).iloc[0]
        highest_severity = top_alert["severity"]
        main_attack_pattern = top_alert["alert_type"]
        main_suspicious_ip = top_alert["source_ip"]
    else:
        highest_risk = 0
        highest_severity = "None"
        main_attack_pattern = "No suspicious pattern detected"
        main_suspicious_ip = "N/A"

    if highest_risk >= 90:
        priority = "Critical - Immediate investigation required"
    elif highest_risk >= 75:
        priority = "High - Investigate as soon as possible"
    elif highest_risk >= 50:
        priority = "Medium - Review and monitor"
    elif highest_risk > 0:
        priority = "Low - Monitor"
    else:
        priority = "No immediate action required"

    return {
        "log_type": log_type,
        "total_events": total_events,
        "total_alerts": total_alerts,
        "highest_severity": highest_severity,
        "highest_risk": highest_risk,
        "main_attack_pattern": main_attack_pattern,
        "main_suspicious_ip": main_suspicious_ip,
        "priority": priority
    }

st.set_page_config(
    page_title="AI SOC Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI SOC Log Analyzer")
st.write("Upload a security log file and detect suspicious activity using Python rules and Gemini-assisted reporting.")

uploaded_file = st.file_uploader(
    "Upload a log file",
    type=["log", "txt", "csv"]
)

if uploaded_file is None:
    st.info("Upload a SSH, Apache, or Firewall log file to start the analysis.")
    st.stop()


raw_bytes = uploaded_file.read()

try:
    log_text = raw_bytes.decode("utf-8")
except UnicodeDecodeError:
    log_text = raw_bytes.decode("latin-1", errors="ignore")


st.subheader("1. Uploaded File")
col_file_1, col_file_2 = st.columns(2)

with col_file_1:
    st.metric("File size", f"{round(len(raw_bytes) / 1024, 2)} KB")

with col_file_2:
    st.metric("Filename", uploaded_file.name)


with st.expander("Preview raw logs"):
    st.text(log_text[:5000])


log_type = detect_log_type(log_text)

st.subheader("2. Detected Log Type")
st.info(f"Detected type: **{log_type}**")


events_df = parse_logs(log_text, log_type)

alerts_df = detect_alerts(events_df, log_type)
summary = build_executive_summary(events_df, alerts_df, log_type)


st.subheader("3. Executive Summary")

col_sum_1, col_sum_2, col_sum_3, col_sum_4 = st.columns(4)

with col_sum_1:
    st.metric("Total Events", summary["total_events"])

with col_sum_2:
    st.metric("Total Alerts", summary["total_alerts"])

with col_sum_3:
    st.metric("Highest Risk", summary["highest_risk"])

with col_sum_4:
    st.metric("Highest Severity", summary["highest_severity"])

st.info(
    f"""
    **Log Type:** {summary["log_type"]}  
    **Main Suspicious IP:** {summary["main_suspicious_ip"]}  
    **Main Attack Pattern:** {summary["main_attack_pattern"]}  
    **Recommended Priority:** {summary["priority"]}
    """
)


st.subheader("4. Filters")

filtered_events_df = events_df.copy()
filtered_alerts_df = alerts_df.copy()

filter_col_1, filter_col_2, filter_col_3 = st.columns(3)

with filter_col_1:
    if "source_ip" in events_df.columns:
        available_ips = sorted(events_df["source_ip"].dropna().unique().tolist())
        selected_ips = st.multiselect("Filter by Source IP", available_ips)
        if selected_ips:
            filtered_events_df = filtered_events_df[filtered_events_df["source_ip"].isin(selected_ips)]

            if not filtered_alerts_df.empty and "source_ip" in filtered_alerts_df.columns:
                filtered_alerts_df = filtered_alerts_df[filtered_alerts_df["source_ip"].isin(selected_ips)]

with filter_col_2:
    if "event_type" in events_df.columns:
        available_event_types = sorted(events_df["event_type"].dropna().unique().tolist())
        selected_event_types = st.multiselect("Filter by Event Type", available_event_types)
        if selected_event_types:
            filtered_events_df = filtered_events_df[filtered_events_df["event_type"].isin(selected_event_types)]

with filter_col_3:
    if not alerts_df.empty and "severity" in alerts_df.columns:
        available_severities = sorted(alerts_df["severity"].dropna().unique().tolist())
        selected_severities = st.multiselect("Filter by Severity", available_severities)
        if selected_severities:
            filtered_alerts_df = filtered_alerts_df[filtered_alerts_df["severity"].isin(selected_severities)]


st.subheader("5. Parsed Events")

events_display_df = filtered_events_df.reset_index(drop=True)
events_display_df.index = events_display_df.index + 1

st.dataframe(events_display_df, use_container_width=True)


st.subheader("6. Key Metrics")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Filtered Events", len(filtered_events_df))

with col2:
    if "source_ip" in filtered_events_df.columns:
        st.metric("Unique Source IPs", filtered_events_df["source_ip"].nunique())
    else:
        st.metric("Unique Source IPs", 0)

with col3:
    if "event_type" in filtered_events_df.columns:
        st.metric("Event Types", filtered_events_df["event_type"].nunique())
    else:
        st.metric("Event Types", 0)

with col4:
    st.metric("Log Type", log_type)


st.subheader("7. Dashboard")

if "event_type" in filtered_events_df.columns:
    st.write("### Event Type Distribution")
    event_counts = filtered_events_df["event_type"].value_counts()
    st.bar_chart(event_counts)

if "source_ip" in filtered_events_df.columns:
    st.write("### Top Source IPs")
    top_ips = filtered_events_df["source_ip"].value_counts().head(10)
    st.bar_chart(top_ips)


st.subheader("8. Detected SOC Alerts")

if filtered_alerts_df.empty:
    st.success("No suspicious alerts detected based on the current filters.")
else:
    alerts_display_df = filtered_alerts_df.reset_index(drop=True)
    alerts_display_df.index = alerts_display_df.index + 1

    st.dataframe(alerts_display_df, use_container_width=True)

    max_risk = filtered_alerts_df["risk_score"].max()

    if max_risk >= 90:
        st.error("Critical risk detected.")
    elif max_risk >= 75:
        st.warning("High risk detected.")
    elif max_risk >= 50:
        st.warning("Medium risk detected.")
    else:
        st.info("Low risk detected.")

st.subheader("9. Export")

col_export_1, col_export_2 = st.columns(2)

with col_export_1:
    st.download_button(
        label="Download Filtered Events CSV",
        data=filtered_events_df.to_csv(index=False).encode("utf-8"),
        file_name="filtered_events.csv",
        mime="text/csv"
    )

with col_export_2:
    if not filtered_alerts_df.empty:
        st.download_button(
            label="Download Filtered Alerts CSV",
            data=filtered_alerts_df.to_csv(index=False).encode("utf-8"),
            file_name="filtered_alerts.csv",
            mime="text/csv"
        )


st.subheader("10. AI SOC Report")

if st.button("Generate SOC Report with Gemini"):
    with st.spinner("Generating SOC report..."):
        report = generate_soc_report(log_type, filtered_events_df, filtered_alerts_df)

    st.markdown(report)

    st.download_button(
        label="Download SOC Report",
        data=report,
        file_name="soc_investigation_report.txt",
        mime="text/plain"
    )