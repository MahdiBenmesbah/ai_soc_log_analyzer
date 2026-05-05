import pandas as pd


def detect_ssh_alerts(df: pd.DataFrame) -> pd.DataFrame:
    alerts = []

    if df.empty or "source_ip" not in df.columns:
        return pd.DataFrame(alerts)

    failed_df = df[df["event_type"] == "failed_login"]
    success_df = df[df["event_type"] == "successful_login"]

    failed_by_ip = failed_df.groupby("source_ip").size().reset_index(name="failed_attempts")

    for _, row in failed_by_ip.iterrows():
        ip = row["source_ip"]
        attempts = row["failed_attempts"]

        if attempts >= 5:
            severity = "High"
            risk_score = 80
        elif attempts >= 3:
            severity = "Medium"
            risk_score = 55
        else:
            continue

        targeted_users = failed_df[failed_df["source_ip"] == ip]["username"].dropna().unique().tolist()

        alerts.append({
            "alert_type": "SSH Brute Force Attempt",
            "severity": severity,
            "risk_score": risk_score,
            "source_ip": ip,
            "details": f"{attempts} failed SSH login attempts.",
            "targeted_users": ", ".join(targeted_users),
            "recommendation": "Block the source IP, review SSH logs, disable root login and enforce key-based authentication."
        })

    root_attempts = failed_df[failed_df["username"] == "root"]

    if not root_attempts.empty:
        for ip in root_attempts["source_ip"].dropna().unique():
            attempts = len(root_attempts[root_attempts["source_ip"] == ip])

            alerts.append({
                "alert_type": "Root Account Targeted",
                "severity": "High",
                "risk_score": 85,
                "source_ip": ip,
                "details": f"{attempts} failed login attempts against root.",
                "targeted_users": "root",
                "recommendation": "Disable direct root SSH login and investigate the source IP."
            })

    for _, success in success_df.iterrows():
        ip = success["source_ip"]
        user = success["username"]

        previous_failures = failed_df[failed_df["source_ip"] == ip]

        if len(previous_failures) >= 3:
            alerts.append({
                "alert_type": "Successful Login After Multiple Failures",
                "severity": "Critical",
                "risk_score": 95,
                "source_ip": ip,
                "details": f"Successful login for user {user} after {len(previous_failures)} failed attempts.",
                "targeted_users": user,
                "recommendation": "Treat as potential compromise. Isolate host, rotate credentials and check persistence."
            })

    return pd.DataFrame(alerts)


def detect_apache_alerts(df: pd.DataFrame) -> pd.DataFrame:
    alerts = []

    if df.empty or "source_ip" not in df.columns:
        return pd.DataFrame(alerts)

    not_found_df = df[df["event_type"] == "not_found"]
    unauthorized_df = df[df["event_type"] == "unauthorized_access"]
    server_error_df = df[df["event_type"] == "server_error"]

    not_found_by_ip = not_found_df.groupby("source_ip").size().reset_index(name="count")

    for _, row in not_found_by_ip.iterrows():
        if row["count"] >= 10:
            alerts.append({
                "alert_type": "Possible Web Directory Scan",
                "severity": "Medium",
                "risk_score": 60,
                "source_ip": row["source_ip"],
                "details": f"{row['count']} HTTP 404 responses from the same IP.",
                "targeted_users": "",
                "recommendation": "Review requested paths, check for scanning tools and block the IP if malicious."
            })

    unauthorized_by_ip = unauthorized_df.groupby("source_ip").size().reset_index(name="count")

    for _, row in unauthorized_by_ip.iterrows():
        if row["count"] >= 3:
            alerts.append({
                "alert_type": "Repeated Unauthorized Web Access",
                "severity": "High",
                "risk_score": 75,
                "source_ip": row["source_ip"],
                "details": f"{row['count']} HTTP 401/403 responses from the same IP.",
                "targeted_users": "",
                "recommendation": "Check admin endpoints, authentication attempts and possible brute-force activity."
            })

    if len(server_error_df) >= 3:
        alerts.append({
            "alert_type": "High Volume of Server Errors",
            "severity": "Medium",
            "risk_score": 50,
            "source_ip": "multiple",
            "details": f"{len(server_error_df)} HTTP 5xx errors detected.",
            "targeted_users": "",
            "recommendation": "Investigate application errors, possible exploitation attempts or service instability."
        })

    return pd.DataFrame(alerts)


def detect_firewall_alerts(df: pd.DataFrame) -> pd.DataFrame:
    alerts = []

    if df.empty or "source_ip" not in df.columns:
        return pd.DataFrame(alerts)

    blocked_df = df[df["event_type"] == "blocked_connection"]

    blocked_by_ip = blocked_df.groupby("source_ip").size().reset_index(name="count")

    for _, row in blocked_by_ip.iterrows():
        if row["count"] >= 10:
            alerts.append({
                "alert_type": "Repeated Blocked Connections",
                "severity": "Medium",
                "risk_score": 60,
                "source_ip": row["source_ip"],
                "details": f"{row['count']} blocked firewall events from the same source IP.",
                "targeted_users": "",
                "recommendation": "Review destination ports, check for scan behavior and consider upstream blocking."
            })

    if "destination_port" in df.columns:
        port_scan_df = df.groupby("source_ip")["destination_port"].nunique().reset_index(name="unique_ports")

        for _, row in port_scan_df.iterrows():
            if row["unique_ports"] >= 8:
                alerts.append({
                    "alert_type": "Possible Port Scan",
                    "severity": "High",
                    "risk_score": 80,
                    "source_ip": row["source_ip"],
                    "details": f"Connections attempted against {row['unique_ports']} different destination ports.",
                    "targeted_users": "",
                    "recommendation": "Investigate the source IP, check firewall rules and block if confirmed malicious."
                })

    return pd.DataFrame(alerts)


def detect_alerts(df: pd.DataFrame, log_type: str) -> pd.DataFrame:
    if log_type == "SSH":
        return detect_ssh_alerts(df)

    if log_type == "Apache":
        return detect_apache_alerts(df)

    if log_type == "Firewall":
        return detect_firewall_alerts(df)

    return pd.DataFrame()