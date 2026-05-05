import re
import pandas as pd


def detect_log_type(log_text: str) -> str:
    sample = log_text[:10000].lower()

    ssh_indicators = [
        "sshd",
        "failed password",
        "accepted password",
        "invalid user",
        "authentication failure"
    ]

    apache_indicators = [
        "get /",
        "post /",
        "http/1.1",
        "http/2",
        " 404 ",
        " 403 ",
        " 500 "
    ]

    firewall_indicators = [
        "ufw",
        "iptables",
        "firewall",
        "blocked",
        "block",
        "denied",
        "drop",
        "reject",
        "src=",
        "dst=",
        "dpt="
    ]

    scores = {
        "SSH": sum(1 for item in ssh_indicators if item in sample),
        "Apache": sum(1 for item in apache_indicators if item in sample),
        "Firewall": sum(1 for item in firewall_indicators if item in sample),
    }

    best_type = max(scores, key=scores.get)

    if scores[best_type] == 0:
        return "Unknown"

    return best_type


def parse_ssh_logs(log_text: str) -> pd.DataFrame:
    events = []

    ssh_regex = re.compile(
        r"(?P<month>\w{3})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"sshd(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.*)"
    )

    for line in log_text.splitlines():
        match = ssh_regex.search(line)

        if not match:
            continue

        message = match.group("message")

        event_type = "other"
        username = None
        source_ip = None
        source_port = None

        failed_match = re.search(
            r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)",
            message
        )

        accepted_match = re.search(
            r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)",
            message
        )

        invalid_user_match = re.search(
            r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
            message
        )

        if failed_match:
            event_type = "failed_login"
            username = failed_match.group("user")
            source_ip = failed_match.group("ip")
            source_port = failed_match.group("port")

        elif accepted_match:
            event_type = "successful_login"
            username = accepted_match.group("user")
            source_ip = accepted_match.group("ip")
            source_port = accepted_match.group("port")

        elif invalid_user_match:
            event_type = "invalid_user"
            username = invalid_user_match.group("user")
            source_ip = invalid_user_match.group("ip")

        events.append({
            "log_type": "SSH",
            "month": match.group("month"),
            "day": match.group("day"),
            "time": match.group("time"),
            "host": match.group("host"),
            "pid": match.group("pid"),
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip,
            "source_port": source_port,
            "raw_log": line
        })

    return pd.DataFrame(events)


def parse_apache_logs(log_text: str) -> pd.DataFrame:
    events = []

    apache_regex = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) .*? '
        r'\[(?P<timestamp>.*?)\] '
        r'"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (?P<path>.*?) (?P<protocol>HTTP/.*?)" '
        r'(?P<status>\d{3}) (?P<size>\S+)'
    )

    for line in log_text.splitlines():
        match = apache_regex.search(line)

        if not match:
            continue

        status_code = int(match.group("status"))

        if status_code >= 500:
            event_type = "server_error"
        elif status_code == 404:
            event_type = "not_found"
        elif status_code in [401, 403]:
            event_type = "unauthorized_access"
        else:
            event_type = "web_request"

        events.append({
            "log_type": "Apache",
            "source_ip": match.group("ip"),
            "timestamp": match.group("timestamp"),
            "method": match.group("method"),
            "path": match.group("path"),
            "protocol": match.group("protocol"),
            "status_code": status_code,
            "size": match.group("size"),
            "event_type": event_type,
            "raw_log": line
        })

    return pd.DataFrame(events)


def parse_firewall_logs(log_text: str) -> pd.DataFrame:
    events = []

    for line in log_text.splitlines():
        lower_line = line.lower()

        source_ip_match = re.search(r"SRC=(?P<src>\d+\.\d+\.\d+\.\d+)", line)
        destination_ip_match = re.search(r"DST=(?P<dst>\d+\.\d+\.\d+\.\d+)", line)
        proto_match = re.search(r"PROTO=(?P<proto>\S+)", line)
        source_port_match = re.search(r"SPT=(?P<spt>\d+)", line)
        destination_port_match = re.search(r"DPT=(?P<dpt>\d+)", line)

        if "block" in lower_line or "drop" in lower_line or "deny" in lower_line or "reject" in lower_line:
            event_type = "blocked_connection"
        else:
            event_type = "firewall_event"

        if source_ip_match or destination_ip_match:
            events.append({
                "log_type": "Firewall",
                "source_ip": source_ip_match.group("src") if source_ip_match else None,
                "destination_ip": destination_ip_match.group("dst") if destination_ip_match else None,
                "protocol": proto_match.group("proto") if proto_match else None,
                "source_port": source_port_match.group("spt") if source_port_match else None,
                "destination_port": destination_port_match.group("dpt") if destination_port_match else None,
                "event_type": event_type,
                "raw_log": line
            })

    return pd.DataFrame(events)


def parse_logs(log_text: str, log_type: str) -> pd.DataFrame:
    if log_type == "SSH":
        return parse_ssh_logs(log_text)

    if log_type == "Apache":
        return parse_apache_logs(log_text)

    if log_type == "Firewall":
        return parse_firewall_logs(log_text)

    return pd.DataFrame()