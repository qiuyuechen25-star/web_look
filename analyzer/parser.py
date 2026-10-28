
import re
from datetime import datetime


# 匹配 Nginx / Apache 常见的 combined 访问日志格式
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+'
    r'(?P<size>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<ua>[^"]*)"'
)


def parse_line(line):
    """解析单行 combined 格式日志；失败时返回 None。"""
    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    data = match.groupdict()
    request_parts = data["request"].split(" ", 2)

    if len(request_parts) == 3:
        method, url, protocol = request_parts
    elif len(request_parts) == 2:
        method, url = request_parts
        protocol = ""
    else:
        method, url, protocol = "", data["request"], ""

    try:
        timestamp = datetime.strptime(
            data["time"], "%d/%b/%Y:%H:%M:%S %z"
        ).isoformat()
    except ValueError:
        timestamp = data["time"]

    return {
        "ip": data["ip"],
        "time": timestamp,
        "method": method,
        "url": url,
        "protocol": protocol,
        "status": int(data["status"]) if data["status"] != "-" else None,
        "size": int(data["size"]) if data["size"] != "-" else None,
        "referer": data["referer"],
        "user_agent": data["ua"],
    }


def parse_log_file(file_object):
    """逐行解析上传文件，返回成功记录和失败行数。"""
    records = []
    failed = 0

    for raw_line in file_object:
        try:
            line = raw_line.decode("utf-8", errors="replace")
        except AttributeError:
            line = str(raw_line)

        if not line.strip():
            continue

        record = parse_line(line)

        if record is None:
            failed += 1
        else:
            records.append(record)

    return records, failed
