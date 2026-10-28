
from collections import Counter


def analyze_records(records):
    """对已经解析的访问日志进行统计。"""

    # 1. 按小时统计访问量
    hourly = Counter()

    # 2. Top 10 来源 IP
    ip_counts = Counter()

    # 3. Top 10 请求 URL
    url_counts = Counter()

    # 4. HTTP 状态码分布
    status_counts = Counter()

    # 5. 请求方法分布
    method_counts = Counter()

    for row in records:
        # 时间字段格式示例：2026-10-22T10:20:30+08:00
        time_value = row.get("time", "")

        if len(time_value) >= 13 and time_value[10] == "T":
            hour = time_value[:13].replace("T", " ")
            hourly[hour] += 1

        ip_counts[row.get("ip", "未知")] += 1
        url_counts[row.get("url", "未知")] += 1

        status = row.get("status")
        if status is not None:
            status_counts[str(status)] += 1

        method = row.get("method", "未知")
        method_counts[method] += 1

    # 排序后仅保留前 10 名
    top_ips = ip_counts.most_common(10)
    top_urls = url_counts.most_common(10)

    return {
        "total_requests": len(records),
        "unique_ips": len(ip_counts),
        "unique_urls": len(url_counts),
        "hourly": [
            {"time": k, "count": v}
            for k, v in sorted(hourly.items())
        ],
        "top_ips": [
            {"name": k, "count": v}
            for k, v in top_ips
        ],
        "top_urls": [
            {"name": k, "count": v}
            for k, v in top_urls
        ],
        "statuses": [
            {"name": k, "count": v}
            for k, v in sorted(status_counts.items())
        ],
        "methods": [
            {"name": k, "count": v}
            for k, v in sorted(method_counts.items())
        ],
    }
