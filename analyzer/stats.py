"""访问日志统计与异常检测。

统计部分：按小时趋势、Top IP、Top URL、状态码、请求方法。
异常部分：基于规则的 Web 访问异常识别，输出风险等级与异常明细。
"""

from collections import Counter

# ---------------------------------------------------------------- 规则库

# 常见的敏感资源路径，命中即视为探测行为
SENSITIVE_PATH_KEYWORDS = (
    ".env", ".git", ".svn", ".ds_store", ".aws",
    "/admin", "wp-login", "wp-admin", "phpmyadmin", "pma/",
    "/config", "/backup", "/shell", "/etc/passwd",
    "actuator", "swagger", "phpinfo", "administrator",
    "manager/html", "xmlrpc.php", "web.config", "database.sql",
)

# 注入 / 目录遍历 / XSS 等攻击载荷特征（只在带参数的请求中检查，降低误报）
ATTACK_SIGNATURES = (
    "union select", "or 1=1", "' or ", "\" or ", "' and ", "\" and ",
    "%20union%20select", "union+select", "%20or%201=1", "%27%20or",
    "../", "..\\", "%2e%2e", "<script", "%3cscript", "sleep(",
    "benchmark(", "waitfor delay", "xp_cmdshell", "into outfile",
    "load_file(", "%00", "/etc/passwd", "cmd=", "exec(", "--",
)

# 自动化扫描器 / 攻击工具 User-Agent
SCANNER_UA_KEYWORDS = (
    "sqlmap", "nikto", "nmap", "masscan", "acunetix", "nessus",
    "openvas", "wpscan", "dirbuster", "gobuster", "hydra",
    "scanner", "hackbar", "python-requests", "python-urllib",
    "go-http-client", "curl/", "wget/", "libwww-perl", "httpie",
    "httpx", "fuzz",
)

# 非只读的 HTTP 方法，正常情况下访问日志里很少出现
RISKY_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

# 高频访问判定：单 IP 请求数达到阈值且占总请求比例达到阈值
HIGH_FREQ_MIN_COUNT = 20
HIGH_FREQ_MIN_RATIO = 0.15
# 目录扫描判定：单 IP 的 404 次数达到阈值
SCAN_404_THRESHOLD = 5
# 明细表中最多保留的异常条数（统计数字仍基于全量）
ANOMALY_PREVIEW_LIMIT = 100

LEVEL_WEIGHT = {"高危": 3, "中危": 2, "低危": 1}
WEIGHT_LEVEL = {3: "高危", 2: "中危", 1: "低危"}

# 每条规则自身的固有等级，与单条记录的综合风险等级区分开
RULE_LEVEL = {
    "敏感路径探测": "高危",
    "注入攻击特征": "高危",
    "扫描器 UA": "中危",
    "可疑请求方法": "中危",
    "服务端错误": "中危",
    "疑似目录扫描": "中危",
    "高频访问": "低危",
}


def _level_of(weight):
    return WEIGHT_LEVEL.get(weight, "低危")


def detect_anomalies(records):
    """对解析后的访问记录执行规则检测，返回异常明细与规则汇总。

    Args:
        records: parse_log_file 返回的记录列表。

    Returns:
        dict: 含 anomalies / anomaly_rules / anomaly_total / risk_level
    """
    ip_total = Counter()
    ip_404 = Counter()

    for row in records:
        ip = row.get("ip", "未知")
        ip_total[ip] += 1
        if row.get("status") == 404:
            ip_404[ip] += 1

    total = len(records)
    heavy_ips = {
        ip for ip, count in ip_total.items()
        if count >= HIGH_FREQ_MIN_COUNT
        and total
        and count / total >= HIGH_FREQ_MIN_RATIO
    }
    scan_ips = {
        ip for ip, count in ip_404.items()
        if count >= SCAN_404_THRESHOLD
    }

    anomalies = []

    for row in records:
        hits = []

        method = (row.get("method") or "").upper()
        url = row.get("url") or ""
        ua = row.get("user_agent") or ""
        status = row.get("status")
        ip = row.get("ip", "未知")
        url_lower = url.lower()
        ua_lower = ua.lower()

        # 规则 1：敏感路径探测
        if any(key in url_lower for key in SENSITIVE_PATH_KEYWORDS):
            hits.append(("敏感路径探测", "高危", "访问敏感资源：" + url[:90]))

        # 规则 2：注入 / 遍历 / XSS 载荷
        if "?" in url and any(sig in url_lower for sig in ATTACK_SIGNATURES):
            hits.append(("注入攻击特征", "高危", "请求参数含攻击载荷：" + url[:90]))

        # 规则 3：扫描器 / 自动化工具 UA
        if ua_lower and any(key in ua_lower for key in SCANNER_UA_KEYWORDS):
            hits.append(("扫描器 UA", "中危", "User-Agent：" + ua[:70]))

        # 规则 4：危险的 HTTP 方法
        if method in RISKY_METHODS:
            hits.append(("可疑请求方法", "中危", "使用 " + method + " 方法"))

        # 规则 5：服务端错误
        if status is not None and status >= 500:
            hits.append(("服务端错误", "中危", "返回 HTTP " + str(status)))

        # 规则 6：单 IP 大量 404，疑似目录爆破
        if ip in scan_ips and status == 404:
            hits.append(("疑似目录扫描", "中危",
                         "该 IP 累计产生 " + str(ip_404[ip]) + " 次 404"))

        # 规则 7：单 IP 请求量异常偏高
        if ip in heavy_ips:
            hits.append(("高频访问", "低危",
                         "该 IP 共发起 " + str(ip_total[ip]) + " 次请求"))

        if not hits:
            continue

        level = max(hits, key=lambda item: LEVEL_WEIGHT[item[1]])[1]
        anomalies.append({
            "ip": ip,
            "time": row.get("time", ""),
            "method": method or "-",
            "url": url or "-",
            "status": status,
            "user_agent": ua or "-",
            "rule": "、".join(item[0] for item in hits),
            "rules": [item[0] for item in hits],
            "level": level,
            "detail": "；".join(item[2] for item in hits),
        })

    # 按风险等级降序、时间升序排列，便于优先查看高危事件
    anomalies.sort(
        key=lambda a: (-LEVEL_WEIGHT[a["level"]], a["time"], a["ip"])
    )

    rule_counter = Counter()
    rule_weight = {}
    for item in anomalies:
        for rule_name in item["rules"]:
            rule_counter[rule_name] += 1
            rule_weight[rule_name] = LEVEL_WEIGHT[RULE_LEVEL[rule_name]]

    anomaly_rules = [
        {"name": name, "count": count, "level": _level_of(rule_weight[name])}
        for name, count in rule_counter.most_common()
    ]

    weights = {LEVEL_WEIGHT[a["level"]] for a in anomalies}
    risk_level = (
        "高危" if 3 in weights
        else "中危" if 2 in weights
        else "低危" if 1 in weights
        else "安全"
    )

    return {
        "anomalies": anomalies[:ANOMALY_PREVIEW_LIMIT],
        "anomaly_rules": anomaly_rules,
        "anomaly_total": len(anomalies),
        "risk_level": risk_level,
    }


def analyze_records(records):
    """对已经解析的访问日志进行统计与异常检测。"""
    hourly = Counter()
    ip_counts = Counter()
    url_counts = Counter()
    status_counts = Counter()
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

        method_counts[row.get("method", "未知")] += 1

    result = {
        "total_requests": len(records),
        "unique_ips": len(ip_counts),
        "unique_urls": len(url_counts),
        "hourly": [
            {"time": k, "count": v}
            for k, v in sorted(hourly.items())
        ],
        "top_ips": [
            {"name": k, "count": v}
            for k, v in ip_counts.most_common(10)
        ],
        "top_urls": [
            {"name": k, "count": v}
            for k, v in url_counts.most_common(10)
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

    result.update(detect_anomalies(records))
    return result
