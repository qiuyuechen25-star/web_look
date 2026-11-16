"""访问日志统计与异常检测。

统计部分：按小时趋势、Top IP、Top URL、状态码、请求方法。
异常部分：基于可配置规则的检测引擎，规则来自 rules/rules.json。
"""

import json
from collections import Counter
from pathlib import Path

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.json"
ANOMALY_PREVIEW_LIMIT = 100

LEVEL_WEIGHT = {"高危": 3, "中危": 2, "低危": 1, "安全": 0}
WEIGHT_LEVEL = {3: "高危", 2: "中危", 1: "低危", 0: "安全"}

DEFAULT_RULES = {
    "sensitive_paths": [],
    "attack_signatures": [],
    "scanner_uas": [],
    "risky_methods": [],
    "thresholds": {
        "high_freq_min_count": 20,
        "high_freq_min_ratio": 0.15,
        "scan_404_threshold": 5,
        "client_error_rate": 0.30,
        "server_error_rate": 0.05,
        "error_rate_min_requests": 20,
    },
    "rule_levels": {},
}


def load_rules(path=RULES_PATH):
    """从 JSON 文件加载检测规则，文件缺失或损坏时回退到默认配置。"""
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        merged = dict(DEFAULT_RULES)
        merged.update(data)
        thresholds = dict(DEFAULT_RULES["thresholds"])
        thresholds.update(data.get("thresholds", {}))
        merged["thresholds"] = thresholds
        return merged
    except (OSError, ValueError):
        return dict(DEFAULT_RULES)


RULES = load_rules()


def _level_of(rule_name):
    return RULES["rule_levels"].get(rule_name, "低危")


def detect_anomalies(records, rules=None):
    """执行规则检测，返回异常明细、规则汇总与综合风险等级。"""
    cfg = rules or RULES
    th = cfg["thresholds"]
    sensitive = tuple(k.lower() for k in cfg["sensitive_paths"])
    signatures = tuple(s.lower() for s in cfg["attack_signatures"])
    scanners = tuple(k.lower() for k in cfg["scanner_uas"])
    risky_methods = set(m.upper() for m in cfg["risky_methods"])

    ip_total = Counter()
    ip_4xx = Counter()
    ip_5xx = Counter()
    ip_404 = Counter()

    for row in records:
        ip = row.get("ip", "未知")
        ip_total[ip] += 1
        status = row.get("status")
        if status is not None:
            if 400 <= status < 500:
                ip_4xx[ip] += 1
                if status == 404:
                    ip_404[ip] += 1
            elif status >= 500:
                ip_5xx[ip] += 1

    total = len(records)
    heavy_ips = {
        ip for ip, count in ip_total.items()
        if count >= th["high_freq_min_count"] and total
        and count / total >= th["high_freq_min_ratio"]
    }
    scan_ips = {
        ip for ip, count in ip_404.items()
        if count >= th["scan_404_threshold"]
    }
    high_4xx_ips = {
        ip for ip, count in ip_total.items()
        if count >= th["error_rate_min_requests"]
        and ip_4xx[ip] / count >= th["client_error_rate"]
    }
    high_5xx_ips = {
        ip for ip, count in ip_total.items()
        if count >= th["error_rate_min_requests"]
        and ip_5xx[ip] / count >= th["server_error_rate"]
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

        if sensitive and any(key in url_lower for key in sensitive):
            hits.append(("敏感路径探测", "访问敏感资源：" + url[:90]))

        if "?" in url and signatures and any(sig in url_lower for sig in signatures):
            hits.append(("注入攻击特征", "请求参数含攻击载荷：" + url[:90]))

        if ua_lower and scanners and any(key in ua_lower for key in scanners):
            hits.append(("扫描器 UA", "User-Agent：" + ua[:70]))

        if method in risky_methods:
            hits.append(("可疑请求方法", "使用 " + method + " 方法"))

        if status is not None and status >= 500:
            hits.append(("服务端错误", "返回 HTTP " + str(status)))

        if ip in scan_ips and status == 404:
            hits.append(("疑似目录扫描",
                         "该 IP 累计产生 " + str(ip_404[ip]) + " 次 404"))

        if ip in high_4xx_ips and status is not None and 400 <= status < 500:
            hits.append(("4xx 错误率异常",
                         "该 IP 4xx 占比 " + format(ip_4xx[ip] / ip_total[ip] * 100, ".1f") + "%"))

        if ip in high_5xx_ips and status is not None and status >= 500:
            hits.append(("5xx 错误率异常",
                         "该 IP 5xx 占比 " + format(ip_5xx[ip] / ip_total[ip] * 100, ".1f") + "%"))

        if ip in heavy_ips:
            hits.append(("高频访问",
                         "该 IP 共发起 " + str(ip_total[ip]) + " 次请求"))

        if not hits:
            continue

        level = max(
            ((name, _level_of(name)) for name, _ in hits),
            key=lambda item: LEVEL_WEIGHT[item[1]],
        )[1]

        anomalies.append({
            "ip": ip,
            "time": row.get("time", ""),
            "method": method or "-",
            "url": url or "-",
            "status": status,
            "user_agent": ua or "-",
            "rule": "、".join(name for name, _ in hits),
            "rules": [name for name, _ in hits],
            "level": level,
            "detail": "；".join(desc for _, desc in hits),
        })

    anomalies.sort(
        key=lambda a: (-LEVEL_WEIGHT[a["level"]], a["time"], a["ip"])
    )

    rule_counter = Counter()
    for item in anomalies:
        for rule_name in item["rules"]:
            rule_counter[rule_name] += 1

    anomaly_rules = [
        {"name": name, "count": count, "level": _level_of(name)}
        for name, count in rule_counter.most_common()
    ]

    weights = {LEVEL_WEIGHT[a["level"]] for a in anomalies}
    risk_level = WEIGHT_LEVEL[max(weights)] if weights else "安全"

    return {
        "anomalies": anomalies[:ANOMALY_PREVIEW_LIMIT],
        "anomaly_rules": anomaly_rules,
        "anomaly_total": len(anomalies),
        "risk_level": risk_level,
    }


def analyze_records(records):
    """对访问日志进行统计聚合与异常检测。"""
    hourly = Counter()
    ip_counts = Counter()
    url_counts = Counter()
    status_counts = Counter()
    method_counts = Counter()

    for row in records:
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
            {"time": k, "count": v} for k, v in sorted(hourly.items())
        ],
        "top_ips": [
            {"name": k, "count": v} for k, v in ip_counts.most_common(10)
        ],
        "top_urls": [
            {"name": k, "count": v} for k, v in url_counts.most_common(10)
        ],
        "statuses": [
            {"name": k, "count": v} for k, v in sorted(status_counts.items())
        ],
        "methods": [
            {"name": k, "count": v} for k, v in sorted(method_counts.items())
        ],
    }

    result.update(detect_anomalies(records))
    return result
