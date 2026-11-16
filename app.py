import os
from pathlib import Path

from flask import Flask, render_template, request
from analyzer.parser import parse_log_file
from analyzer.stats import analyze_records

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

# 明细表最多渲染的条数，避免大文件拖垮页面（统计仍基于全部数据）
PREVIEW_LIMIT = 100
DEMO_LOG_PATH = Path(__file__).resolve().parent / "logs" / "demo.log"


def _empty_page(filename="", error=None):
    """渲染未分析时的初始页面。"""
    return render_template(
        "index.html",
        records=[],
        stats=None,
        total_lines=0,
        parsed_count=0,
        failed_lines=0,
        filename=filename,
        error=error,
    )


def _analysis_page(records, failed_lines, filename):
    """解析完成后渲染分析结果。"""
    stats = analyze_records(records)
    return render_template(
        "index.html",
        records=records[:PREVIEW_LIMIT],
        stats=stats,
        total_lines=len(records) + failed_lines,
        parsed_count=stats["total_requests"],
        failed_lines=failed_lines,
        filename=filename,
        error=None,
    )


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return _empty_page()

    uploaded = request.files.get("logfile")

    if not uploaded or not uploaded.filename:
        return _empty_page(error="请先选择一个 .log 文件。")
    if not uploaded.filename.lower().endswith(".log"):
        return _empty_page(error="目前只接受 .log 文件。")

    filename = uploaded.filename
    try:
        records, failed_lines = parse_log_file(uploaded.stream)
    except Exception:
        app.logger.exception("日志分析失败")
        return _empty_page(
            filename=filename,
            error="日志分析失败，请检查文件内容和程序错误。",
        )

    if not records and not failed_lines:
        return _empty_page(filename=filename, error="文件为空，没有可分析的日志。")

    return _analysis_page(records, failed_lines, filename)


@app.route("/demo")
def demo():
    """一键加载内置演示日志，便于现场演示。"""
    if not DEMO_LOG_PATH.exists():
        return _empty_page(error="演示日志不存在，请检查 logs/demo.log。")

    with DEMO_LOG_PATH.open("rb") as fh:
        records, failed_lines = parse_log_file(fh)

    return _analysis_page(records, failed_lines, "demo.log（内置演示数据）")


@app.errorhandler(413)
def too_large(error):
    return "文件超过 32 MB 限制，请缩小文件后重试。", 413


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "1") == "1")
