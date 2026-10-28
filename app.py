
from flask import Flask, render_template, request
from analyzer.parser import parse_log_file
from analyzer.stats import analyze_records

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024


@app.route("/", methods=["GET", "POST"])
def index():
    records = []
    stats = None
    total_lines = 0
    failed_lines = 0
    error = None
    filename = ""

    if request.method == "POST":
        uploaded = request.files.get("logfile")

        if not uploaded or not uploaded.filename:
            error = "请先选择一个 .log 文件。"
        elif not uploaded.filename.lower().endswith(".log"):
            error = "目前只接受 .log 文件。"
        else:
            filename = uploaded.filename

            try:
                parsed_records, failed_lines = parse_log_file(
                    uploaded.stream
                )
                total_lines = len(parsed_records) + failed_lines

                # 对完整解析结果进行统计
                stats = analyze_records(parsed_records)

                # 页面仅展示前 100 条明细
                records = parsed_records[:100]

            except Exception:
                app.logger.exception("日志分析失败")
                records = []
                stats = None
                failed_lines = 0
                total_lines = 0
                error = "日志分析失败，请检查文件内容和程序错误。"

    return render_template(
        "index.html",
        records=records,
        stats=stats,
        total_lines=total_lines,
        parsed_count=stats["total_requests"] if stats else 0,
        failed_lines=failed_lines,
        filename=filename,
        error=error,
    )


@app.errorhandler(413)
def too_large(error):
    return "文件超过 32 MB 限制，请缩小文件后重试。", 413


if __name__ == "__main__":
    app.run(debug=True)
