/* LogLens 纯前端分析引擎：解析、统计、异常检测、图表渲染全部在浏览器完成 */
(function () {
    'use strict';

    /* ---------------- 规则库（与 analyzer/stats.py 保持一致） ---------------- */
    const SENSITIVE_PATH_KEYWORDS = [
        '.env', '.git', '.svn', '.ds_store', '.aws',
        '/admin', 'wp-login', 'wp-admin', 'phpmyadmin', 'pma/',
        '/config', '/backup', '/shell', '/etc/passwd',
        'actuator', 'swagger', 'phpinfo', 'administrator',
        'manager/html', 'xmlrpc.php', 'web.config', 'database.sql'
    ];
    const ATTACK_SIGNATURES = [
        'union select', 'or 1=1', "' or ", '" or ', "' and ", '" and ',
        '%20union%20select', 'union+select', '%20or%201=1', '%27%20or',
        '../', '..\\', '%2e%2e', '<script', '%3cscript', 'sleep(',
        'benchmark(', 'waitfor delay', 'xp_cmdshell', 'into outfile',
        'load_file(', '%00', '/etc/passwd', 'cmd=', 'exec(', '--'
    ];
    const SCANNER_UA_KEYWORDS = [
        'sqlmap', 'nikto', 'nmap', 'masscan', 'acunetix', 'nessus',
        'openvas', 'wpscan', 'dirbuster', 'gobuster', 'hydra',
        'scanner', 'hackbar', 'python-requests', 'python-urllib',
        'go-http-client', 'curl/', 'wget/', 'libwww-perl', 'httpie',
        'httpx', 'fuzz'
    ];
    const RISKY_METHODS = new Set(['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']);
    const LEVEL_WEIGHT = { '高危': 3, '中危': 2, '低危': 1, '安全': 0 };
    const RULE_LEVEL = {
        '敏感路径探测': '高危', '注入攻击特征': '高危', '扫描器 UA': '中危',
        '可疑请求方法': '中危', '服务端错误': '中危', '疑似目录扫描': '中危',
        '高频访问': '低危'
    };
    const HIGH_FREQ_MIN_COUNT = 20;
    const HIGH_FREQ_MIN_RATIO = 0.15;
    const SCAN_404_THRESHOLD = 5;
    const PREVIEW_LIMIT = 100;

    /* ---------------- 解析 combined 日志 ---------------- */
    const LOG_RE = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3}|-)\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"/;
    const MONTHS = { Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06',
                     Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12' };

    function normalizeTime(raw) {
        const m = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})$/.exec(raw);
        if (!m) return raw;
        const zone = m[7].slice(0, 3) + ':' + m[7].slice(3);
        return m[3] + '-' + (MONTHS[m[2]] || '01') + '-' + m[1] + 'T' +
               m[4] + ':' + m[5] + ':' + m[6] + zone;
    }

    function parseLine(line) {
        const m = LOG_RE.exec(line.trim());
        if (!m) return null;
        const parts = m[3].split(' ');
        return {
            ip: m[1],
            time: normalizeTime(m[2]),
            method: parts[0] || '',
            url: parts[1] || m[3],
            status: m[4] === '-' ? null : parseInt(m[4], 10),
            size: m[5] === '-' ? null : parseInt(m[5], 10),
            referer: m[6],
            user_agent: m[7]
        };
    }

    function parseText(text) {
        const records = [];
        let failed = 0;
        text.split(/\r?\n/).forEach(function (line) {
            if (!line.trim()) return;
            const rec = parseLine(line);
            if (rec) records.push(rec); else failed++;
        });
        return { records: records, failed: failed };
    }

    /* ---------------- 统计与异常检测 ---------------- */
    function analyze(records) {
        const hourly = new Map(), ipCounts = new Map(), urlCounts = new Map();
        const statusCounts = new Map(), methodCounts = new Map();

        records.forEach(function (row) {
            const t = row.time || '';
            if (t.length >= 13 && t[10] === 'T') {
                const hour = t.slice(0, 13).replace('T', ' ');
                hourly.set(hour, (hourly.get(hour) || 0) + 1);
            }
            ipCounts.set(row.ip, (ipCounts.get(row.ip) || 0) + 1);
            urlCounts.set(row.url, (urlCounts.get(row.url) || 0) + 1);
            if (row.status !== null) {
                statusCounts.set(String(row.status), (statusCounts.get(String(row.status)) || 0) + 1);
            }
            methodCounts.set(row.method, (methodCounts.get(row.method) || 0) + 1);
        });

        const ip404 = new Map();
        records.forEach(function (row) {
            if (row.status === 404) ip404.set(row.ip, (ip404.get(row.ip) || 0) + 1);
        });

        const total = records.length;
        const heavyIps = new Set(), scanIps = new Set();
        ipCounts.forEach(function (count, ip) {
            if (count >= HIGH_FREQ_MIN_COUNT && total && count / total >= HIGH_FREQ_MIN_RATIO) {
                heavyIps.add(ip);
            }
        });
        ip404.forEach(function (count, ip) {
            if (count >= SCAN_404_THRESHOLD) scanIps.add(ip);
        });

        const anomalies = [];
        records.forEach(function (row) {
            const hits = [];
            const method = (row.method || '').toUpperCase();
            const url = row.url || '';
            const ua = row.user_agent || '';
            const u = url.toLowerCase(), uaLow = ua.toLowerCase();

            if (SENSITIVE_PATH_KEYWORDS.some(function (k) { return u.includes(k); })) {
                hits.push(['敏感路径探测', '高危', '访问敏感资源：' + url.slice(0, 90)]);
            }
            if (url.includes('?') && ATTACK_SIGNATURES.some(function (s) { return u.includes(s); })) {
                hits.push(['注入攻击特征', '高危', '请求参数含攻击载荷：' + url.slice(0, 90)]);
            }
            if (uaLow && SCANNER_UA_KEYWORDS.some(function (k) { return uaLow.includes(k); })) {
                hits.push(['扫描器 UA', '中危', 'User-Agent：' + ua.slice(0, 70)]);
            }
            if (RISKY_METHODS.has(method)) {
                hits.push(['可疑请求方法', '中危', '使用 ' + method + ' 方法']);
            }
            if (row.status !== null && row.status >= 500) {
                hits.push(['服务端错误', '中危', '返回 HTTP ' + row.status]);
            }
            if (scanIps.has(row.ip) && row.status === 404) {
                hits.push(['疑似目录扫描', '中危', '该 IP 累计产生 ' + ip404.get(row.ip) + ' 次 404']);
            }
            if (heavyIps.has(row.ip)) {
                hits.push(['高频访问', '低危', '该 IP 共发起 ' + ipCounts.get(row.ip) + ' 次请求']);
            }
            if (!hits.length) return;

            let level = '低危';
            hits.forEach(function (h) {
                if (LEVEL_WEIGHT[h[1]] > LEVEL_WEIGHT[level]) level = h[1];
            });
            anomalies.push({
                ip: row.ip, time: row.time, method: method || '-', url: url,
                status: row.status, user_agent: ua || '-', level: level,
                rules: hits.map(function (h) { return h[0]; }),
                detail: hits.map(function (h) { return h[2]; }).join('；')
            });
        });

        anomalies.sort(function (a, b) {
            const d = LEVEL_WEIGHT[b.level] - LEVEL_WEIGHT[a.level];
            if (d) return d;
            if (a.time < b.time) return -1;
            if (a.time > b.time) return 1;
            return a.ip < b.ip ? -1 : 1;
        });

        const ruleCounter = new Map();
        anomalies.forEach(function (a) {
            a.rules.forEach(function (r) { ruleCounter.set(r, (ruleCounter.get(r) || 0) + 1); });
        });
        const anomalyRules = Array.from(ruleCounter, function (e) {
            return { name: e[0], count: e[1], level: RULE_LEVEL[e[0]] || '低危' };
        }).sort(function (a, b) { return b.count - a.count; });

        let riskLevel = '安全';
        anomalies.forEach(function (a) {
            if (LEVEL_WEIGHT[a.level] > LEVEL_WEIGHT[riskLevel]) riskLevel = a.level;
        });

        function toRows(map, limit) {
            const arr = Array.from(map, function (e) { return { name: e[0], count: e[1] }; });
            arr.sort(function (a, b) { return b.count - a.count; });
            return limit ? arr.slice(0, limit) : arr;
        }

        return {
            total_requests: total, unique_ips: ipCounts.size, unique_urls: urlCounts.size,
            hourly: Array.from(hourly, function (e) { return { time: e[0], count: e[1] }; })
                         .sort(function (a, b) { return a.time < b.time ? -1 : 1; }),
            top_ips: toRows(ipCounts, 10), top_urls: toRows(urlCounts, 10),
            statuses: toRows(statusCounts), methods: toRows(methodCounts),
            anomalies: anomalies.slice(0, PREVIEW_LIMIT),
            anomaly_total: anomalies.length,
            anomaly_rules: anomalyRules,
            risk_level: riskLevel
        };
    }

    /* ---------------- DOM 工具 ---------------- */
    function $(id) { return document.getElementById(id); }
    function esc(s) {
        return String(s === null || s === undefined ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    // 把 URL 里的 %27 / %20 这类百分号编码还原成可读字符
    function decodeUrl(s) {
        try {
            let out = String(s === null || s === undefined ? '' : s);
            for (let i = 0; i < 3; i++) {
                const next = decodeURIComponent(out);
                if (next === out) break;
                out = next;
            }
            return out;
        } catch (e) {
            return String(s === null || s === undefined ? '' : s);
        }
    }
    function statusBadge(status) {
        if (status === null || status === undefined) return '<span class="badge badge-na">-</span>';
        const cls = status < 300 ? 'badge-2xx' : status < 400 ? 'badge-3xx' :
                    status < 500 ? 'badge-4xx' : 'badge-5xx';
        return '<span class="badge ' + cls + '">' + status + '</span>';
    }
    function statusColor(name) {
        const n = parseInt(name, 10);
        if (n >= 200 && n < 300) return '#10b981';
        if (n >= 300 && n < 400) return '#3b82f6';
        if (n >= 400 && n < 500) return '#f59e0b';
        if (n >= 500) return '#f43f5e';
        return '#94a3b8';
    }

    /* ---------------- 图表渲染 ---------------- */
    const EMPTY = '<div class="chart-empty">暂无数据</div>';
    const charts = [];
    let currentAnomalies = [];

    function csvCell(value) {
        const text = String(value === null || value === undefined ? '' : value);
        return '"' + text.replace(/"/g, '""') + '"';
    }

    function exportCSV() {
        if (!currentAnomalies.length) {
            alert('当前没有异常记录可导出');
            return;
        }
        const header = ['风险等级', '命中规则', '时间', '来源IP', '请求方法',
                        'URL', '状态码', 'User-Agent', '判定依据'];
        const lines = [header.map(csvCell).join(',')];
        currentAnomalies.forEach(function (a) {
            lines.push([
                a.level, a.rules.join('、'), a.time, a.ip, a.method,
                a.url, a.status === null ? '' : a.status, a.user_agent, a.detail
            ].map(csvCell).join(','));
        });
        const blob = new Blob(['\ufeff' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'loglens_anomalies.csv';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }


    // 给 hex / rgb 颜色附加透明度，用于 ECharts 渐变
    function withAlpha(color, alpha) {
        color = String(color || '').trim();
        if (color.startsWith('#')) {
            let hex = color.slice(1);
            if (hex.length === 3) hex = hex.split('').map(function (c) { return c + c; }).join('');
            const r = parseInt(hex.slice(0, 2), 16);
            const g = parseInt(hex.slice(2, 4), 16);
            const b = parseInt(hex.slice(4, 6), 16);
            return 'rgba(' + r + ',' + g + ',' + b + ',' + alpha + ')';
        }
        const m = color.match(/\d+/g);
        if (m && m.length >= 3) return 'rgba(' + m[0] + ',' + m[1] + ',' + m[2] + ',' + alpha + ')';
        return color;
    }

    function themeColors() {
        const s = getComputedStyle(document.documentElement);
        return {
            text: s.getPropertyValue('--muted').trim() || '#8d9bb5',
            grid: s.getPropertyValue('--border').trim() || 'rgba(148,163,184,.14)',
            primary: s.getPropertyValue('--primary').trim() || '#6366f1',
            cyan: s.getPropertyValue('--cyan').trim() || '#22d3ee',
            surface: s.getPropertyValue('--card-solid').trim() || '#111a2e'
        };
    }

    function baseTooltip() {
        const c = themeColors();
        return {
            trigger: 'axis',
            backgroundColor: c.surface,
            borderColor: c.grid,
            textStyle: { color: c.text, fontSize: 12 },
            extraCssText: 'border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.28)'
        };
    }

    function makeChart(id, option) {
        const el = $(id);
        if (!el) return null;
        const chart = echarts.init(el, null, { renderer: 'canvas' });
        chart.setOption(option);
        charts.push({ id: id, chart: chart, option: option });
        return chart;
    }

    function renderTrend(data) {
        const wrap = $('trend');
        if (!data.length) { wrap.innerHTML = EMPTY; return; }
        const c = themeColors();
        makeChart('trend', {
            color: [c.primary],
            tooltip: baseTooltip(),
            grid: { left: 48, right: 20, top: 30, bottom: 56 },
            xAxis: {
                type: 'category', boundaryGap: false,
                data: data.map(d => d.time.slice(5, 10) + ' ' + d.time.slice(11, 13) + ':00'),
                axisLine: { lineStyle: { color: c.grid } },
                axisLabel: { color: c.text, fontSize: 10, hideOverlap: true },
                axisTick: { show: false }
            },
            yAxis: {
                type: 'value', minInterval: 1,
                splitLine: { lineStyle: { color: c.grid, type: 'dashed' } },
                axisLabel: { color: c.text, fontSize: 10 }
            },
            series: [{
                name: '请求数', type: 'line', smooth: true, symbol: 'circle', symbolSize: 5,
                data: data.map(d => d.count),
                lineStyle: { width: 3 },
                itemStyle: { color: c.primary },
                areaStyle: {
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        { offset: 0, color: withAlpha(c.primary, 0.38) },
                        { offset: 1, color: withAlpha(c.primary, 0.02) }
                    ])
                }
            }]
        });
    }

    function renderStatus(data) {
        const wrap = $('statuses');
        if (!data.length) { wrap.innerHTML = EMPTY; return; }
        const total = data.reduce((s, d) => s + d.count, 0);
        makeChart('statuses', {
            color: data.map(d => statusColor(d.name)),
            tooltip: Object.assign(baseTooltip(), {
                trigger: 'item', formatter: '{b}：{c} 次（{d}%）'
            }),
            legend: {
                bottom: 0, textStyle: { color: themeColors().text, fontSize: 11 },
                data: data.map(d => d.name)
            },
            graphic: [{
                type: 'text', left: 'center', top: '43%',
                style: { text: String(total), fill: getComputedStyle(document.documentElement).getPropertyValue('--text').trim() || '#e9eefb', fontSize: 26, fontWeight: 700, textAlign: 'center' }
            }, {
                type: 'text', left: 'center', top: '54%',
                style: { text: '总请求', fill: themeColors().text, fontSize: 11, textAlign: 'center' }
            }],
            series: [{
                name: '状态码', type: 'pie', radius: ['52%', '74%'], center: ['50%', '48%'],
                avoidLabelOverlap: true,
                label: { show: false },
                itemStyle: { borderColor: themeColors().surface, borderWidth: 2 },
                data: data.map(d => ({ name: d.name, value: d.count }))
            }]
        });
    }

    function renderHBars(id, rows) {
        const wrap = $(id);
        if (!rows.length) { wrap.innerHTML = EMPTY; return; }
        const c = themeColors();
        const items = rows.slice().reverse();
        makeChart(id, {
            color: [c.primary],
            tooltip: Object.assign(baseTooltip(), { trigger: 'item', formatter: '{b}：{c} 次' }),
            grid: { left: 8, right: 36, top: 8, bottom: 8, containLabel: true },
            xAxis: {
                type: 'value', minInterval: 1,
                splitLine: { lineStyle: { color: c.grid, type: 'dashed' } },
                axisLabel: { color: c.text, fontSize: 10 }
            },
            yAxis: {
                type: 'category',
                data: items.map(r => r.name.length > 18 ? r.name.slice(0, 18) + '…' : r.name),
                axisLine: { show: false }, axisTick: { show: false },
                axisLabel: { color: c.text, fontSize: 10 }
            },
            series: [{
                type: 'bar', data: items.map(r => r.count), barWidth: '58%',
                itemStyle: {
                    borderRadius: [0, 5, 5, 0],
                    color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
                        { offset: 0, color: c.primary }, { offset: 1, color: c.cyan }
                    ])
                }
            }]
        });
    }

    function renderMethods(rows) {
        const wrap = $('methods');
        if (!rows.length) { wrap.innerHTML = EMPTY; return; }
        const c = themeColors();
        makeChart('methods', {
            color: [c.cyan],
            tooltip: baseTooltip(),
            grid: { left: 40, right: 16, top: 30, bottom: 28 },
            xAxis: {
                type: 'category',
                data: rows.map(r => r.name || '-'),
                axisLine: { lineStyle: { color: c.grid } }, axisTick: { show: false },
                axisLabel: { color: c.text, fontSize: 11 }
            },
            yAxis: {
                type: 'value', minInterval: 1,
                splitLine: { lineStyle: { color: c.grid, type: 'dashed' } },
                axisLabel: { color: c.text, fontSize: 10 }
            },
            series: [{
                name: '请求数', type: 'bar', barWidth: '46%',
                data: rows.map(r => r.count),
                itemStyle: {
                    borderRadius: [6, 6, 0, 0],
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        { offset: 0, color: c.cyan }, { offset: 1, color: c.primary }
                    ])
                }
            }]
        });
    }

    function fillResult(parsed, filename, totalLines) {
        const s = analyze(parsed.records);
        currentAnomalies = s.anomalies;

        $('kpiTotal').textContent = s.total_requests;
        $('kpiIps').textContent = s.unique_ips;
        $('kpiUrls').textContent = s.unique_urls;
        $('kpiAnomalies').textContent = s.anomaly_total;

        const banner = $('riskBanner');
        banner.className = 'risk-banner risk-' + s.risk_level;
        $('riskLevel').textContent = s.risk_level;
        $('riskSummary').textContent = '检出 ' + s.anomaly_total + ' 条异常访问；原始行数 ' +
            totalLines + '，解析成功 ' + s.total_requests + '，失败 ' + parsed.failed + '。';
        $('riskChips').innerHTML = s.anomaly_rules.length
            ? s.anomaly_rules.map(function (r) {
                return '<span class="risk-chip">' + esc(r.name) + '<b>' + r.count + '</b></span>';
              }).join('')
            : '<span class="risk-chip">未命中任何检测规则</span>';

        $('anomalySummary').innerHTML = '基于规则库识别敏感路径探测、注入载荷、扫描器 UA、危险方法、服务端错误、目录扫描与高频访问；共命中 <b>' +
            s.anomaly_total + '</b> 条，下表展示前 <b>' + s.anomalies.length + '</b> 条。';
        $('anomalyBody').innerHTML = s.anomalies.length
            ? s.anomalies.map(function (a) {
                return '<tr><td><span class="badge lv-' + a.level + '">' + a.level + '</span></td>' +
                    '<td><div class="rule-tags">' + a.rules.map(function (r) {
                        return '<span class="rule-tag">' + esc(r) + '</span>';
                    }).join('') + '</div></td>' +
                    '<td class="mono">' + esc(a.time) + '</td>' +
                    '<td class="mono cell-strong">' + esc(a.ip) + '</td>' +
                    '<td class="mono">' + esc(a.method) + '</td>' +
                    '<td class="mono cell-url" title="' + esc(decodeUrl(a.url)) + '">' + esc(decodeUrl(a.url)) + '</td>' +
                    '<td>' + statusBadge(a.status) + '</td>' +
                    '<td class="cell-url" title="' + esc(decodeUrl(a.detail)) + '">' + esc(decodeUrl(a.detail)) + '</td></tr>';
              }).join('')
            : '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:28px">未检测到异常访问，日志看起来很干净。</td></tr>';

        const preview = parsed.records.slice(0, PREVIEW_LIMIT);
        $('recordSummary').innerHTML = '共解析 ' + s.total_requests + ' 条记录，此处展示前 ' + preview.length + ' 条。';
        $('recordBody').innerHTML = preview.map(function (r) {
            return '<tr><td class="mono">' + esc(r.ip) + '</td>' +
                '<td class="mono">' + esc(r.time) + '</td>' +
                '<td class="mono">' + esc(r.method) + '</td>' +
                '<td class="mono cell-url" title="' + esc(decodeUrl(r.url)) + '">' + esc(decodeUrl(r.url)) + '</td>' +
                '<td>' + statusBadge(r.status) + '</td>' +
                '<td class="cell-url" title="' + esc(r.user_agent) + '">' + esc(r.user_agent) + '</td></tr>';
        }).join('');

        renderTrend(s.hourly);
        renderStatus(s.statuses);
        renderHBars('ips', s.top_ips);
        renderHBars('urls', s.top_urls);
        renderMethods(s.methods);

        $('filename').textContent = '当前文件：' + filename;
        $('emptyState').hidden = true;
        $('result').hidden = false;
        // result 由 hidden 变为可见后再初始化图表，否则容器宽度为 0
        requestAnimationFrame(function () {
            charts.forEach(function (item) { item.chart.resize(); });
        });
        $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function showError(message) {
        $('emptyState').hidden = true;
        $('result').hidden = true;
        $('errorBox').textContent = '⚠ ' + message;
        $('errorBox').hidden = false;
    }

    /* ---------------- 交互绑定 ---------------- */
    function init() {
        // 主题切换
        const root = document.documentElement;
        const themeBtn = $('themeToggle');
        if (localStorage.getItem('loglens-theme') === 'light') root.setAttribute('data-theme', 'light');
        function syncIcon() { themeBtn.textContent = root.getAttribute('data-theme') === 'light' ? '☀' : '☾'; }
        syncIcon();
        themeBtn.addEventListener('click', function () {
            const next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
            root.setAttribute('data-theme', next);
            localStorage.setItem('loglens-theme', next);
            syncIcon();
            // 主题变化后重绘图表以适配新配色
            const idMap = { trend: 'trend', statuses: 'statuses', ips: 'ips', urls: 'urls', methods: 'methods' };
            charts.forEach(function (item) {
                const c = themeColors();
                const opt = item.option;
                if (opt.color) opt.color = item.id === 'statuses' ? opt.color : [c.primary];
                if (opt.xAxis && opt.xAxis.axisLabel) opt.xAxis.axisLabel.color = c.text;
                if (opt.yAxis && opt.yAxis.axisLabel) opt.yAxis.axisLabel.color = c.text;
                if (opt.legend && opt.legend.textStyle) opt.legend.textStyle.color = c.text;
                item.chart.setOption(opt, true);
            });
        });

        window.addEventListener('resize', function () {
            charts.forEach(function (item) { item.chart.resize(); });
        });

        $('exportBtn').addEventListener('click', exportCSV);

        const input = $('logfile');
        const drop = $('drop');
        const nameEl = $('filename');
        const submitBtn = $('submitBtn');

        function showName() {
            if (input.files && input.files[0]) nameEl.textContent = '已选择：' + input.files[0].name;
        }
        ['dragenter', 'dragover'].forEach(function (ev) {
            drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('drag'); });
        });
        ['dragleave', 'drop'].forEach(function (ev) {
            drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('drag'); });
        });
        drop.addEventListener('drop', function (e) {
            if (e.dataTransfer.files && e.dataTransfer.files.length) {
                input.files = e.dataTransfer.files; showName();
            }
        });
        input.addEventListener('change', showName);

        $('uploadForm').addEventListener('submit', function (e) {
            e.preventDefault();
            if (!input.files || !input.files[0]) return;
            submitBtn.disabled = true;
            submitBtn.textContent = '分析中…';
            const file = input.files[0];
            const reader = new FileReader();
            reader.onload = function () {
                fillResult(parseText(String(reader.result)), file.name, String(reader.result).split(/\r?\n/).filter(Boolean).length);
                submitBtn.disabled = false;
                submitBtn.textContent = '开始分析';
            };
            reader.onerror = function () { showError('文件读取失败'); submitBtn.disabled = false; submitBtn.textContent = '开始分析'; };
            reader.readAsText(file, 'utf-8');
        });

    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
