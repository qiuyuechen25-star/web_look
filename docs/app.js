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

    function smoothPath(pts) {
        if (!pts.length) return '';
        if (pts.length === 1) return 'M ' + pts[0][0].toFixed(1) + ',' + pts[0][1].toFixed(1);
        let d = 'M ' + pts[0][0].toFixed(1) + ',' + pts[0][1].toFixed(1);
        for (let i = 0; i < pts.length - 1; i++) {
            const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
            const c1x = p1[0] + (p2[0] - p0[0]) / 6, c1y = p1[1] + (p2[1] - p0[1]) / 6;
            const c2x = p2[0] - (p3[0] - p1[0]) / 6, c2y = p2[1] - (p3[1] - p1[1]) / 6;
            d += ' C ' + c1x.toFixed(1) + ',' + c1y.toFixed(1) + ' ' +
                 c2x.toFixed(1) + ',' + c2y.toFixed(1) + ' ' +
                 p2[0].toFixed(1) + ',' + p2[1].toFixed(1);
        }
        return d;
    }

    function renderTrend(data) {
        const wrap = $('trend');
        if (!data.length) { wrap.innerHTML = EMPTY; return; }
        const W = 1000, H = 320, padL = 46, padR = 18, padT = 24, padB = 48;
        const iW = W - padL - padR, iH = H - padT - padB;
        const maxV = Math.max.apply(null, data.map(function (d) { return d.count; }).concat([1]));
        const n = data.length;
        const X = function (i) { return n === 1 ? padL + iW / 2 : padL + iW * i / (n - 1); };
        const Y = function (v) { return padT + iH * (1 - v / maxV); };
        const pts = data.map(function (d, i) { return [X(i), Y(d.count)]; });
        const line = smoothPath(pts);
        const area = line + ' L ' + pts[n - 1][0].toFixed(1) + ',' + (padT + iH) +
                     ' L ' + pts[0][0].toFixed(1) + ',' + (padT + iH) + ' Z';
        let svg = '<svg class="svg-trend" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="xMidYMid meet">';
        svg += '<defs>' +
            '<linearGradient id="lineGrad" x1="0" y1="0" x2="1" y2="0">' +
                '<stop offset="0%" style="stop-color:var(--primary)"/>' +
                '<stop offset="100%" style="stop-color:var(--cyan)"/>' +
            '</linearGradient>' +
            '<linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">' +
                '<stop offset="0%" style="stop-color:var(--primary);stop-opacity:.32"/>' +
                '<stop offset="100%" style="stop-color:var(--primary);stop-opacity:0"/>' +
            '</linearGradient></defs>';
        for (let g = 0; g <= 4; g++) {
            const gy = padT + iH * g / 4;
            svg += '<line class="grid-line" x1="' + padL + '" y1="' + gy.toFixed(1) +
                   '" x2="' + (W - padR) + '" y2="' + gy.toFixed(1) + '"/>';
            svg += '<text class="axis-y" x="' + (padL - 9) + '" y="' + (gy + 4).toFixed(1) + '">' +
                   Math.round(maxV * (4 - g) / 4) + '</text>';
        }
        svg += '<path d="' + area + '" fill="url(#areaGrad)"/>';
        svg += '<path class="trend-line" d="' + line + '"/>';
        pts.forEach(function (p) {
            svg += '<circle class="trend-dot" cx="' + p[0].toFixed(1) + '" cy="' + p[1].toFixed(1) + '" r="3.2"/>';
        });
        const step = Math.max(1, Math.ceil(n / 8));
        data.forEach(function (d, i) {
            if (i % step === 0 || i === n - 1) {
                const label = d.time.slice(5, 10) + ' ' + d.time.slice(11, 13) + ':00';
                svg += '<text class="axis-t" x="' + X(i).toFixed(1) + '" y="' + (H - 16) + '">' + label + '</text>';
            }
        });
        svg += '<line class="trend-cursor" x1="0" y1="' + padT + '" x2="0" y2="' + (padT + iH) + '"/>';
        svg += '</svg><div class="chart-tip" id="trendTip"></div>';
        wrap.innerHTML = svg;

        const svgEl = wrap.querySelector('svg');
        const tip = wrap.querySelector('.chart-tip');
        const cursor = wrap.querySelector('.trend-cursor');
        svgEl.addEventListener('mousemove', function (e) {
            const pt = svgEl.createSVGPoint();
            pt.x = e.clientX; pt.y = e.clientY;
            const loc = pt.matrixTransform(svgEl.getScreenCTM().inverse());
            if (loc.x < padL - 8 || loc.x > W - padR + 8) {
                tip.style.opacity = 0; cursor.style.opacity = 0; return;
            }
            let idx = n === 1 ? 0 : Math.round((loc.x - padL) / iW * (n - 1));
            idx = Math.max(0, Math.min(n - 1, idx));
            const p = pts[idx];
            cursor.setAttribute('x1', p[0].toFixed(1));
            cursor.setAttribute('x2', p[0].toFixed(1));
            cursor.style.opacity = 1;
            tip.innerHTML = data[idx].time + ' · <b>' + data[idx].count + '</b> 次请求';
            const scale = svgEl.getBoundingClientRect().width / W;
            tip.style.left = (p[0] * scale) + 'px';
            tip.style.top = (p[1] * scale) + 'px';
            tip.style.opacity = 1;
        });
        svgEl.addEventListener('mouseleave', function () {
            tip.style.opacity = 0; cursor.style.opacity = 0;
        });
    }

    function renderStatus(data) {
        const wrap = $('statuses');
        if (!data.length) { wrap.innerHTML = EMPTY; return; }
        const total = data.reduce(function (s, d) { return s + d.count; }, 0);
        const cx = 110, cy = 110, r = 76, sw = 25, C = 2 * Math.PI * r;
        let off = 0, segs = '';
        data.forEach(function (d) {
            const len = d.count / total * C;
            segs += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' +
                statusColor(d.name) + '" stroke-width="' + sw + '" stroke-dasharray="' +
                len.toFixed(2) + ' ' + (C - len).toFixed(2) + '" stroke-dashoffset="' +
                (-off).toFixed(2) + '" transform="rotate(-90 ' + cx + ' ' + cy + ')">' +
                '<title>' + esc(d.name) + '：' + d.count + ' 次（' + Math.round(d.count / total * 100) + '%）</title></circle>';
            off += len;
        });
        let html = '<div class="donut-wrap"><svg class="donut" viewBox="0 0 220 220" width="210" height="210">' + segs +
            '<text class="donut-num" x="' + cx + '" y="' + (cy - 2) + '">' + total + '</text>' +
            '<text class="donut-lbl" x="' + cx + '" y="' + (cy + 17) + '">总请求</text></svg>';
        html += '<div class="legend">' + data.map(function (d) {
            return '<span><i style="background:' + statusColor(d.name) + '"></i>' + esc(d.name) + ' · ' + d.count + '</span>';
        }).join('') + '</div></div>';
        wrap.innerHTML = html;
    }

    function renderHBars(id, rows) {
        const wrap = $(id);
        if (!rows.length) { wrap.innerHTML = EMPTY; return; }
        const max = Math.max.apply(null, rows.map(function (r) { return r.count; }));
        let html = '<div class="hbars">';
        rows.forEach(function (r) {
            const pct = (r.count / max * 100).toFixed(1);
            html += '<div class="hbar"><span class="hname" title="' + esc(r.name) + '">' + esc(r.name) + '</span>' +
                '<span class="htrack"><span class="hfill" data-w="' + pct + '"></span></span>' +
                '<span class="hval">' + r.count + '</span></div>';
        });
        wrap.innerHTML = html + '</div>';
        requestAnimationFrame(function () {
            wrap.querySelectorAll('.hfill').forEach(function (el) { el.style.width = el.dataset.w + '%'; });
        });
    }

    function renderMethods(rows) {
        const wrap = $('methods');
        if (!rows.length) { wrap.innerHTML = EMPTY; return; }
        const max = Math.max.apply(null, rows.map(function (r) { return r.count; }));
        let html = '<div class="vbars">';
        rows.forEach(function (r) {
            const pct = (r.count / max * 100).toFixed(1);
            html += '<div class="vbar"><span class="vval">' + r.count + '</span>' +
                '<span class="vfill" data-h="' + pct + '"></span>' +
                '<span class="vlbl" title="' + esc(r.name) + '">' + esc(r.name || '-') + '</span></div>';
        });
        wrap.innerHTML = html + '</div>';
        requestAnimationFrame(function () {
            wrap.querySelectorAll('.vfill').forEach(function (el) { el.style.height = el.dataset.h + '%'; });
        });
    }

    /* ---------------- 结果填充 ---------------- */
    function fillResult(parsed, filename, totalLines) {
        const s = analyze(parsed.records);

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
        });

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

        $('uploadForm').addEventListener('submit', function () {
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
