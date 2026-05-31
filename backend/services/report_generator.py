"""HTML report generation service."""

from __future__ import annotations

import html
import os
from datetime import datetime
from itertools import groupby


def _status_label(status: str) -> str:
    return {
        "pending": "待处理",
        "running": "运行中",
        "completed": "已完成",
        "failed": "失败",
        "cancelled": "已取消",
    }.get(status, status or "-")


def _severity_label(severity: str) -> str:
    return {
        "Critical": "严重",
        "High": "高危",
        "Medium": "中危",
        "Low": "低危",
        "Info": "提示",
    }.get(severity, severity or "-")


def _poc_status_label(status: str) -> str:
    return {
        "valid": "已通过",
        "invalid": "不完整",
        "unknown": "待校验",
    }.get(status, status or "待校验")


def _severity_rank(severity: str) -> int:
    return {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Info": 4,
    }.get(severity, 5)


def _build_severity_counts(vulns) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for vuln in vulns:
        severity = getattr(vuln, "severity", "Info") or "Info"
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _build_poc_counts(vulns) -> dict:
    counts = {"valid": 0, "invalid": 0, "unknown": 0}
    for vuln in vulns:
        status = getattr(vuln, "poc_validation_status", "unknown") or "unknown"
        if status not in counts:
            status = "unknown"
        counts[status] += 1
    return counts


def _get_summary_severity_counts(task) -> dict | None:
    summary = getattr(task, "summary", None) or {}
    severity_stats = summary.get("severity_stats", {})
    if not isinstance(severity_stats, dict):
        return None
    return {
        "Critical": int(severity_stats.get("Critical", 0) or 0),
        "High": int(severity_stats.get("High", 0) or 0),
        "Medium": int(severity_stats.get("Medium", 0) or 0),
        "Low": int(severity_stats.get("Low", 0) or 0),
        "Info": int(severity_stats.get("Info", 0) or 0),
    }


def _get_scan_stats(task) -> dict:
    summary = getattr(task, "summary", None) or {}
    scan_stats = summary.get("scan_stats", {})
    if not isinstance(scan_stats, dict):
        return {}
    return {
        **scan_stats,
        "total_files": int(scan_stats.get("total_files", scan_stats.get("source_files_detected", 0)) or 0),
        "indexed_files": int(scan_stats.get("indexed_files", scan_stats.get("source_files_indexed", scan_stats.get("source_files_detected", 0))) or 0),
        "selected_files": int(scan_stats.get("selected_files", scan_stats.get("files_selected_for_audit", scan_stats.get("files_considered_for_chunks", 0))) or 0),
        "included_files": int(scan_stats.get("included_files", scan_stats.get("files_considered_for_chunks", 0)) or 0),
        "total_chunks": int(scan_stats.get("total_chunks", scan_stats.get("chunk_count", 0)) or 0),
    }


def _vuln_location(vuln) -> str:
    path = getattr(vuln, "file_path", "") or "-"
    line_start = getattr(vuln, "line_start", None)
    line_end = getattr(vuln, "line_end", None)
    if line_start:
        path += f":L{line_start}"
        if line_end:
            path += f"-{line_end}"
    return path


def _esc(value) -> str:
    return html.escape(str(value or ""), quote=True)


def _nl2br(value) -> str:
    return _esc(value).replace("\n", "<br>")


def _severity_class(severity: str) -> str:
    return f"sev-{str(severity or 'Info').lower()}"


def _confidence_label(value: str) -> str:
    return {
        "high": "高",
        "medium": "中",
        "low": "低",
    }.get(str(value or "").lower(), value or "-")


def _group_vulnerabilities(vulns) -> list[tuple[str, list]]:
    sorted_vulns = sorted(
        vulns,
        key=lambda item: (
            str(getattr(item, "vuln_type", "") or "未分类漏洞"),
            _severity_rank(getattr(item, "severity", "")),
            str(getattr(item, "title", "") or ""),
        ),
    )
    groups = []
    for vuln_type, items in groupby(sorted_vulns, key=lambda item: getattr(item, "vuln_type", "") or "未分类漏洞"):
        groups.append((vuln_type, list(items)))
    groups.sort(
        key=lambda item: (
            min(_severity_rank(getattr(vuln, "severity", "")) for vuln in item[1]),
            item[0],
        )
    )
    return groups


def _render_metric(label: str, value) -> str:
    return f"""
      <div class="metric">
        <span>{_esc(label)}</span>
        <strong>{_esc(value)}</strong>
      </div>
    """


def _render_badge(text: str, class_name: str = "") -> str:
    classes = "badge" + (f" {class_name}" if class_name else "")
    return f'<span class="{classes}">{_esc(text)}</span>'


def _render_vulnerability(vuln, index: int) -> str:
    severity = getattr(vuln, "severity", "Info") or "Info"
    endpoint = getattr(vuln, "endpoint", "") or ""
    poc_status = getattr(vuln, "poc_validation_status", "unknown") or "unknown"
    poc_note = getattr(vuln, "poc_validation_note", "") or ""
    confidence = getattr(vuln, "confidence", "") or ""

    parts = [
        '<article class="finding">',
        '<div class="finding-head">',
        f'<h3>{index}. {_esc(getattr(vuln, "title", "") or "未命名漏洞")}</h3>',
        '<div class="badges">',
        _render_badge(_severity_label(severity), _severity_class(severity)),
        _render_badge(f"POC {_poc_status_label(poc_status)}", f"poc-{poc_status}"),
        _render_badge(f"置信度 {_confidence_label(confidence)}", "confidence"),
        "</div>",
        "</div>",
        '<dl class="finding-meta">',
        f"<dt>位置</dt><dd><code>{_esc(_vuln_location(vuln))}</code></dd>",
    ]
    if endpoint:
        parts.append(f"<dt>接口</dt><dd><code>{_esc(endpoint)}</code></dd>")
    parts.append("</dl>")

    description = getattr(vuln, "description", "") or ""
    if description:
        parts.append('<section><h4>根因与影响</h4>')
        parts.append(f'<p class="text">{_nl2br(description)}</p></section>')

    code_snippet = getattr(vuln, "code_snippet", "") or ""
    if code_snippet:
        parts.append('<section><h4>代码证据</h4>')
        parts.append(f"<pre><code>{_esc(code_snippet[:1600])}</code></pre></section>")

    poc_raw = getattr(vuln, "poc_raw", "") or ""
    if poc_raw:
        parts.append('<section><h4>复现方式</h4>')
        parts.append(f"<pre><code>{_esc(poc_raw[:2200])}</code></pre></section>")
    if poc_note:
        parts.append(f'<p class="note">POC 校验说明：{_nl2br(poc_note)}</p>')

    fix_suggestion = getattr(vuln, "fix_suggestion", "") or ""
    if fix_suggestion:
        parts.append('<section><h4>修复建议</h4>')
        parts.append(f'<p class="text">{_nl2br(fix_suggestion)}</p></section>')

    parts.append("</article>")
    return "\n".join(parts)


def _render_vulnerability_groups(vulns) -> str:
    if not vulns:
        return '<section class="empty">未发现已确认的安全漏洞。</section>'

    sections = []
    for vuln_type, group_items in _group_vulnerabilities(vulns):
        severity_counts = _build_severity_counts(group_items)
        group_badges = "".join(
            _render_badge(f"{_severity_label(sev)} {count}", _severity_class(sev))
            for sev, count in severity_counts.items()
            if count
        )
        findings = "\n".join(
            _render_vulnerability(vuln, index)
            for index, vuln in enumerate(
                sorted(
                    group_items,
                    key=lambda item: (
                        _severity_rank(getattr(item, "severity", "")),
                        str(getattr(item, "title", "") or ""),
                    ),
                ),
                1,
            )
        )
        sections.append(
            f"""
            <section class="vuln-group">
              <div class="group-head">
                <h2>{_esc(vuln_type)}</h2>
                <div class="badges">{group_badges}</div>
              </div>
              {findings}
            </section>
            """
        )
    return "\n".join(sections)


def _build_html_content(project, task, stages, vulns) -> str:
    severity_counts = _get_summary_severity_counts(task) or _build_severity_counts(vulns)
    poc_counts = _build_poc_counts(vulns)
    scan_stats = _get_scan_stats(task)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    project_name = project.name if project else "未知项目"
    tech_stack = project.tech_stack if project and project.tech_stack else "未识别"

    severity_metrics = "".join(
        _render_metric(_severity_label(sev), severity_counts.get(sev, 0))
        for sev in ["Critical", "High", "Medium", "Low", "Info"]
    )
    scan_metrics = "".join(
        [
            _render_metric("漏洞总数", len(vulns)),
            _render_metric("POC 通过", poc_counts["valid"]),
            _render_metric("POC 不完整", poc_counts["invalid"]),
            _render_metric("扫描文件数", scan_stats.get("total_files", 0)),
            _render_metric("分析文件数", scan_stats.get("included_files", 0)),
            _render_metric("代码块数", scan_stats.get("total_chunks", 0)),
            _render_metric("规则命中", scan_stats.get("rule_hit_count", 0)),
        ]
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI 代码安全审计报告 - {_esc(project_name)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f8fb;
      --panel: #ffffff;
      --text: #172033;
      --muted: #667085;
      --border: #d9e1ec;
      --blue: #2563eb;
      --red: #d92d20;
      --orange: #b54708;
      --green: #027a48;
      --gray: #475467;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Microsoft YaHei", "PingFang SC", "Noto Sans SC", Arial, sans-serif;
      color: var(--text);
      background: var(--bg);
      line-height: 1.65;
    }}
    .page {{ max-width: 1180px; margin: 0 auto; padding: 32px 24px 56px; }}
    .hero {{
      background: #111827;
      color: #fff;
      border-radius: 8px;
      padding: 28px 32px;
      margin-bottom: 20px;
    }}
    .hero h1 {{ margin: 0 0 12px; font-size: 28px; line-height: 1.25; }}
    .hero-meta {{ display: flex; flex-wrap: wrap; gap: 12px 24px; color: #d1d5db; font-size: 14px; }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 18px;
      box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
    }}
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }}
    .metric {{ border: 1px solid var(--border); border-radius: 8px; padding: 12px; background: #fbfdff; }}
    .metric span {{ display: block; color: var(--muted); font-size: 13px; }}
    .metric strong {{ display: block; margin-top: 4px; font-size: 24px; }}
    h2 {{ margin: 0 0 14px; font-size: 20px; }}
    h3 {{ margin: 0; font-size: 17px; }}
    h4 {{ margin: 16px 0 8px; font-size: 14px; color: var(--gray); }}
    .vuln-group {{ margin-top: 24px; }}
    .group-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      border-bottom: 2px solid var(--border);
      padding-bottom: 10px;
      margin-bottom: 14px;
    }}
    .finding {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 18px;
      margin-bottom: 14px;
    }}
    .finding-head {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }}
    .badges {{ display: flex; flex-wrap: wrap; gap: 6px; }}
    .badge {{
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 2px 9px;
      font-size: 12px;
      font-weight: 600;
      border: 1px solid var(--border);
      background: #f8fafc;
      color: var(--gray);
      white-space: nowrap;
    }}
    .sev-critical {{ color: #fff; background: var(--red); border-color: var(--red); }}
    .sev-high {{ color: #fff; background: var(--orange); border-color: var(--orange); }}
    .sev-medium {{ color: #fff; background: var(--blue); border-color: var(--blue); }}
    .sev-low {{ color: #fff; background: var(--green); border-color: var(--green); }}
    .sev-info {{ color: var(--gray); background: #eef2f6; }}
    .poc-valid {{ color: var(--green); border-color: #abefc6; background: #ecfdf3; }}
    .poc-invalid {{ color: var(--red); border-color: #fecdca; background: #fef3f2; }}
    .poc-unknown, .confidence {{ color: var(--gray); background: #f2f4f7; }}
    .finding-meta {{
      display: grid;
      grid-template-columns: 56px 1fr;
      gap: 6px 10px;
      margin: 14px 0 0;
      font-size: 13px;
    }}
    .finding-meta dt {{ color: var(--muted); }}
    .finding-meta dd {{ margin: 0; word-break: break-all; }}
    code {{ font-family: Consolas, "Courier New", monospace; }}
    pre {{
      margin: 0;
      padding: 14px;
      border-radius: 8px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
      background: #101828;
      color: #e5e7eb;
      font-size: 12px;
      line-height: 1.55;
    }}
    .text {{ margin: 0; }}
    .note {{
      margin: 12px 0 0;
      padding: 10px 12px;
      border-radius: 8px;
      background: #fff7ed;
      border: 1px solid #fed7aa;
      color: #9a3412;
      font-size: 13px;
    }}
    .empty {{
      background: var(--panel);
      border: 1px dashed var(--border);
      border-radius: 8px;
      padding: 24px;
      color: var(--muted);
      text-align: center;
    }}
    @media print {{
      body {{ background: #fff; }}
      .page {{ max-width: none; padding: 0; }}
      .panel, .finding, .hero {{ box-shadow: none; break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <main class="page">
    <header class="hero">
      <h1>AI 代码安全审计报告</h1>
      <div class="hero-meta">
        <span>项目：{_esc(project_name)}</span>
        <span>技术栈：{_esc(tech_stack)}</span>
        <span>审计状态：{_esc(_status_label(task.status))}</span>
        <span>生成时间：{_esc(generated_at)}</span>
      </div>
    </header>

    <section class="panel">
      <h2>风险等级概览</h2>
      <div class="metrics">{severity_metrics}</div>
    </section>

    <section class="panel">
      <h2>审计统计</h2>
      <div class="metrics">{scan_metrics}</div>
    </section>

    {_render_vulnerability_groups(vulns)}
  </main>
</body>
</html>
"""


def generate_html(report_dir, project, task, stages, vulns) -> str:
    content = _build_html_content(project, task, stages, vulns)
    filepath = os.path.join(report_dir, f"audit_report_{task.id}.html")
    with open(filepath, "w", encoding="utf-8") as file:
        file.write(content)
    return filepath
