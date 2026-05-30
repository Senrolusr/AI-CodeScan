"""报告生成服务，支持 Markdown 和 PDF。"""

import os
import re
import textwrap
from datetime import datetime

from services.code_parser import load_project_cache


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
    counts = {}
    for vuln in vulns:
        counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
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


def _get_cache_trace(project) -> dict:
    if not project:
        return {"available": False}
    cached = load_project_cache(project.id, file_tree=getattr(project, "file_tree", None) or [])
    if not cached:
        return {"available": False}
    return {
        "available": True,
        "cache_schema_version": cached.get("cache_schema_version"),
        "project_fingerprint": cached.get("project_fingerprint") or "",
        "analysis_strategy_fingerprint": cached.get("analysis_strategy_fingerprint") or "",
    }


def _vuln_location(vuln) -> str:
    path = vuln.file_path or "-"
    if vuln.line_start:
        path += f":L{vuln.line_start}"
        if vuln.line_end:
            path += f"-{vuln.line_end}"
    return path


def _append_table(lines: list[str], headers: list[str], rows: list[list[str]]) -> None:
    lines.append("| " + " | ".join(headers) + " |\n")
    lines.append("|" + "|".join(["---"] * len(headers)) + "|\n")
    for row in rows:
        safe_row = [str(item).replace("\n", " ").replace("|", "\\|").strip() for item in row]
        lines.append("| " + " | ".join(safe_row) + " |\n")
    lines.append("\n")


def _build_markdown_content(project, task, stages, vulns) -> str:
    lines = []
    severity_counts = _get_summary_severity_counts(task) or _build_severity_counts(vulns)
    poc_counts = _build_poc_counts(vulns)
    scan_stats = _get_scan_stats(task)

    # ── 标题 ──
    lines.append("# AI 代码安全审计报告\n\n")

    # ── 基本信息 ──
    lines.append("## 基本信息\n\n")
    lines.append(f"| 项目 | {project.name if project else '未知项目'} |\n")
    lines.append(f"| --- | --- |\n")
    lines.append(f"| 技术栈 | {project.tech_stack if project and project.tech_stack else '未识别'} |\n")
    lines.append(f"| 审计时间 | {datetime.now().strftime('%Y-%m-%d %H:%M')} |\n")
    lines.append(f"| 状态 | {_status_label(task.status)} |\n\n")

    # ── 风险概览（合并统计） ──
    lines.append("## 风险概览\n\n")
    sev_rows = []
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        cnt = severity_counts.get(sev, 0)
        if cnt:
            sev_rows.append(f"**{_severity_label(sev)}** {cnt}")
    lines.append("> " + " / ".join(sev_rows) + f" / **总计** {len(vulns)}\n\n")

    overview_rows = [
        ["POC 已通过", str(poc_counts["valid"])],
        ["POC 不完整", str(poc_counts["invalid"])],
        ["POC 待校验", str(poc_counts["unknown"])],
        ["扫描文件数", str(scan_stats.get("total_files", 0))],
        ["分析文件数", str(scan_stats.get("included_files", 0))],
        ["代码块数", str(scan_stats.get("total_chunks", 0))],
        ["规则命中", str(scan_stats.get("rule_hit_count", 0))],
    ]
    _append_table(lines, ["指标", "值"], overview_rows)

    # ── 重点关注 ──
    sorted_vulns = sorted(
        vulns,
        key=lambda v: (
            _severity_rank(getattr(v, "severity", "")),
            getattr(v, "title", "") or "",
        ),
    )
    top_vulns = sorted_vulns[:5]
    if top_vulns:
        lines.append("## 重点关注\n\n")
        _append_table(
            lines,
            ["#", "漏洞", "等级", "类型", "位置"],
            [
                [i, v.title or "未命名", _severity_label(v.severity), v.vuln_type or "-", _vuln_location(v)]
                for i, v in enumerate(top_vulns, 1)
            ],
        )

    # ── 漏洞详情 ──
    lines.append("## 漏洞详情\n\n")
    if not vulns:
        lines.append("未发现已确认的安全漏洞。\n")
        return "".join(lines)

    for index, vuln in enumerate(sorted_vulns, 1):
        lines.append(f"### {index}. {vuln.title} [{_severity_label(vuln.severity)}]\n\n")
        meta_parts = [f"`{vuln.vuln_type or '-'}`"]
        meta_parts.append(f"`{_vuln_location(vuln)}`")
        if vuln.endpoint:
            meta_parts.append(f"`{vuln.endpoint}`")
        lines.append(" / ".join(meta_parts) + "\n\n")

        if vuln.description:
            lines.append(f"{vuln.description}\n\n")
        if vuln.code_snippet:
            snippet = vuln.code_snippet
            if len(snippet) > 800:
                snippet = snippet[:800] + "\n... (已截断)"
            lines.append("```text\n" + snippet + "\n```\n\n")
        if vuln.poc_raw:
            poc = vuln.poc_raw
            if len(poc) > 1200:
                poc = poc[:1200] + "\n... (已截断)"
            lines.append("```http\n" + poc + "\n```\n\n")
        if vuln.fix_suggestion:
            lines.append(f"**修复**：{vuln.fix_suggestion}\n\n")
        lines.append("---\n\n")

    return "".join(lines)


def _build_plaintext_content(project, task, stages, vulns) -> str:
    severity_counts = _get_summary_severity_counts(task) or _build_severity_counts(vulns)
    poc_counts = _build_poc_counts(vulns)
    scan_stats = _get_scan_stats(task)

    sorted_vulns = sorted(
        vulns,
        key=lambda v: (
            _severity_rank(getattr(v, "severity", "")),
            getattr(v, "title", "") or "",
        ),
    )

    lines = [
        "AI 代码安全审计报告",
        "",
        f"项目：{project.name if project else '未知项目'}",
        f"技术栈：{project.tech_stack if project and project.tech_stack else '未识别'}",
        f"审计时间：{datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"状态：{_status_label(task.status)}",
        "",
        "风险概览",
    ]
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        cnt = severity_counts.get(sev, 0)
        if cnt:
            lines.append(f"  {_severity_label(sev)}：{cnt}")
    lines.append(f"  总计：{len(vulns)}")
    lines.append(f"  POC 通过：{poc_counts['valid']} / 不完整：{poc_counts['invalid']} / 待校验：{poc_counts['unknown']}")
    lines.append(f"  扫描文件：{scan_stats.get('total_files', 0)} / 代码块：{scan_stats.get('total_chunks', 0)}")

    lines.extend(["", "漏洞详情"])
    if not vulns:
        lines.append("未发现已确认的安全漏洞。")
    else:
        for index, vuln in enumerate(sorted_vulns, 1):
            lines.append("")
            lines.append(f"{index}. {vuln.title} [{_severity_label(vuln.severity)}]")
            lines.append(f"  类型：{vuln.vuln_type or '-'} | 位置：{_vuln_location(vuln)}")
            if vuln.endpoint:
                lines.append(f"  接口：{vuln.endpoint}")
            if vuln.description:
                lines.append(f"  说明：{vuln.description}")
            if vuln.fix_suggestion:
                lines.append(f"  修复：{vuln.fix_suggestion}")
            lines.append("-" * 60)

    return "\n".join(lines)


def generate_markdown(report_dir, project, task, stages, vulns) -> str:
    content = _build_markdown_content(project, task, stages, vulns)
    filepath = os.path.join(report_dir, f"audit_report_{task.id}.md")
    with open(filepath, "w", encoding="utf-8") as file:
        file.write(content)
    return filepath


_PDF_STYLE = """\
body {
  font-family: "Microsoft YaHei", "PingFang SC", "Noto Sans SC", "SimSun", sans-serif;
  font-size: 13px;
  line-height: 1.75;
  color: #1d1d1f;
  padding: 0;
  margin: 0;
}

/* ── cover header ── */
h1 {
  font-size: 22px;
  font-weight: 700;
  color: #fff;
  background: linear-gradient(135deg, #1a1a2e, #16213e);
  padding: 28px 32px;
  margin: 0 -32px 32px;
  border-radius: 0;
  letter-spacing: 1px;
}

/* ── sections ── */
h2 {
  font-size: 16px;
  font-weight: 600;
  color: #1a1a2e;
  margin-top: 32px;
  margin-bottom: 12px;
  padding-left: 12px;
  border-left: 4px solid #3b82f6;
}

h3 {
  font-size: 14px;
  font-weight: 600;
  color: #1e293b;
  margin-top: 24px;
  margin-bottom: 8px;
  break-after: avoid;
}

/* ── tables ── */
table {
  border-collapse: separate;
  border-spacing: 0;
  width: 100%;
  margin: 12px 0 20px;
  font-size: 12.5px;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 1px 3px rgba(0,0,0,0.08);
}
th {
  background: #f1f5f9;
  font-weight: 600;
  color: #334155;
  padding: 10px 14px;
  text-align: left;
  border-bottom: 2px solid #e2e8f0;
}
td {
  padding: 9px 14px;
  border-bottom: 1px solid #f1f5f9;
  vertical-align: top;
}
tr:nth-child(even) td { background: #f8fafc; }
tr:last-child td { border-bottom: none; }

/* ── blockquote (概览) ── */
blockquote {
  margin: 12px 0 20px;
  padding: 14px 18px;
  background: linear-gradient(90deg, #eff6ff, #f8fafc);
  border-left: 4px solid #3b82f6;
  border-radius: 0 8px 8px 0;
  font-size: 13px;
  color: #1e293b;
}

/* ── code blocks ── */
pre {
  background: #1e293b;
  color: #e2e8f0;
  padding: 16px 18px;
  border-radius: 8px;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 12px;
  line-height: 1.6;
  margin: 12px 0 20px;
}
pre code { background: transparent; color: inherit; padding: 0; }

code {
  background: #f1f5f9;
  color: #0f172a;
  padding: 2px 7px;
  border-radius: 4px;
  font-size: 12px;
}

/* ── strong / bold ── */
strong { color: #0f172a; }

/* ── hr ── */
hr {
  border: none;
  border-top: 1px dashed #cbd5e1;
  margin: 20px 0;
}

/* ── page break before each vuln after the first ── */
h3 { break-before: auto; }
"""

_BODY_WRAPPER_CSS = f"""
@page {{
  size: A4;
  margin: 32px;
}}
{_PDF_STYLE}
"""


def _render_pdf_with_weasyprint(md_path: str, pdf_path: str) -> str:
    import markdown as md_lib
    from weasyprint import HTML

    with open(md_path, "r", encoding="utf-8") as file:
        md_content = file.read()

    html_content = md_lib.markdown(md_content, extensions=["tables", "fenced_code"])
    full_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>{_BODY_WRAPPER_CSS}</style>
</head>
<body>
{html_content}
</body>
</html>"""

    HTML(string=full_html).write_pdf(pdf_path)
    return pdf_path


def _pick_chinese_font() -> str | None:
    candidates = [
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\simsun.ttc",
        r"C:\Windows\Fonts\simhei.ttf",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def _sanitize_line(line: str) -> str:
    line = line.replace("\t", "    ").rstrip()
    return re.sub(r"\r", "", line)


def _wrap_text_for_pdf(text: str, width: int = 44) -> list[str]:
    wrapped = []
    for raw_line in text.splitlines():
        line = _sanitize_line(raw_line)
        if not line:
            wrapped.append("")
            continue
        if len(line) <= width:
            wrapped.append(line)
            continue
        wrapped.extend(textwrap.wrap(line, width=width, break_long_words=True, break_on_hyphens=False))
    return wrapped


def _render_pdf_with_pillow(pdf_path: str, text_content: str) -> str:
    from PIL import Image, ImageDraw, ImageFont

    font_path = _pick_chinese_font()
    if not font_path:
        raise RuntimeError("未找到可用的中文字体，无法生成 PDF。")

    title_font = ImageFont.truetype(font_path, 24)
    body_font = ImageFont.truetype(font_path, 16)

    page_width = 1240
    page_height = 1754
    margin_x = 72
    margin_y = 72
    line_height = 28
    body_top = margin_y + 50
    max_lines = (page_height - body_top - margin_y) // line_height

    lines = _wrap_text_for_pdf(text_content, width=46)
    pages = []

    while lines:
        current_lines = lines[:max_lines]
        lines = lines[max_lines:]

        image = Image.new("RGB", (page_width, page_height), "white")
        draw = ImageDraw.Draw(image)
        draw.text((margin_x, margin_y), "AI 代码审计报告", fill="black", font=title_font)

        y = body_top
        for line in current_lines:
            draw.text((margin_x, y), line, fill="black", font=body_font)
            y += line_height
        pages.append(image)

    if not pages:
        pages = [Image.new("RGB", (page_width, page_height), "white")]

    first_page, rest_pages = pages[0], pages[1:]
    first_page.save(pdf_path, "PDF", resolution=150.0, save_all=True, append_images=rest_pages)
    return pdf_path


def generate_pdf(report_dir, project, task, stages, vulns) -> str:
    md_path = generate_markdown(report_dir, project, task, stages, vulns)
    pdf_path = md_path.replace(".md", ".pdf")

    try:
        return _render_pdf_with_weasyprint(md_path, pdf_path)
    except Exception:
        text_content = _build_plaintext_content(project, task, stages, vulns)
        return _render_pdf_with_pillow(pdf_path, text_content)
