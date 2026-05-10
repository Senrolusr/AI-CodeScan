import asyncio
import sys
import json
import copy

sys.path.append("backend")

from sqlalchemy import select

from database import async_session
from models import AuditTask, AuditStage
from services.audit_engine import _enforce_vulnerability_output_policy, _parse_structured_response, _store_vulnerabilities


async def main(task_id: int):
    async with async_session() as session:
        task = (await session.execute(select(AuditTask).where(AuditTask.id == task_id))).scalar_one_or_none()
        if not task:
            print(f"task_not_found:{task_id}")
            return

        stages = (
            await session.execute(
                select(AuditStage).where(
                    AuditStage.task_id == task_id,
                    AuditStage.status == "completed",
                )
            )
        ).scalars().all()

        repaired = []
        for stage in stages:
            findings = stage.findings if isinstance(stage.findings, dict) else None
            if not findings:
                findings = {}
            original_vuln_count = len(findings.get("vulnerabilities", [])) if isinstance(findings.get("vulnerabilities"), list) else 0

            llm_response_payload = {}
            if stage.llm_response:
                try:
                    llm_response_payload = json.loads(stage.llm_response)
                except Exception:
                    llm_response_payload = {}

            response_content = str(llm_response_payload.get("content", "") or "").strip()
            if response_content:
                reparsed = _parse_structured_response(response_content)
                if isinstance(reparsed, dict) and isinstance(reparsed.get("vulnerabilities"), list):
                    findings = reparsed

            normalized, stats = _enforce_vulnerability_output_policy(stage, copy.deepcopy(findings))
            normalized_vuln_count = len(normalized.get("vulnerabilities", [])) if isinstance(normalized.get("vulnerabilities"), list) else 0
            if stage.findings != normalized or normalized_vuln_count != original_vuln_count or stats.get("rejected_vulnerabilities", 0):
                stage.findings = normalized
                created = await _store_vulnerabilities(session, task, stage, normalized.get("vulnerabilities", []))
                repaired.append(
                    {
                        "stage_num": stage.stage_num,
                        "created": created,
                        "accepted": len(normalized.get("vulnerabilities", [])),
                        "rejected": stats.get("rejected_vulnerabilities", 0),
                    }
                )

        await session.commit()
        print(repaired)


if __name__ == "__main__":
    arg = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    asyncio.run(main(arg))
