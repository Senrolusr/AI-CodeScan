import asyncio
import copy
import json
import sys

sys.path.append("backend")

from sqlalchemy import select

from database import async_session
from models import AuditTask, AuditStage
from services.audit_engine import _enforce_vulnerability_output_policy, _parse_structured_response, _store_vulnerabilities


async def main(task_id: int, stage_num: int):
    async with async_session() as session:
        task = (await session.execute(select(AuditTask).where(AuditTask.id == task_id))).scalar_one_or_none()
        stage = (
            await session.execute(
                select(AuditStage).where(AuditStage.task_id == task_id, AuditStage.stage_num == stage_num)
            )
        ).scalar_one_or_none()
        if not task or not stage:
            print("not_found")
            return

        llm_payload = json.loads(stage.llm_response or "{}")
        reparsed = _parse_structured_response(str(llm_payload.get("content", "") or ""))
        if not isinstance(reparsed, dict):
            print("no_structured_response")
            return

        normalized, stats = _enforce_vulnerability_output_policy(stage, copy.deepcopy(reparsed))
        stage.findings = normalized
        created = await _store_vulnerabilities(session, task, stage, normalized.get("vulnerabilities", []))
        await session.commit()
        print(
            {
                "stage_num": stage_num,
                "accepted": len(normalized.get("vulnerabilities", [])),
                "created": created,
                "rejected": stats.get("rejected_vulnerabilities", 0),
            }
        )


if __name__ == "__main__":
    task_id = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    stage_num = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    asyncio.run(main(task_id, stage_num))
