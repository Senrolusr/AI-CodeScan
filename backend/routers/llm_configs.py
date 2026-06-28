from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from errors import ApiError
from models import LlmConfig
from schemas import LlmConfigCreate, LlmConfigOut, LlmConfigUpdate
from services.llm_client import test_llm_connection
from services.secret_crypto import encrypt_api_key

router = APIRouter()


def _serialize_config(config: LlmConfig) -> dict:
    return {
        "id": config.id,
        "name": config.name,
        "provider": config.provider,
        "base_url": config.base_url,
        "api_mode": config.api_mode or "chat_completions",
        "model_name": config.model_name,
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
        "is_default": config.is_default,
        "has_api_key": bool(config.api_key),
        "created_at": config.created_at,
    }


@router.post("", response_model=LlmConfigOut)
async def create_config(data: LlmConfigCreate, db: AsyncSession = Depends(get_db)):
    if data.is_default:
        await _clear_defaults(db)

    data_dict = data.model_dump()
    data_dict["api_key"] = encrypt_api_key(data_dict["api_key"])
    config = LlmConfig(**data_dict)
    db.add(config)
    await db.commit()
    await db.refresh(config)
    return _serialize_config(config)


@router.get("", response_model=list[LlmConfigOut])
async def list_configs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LlmConfig).order_by(LlmConfig.created_at.desc()))
    return [_serialize_config(config) for config in result.scalars().all()]


@router.get("/{config_id}", response_model=LlmConfigOut)
async def get_config(config_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LlmConfig).where(LlmConfig.id == config_id))
    config = result.scalar_one_or_none()
    if not config:
        raise ApiError("LLM_CONFIG_NOT_FOUND", "模型配置不存在", status_code=404)
    return _serialize_config(config)


@router.put("/{config_id}", response_model=LlmConfigOut)
async def update_config(config_id: int, data: LlmConfigUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LlmConfig).where(LlmConfig.id == config_id))
    config = result.scalar_one_or_none()
    if not config:
        raise ApiError("LLM_CONFIG_NOT_FOUND", "模型配置不存在", status_code=404)

    update_data = data.model_dump(exclude_unset=True)
    if update_data.get("is_default"):
        await _clear_defaults(db)
    if update_data.get("api_key") == "":
        update_data.pop("api_key")
    if update_data.get("api_key"):
        update_data["api_key"] = encrypt_api_key(update_data["api_key"])

    for key, value in update_data.items():
        setattr(config, key, value)

    await db.commit()
    await db.refresh(config)
    return _serialize_config(config)


@router.delete("/{config_id}")
async def delete_config(config_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LlmConfig).where(LlmConfig.id == config_id))
    config = result.scalar_one_or_none()
    if not config:
        raise ApiError("LLM_CONFIG_NOT_FOUND", "模型配置不存在", status_code=404)
    await db.delete(config)
    await db.commit()
    return {"message": "模型配置已删除"}


@router.post("/{config_id}/test")
async def test_config(config_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LlmConfig).where(LlmConfig.id == config_id))
    config = result.scalar_one_or_none()
    if not config:
        raise ApiError("LLM_CONFIG_NOT_FOUND", "模型配置不存在", status_code=404)
    if not config.api_key:
        raise HTTPException(400, "未配置 API Key")

    try:
        result = await test_llm_connection(config)
    except Exception as exc:
        raise HTTPException(
            400,
            {
                "message": "连通性测试执行失败",
                "detail": str(exc),
                "preferred_mode": config.api_mode or "chat_completions",
                "attempts": [],
            },
        )

    if not result["success"]:
        raise HTTPException(
            400,
            {
                "message": "连通性测试失败",
                "detail": result["message"],
                "preferred_mode": result.get("preferred_mode"),
                "successful_mode": result.get("successful_mode"),
                "strict_success": result.get("strict_success", False),
                "strict_successful_mode": result.get("strict_successful_mode"),
                "attempts": result.get("attempts", []),
                "model": result.get("model"),
            },
        )

    return result


async def _clear_defaults(db: AsyncSession):
    result = await db.execute(select(LlmConfig).where(LlmConfig.is_default == True))
    for cfg in result.scalars().all():
        cfg.is_default = False
