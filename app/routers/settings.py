from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.connectors import connector_map
from app.db import get_db
from app.dependencies import get_current_user
from app.services.assessment_service import (
    get_llm_state,
    get_rag_advanced_state,
    list_connector_states,
    save_connector_setting,
    save_rag_advanced_settings,
    save_llm_setting,
    test_connector,
)

router = APIRouter(tags=["settings"])


@router.get("/settings")
def settings_page(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    connectors = list_connector_states(db)
    llm_state = get_llm_state(db)
    rag_state = get_rag_advanced_state(db)
    return request.app.state.templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "user": user,
            "active": "settings",
            "connectors": connectors,
            "llm_state": llm_state,
            "rag_state": rag_state,
            "test_result": request.query_params.get("test_result", ""),
        },
    )


@router.post("/settings/connector/save")
async def save_connector(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    form = await request.form()
    connector_name = str(form.get("connector_name", "")).strip()
    cmap = connector_map()
    if connector_name not in cmap:
        return RedirectResponse(url="/settings?test_result=Unknown+connector", status_code=302)

    enabled = str(form.get("enabled", "off")) == "on"
    connector = cmap.get(connector_name)
    api_key_raw = form.get("api_key")  # may be absent for connectors with no API key support
    api_key = str(api_key_raw) if api_key_raw is not None else None
    if connector and not bool(getattr(connector, "requires_api_key", False)):
        api_key = None

    save_connector_setting(db, connector_name, enabled=enabled, api_key=api_key)
    return RedirectResponse(url="/settings?test_result=Connector+saved", status_code=302)


@router.post("/settings/connector/test")
async def test_connector_route(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    form = await request.form()
    connector_name = str(form.get("connector_name", "")).strip()
    ok, msg = test_connector(db, connector_name)
    status = "OK" if ok else "FAIL"
    return RedirectResponse(url=f"/settings?test_result={status}+{msg}", status_code=302)


@router.post("/settings/llm/save")
async def save_llm_route(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    form = await request.form()
    provider = str(form.get("llm_provider", "openai")).strip().lower()
    model = str(form.get("llm_model", "gpt-4.1")).strip()
    openai_api_key = str(form.get("openai_api_key", ""))
    anthropic_api_key = str(form.get("anthropic_api_key", ""))
    clear_openai_api_key = str(form.get("clear_openai_api_key", "off")) == "on"
    clear_anthropic_api_key = str(form.get("clear_anthropic_api_key", "off")) == "on"
    save_llm_setting(
        db,
        provider=provider,
        model=model,
        openai_api_key=openai_api_key,
        anthropic_api_key=anthropic_api_key,
        clear_openai_api_key=clear_openai_api_key,
        clear_anthropic_api_key=clear_anthropic_api_key,
    )
    return RedirectResponse(url="/settings?test_result=LLM+settings+saved", status_code=302)


@router.post("/settings/rag/save")
async def save_rag_route(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    form = await request.form()
    top_k_raw = str(form.get("rag_top_k", "4")).strip()
    ratio_raw = str(form.get("rag_min_ratio", "0.70")).strip()
    top_k = 4
    min_ratio = 0.70
    if top_k_raw.isdigit():
        top_k = int(top_k_raw)
    try:
        min_ratio = float(ratio_raw)
    except Exception:
        min_ratio = 0.70
    save_rag_advanced_settings(db, top_k=top_k, min_ratio=min_ratio)
    return RedirectResponse(url="/settings?test_result=RAG+advanced+saved", status_code=302)
