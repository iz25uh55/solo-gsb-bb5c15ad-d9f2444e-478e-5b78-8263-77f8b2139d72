"""FastAPI 入口：网络前缀策略分析 API。"""

from __future__ import annotations

import hashlib
import json
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Response, status

from . import __version__
from . import database as db
from .prefix_logic import (
    MAX_RULES,
    PRECEDENCE_DESCRIPTION,
    RuleValidationError,
    analyze_rules,
)
from .schemas import (
    AnalysisDetail,
    AnalysisIn,
    AnalysisList,
    AnalysisResult,
)

@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db()
    yield


app = FastAPI(
    title="网络前缀策略分析 API",
    description=(
        "提交带优先级、动作与来源标签的 IPv4/IPv6 CIDR 规则集，"
        "按最长前缀匹配与优先级计算实际覆盖范围，识别完全遮蔽、部分重叠与动作冲突，"
        "给出可复现的最小冲突对；支持分析版本保存、结果查询与 JSON 导出。\n\n"
        f"有效顺序策略：{PRECEDENCE_DESCRIPTION}。"
    ),
    version=__version__,
    lifespan=lifespan,
)


def _content_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validation_error(errors: list[dict[str, Any]]) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"message": "规则集校验失败", "errors": errors},
    )


@app.get("/", tags=["meta"])
def root() -> dict[str, str]:
    return {
        "service": "network-prefix-policy-analyzer",
        "version": __version__,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", tags=["meta"])
def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__}


@app.post(
    "/api/v1/analyze",
    response_model=AnalysisResult,
    tags=["analyze"],
    summary="仅分析不保存（无副作用）",
)
def analyze_only(payload: AnalysisIn) -> dict[str, Any]:
    try:
        return analyze_rules(payload.rules)
    except RuleValidationError as exc:
        raise _validation_error(exc.errors) from exc


@app.post(
    "/api/v1/analyses",
    response_model=AnalysisDetail,
    status_code=status.HTTP_201_CREATED,
    tags=["analyses"],
    summary="分析并保存为一个可查询、可导出的版本",
)
def create_analysis(payload: AnalysisIn) -> dict[str, Any]:
    if len(payload.rules) > MAX_RULES:
        raise _validation_error(
            [
                {
                    "index": None,
                    "rule_id": None,
                    "message": f"规则数 {len(payload.rules)} 超过上限 {MAX_RULES}",
                }
            ]
        )
    try:
        result = analyze_rules(payload.rules)
    except RuleValidationError as exc:
        raise _validation_error(exc.errors) from exc

    request_payload = payload.model_dump(mode="json")
    analysis_id = uuid.uuid4().hex
    db.save_analysis(
        analysis_id=analysis_id,
        name=payload.name,
        content_hash=_content_hash(request_payload),
        request_payload=request_payload,
        result=result,
    )
    saved = db.get_analysis(analysis_id)
    assert saved is not None
    return saved


@app.get(
    "/api/v1/analyses",
    response_model=AnalysisList,
    tags=["analyses"],
    summary="列出已保存的分析版本（含摘要）",
)
def list_analyses(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    return {
        "items": db.list_analyses(limit, offset),
        "total": db.count_analyses(),
    }


def _require_analysis(analysis_id: str) -> dict[str, Any]:
    analysis = db.get_analysis(analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail=f"分析版本不存在: {analysis_id}")
    return analysis


@app.get(
    "/api/v1/analyses/{analysis_id}",
    response_model=AnalysisDetail,
    tags=["analyses"],
    summary="查询某个分析版本的完整结果",
)
def get_analysis(analysis_id: str) -> dict[str, Any]:
    return _require_analysis(analysis_id)


@app.get(
    "/api/v1/analyses/{analysis_id}/rules",
    tags=["analyses"],
    summary="查询某个版本的原始规则（含每条规则的状态摘要）",
)
def get_analysis_rules(analysis_id: str) -> dict[str, Any]:
    analysis = _require_analysis(analysis_id)
    statuses = {r["id"]: r for r in analysis["result"]["rules"]}
    rules = db.get_analysis_rules(analysis_id)
    for rule in rules:
        extra = statuses[rule["rule_id"]]
        rule["status"] = extra["status"]
        rule["effective_cidrs"] = extra["effective_cidrs"]
        rule["effective_addresses"] = extra["effective_addresses"]
        rule["coverage_ratio"] = extra["coverage_ratio"]
        rule["shadowed_by"] = extra["shadowed_by"]
    return {"analysis_id": analysis_id, "total": len(rules), "rules": rules}


@app.get(
    "/api/v1/analyses/{analysis_id}/findings",
    tags=["analyses"],
    summary="查询遮蔽/冲突明细（可用 kind 过滤最小动作冲突对）",
)
def get_findings(
    analysis_id: str,
    kind: str = Query(
        default="all",
        pattern="^(all|action_conflict|shadowed_same_action)$",
    ),
) -> dict[str, Any]:
    analysis = _require_analysis(analysis_id)
    findings = analysis["result"]["findings"]
    if kind != "all":
        findings = [f for f in findings if f["conflict_kind"] == kind]
    return {
        "analysis_id": analysis_id,
        "kind": kind,
        "total": len(findings),
        "findings": findings,
    }


@app.delete(
    "/api/v1/analyses/{analysis_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["analyses"],
    summary="删除某个分析版本",
)
def delete_analysis(analysis_id: str) -> Response:
    if not db.delete_analysis(analysis_id):
        raise HTTPException(status_code=404, detail=f"分析版本不存在: {analysis_id}")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get(
    "/api/v1/analyses/{analysis_id}/export",
    tags=["export"],
    summary="导出完整 JSON（Content-Disposition 附件，可直接落盘复现）",
)
def export_analysis(analysis_id: str) -> Response:
    analysis = _require_analysis(analysis_id)
    body = json.dumps(analysis, ensure_ascii=False, indent=2, sort_keys=True)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="analysis-{analysis_id}.json"'
        },
    )
