"""请求 / 响应的 Pydantic 模型。"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class RuleIn(BaseModel):
    """提交的单条前缀规则。"""

    id: str | None = Field(
        default=None,
        alias="id",
        description="规则标识；省略时自动生成 rule-1, rule-2 ...，需在本次提交内唯一",
    )
    cidr: str = Field(..., description="IPv4/IPv6 CIDR，必须是规范网络地址，如 10.0.0.0/8")
    action: str = Field(..., min_length=1, description="动作，如 permit / deny")
    priority: int = Field(default=0, description="优先级，数字越大越优先")
    source: str = Field(default="default", description="来源标签，如 team-a / legacy")

    model_config = {"populate_by_name": True, "extra": "forbid"}

    @field_validator("cidr", "action", "source", "id")
    @classmethod
    def _strip(cls, v: str | None) -> str | None:
        return v.strip() if isinstance(v, str) else v


class AnalysisIn(BaseModel):
    """创建分析版本的请求体。"""

    name: str | None = Field(default=None, description="可选的版本名称")
    rules: list[RuleIn] = Field(..., min_length=1)


class RuleRef(BaseModel):
    index: int
    id: str


class Finding(BaseModel):
    higher_rule: RuleRef
    lower_rule: RuleRef
    relation: Literal["contains", "equal", "within"]
    overlap_cidr: str
    overlap_addresses: int
    governing_cidrs: list[str]
    governing_addresses: int
    higher_action: str
    lower_action: str
    conflict_kind: Literal["action_conflict", "shadowed_same_action"]
    higher_covers_lower_entirely: bool


class AnalyzedRule(BaseModel):
    index: int
    id: str
    cidr: str
    version: Literal[4, 6]
    action: str
    priority: int
    source: str
    status: Literal["active", "partially_shadowed", "fully_shadowed"]
    effective_cidrs: list[str]
    effective_cidrs_truncated: bool
    effective_addresses: int
    covered_addresses: int
    coverage_ratio: float
    shadowed_by: list[str]


class VersionSummary(BaseModel):
    rule_count: int
    active: int
    partially_shadowed: int
    fully_shadowed: int
    total_addresses: int
    effective_addresses: int


class Summary(BaseModel):
    rule_count: int
    active: int
    partially_shadowed: int
    fully_shadowed: int
    pair_count: int
    minimal_conflict_pair_count: int
    by_version: dict[str, VersionSummary]


class AnalysisResult(BaseModel):
    summary: Summary
    precedence_policy: str
    rules: list[AnalyzedRule]
    findings: list[Finding]
    minimal_conflict_pairs: list[Finding]


class AnalysisMeta(BaseModel):
    id: str
    name: str | None
    rule_count: int
    content_hash: str
    created_at: str


class AnalysisDetail(AnalysisMeta):
    request: dict[str, Any]
    result: AnalysisResult


class AnalysisSummaryItem(BaseModel):
    id: str
    name: str | None
    rule_count: int
    content_hash: str
    created_at: str
    summary: Summary


class AnalysisList(BaseModel):
    items: list[AnalysisSummaryItem]
    total: int
