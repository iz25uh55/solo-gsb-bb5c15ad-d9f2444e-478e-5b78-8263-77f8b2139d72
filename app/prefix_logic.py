"""核心算法：CIDR 规则集的实际覆盖、遮蔽与冲突分析。

模型说明
========

* 每条规则为一个 CIDR 网络（IPv4 / IPv6），带优先级 priority（数字越大
  优先级越高）、动作 action（如 permit / deny）与来源标签 source。
* 规则间的有效顺序（pre-order）按下面的键排序，键越小越先获得地址：
      1. 优先级（高者优先）
      2. 前缀长度（最长前缀匹配，长者优先）
      3. 提交序号（同优先级同长度时，靠前的规则优先）
  该顺序完全确定，因此同一输入永远得到同一输出（可复现）。
* 某条规则 R 的“实际覆盖范围” effective_cidrs = R 的地址区间减去所有
  排在 R 之前（更高优先序）规则地址区间的并集。
* 结构事实：任意两个 CIDR 块要么互不相交，要么其中一个完整包含另一个。
  因此“部分重叠”只可能出现在：某条规则被若干更高优先序的规则各自遮住
  一部分、但没有被任何单条规则完整遮住的情况。
* “最小冲突对” (minimal_conflict_pairs)：对每个被遮蔽规则 L，只保留那些
  对 L 的实际失效区域真正有“不可替代贡献”的更高规则 H —— 即 H 与 L 的
  交集，减去所有优先序严格高于 H 的规则区域后仍非空。传递遮蔽（被更高
  规则完全盖住的 H）不会出现，保证冲突对数量最小且可复现。
"""

from __future__ import annotations

import ipaddress
from bisect import bisect_left
from dataclasses import dataclass
from typing import Any, Literal, Union

# 单次分析允许的最大规则数；区间运算为 O(n^2)，2000 条以内响应迅速。
MAX_RULES = 2000

# 每条规则返回的实际覆盖 CIDR 数量上限，防止极端切分产生过大响应。
MAX_CIDR_OUTPUT = 2000

PRECEDENCE_DESCRIPTION = (
    "higher_priority_then_longer_prefix_then_earlier_index"
)

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
Version = Literal[4, 6]


class RuleValidationError(ValueError):
    """规则集校验失败，errors 中为逐条结构化错误。"""

    def __init__(self, errors: list[dict[str, Any]]):
        self.errors = errors
        super().__init__(f"{len(errors)} validation error(s)")


@dataclass(frozen=True)
class ParsedRule:
    """解析后的规则。

    index 为规则在提交列表中的 0 基序号，即使规则自定义 id 也保证唯一，
    是整个分析（排序、交叉引用）使用的稳定标识。
    """

    index: int
    id: str
    action: str
    priority: int
    source: str
    network: IPNetwork
    version: Version
    start: int
    end: int  # 半开区间上界：最后一个地址 + 1
    size: int


def _format_network(address: str, prefixlen: int, version: Version) -> str:
    return f"{address}/{prefixlen}"


def parse_and_validate_rules(raw_rules: list[Any]) -> list[ParsedRule]:
    """把 API 入参（pydantic RuleIn）解析为 ParsedRule 列表。

    校验全部通过才返回；失败时抛出带结构化错误列表的 RuleValidationError。
    """
    errors: list[dict[str, Any]] = []

    if not raw_rules:
        errors.append({"index": None, "rule_id": None, "message": "rules 不能为空"})
        raise RuleValidationError(errors)
    if len(raw_rules) > MAX_RULES:
        errors.append(
            {
                "index": None,
                "rule_id": None,
                "message": f"规则数 {len(raw_rules)} 超过上限 {MAX_RULES}",
            }
        )
        raise RuleValidationError(errors)

    seen_ids: set[str] = set()
    parsed: list[ParsedRule] = []

    for idx, raw in enumerate(raw_rules):
        rule_id = (raw.id or f"rule-{idx + 1}").strip()
        action = (raw.action or "").strip()
        source = (raw.source or "default").strip() or "default"
        priority = raw.priority
        cidr = (raw.cidr or "").strip()
        problems: list[str] = []

        if not rule_id:
            problems.append("id 不能为空")
        elif rule_id in seen_ids:
            problems.append(f"规则 id 重复: {rule_id}")
        if not action:
            problems.append("action 不能为空")
        if not cidr:
            problems.append("cidr 不能为空")

        network: IPNetwork | None = None
        if cidr:
            try:
                network = ipaddress.ip_network(cidr, strict=True)
            except ValueError as exc:
                hint = ""
                try:
                    loose = ipaddress.ip_network(cidr, strict=False)
                    if str(loose) != cidr:
                        hint = f"；是否想写 {loose} ?"
                except ValueError:
                    if "/" not in cidr:
                        hint = "；请提供前缀长度，如 10.0.0.0/24"
                problems.append(f"非法 CIDR '{cidr}': {exc}{hint}")

        if problems:
            for msg in problems:
                errors.append({"index": idx, "rule_id": rule_id or None, "message": msg})
            continue

        assert network is not None
        seen_ids.add(rule_id)
        parsed.append(
            ParsedRule(
                index=idx,
                id=rule_id,
                action=action,
                priority=priority,
                source=source,
                network=network,
                version=network.version,
                start=int(network.network_address),
                end=int(network.network_address) + network.num_addresses,
                size=network.num_addresses,
            )
        )

    if errors:
        raise RuleValidationError(errors)
    return parsed


# ---------------------------------------------------------------------------
# 整数区间运算（半开区间 [start, end)；IPv4/IPv6 统一用 Python 大整数）
# ---------------------------------------------------------------------------


def merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """合并相交/相邻的区间。CIDR 区间相邻时合并是安全的：区间仅用于做差集。"""
    if not intervals:
        return []
    ordered = sorted(intervals)
    merged: list[tuple[int, int]] = [ordered[0]]
    for s, e in ordered[1:]:
        ls, le = merged[-1]
        if s <= le:
            if e > le:
                merged[-1] = (ls, e)
        else:
            merged.append((s, e))
    return merged


def subtract_intervals(
    interval: tuple[int, int], others: list[tuple[int, int]]
) -> list[tuple[int, int]]:
    """从单个区间中减去若干（已合并的）区间，返回至多 2 段结果。"""
    s, e = interval
    result: list[tuple[int, int]] = [(s, e)]
    for os_, oe in others:
        next_result: list[tuple[int, int]] = []
        for rs, re_ in result:
            if oe <= rs or os_ >= re_:
                next_result.append((rs, re_))
            else:
                if os_ > rs:
                    next_result.append((rs, os_))
                if oe < re_:
                    next_result.append((oe, re_))
        result = next_result
        if not result:
            break
    return result


def intersect_intervals(
    a: tuple[int, int], b: tuple[int, int]
) -> tuple[int, int] | None:
    s = max(a[0], b[0])
    e = min(a[1], b[1])
    return (s, e) if s < e else None


def range_to_cidrs(start: int, end: int, version: Version) -> list[str]:
    """把任意地址区间 [start, end) 切分为最少的规范 CIDR 列表。

    贪心：每一步取起点上能够容纳的最大 CIDR（起点对齐 2^k 且不越过 end）。
    """
    if start >= end:
        return []
    max_prefix = 32 if version == 4 else 128
    cidrs: list[str] = []
    cur = start
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    while cur < end:
        # cur 末尾连续 0 比特数决定可对齐的最大块。
        trailing_zeroes = (cur & -cur).bit_length() - 1 if cur else max_prefix
        remaining_bits = (end - cur).bit_length() - 1
        k = min(trailing_zeroes, remaining_bits, max_prefix)
        size = 1 << k
        address = str(cls(cur))
        cidrs.append(_format_network(address, max_prefix - k, version))
        cur += size
    return cidrs


# ---------------------------------------------------------------------------
# 主分析
# ---------------------------------------------------------------------------


def _precedence_key(rule: ParsedRule) -> tuple[int, int, int]:
    """排序键：越小有效顺序越靠前。"""
    return (-rule.priority, rule.network.prefixlen, rule.index)


def analyze_rules(raw_rules: list[Any]) -> dict[str, Any]:
    """分析规则集，返回可直接 JSON 序列化的结果字典。"""
    rules = parse_and_validate_rules(raw_rules)
    order = sorted(rules, key=_precedence_key)

    # 版本分开处理：IPv4 与 IPv6 的地址空间互不相交。
    by_version: dict[Version, list[ParsedRule]] = {4: [], 6: []}
    for r in order:
        by_version[r.version].append(r)

    findings: list[dict[str, Any]] = []
    rule_results: dict[int, dict[str, Any]] = {}
    fully_shadowed = 0
    partially_shadowed = 0
    active = 0

    for version, group in by_version.items():
        # union 为已处理（优先序严格更高）规则地址区间的增量合并结果，
        # 始终保持有序、互不相交。处理当前规则时先做差集，再把其区间并入。
        union: list[tuple[int, int]] = []
        # 每条规则“实际生效”的区间段（做差集后至多 2 段），供最小对计算复用。
        effective_parts_by_index: dict[int, list[tuple[int, int]]] = {}

        for rule in group:
            effective_parts = subtract_intervals((rule.start, rule.end), union)
            effective_parts_by_index[rule.index] = effective_parts

            # 把当前规则区间增量并入 union：二分定位受影响的连续段后局部合并。
            lo = bisect_left(union, (rule.start, -1))
            if lo > 0 and union[lo - 1][1] >= rule.start:
                lo -= 1
            hi = lo
            new_start, new_end = rule.start, rule.end
            while hi < len(union) and union[hi][0] <= rule.end:
                new_start = min(new_start, union[hi][0])
                new_end = max(new_end, union[hi][1])
                hi += 1
            union[lo:hi] = [(new_start, new_end)]

            effective_count = sum(e - s for s, e in effective_parts)
            effective_cidrs = [
                c
                for s, e in effective_parts
                for c in range_to_cidrs(s, e, version)
            ]
            truncated = False
            if len(effective_cidrs) > MAX_CIDR_OUTPUT:
                # 理论上 CIDR 做差集切分数量很小；保留保险并显式标注。
                effective_cidrs = effective_cidrs[:MAX_CIDR_OUTPUT]
                truncated = True

            if effective_count == 0:
                status = "fully_shadowed"
                fully_shadowed += 1
            elif effective_count < rule.size:
                status = "partially_shadowed"
                partially_shadowed += 1
            else:
                status = "active"
                active += 1

            shadowed_by: list[str] = []
            # 枚举优先序更高的规则；跳过与本块不相交者（含不同容器）。
            for higher in group:
                if higher.index == rule.index:
                    break
                if higher.end <= rule.start or higher.start >= rule.end:
                    continue

                if higher.start == rule.start and higher.end == rule.end:
                    relation = "equal"
                    entirely = True
                elif higher.start <= rule.start and higher.end >= rule.end:
                    relation = "contains"  # H 的 CIDR 完整包含 L 的 CIDR
                    entirely = True
                else:
                    # CIDR 结构性质：不相交（上面已跳过）、相等或包含，
                    # 走到这里说明 H 是 L 的严格子网，H 只遮住 L 的一部分。
                    relation = "within"
                    entirely = False

                # H 在 L 内的“独立贡献区” = H 的实际生效区间 ∩ L：
                # H 的生效区间已扣除所有严格高于 H 的规则，天然去掉传递遮蔽。
                governing: list[tuple[int, int]] = []
                for part in effective_parts_by_index[higher.index]:
                    hit = intersect_intervals(part, (rule.start, rule.end))
                    if hit is not None:
                        governing.append(hit)
                if not governing:
                    continue  # 纯传递遮蔽，不是最小对

                governing_cidrs = [
                    c
                    for s, e in governing
                    for c in range_to_cidrs(s, e, version)
                ]
                shadowed_by.append(higher.id)

                if relation == "within":
                    overlap_size = higher.size
                    overlap_cidr = str(higher.network)
                else:
                    # contains / equal：重叠块就是较低规则 L 自身的 CIDR
                    overlap_size = rule.size
                    overlap_cidr = str(rule.network)

                findings.append(
                    {
                        "higher_rule": {"index": higher.index, "id": higher.id},
                        "lower_rule": {"index": rule.index, "id": rule.id},
                        "relation": relation,
                        "overlap_cidr": overlap_cidr,
                        "overlap_addresses": overlap_size,
                        "governing_cidrs": governing_cidrs,
                        "governing_addresses": sum(
                            e - s for s, e in governing
                        ),
                        "higher_action": higher.action,
                        "lower_action": rule.action,
                        "conflict_kind": (
                            "action_conflict"
                            if higher.action != rule.action
                            else "shadowed_same_action"
                        ),
                        "higher_covers_lower_entirely": entirely,
                    }
                )

            covered_addresses = rule.size - effective_count
            rule_results[rule.index] = {
                "index": rule.index,
                "id": rule.id,
                "cidr": str(rule.network),
                "version": version,
                "action": rule.action,
                "priority": rule.priority,
                "source": rule.source,
                "status": status,
                "effective_cidrs": effective_cidrs,
                "effective_cidrs_truncated": truncated,
                "effective_addresses": effective_count,
                "covered_addresses": covered_addresses,
                "coverage_ratio": round(
                    effective_count / rule.size, 6) if rule.size else 0.0,
                "shadowed_by": shadowed_by,
            }

    findings.sort(
        key=lambda f: (
            f["lower_rule"]["index"],
            f["higher_rule"]["index"],
        )
    )
    minimal_conflict_pairs = [
        f for f in findings if f["conflict_kind"] == "action_conflict"
    ]

    version_summary: dict[str, Any] = {}
    for version, group in by_version.items():
        if not group:
            continue
        total_addr = sum(r.size for r in group)
        eff_addr = sum(
            rule_results[r.index]["effective_addresses"] for r in group
        )
        version_summary[f"ipv{version}"] = {
            "rule_count": len(group),
            "active": sum(
                1 for r in group if rule_results[r.index]["status"] == "active"
            ),
            "partially_shadowed": sum(
                1
                for r in group
                if rule_results[r.index]["status"] == "partially_shadowed"
            ),
            "fully_shadowed": sum(
                1
                for r in group
                if rule_results[r.index]["status"] == "fully_shadowed"
            ),
            "total_addresses": total_addr,
            "effective_addresses": eff_addr,
        }

    return {
        "summary": {
            "rule_count": len(rules),
            "active": active,
            "partially_shadowed": partially_shadowed,
            "fully_shadowed": fully_shadowed,
            "pair_count": len(findings),
            "minimal_conflict_pair_count": len(minimal_conflict_pairs),
            "by_version": version_summary,
        },
        "precedence_policy": PRECEDENCE_DESCRIPTION,
        "rules": [rule_results[r.index] for r in rules],
        "findings": findings,
        "minimal_conflict_pairs": minimal_conflict_pairs,
    }
