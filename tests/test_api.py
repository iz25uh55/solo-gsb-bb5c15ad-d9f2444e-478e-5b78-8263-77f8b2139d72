"""API 端到端测试（使用临时 SQLite 文件）。"""

from __future__ import annotations

import importlib
import os
import tempfile

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("PREFIX_DB_PATH", str(db_file))

    from app import database, main

    importlib.reload(database)
    importlib.reload(main)
    database.init_db()

    from fastapi.testclient import TestClient

    with TestClient(main.app) as c:
        yield c


def r(rule_id, cidr, action, priority=0, source="default"):
    return {"id": rule_id, "cidr": cidr, "action": action,
            "priority": priority, "source": source}


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_analyze_shadowing_conflicts_and_effective_cidrs(client):
    payload = {"rules": [
        r("a", "10.0.0.0/8", "permit", 100),
        r("b", "10.10.0.0/16", "deny", 200),
        r("c", "10.10.8.0/22", "permit", 300),
        r("d", "10.10.9.0/24", "deny", 50),   # 完全被 b/c 遮蔽
    ]}
    resp = client.post("/api/v1/analyze", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    by_id = {x["id"]: x for x in data["rules"]}
    assert by_id["a"]["status"] == "partially_shadowed"
    # 10.0.0.0/8 减去 10.10.0.0/16 的贪心规范 CIDR 分解
    assert by_id["a"]["effective_cidrs"] == [
        "10.0.0.0/13",
        "10.8.0.0/15",
        "10.11.0.0/16",
        "10.12.0.0/14",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9",
    ]
    assert by_id["a"]["effective_addresses"] == 2 ** 24 - 2 ** 16
    assert by_id["b"]["status"] == "partially_shadowed"
    assert by_id["b"]["effective_cidrs"] == [
        "10.10.0.0/21",
        "10.10.12.0/22",
        "10.10.16.0/20",
        "10.10.32.0/19",
        "10.10.64.0/18",
        "10.10.128.0/17",
    ]
    assert by_id["c"]["status"] == "active"
    assert by_id["c"]["effective_cidrs"] == ["10.10.8.0/22"]
    assert by_id["d"]["status"] == "fully_shadowed"
    assert by_id["d"]["effective_cidrs"] == []
    assert by_id["d"]["effective_addresses"] == 0
    # 最小遮蔽集合：c 完整覆盖 d，b 对 d 无独立贡献（被 c 传递遮蔽）
    assert by_id["d"]["shadowed_by"] == ["c"]

    # 最小冲突对（动作不同且对失效区域有不可替代贡献）
    pairs = {(p["higher_rule"]["id"], p["lower_rule"]["id"])
             for p in data["minimal_conflict_pairs"]}
    assert pairs == {("b", "a"), ("c", "b"), ("c", "d")}
    # a-d、b-d 均为纯传递遮蔽（c 已完整覆盖 d），不出现在任何明细对中
    all_pairs = {(p["higher_rule"]["id"], p["lower_rule"]["id"])
                 for p in data["findings"]}
    assert ("a", "d") not in all_pairs
    assert ("b", "d") not in all_pairs
    cd = next(p for p in data["findings"]
              if p["higher_rule"]["id"] == "c" and p["lower_rule"]["id"] == "d")
    assert cd["conflict_kind"] == "action_conflict"
    assert cd["governing_cidrs"] == ["10.10.9.0/24"]

    summary = data["summary"]
    assert summary["fully_shadowed"] == 1
    assert summary["minimal_conflict_pair_count"] == 3


def test_same_action_shadow_is_finding_but_not_conflict(client):
    payload = {"rules": [
        r("a", "10.0.0.0/8", "permit", 100),
        r("b", "10.10.0.0/16", "permit", 200),  # 同动作遮蔽
    ]}
    data = client.post("/api/v1/analyze", json=payload).json()
    assert data["minimal_conflict_pairs"] == []
    pair = data["findings"][0]
    assert pair["conflict_kind"] == "shadowed_same_action"
    assert (pair["higher_rule"]["id"], pair["lower_rule"]["id"]) == ("b", "a")
    assert pair["relation"] == "within"
    assert pair["higher_covers_lower_entirely"] is False
    assert data["summary"]["fully_shadowed"] == 0


def test_equal_cidr_same_priority_breaks_tie_by_index(client):
    payload = {"rules": [
        r("first", "198.51.100.0/24", "permit", 10),
        r("second", "198.51.100.0/24", "deny", 10),
    ]}
    data = client.post("/api/v1/analyze", json=payload).json()
    by_id = {x["id"]: x for x in data["rules"]}
    assert by_id["first"]["status"] == "active"
    assert by_id["second"]["status"] == "fully_shadowed"
    pair = data["minimal_conflict_pairs"][0]
    assert (pair["higher_rule"]["id"], pair["lower_rule"]["id"]) == ("first", "second")
    assert pair["relation"] == "equal"
    assert pair["overlap_cidr"] == "198.51.100.0/24"


def test_ipv4_and_ipv6_are_independent(client):
    payload = {"rules": [
        r("v4", "10.0.0.0/8", "permit", 100),
        r("v6", "2001:db8::/32", "deny", 100),
    ]}
    data = client.post("/api/v1/analyze", json=payload).json()
    assert all(x["status"] == "active" for x in data["rules"])
    assert data["findings"] == []
    assert set(data["summary"]["by_version"]) == {"ipv4", "ipv6"}
    assert data["summary"]["by_version"]["ipv6"]["total_addresses"] == 2 ** 96


def test_invalid_cidr_host_bits_returns_400_with_suggestion(client):
    payload = {"rules": [r("bad", "10.0.0.5/24", "permit")]}
    resp = client.post("/api/v1/analyze", json=payload)
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert "10.0.0.0/24" in detail["errors"][0]["message"]


def test_duplicate_id_rejected(client):
    payload = {"rules": [
        r("x", "10.0.0.0/8", "permit"),
        r("x", "10.1.0.0/16", "deny"),
    ]}
    resp = client.post("/api/v1/analyze", json=payload)
    assert resp.status_code == 400
    assert "重复" in resp.json()["detail"]["errors"][0]["message"]


def test_save_get_findings_export_delete(client):
    payload = {"name": "v1", "rules": [
        r("a", "10.0.0.0/8", "permit", 100),
        r("b", "10.10.0.0/16", "deny", 200),
    ]}
    created = client.post("/api/v1/analyses", json=payload)
    assert created.status_code == 201, created.text
    analysis_id = created.json()["id"]

    listing = client.get("/api/v1/analyses").json()
    assert listing["total"] == 1
    assert listing["items"][0]["name"] == "v1"

    fetched = client.get(f"/api/v1/analyses/{analysis_id}").json()
    assert fetched["result"]["summary"]["rule_count"] == 2

    rules = client.get(f"/api/v1/analyses/{analysis_id}/rules").json()
    assert rules["rules"][0]["cidr"] == "10.0.0.0/8"
    assert rules["rules"][0]["status"] == "partially_shadowed"

    conflicts = client.get(
        f"/api/v1/analyses/{analysis_id}/findings", params={"kind": "action_conflict"}
    ).json()
    assert conflicts["total"] == 1
    assert conflicts["findings"][0]["higher_rule"]["id"] == "b"

    export = client.get(f"/api/v1/analyses/{analysis_id}/export")
    assert export.status_code == 200
    assert export.headers["content-type"] == "application/json"
    assert "attachment" in export.headers["content-disposition"]
    assert export.json()["id"] == analysis_id

    assert client.delete(f"/api/v1/analyses/{analysis_id}").status_code == 204
    assert client.get(f"/api/v1/analyses/{analysis_id}").status_code == 404


def test_get_missing_analysis_404(client):
    assert client.get("/api/v1/analyses/deadbeef").status_code == 404


def test_empty_rules_rejected(client):
    assert client.post("/api/v1/analyze", json={"rules": []}).status_code == 422
