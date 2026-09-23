# 网络前缀策略分析 API（Network Prefix Policy Analyzer）

用 Python + FastAPI 构建的 CIDR 前缀策略分析服务。用户提交带**优先级、动作、来源标签**的
IPv4/IPv6 CIDR 规则集，服务端按**最长前缀匹配 + 优先级**计算每条规则的**实际覆盖范围**，
识别**完全遮蔽、部分重叠、动作冲突**，并给出**可复现的最小冲突对**。支持分析版本保存、
结果查询与 JSON 导出，数据持久化在 SQLite 中。

## 一条命令启动

```bash
docker compose up -d --build
```

- 服务端口：**`8080`**（HTTP，映射到宿主机 `127.0.0.1:8080`，可在 `docker-compose.yml` 修改）
- 交互文档（Swagger UI）：<http://localhost:8080/docs>
- ReDoc：<http://localhost:8080/redoc>
- 健康检查：<http://localhost:8080/health>
- SQLite 数据保存在命名卷 `prefix-data`（容器内 `/data/prefix.db`），重启不丢失

停止：`docker compose down`（加 `-v` 可同时删除数据卷）。

不使用 Docker 时的本地启动方式：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
# 数据库路径可用环境变量覆盖：PREFIX_DB_PATH=/path/to/prefix.db
```

## 有效顺序（precedence）与算法模型

当多条规则覆盖同一地址时，地址归属由以下**确定性顺序**决定（键越小越先获得地址）：

1. **优先级高者优先**（`priority` 数字越大越优先）；
2. 优先级相同则**最长前缀优先**（prefixlen 更大、更具体的 CIDR 获胜）；
3. 仍相同则**提交顺序靠前者优先**（请求数组中的下标）。

每条规则 R 的实际覆盖范围：

```
effective(R) = R 的地址区间 − ⋃ { 所有优先序排在 R 之前规则的地址区间 }
```

规则状态：

| 状态 | 含义 |
| --- | --- |
| `active` | 完全未被遮蔽，整块地址都生效 |
| `partially_shadowed` | 部分地址被更高优先序规则抢走（即“部分重叠”） |
| `fully_shadowed` | 整块地址 100% 被遮蔽，规则形同虚设 |

结构事实：任意两个 CIDR 块要么互不相交，要么其中一个完整包含另一个。因此真正的“部分
重叠”表现为一条规则被若干更高规则分别遮住一部分，而没有任何单条规则能完整遮住它。
IPv4 与 IPv6 地址空间独立，分别计算。

**最小冲突对（`minimal_conflict_pairs`）**：对每条被遮蔽规则 L，只保留对其失效区域有
*不可替代贡献*的更高规则 H —— 即 `(H ∩ L) − ⋃{严格高于 H 的规则}` 仍非空的 H。
纯传递遮蔽（H 对 L 的覆盖已被更上面的规则完全覆盖）不会出现，因此冲突对数量最小；
排序固定（按下规则序号、上规则序号），同一输入永远得到同一输出，可复现。

每条 finding 的 `conflict_kind`：

- `action_conflict`：遮蔽与被遮蔽规则的 `action` 不同（permit/deny 策略冲突）；
- `shadowed_same_action`：动作相同的冗余遮蔽（可用于清理规则）。

## API 一览

基路径 `/api/v1`，所有请求/响应均为 JSON。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/v1/analyze` | 仅分析不保存（无副作用） |
| POST | `/api/v1/analyses` | 分析并保存为一个版本，返回完整结果（201） |
| GET | `/api/v1/analyses?limit=&offset=` | 列出已保存版本（含摘要） |
| GET | `/api/v1/analyses/{id}` | 查询某个版本的完整结果 |
| GET | `/api/v1/analyses/{id}/rules` | 查询该版本的原始规则 + 每条状态 |
| GET | `/api/v1/analyses/{id}/findings?kind=` | 遮蔽/冲突明细；`kind=action_conflict` 只看最小动作冲突对，`shadowed_same_action` 只看同动作遮蔽 |
| GET | `/api/v1/analyses/{id}/export` | 导出完整 JSON（`Content-Disposition: attachment`） |
| DELETE | `/api/v1/analyses/{id}` | 删除版本（级联删除规则） |
| GET | `/health` · `/` | 健康检查 / 服务信息 |

### 快速体验

```bash
# 1) 提交分析并保存版本（仓库自带示例）
curl -s -X POST http://localhost:8080/api/v1/analyses \
  -H 'Content-Type: application/json' \
  -d @examples/sample-rules.json

# 2) 仅分析、不落库
curl -s -X POST http://localhost:8080/api/v1/analyze \
  -H 'Content-Type: application/json' \
  -d '{"rules":[{"cidr":"10.0.0.0/8","action":"permit","priority":100},
                 {"cidr":"10.10.0.0/16","action":"deny","priority":200},
                 {"cidr":"10.10.8.0/22","action":"permit","priority":300}]}'

# 3) 列出版本 / 导出
curl -s http://localhost:8080/api/v1/analyses
curl -s -OJ http://localhost:8080/api/v1/analyses/<ID>/export
```

### 请求体字段

```jsonc
{
  "name": "可选版本名称",
  "rules": [
    {
      "id": "rule-1",                 // 可省略，自动生成 rule-1..；提交内唯一
      "cidr": "10.10.0.0/16",         // 必填，规范网络地址（带主机位会被拒绝并给出修正建议）
      "action": "deny",               // 必填，如 permit / deny，按字符串原样比较
      "priority": 200,                // 可选，默认 0，数字越大越优先
      "source": "team-b"              // 可选，默认 default，来源标签
    }
  ]
}
```

### 响应中的关键字段

- `rules[].effective_cidrs`：实际覆盖范围的规范 CIDR 列表；
- `rules[].effective_addresses` / `covered_addresses` / `coverage_ratio`：生效地址数 /
  被遮蔽地址数 / 覆盖率（IPv6 地址数为大整数，以 JSON number 传输）；
- `rules[].shadowed_by`：对本规则失效区域有不可替代贡献的最小更高规则 id 集合；
- `findings[]`：全部最小遮蔽对，含重叠块、`governing_cidrs`（H 独立贡献的区域）、
  关系（`contains` 完整包含 / `equal` 同块 / `within` 子网部分遮蔽）与冲突类型；
- `minimal_conflict_pairs[]`：其中 `action_conflict` 的子集，即最小动作冲突对；
- `summary.by_version.ipv4|ipv6`：按协议族的统计。

约束：单次最多 **2000** 条规则；CIDR 必须是规范网络地址（如 `10.0.0.5/24` 会被拒绝，
错误信息会提示 `10.0.0.0/24`）。

## 项目结构

```
app/
  main.py          # FastAPI 路由（分析 / 版本 CRUD / 导出）
  prefix_logic.py  # 核心算法：CIDR 解析、区间运算、覆盖、遮蔽、最小冲突对
  schemas.py       # Pydantic 请求/响应模型
  database.py      # SQLite 持久化（analyses / rules 两张表，事务写入）
examples/
  sample-rules.json
tests/
  test_api.py      # 端到端测试（遮蔽、冲突、IPv6、持久化、导出…）
Dockerfile
docker-compose.yml
requirements.txt
```

## 测试

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

## 复现性说明

- 输入相同 ⇒ 输出逐字节相同（有效顺序、finding 排序、JSON 键序均确定；
  `POST /analyze` 两次结果可直接 diff）。
- 每个保存版本记录 `content_hash`（请求体规范化后的 SHA-256），可用于核对输入是否一致；
  `GET .../export` 导出含请求、结果、时间戳与哈希的完整 JSON，供归档与离线复现。
