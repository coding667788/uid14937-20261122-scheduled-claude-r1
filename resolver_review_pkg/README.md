# resolver_review —— 内网分区离线解析复核工具

一个**完全离线、纯 Python 标准库、CPU 运行**的合成目录解析器。它只消费文档中
给出的合成目录、逻辑时钟与请求，不发起任何真实 DNS 查询或网络连接，也不套用
外部 DNS 实现的隐含规则。目标是判断给定离线请求能否在指定逻辑时刻安全解析到
一个**本轮获批（admitted）**的 endpoint，并对两套缓存依据在所有允许的事件交错
下是否等价给出可证明的结论。

- 运行环境：Windows 原生 Python 3.12（仅标准库）
- 入口模块：`python -m resolver_review ...`（或隔离启动器 `run_tool.py`）
- 输出：确定性、可复现的 UTF-8 JSON
- 规模上限：22 个偏序事件、60 个名称、名称深度 12

---

## 1. 目录结构

```
resolver_review_pkg/
├── resolver_review/            # 可导入包
│   ├── __init__.py
│   ├── __main__.py             # python -m resolver_review 入口
│   ├── errors.py               # 带 JSON Pointer 的校验错误模型
│   ├── model.py                # 名称后缀代数 + 不可变事件数据模型
│   ├── validator.py            # CASE.json 结构校验（错误可定位）
│   ├── cache.py                # 缓存条目与键控缓存容器
│   ├── view.py                 # 事件溯源的目录视图
│   ├── resolve.py              # 解析引擎（活目录/缓存/故障兜底）
│   ├── simulate.py             # 固定时间线模拟
│   ├── compare.py              # 偏序理想（ideal）位掩码 BFS 对比
│   └── jsonio.py               # 确定性 UTF-8 JSON 与 CLI
├── examples/                   # 可直接生效的虚构目录与请求
│   ├── simulate_case.json          # 生命周期：别名链/缓存/撤销失效/故障兜底
│   ├── simulate_policy_case.json   # 策略：越界否定/子树扣减/未授权/闭环
│   ├── compare_eq_case.json    # 等价对
│   └── compare_diff_case.json  # 非等价对（含最短区分序列）
├── sample_output/              # 上述样本的确定性参考输出
│   ├── simulate_result.json
│   ├── simulate_policy_result.json
│   ├── compare_equivalent_result.json
│   └── compare_witness_result.json
├── tests/
│   └── test_resolver.py        # unittest 验收（22 个用例）
├── run_tool.py                 # 隔离模式 CLI 启动器
└── run_tests.py                # 隔离模式测试启动器
```

---

## 2. 运行方法

### 2.1 推荐：隔离模式（处理不可信输入）

`-I`（隔离模式）下解释器不读取 `PYTHONPATH`、用户站点包，也不把当前目录加入
模块搜索路径，从而避免数据目录里被植入的 `json.py` 等模块被意外导入。
启动器只把**受信任的包目录**显式插入 `sys.path`，数据文件始终以路径参数传入，
不会进入模块搜索路径。

```bash
# 模拟（生命周期样本 + 策略判定样本）
python -I run_tool.py simulate examples/simulate_case.json        sample_output/simulate_result.json
python -I run_tool.py simulate examples/simulate_policy_case.json sample_output/simulate_policy_result.json

# 对比（等价对 / 非等价对）
python -I run_tool.py compare examples/compare_eq_case.json   sample_output/compare_equivalent_result.json
python -I run_tool.py compare examples/compare_diff_case.json sample_output/compare_witness_result.json
```

### 2.2 标准模块入口

当包目录已在 `PYTHONPATH` 中时，也可直接使用模块入口：

```bash
python -m resolver_review simulate examples/simulate_policy_case.json
python -m resolver_review compare  examples/compare_diff_case.json
```

省略输出文件时，结果以 UTF-8 写到标准输出。

### 2.3 运行测试

```bash
python -I run_tests.py
```

### 2.4 退出码

| 退出码 | 含义 |
| --- | --- |
| 0 | 成功，结果 JSON 含 `"ok": true` |
| 1 | 输入结构/语义错误，stderr 输出带 JSON Pointer 的错误对象 |
| 2 | 命令行用法错误 |

结构错误示例（精确定位到字段）：

```json
{
  "ok": false,
  "error": {"pointer": "/events/0/record/partition", "message": "缺少必填字段"}
}
```

---

## 3. 协议模型

### 3.1 名称与后缀

名称是点分小写标签序列（如 `db.alpha.internal`），深度上限 12。空串 `""`
表示**根后缀**，覆盖一切。后缀 `s` 覆盖名称 `n` 当且仅当 `s` 为根、`s == n`
或 `n` 以 `.s` 结尾。匹配取**最长后缀**（标签数最多者）；同长按事件输入顺序
（`order`）处理。

### 3.2 信任范围（trust scope）

信任范围以 `(分区, 名称后缀, 目录代次)` 绑定。一个名称在某分区可见，当且仅当
存在一条覆盖它的、活动（未过期）且未被 `trust_remove`/撤销的信任范围。
信息访问始终以**外层请求的服务身份与起始分区**复核。

### 3.3 分区隔离

每个内网分区有独立的别名目录与准入表。解析过程中：

- **不能从另一分区进口正项**；
- **不能从另一分区进口否定项**；
- 整条别名链的每一跳都必须在**起始分区**可见；
- 终点 endpoint 只能交回**该分区本轮获批**的地址。

### 3.4 记录种类

| kind | 含义 | 必需字段 |
| --- | --- | --- |
| `positive` | 正向地址记录 | `value` = endpoint |
| `alias` | 需继续解析的别名 | `value` = 下一名称 |
| `negative` | 带证明的否定记录，可覆盖某名称子树 | `proof` |

每条记录绑定一个分区内**唯一且不可复用**的代次 `generation`。同名记录的新
upsert 取代旧条目，但恢复同名记录**不会复用旧代次**。

### 3.5 否定覆盖与存在子树扣减

覆盖性否定遇到**同分区更具体的可信存在子树**时：

- 仅扣除与该存在子树交叠的部分；
- 在存在证据生效期间，否定范围的其余部分仍然有效。

例：否定后缀 `wide.alpha.internal` 与存在点 `kept.wide.alpha.internal` 并存时，
`kept.wide.alpha.internal` 可正常解析，而 `lonely.wide.alpha.internal` 仍被否定。

### 3.6 有效期（expires / deadline）

- 记录的 `expires` 为半开区间上界：槽 `slot` 满足 `slot < expires` 时存活。
- 命中正项的缓存截止取**整条别名链与授权的最早截止**；无任何截止时用协议
  常量 `FAR_FUTURE = 2^31 - 1`，保证输出是稳定的有限整数。
- 否定缓存截止取否定记录自身的有效期。

### 3.7 撤销（revoke）与缓存失效

撤销从指定逻辑槽生效，按 `(分区, 代次)` 作用：

- 目录正表中属于该代次的条目被撤下；
- 缓存中绑定该代次的**正项与否定项都失效**（按代次批量清除）；
- 撤销是兜底的硬性禁止条件，故障宽限也不能绕过。

### 3.8 别名闭环

多级别名跟随过程中若再次遇到已访问名称，立即报告**最短闭环**并结束，
决策码为 `alias_cycle`，输出 `cycle`（如 `["x","y","x"]`）与 `cycle_length`。

### 3.9 故障期间的限时旧正项（stale fallback）

仅当**全部**条件成立时才允许把旧正项限时交付（来源标记为 `stale`）：

1. 请求显式携带 `stale` 配置且 `enabled=true`；
2. 该服务当前处于 `failure_begin … failure_end` 故障窗口内；
3. 原链的当前信任范围仍有效（起始名仍可见）；
4. 终点 endpoint 仍在该分区本轮获批；
5. 旧正项缓存仍在 `deadline + extra_slots` 宽限内；
6. **现行否定不存在、代次未被撤销**——这两条始终禁止兜底。

兜底交付的实际截止为 `deadline + extra_slots`，且**不重写缓存**。

---

## 4. 决策码与来源

### 4.1 决策码 `decision`

| decision | 含义 |
| --- | --- |
| `resolved` | 安全解析到本轮获批 endpoint |
| `negative_denied` | 被（已扣减的）覆盖性否定命中 |
| `untrusted` | 名称在起始分区无活动信任范围 |
| `no_record` | 受信任但无活动记录，或代次已撤销 |
| `unadmitted` | 正项终点未在本轮获批 |
| `alias_cycle` | 别名链闭环 |

### 4.2 来源 `source`

| source | 含义 |
| --- | --- |
| `live` | 来自当前活目录解析 |
| `cache` | 来自经复核仍有效的缓存 |
| `stale` | 故障窗口内的限时旧正项兜底 |

---

## 5. simulate 命令

按**固定逻辑事件序列**重放（数组顺序即执行顺序；校验器保证 `slot` 非递减、
`after` 依赖在数组中先出现）。输出每个事件的处理结果，对请求给出选择路径、
来源、别名链、终点、授权依据与**实际缓存截止**，并在撤销事件上报告
`cache_invalidated`（被失效的缓存条目数）。

关键输出字段：

- `result.chain`：实际跟随的别名链；
- `result.effective_deadline`：本次交付使用的截止（兜底时含宽限）；
- `result.cache_deadline`：写回/命中的缓存条目截止；
- `result.subtracted_subtrees`：否定判定中被扣减的存在子树；
- `cache_after` / `final_cache`：每步后与最终的缓存快照。

---

## 6. compare 命令

### 6.1 偏序与序理想

事件通过 `after` 构成有限偏序（校验器保证无环、不允许时间倒流）。一个
“已执行事件集合”是**序理想（ideal）**：执行事件 `e` 前必须先执行其全部
`after` 依赖。所有允许的目录更新交错，恰好等于从空集出发按理想闭包可达的
全部状态。

### 6.2 为什么不需要枚举全部排列

22 个事件用一个整数**位掩码**表示已执行集合。目录视图是已执行集合的纯函数
（按 mask 记忆化、按需从父理想增量重建），缓存状态以可哈希的 `immutable_key`
参与去重。算法对理想做宽度优先搜索（BFS），每个产品状态只处理一次：

- 状态数上界为不同理想数（远小于 `22!` 排列数）；
- BFS 按边数逐层扩展，**首次发现分歧时的路径即最短区分序列**；
- 已执行事件集合、缓存分区与代次都进入状态键，因此后继可见性被完整刻画。

#### 性能特征与状态预算

单次转移的成本被压到接近纯集合枚举：普通目录事件（upsert/trust/admission）
既不改缓存也不构建视图，直接共享父缓存引用、零拷贝；只有 `revoke`/`request`
事件才复制缓存并按需构建视图。成本随**实际理想数**线性增长，与排列数无关。

绝大多数实际偏序（带依赖链）的理想数很小，毫秒级完成。刻意构造的极端高分支
偏序（十几个互相独立的事件）理想数可达 `2^N` 量级，纯 CPython 枚举百万级
理想约需百秒——这是解释器语言天花板，而非算法问题（算法本身不枚举排列）。
默认 `limits.max_states = 200000` 覆盖典型场景并保证交互式响应；需要穷尽
更大空间时可显式调高。**触发上限时 `truncated=true` 且 `equivalent=false`，
绝不会在未穷尽时误报等价。**

### 6.3 产品状态与观察比对

两侧（`cache_a` / `cache_b`）从各自初始缓存依据出发，在同一条事件边上同步
转移。视图共享（事件序列相同），缓存各自独立演化。当转移的是窗口
`[lo, hi]` 内的 `request` 事件时，用缓存**探针副本**计算观察向量（不污染
状态），按 `compare_fields` 逐字段比较：

| 字段 | 比较内容 |
| --- | --- |
| `reachability` | `reachable` / `unreachable` |
| `name_list` | 起始分区当前存在活动记录的名称（字典序） |
| `authorization` | endpoint + admission_id + 代次（不可达时为 null） |

发现不同即输出 `witness`：合法理想路径 `event_sequence`、分歧事件、分歧槽、
分歧字段列表与两侧观察。可用 `limits.max_states` 限制状态预算，触发上限时
`truncated=true` 且不会误报等价。

### 6.4 样本预期

- `compare_eq_case.json`：两侧缓存依据相同 → `"equivalent": true`，无 witness。
- `compare_diff_case.json`：两侧缓存绑定同一名称的不同代次，其中一代次被
  撤销 → `"equivalent": false`，witness 显示在撤销前的候选观察点上两侧
  `authorization` 已不同（这正是“候选等待导致短反例不同于无缓存模型”的情形：
  若强行等到撤销之后，活目录反而会让两边收敛）。

---

## 7. CASE.json 结构摘要

```jsonc
{
  "mode": "simulate | compare",
  "partitions": ["zone_alpha"],
  "names": ["app.alpha.internal"],          // 可选名称登记表（上限 60）
  "compare_fields": ["reachability", "name_list", "authorization"],
  "limits": {"max_states": 200000},
  "cache_a": {"entries": [ /* 仅 compare */ ]},
  "cache_b": {"entries": [ /* 仅 compare */ ]},
  "events": [
    {"id": "e1", "slot": 0, "etype": "trust_add",
     "after": ["dep0"],
     "scope": {"partition": "...", "suffix": "...", "generation": "..."}},
    {"id": "e2", "slot": 1, "etype": "upsert",
     "record": {"kind": "positive|alias|negative", "partition": "...",
                "name": "...", "generation": "...", "value": "...",
                "proof": "...", "expires": 10}},
    {"id": "e3", "slot": 2, "etype": "revoke",
     "partition": "...", "generation": "..."},
    {"id": "e4", "slot": 3, "etype": "request",
     "request": {"name": "...", "service": "...", "partition": "...",
                 "lo": 1, "hi": 9,
                 "stale": {"enabled": true, "extra_slots": 5}}}
  ]
}
```

事件类型：`upsert`、`revoke`、`trust_add`、`trust_remove`、`admission_add`、
`admission_remove`、`failure_begin`、`failure_end`、`request`。

正项缓存条目额外需要 `endpoint`；否定缓存条目额外携带 `proof`。

---

## 8. 安全与可复现性说明

- 所有 JSON 以 UTF-8 读写；输出使用 `sort_keys` + 固定分隔符，两次运行
  字节一致（已在样本上验证）。
- 推荐始终用 `python -I run_tool.py ...` 处理外部数据；数据目录中的植入
  模块（如伪造的 `json.py`）不会进入导入路径。
- 不使用网络、线程、随机数或墙钟时间，全部行为由输入的逻辑事件决定。
