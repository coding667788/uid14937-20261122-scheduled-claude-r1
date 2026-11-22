"""compare：偏序事件交错下的等价性验证。

事件以 ``after`` 构成有限偏序（校验器保证无环）。每一个“已执行事件集合”
都是一个序理想（ideal）：执行 ``e`` 前必须先执行其全部 ``after`` 依赖。
所有允许的目录更新交错 = 从空集出发、按理想闭包可达的全部状态。

不枚举全部排列，而是对理想做宽度优先搜索：22 个事件用一个整数位掩码表示
已执行集合。视图是已执行集合的纯函数（按 mask 记忆化、按需从父理想增量
重建）；缓存状态以可哈希的 ``immutable_key`` 作为状态键。普通目录事件不改
缓存也不构建视图，直接共享父缓存引用；只有 revoke/request 才复制缓存并构建
视图。两侧（a/b）各自从自己的初始缓存依据出发，产品状态同步转移，在每条
request 转移边上对窗口 ``[lo, hi]`` 内的请求取观察向量，并按
``compare_fields`` 逐字段比较；一旦不同，回溯给出最短精确区分序列。

名称列表（name_list）的结构性定义：起始分区中当前存在活动记录
（未撤销、未过期）的名称，字典序排列。
"""

from __future__ import annotations

from dataclasses import dataclass

from .cache import Cache
from .model import RequestSpec
from .resolve import Engine, LiveResult
from .view import View
from .validator import Case

FIELD_LABELS = {
    "reachability": "是否可达",
    "name_list": "名称列表",
    "authorization": "授权依据",
}


@dataclass
class _Node:
    mask: int
    parent: "_Node | None"
    event_id: str | None
    depth: int


def _build_view(case: Case, mask: int) -> View:
    view = View(case.partitions)
    for i, event in enumerate(case.events):
        if mask & (1 << i):
            view.apply_event(event)
    return view


def _partition_name_list(view: View, partition: str) -> list[str]:
    return sorted(name for part, name in view.records if part == partition)


def _answer(view: View, cache: Cache, req: RequestSpec, slot: int) -> dict:
    """计算一次窗口内请求的观察向量（探针副本，不改变缓存）。"""

    probe = cache.copy()
    result: LiveResult = Engine(view, probe).query(req, slot)

    if result.decision == "resolved":
        authorization = {
            "endpoint": result.endpoint,
            "admission_id": result.admission_id,
            "generation": result.generation,
        }
    else:
        authorization = None
    return {
        "service": req.service,
        "partition": req.partition,
        "name": req.name,
        "slot": slot,
        "reachability": "reachable" if result.decision == "resolved" else "unreachable",
        "name_list": _partition_name_list(view, req.partition),
        "authorization": authorization,
        "decision": result.decision,
        "source": result.source,
    }


def _advance_cache(cache: Cache, view: View, case: Case, event_index: int) -> None:
    """执行事件对缓存的副作用（revoke 失效 / request 写回）。"""

    event = case.events[event_index]
    if event.etype == "revoke":
        assert event.rev_partition is not None and event.rev_generation is not None
        cache.invalidate_generation(event.rev_partition, event.rev_generation)
    elif event.etype == "request":
        assert event.request is not None
        Engine(view, cache).query(event.request, event.slot)


def _node_path(node: _Node) -> list[str]:
    path: list[str] = []
    cur = node
    while cur.parent is not None:
        path.append(cur.event_id)  # type: ignore[arg-type]
        cur = cur.parent
    path.reverse()
    return path


def run_compare(case: Case) -> dict:
    n = len(case.events)
    index_of = {event.id: i for i, event in enumerate(case.events)}
    after_masks: list[int] = []
    for event in case.events:
        mask = 0
        for ref in event.after:
            mask |= 1 << index_of[ref]
        after_masks.append(mask)

    cache_a0 = Cache.from_entries(case.cache_a or ())
    cache_b0 = Cache.from_entries(case.cache_b or ())
    key_a0 = cache_a0.immutable_key()
    key_b0 = cache_b0.immutable_key()

    # 只有 revoke 与 request 会改变缓存；其余事件转移时直接共享父缓存引用，
    # 零拷贝、零键重建。也只有这两类事件需要目录视图（普通 upsert/trust/
    # admission 转移既不读也不写缓存，无需构建 View）。
    needs_view = frozenset(
        i for i, e in enumerate(case.events) if e.etype in ("revoke", "request")
    )

    # View 仅在 revoke/request 状态按需重建，并按 mask 记忆化。
    # 事件数 <= 22，不同 mask 的 View 对象很小（dict 引用），无界缓存的
    # 内存可接受；关键是避免 LRU 颠簸导致同一 mask 被反复全量重建。
    view_cache: dict[int, View] = {0: _build_view(case, 0)}

    def view_for(mask: int) -> View:
        cached = view_cache.get(mask)
        if cached is not None:
            return cached
        # 迭代回溯到最近的已缓存父理想，再正向增量 apply；链长 <= 事件数。
        chain: list[int] = []
        ancestor = mask
        while ancestor not in view_cache:
            lowest = ancestor & -ancestor
            chain.append(lowest.bit_length() - 1)
            ancestor ^= lowest
        view = view_cache[ancestor].copy()
        for event_index in reversed(chain):
            view.apply_event(case.events[event_index])
        view_cache[mask] = view
        return view

    start = _Node(mask=0, parent=None, event_id=None, depth=0)
    # 队列元素：(node, cache_a, cache_b, key_a, key_b)。缓存对象在非变更
    # 转移上按引用共享，只有 revoke/request 事件才产生新副本。
    queue: list[tuple[_Node, Cache, Cache, frozenset, frozenset]] = [
        (start, cache_a0, cache_b0, key_a0, key_b0)
    ]
    visited: set[tuple[int, frozenset, frozenset]] = {(0, key_a0, key_b0)}
    head = 0
    states_seen = 1
    truncated = False
    witness: dict | None = None

    while head < len(queue):
        node, cache_a, cache_b, ka, kb = queue[head]
        head += 1
        mask = node.mask

        for i, event in enumerate(case.events):
            bit = 1 << i
            if mask & bit or (after_masks[i] & ~mask):
                continue

            next_mask = mask | bit

            if i in needs_view:
                next_view = view_for(next_mask)
                next_a = cache_a.copy()
                next_b = cache_b.copy()
                _advance_cache(next_a, next_view, case, i)
                _advance_cache(next_b, next_view, case, i)
                nka = next_a.immutable_key()
                nkb = next_b.immutable_key()
                next_node_caches = (next_a, next_b)
            else:
                # 目录类事件不改缓存：共享引用与键，零拷贝、零键重建。
                next_view = None
                nka, nkb = ka, kb
                next_node_caches = (cache_a, cache_b)

            if event.etype == "request":
                req = event.request
                assert req is not None
                if req.lo is not None and req.lo <= event.slot <= req.hi:
                    assert next_view is not None
                    obs_a = _answer(next_view, next_a, req, event.slot)
                    obs_b = _answer(next_view, next_b, req, event.slot)
                    diff = [
                        field
                        for field in case.compare_fields
                        if obs_a[field] != obs_b[field]
                    ]
                    if diff:
                        sequence_ids = _node_path(node) + [event.id]
                        witness = {
                            "event_sequence": sequence_ids,
                            "length": len(sequence_ids),
                            "diverging_event": event.id,
                            "diverging_slot": event.slot,
                            "differing_fields": [
                                {"field": f, "label": FIELD_LABELS[f]} for f in diff
                            ],
                            "observation_a": obs_a,
                            "observation_b": obs_b,
                        }
                        break

            state_key = (next_mask, nka, nkb)
            if state_key not in visited:
                if states_seen >= case.max_states:
                    truncated = True
                    break
                visited.add(state_key)
                states_seen += 1
                queue.append(
                    (
                        _Node(
                            mask=next_mask,
                            parent=node,
                            event_id=event.id,
                            depth=node.depth + 1,
                        ),
                        next_node_caches[0],
                        next_node_caches[1],
                        nka,
                        nkb,
                    )
                )
        if witness is not None or truncated:
            break

    return {
        "mode": "compare",
        "equivalent": witness is None and not truncated,
        "ideal_states_explored": states_seen,
        "events": n,
        "max_linearization_length": n,
        "truncated": truncated,
        "max_states_limit": case.max_states,
        "compare_fields": list(case.compare_fields),
        **({"witness": witness} if witness is not None else {}),
    }
