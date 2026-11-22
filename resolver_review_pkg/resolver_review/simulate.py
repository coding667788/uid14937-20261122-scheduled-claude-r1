"""simulate：按固定逻辑事件序列重放，输出解析选择路径。

事件按数组顺序重放（校验器已保证 slot 非递减、``after`` 依赖在数组中先出现）。
revoke 同时使缓存中绑定该代次的正项与否定项失效；每次 request 产出一条
结构化决策记录，含来源（live/cache/stale）、别名链、终点、授权依据与
实际缓存截止（``cache_deadline`` 为写回/命中的缓存条目截止，
``effective_deadline`` 为本次交付使用的截止，兜底时含宽限）。
"""

from __future__ import annotations

from .cache import Cache
from .resolve import Engine, LiveResult
from .view import View
from .validator import Case


def _result_to_dict(result: LiveResult) -> dict:
    data: dict = {
        "decision": result.decision,
        "source": result.source,
        "partition": result.partition,
        "name": result.name,
        "slot": result.slot,
        "chain": list(result.chain),
    }
    if result.endpoint is not None:
        data["endpoint"] = result.endpoint
    if result.generation is not None:
        data["generation"] = result.generation
    if result.admission_id is not None:
        data["admission_id"] = result.admission_id
    if result.deadline is not None:
        data["effective_deadline"] = result.deadline
    if result.negative_suffix is not None:
        data["negative_suffix"] = result.negative_suffix
        data["negative_generation"] = result.negative_generation
        data["proof"] = result.proof
        data["remaining_suffix"] = result.remaining_suffix
        data["subtracted_subtrees"] = list(result.subtracted)
    if result.cycle:
        data["cycle"] = list(result.cycle)
        data["cycle_length"] = len(result.cycle)
    if result.cache_write is not None:
        data["cache_deadline"] = result.cache_write.deadline
    elif result.source == "cache":
        data["cache_deadline"] = result.deadline
    return data


def run_simulate(case: Case) -> dict:
    view = View(case.partitions)
    cache = Cache()
    engine = Engine(view, cache)
    timeline: list[dict] = []
    request_index = 0

    for event in case.events:
        if event.etype == "revoke":
            assert event.rev_partition is not None and event.rev_generation is not None
            invalidated = cache.invalidate_generation(
                event.rev_partition, event.rev_generation
            )
            view.apply_event(event)
            timeline.append(
                {
                    "event_id": event.id,
                    "slot": event.slot,
                    "etype": event.etype,
                    "cache_invalidated": invalidated,
                }
            )
            continue

        view.apply_event(event)

        if event.etype != "request":
            timeline.append(
                {"event_id": event.id, "slot": event.slot, "etype": event.etype}
            )
            continue

        assert event.request is not None
        request_index += 1
        result = engine.query(event.request, event.slot)
        entry = cache.get(event.request.partition, event.request.name)
        record = {
            "event_id": event.id,
            "slot": event.slot,
            "etype": "request",
            "request_no": request_index,
            "service": event.request.service,
            "result": _result_to_dict(result),
            "cache_after": cache.snapshot(),
        }
        if entry is not None:
            record["cache_entry_deadline"] = entry.deadline
        timeline.append(record)

    return {
        "mode": "simulate",
        "requests": request_index,
        "timeline": timeline,
        "final_cache": cache.snapshot(),
    }
