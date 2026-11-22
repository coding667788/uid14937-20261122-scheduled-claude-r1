"""CASE.json 结构校验与解析。

所有结构错误都抛出 :class:`ValidationError`，其 ``pointer`` 字段使用
RFC 6901 JSON Pointer 精确定位（如 ``/events/7/record/generation``）。
"""

from __future__ import annotations

from dataclasses import dataclass

from .cache import CacheEntry
from .errors import (
    ValidationError,
    expect_bool,
    expect_int,
    expect_list,
    expect_object,
    expect_str,
    join,
    require_fields,
)
from .model import (
    Admission,
    Event,
    Record,
    RequestSpec,
    StaleConfig,
    TrustScope,
    normalize_label,
    split_label,
)

MAX_EVENTS = 22
MAX_NAMES = 60
MAX_DEPTH = 12
KNOWN_ETYPES = frozenset(
    {
        "upsert",
        "revoke",
        "trust_add",
        "trust_remove",
        "admission_add",
        "admission_remove",
        "failure_begin",
        "failure_end",
        "request",
    }
)
COMPARE_FIELDS = ("reachability", "name_list", "authorization")


@dataclass(frozen=True)
class Case:
    mode: str
    partitions: tuple[str, ...]
    names: tuple[str, ...] | None
    events: tuple[Event, ...]
    compare_fields: tuple[str, ...]
    cache_a: tuple[CacheEntry, ...] | None
    cache_b: tuple[CacheEntry, ...] | None
    max_states: int


def _label(value: object, pointer: str, what: str, allow_root: bool = False) -> str:
    if not isinstance(value, str):
        raise ValidationError(pointer, f"{what}必须是字符串，实际为 {type_name(value)}")
    if allow_root and value == "":
        return ""
    text = expect_str(value, pointer, what)
    try:
        normalized = normalize_label(text)
    except ValueError as exc:
        raise ValidationError(pointer, f"{what}不是合法点分名称: {exc}") from exc
    if allow_root and normalized == "":
        return normalized
    depth = len(split_label(normalized))
    if depth > MAX_DEPTH:
        raise ValidationError(pointer, f"{what}标签深度 {depth} 超过上限 {MAX_DEPTH}")
    return normalized


def _optional_expires(obj: dict, pointer: str, slot: int) -> int | None:
    if "expires" not in obj or obj["expires"] is None:
        return None
    expires = expect_int(obj["expires"], join(pointer, "expires"), "expires")
    if expires < 0:
        raise ValidationError(join(pointer, "expires"), "expires 不能为负数")
    if expires <= slot:
        raise ValidationError(
            join(pointer, "expires"), "expires 必须晚于事件 slot，否则记录出生即失效"
        )
    return expires


def _parse_after(obj: dict, pointer: str) -> tuple[str, ...]:
    if "after" not in obj:
        return ()
    raw = expect_list(obj["after"], join(pointer, "after"), "after")
    result: list[str] = []
    for i, item in enumerate(raw):
        result.append(expect_str(item, join(join(pointer, "after"), i), "after 元素"))
    if len(set(result)) != len(result):
        raise ValidationError(join(pointer, "after"), "after 存在重复事件 id")
    return tuple(result)


def _parse_stale(obj: dict, pointer: str) -> StaleConfig | None:
    if "stale" not in obj or obj["stale"] is None:
        return None
    raw = expect_object(obj["stale"], join(pointer, "stale"), "stale")
    enabled = True
    if "enabled" in raw:
        enabled = expect_bool(raw["enabled"], join(join(pointer, "stale"), "enabled"))
    if "extra_slots" not in raw:
        raise ValidationError(join(join(pointer, "stale"), "extra_slots"), "缺少必填字段")
    extra = expect_int(
        raw["extra_slots"], join(join(pointer, "stale"), "extra_slots"), "extra_slots"
    )
    if extra < 0:
        raise ValidationError(
            join(join(pointer, "stale"), "extra_slots"), "extra_slots 不能为负数"
        )
    return StaleConfig(extra_slots=extra, enabled=enabled)


def _parse_request(obj: dict, pointer: str, order: int, mode: str) -> RequestSpec:
    raw = expect_object(obj["request"], join(pointer, "request"), "request")
    require_fields(raw, ("name", "service", "partition"), join(pointer, "request"))
    rp = join(pointer, "request")
    name = _label(raw["name"], join(rp, "name"), "请求名称")
    service = expect_str(raw["service"], join(rp, "service"), "service")
    partition = expect_str(raw["partition"], join(rp, "partition"), "起始分区")
    lo = hi = None
    has_lo = "lo" in raw and raw["lo"] is not None
    has_hi = "hi" in raw and raw["hi"] is not None
    if has_lo != has_hi:
        raise ValidationError(rp, "lo 与 hi 必须同时给出或同时省略")
    if has_lo:
        lo = expect_int(raw["lo"], join(rp, "lo"), "查询窗口下界 lo")
        hi = expect_int(raw["hi"], join(rp, "hi"), "查询窗口上界 hi")
        if lo < 0 or hi < lo:
            raise ValidationError(rp, "查询窗口需满足 0 <= lo <= hi")
    if mode == "compare" and not has_lo:
        raise ValidationError(rp, "compare 模式的 request 必须给出 lo/hi 查询窗口")
    if mode == "simulate" and has_lo:
        raise ValidationError(rp, "simulate 模式的 request 不允许 lo/hi 窗口")
    return RequestSpec(
        name=name,
        service=service,
        partition=partition,
        order=order,
        lo=lo,
        hi=hi,
        stale=_parse_stale(raw, rp),
    )


def _parse_upsert(obj: dict, pointer: str, slot: int, order: int) -> Record:
    raw = expect_object(obj["record"], join(pointer, "record"), "record")
    require_fields(
        raw, ("kind", "partition", "name", "generation"), join(pointer, "record")
    )
    rp = join(pointer, "record")
    kind = expect_str(raw["kind"], join(rp, "kind"), "记录 kind")
    if kind not in ("positive", "alias", "negative"):
        raise ValidationError(
            join(rp, "kind"), "记录 kind 必须是 positive / alias / negative"
        )
    partition = expect_str(raw["partition"], join(rp, "partition"), "partition")
    name = _label(raw["name"], join(rp, "name"), "记录名称", allow_root=(kind == "negative"))
    generation = expect_str(raw["generation"], join(rp, "generation"), "generation")
    expires = _optional_expires(raw, rp, slot)
    value = proof = None
    if kind in ("positive", "alias"):
        if "value" not in raw:
            raise ValidationError(join(rp, "value"), f"{kind} 记录缺少 value")
        value = expect_str(raw["value"], join(rp, "value"), "value")
        if kind == "alias":
            value = _label(value, join(rp, "value"), "别名目标")
    else:
        proof = expect_str(raw.get("proof", ""), join(rp, "proof"), "否定证明 proof")
    return Record(
        kind=kind,
        partition=partition,
        name=name,
        generation=generation,
        order=order,
        expires=expires,
        value=value,
        proof=proof,
    )


def _parse_scope(obj: dict, pointer: str, slot: int, order: int) -> TrustScope:
    raw = expect_object(obj["scope"], join(pointer, "scope"), "scope")
    require_fields(
        raw, ("partition", "suffix", "generation"), join(pointer, "scope")
    )
    sp = join(pointer, "scope")
    partition = expect_str(raw["partition"], join(sp, "partition"), "partition")
    suffix = _label(raw["suffix"], join(sp, "suffix"), "信任后缀", allow_root=True)
    generation = expect_str(raw["generation"], join(sp, "generation"), "generation")
    expires = _optional_expires(raw, sp, slot)
    return TrustScope(
        partition=partition,
        suffix=suffix,
        generation=generation,
        order=order,
        expires=expires,
        active=True,
    )


def _parse_admission(obj: dict, pointer: str, slot: int, order: int) -> Admission:
    raw = expect_object(obj["admission"], join(pointer, "admission"), "admission")
    require_fields(
        raw,
        ("admission_id", "endpoint", "partition", "generation"),
        join(pointer, "admission"),
    )
    ap = join(pointer, "admission")
    admission_id = expect_str(raw["admission_id"], join(ap, "admission_id"), "admission_id")
    endpoint = expect_str(raw["endpoint"], join(ap, "endpoint"), "endpoint")
    partition = expect_str(raw["partition"], join(ap, "partition"), "partition")
    generation = expect_str(raw["generation"], join(ap, "generation"), "generation")
    expires = _optional_expires(raw, ap, slot)
    return Admission(
        admission_id=admission_id,
        endpoint=endpoint,
        partition=partition,
        generation=generation,
        order=order,
        expires=expires,
        active=True,
    )


def _parse_cache(raw: object, pointer: str) -> tuple[CacheEntry, ...]:
    root = expect_object(raw, pointer, "初始缓存依据")
    if "entries" not in raw:
        raise ValidationError(join(pointer, "entries"), "缺少必填字段")
    items = expect_list(root["entries"], join(pointer, "entries"), "缓存条目数组")
    entries: list[CacheEntry] = []
    for i, item in enumerate(items):
        ep = join(join(pointer, "entries"), i)
        obj = expect_object(item, ep, "缓存条目")
        require_fields(obj, ("partition", "name", "kind", "generation", "deadline"), ep)
        partition = expect_str(obj["partition"], join(ep, "partition"), "partition")
        name = _label(obj["name"], join(ep, "name"), "缓存名称")
        kind = expect_str(obj["kind"], join(ep, "kind"), "缓存 kind")
        if kind not in ("positive", "negative"):
            raise ValidationError(join(ep, "kind"), "缓存 kind 必须是 positive / negative")
        generation = expect_str(obj["generation"], join(ep, "generation"), "generation")
        deadline = expect_int(obj["deadline"], join(ep, "deadline"), "deadline")
        if deadline < 0:
            raise ValidationError(join(ep, "deadline"), "deadline 不能为负数")
        proof = obj.get("proof")
        if proof is not None and not isinstance(proof, str):
            raise ValidationError(join(ep, "proof"), "proof 必须是字符串")
        endpoint = obj.get("endpoint")
        if endpoint is not None and not isinstance(endpoint, str):
            raise ValidationError(join(ep, "endpoint"), "endpoint 必须是字符串")
        if kind == "positive" and not endpoint:
            raise ValidationError(join(ep, "endpoint"), "正项缓存必须给出 endpoint")
        entries.append(
            CacheEntry(
                partition=partition,
                name=name,
                kind=kind,
                generation=generation,
                deadline=deadline,
                proof=proof,
                endpoint=endpoint,
            )
        )
    return tuple(entries)


def parse_case(root: object, expected_mode: str) -> Case:
    """解析并交叉校验整个 CASE 文档。"""

    doc = expect_object(root, "", "CASE 根文档")
    mode = expected_mode
    if "mode" in doc and doc["mode"] is not None:
        declared = expect_str(doc["mode"], "/mode", "mode")
        if declared not in ("simulate", "compare"):
            raise ValidationError("/mode", "mode 必须是 simulate 或 compare")
        if declared != mode:
            raise ValidationError(
                "/mode", f"文档声明 mode={declared}，与命令 {mode} 不一致"
            )

    if "partitions" not in doc:
        raise ValidationError("/partitions", "缺少必填字段")
    raw_parts = expect_list(doc["partitions"], "/partitions", "分区数组")
    if not raw_parts:
        raise ValidationError("/partitions", "至少需要一个分区")
    partitions: list[str] = []
    for i, item in enumerate(raw_parts):
        partitions.append(expect_str(item, join("/partitions", i), "分区标识"))
    if len(set(partitions)) != len(partitions):
        raise ValidationError("/partitions", "分区标识重复")
    part_set = set(partitions)

    names_registry: tuple[str, ...] | None = None
    if "names" in doc and doc["names"] is not None:
        raw_names = expect_list(doc["names"], "/names", "名称表")
        registry: list[str] = []
        for i, item in enumerate(raw_names):
            registry.append(_label(item, join("/names", i), "名称"))
        if len(set(registry)) != len(registry):
            raise ValidationError("/names", "名称表存在重复名称")
        if len(registry) > MAX_NAMES:
            raise ValidationError("/names", f"名称数量超过上限 {MAX_NAMES}")
        names_registry = tuple(registry)

    if "events" not in doc:
        raise ValidationError("/events", "缺少必填字段")
    raw_events = expect_list(doc["events"], "/events", "事件数组")
    if len(raw_events) > MAX_EVENTS:
        raise ValidationError("/events", f"事件数 {len(raw_events)} 超过上限 {MAX_EVENTS}")

    events: list[Event] = []
    seen_ids: set[str] = set()
    upsert_gens: dict[tuple[str, str], int] = {}      # (partition, gen) -> 事件下标
    scope_gens: dict[tuple[str, str], int] = {}
    admission_gens: dict[tuple[str, str], int] = {}
    admission_ids: dict[str, int] = {}
    open_failures: dict[str, int] = {}
    distinct_names: set[str] = set()

    for i, raw_ev in enumerate(raw_events):
        ep = join("/events", i)
        obj = expect_object(raw_ev, ep, "事件")
        require_fields(obj, ("id", "slot", "etype"), ep)
        ev_id = expect_str(obj["id"], join(ep, "id"), "事件 id")
        if ev_id in seen_ids:
            raise ValidationError(join(ep, "id"), f"事件 id 重复: {ev_id}")
        seen_ids.add(ev_id)
        slot = expect_int(obj["slot"], join(ep, "slot"), "slot")
        if slot < 0:
            raise ValidationError(join(ep, "slot"), "slot 不能为负数")
        etype = expect_str(obj["etype"], join(ep, "etype"), "etype")
        if etype not in KNOWN_ETYPES:
            raise ValidationError(join(ep, "etype"), f"未知事件类型 {etype}")
        after = _parse_after(obj, ep)

        record = scope = admission = request = None
        rev_partition = rev_generation = remove_generation = service = None

        if etype == "upsert":
            record = _parse_upsert(obj, ep, slot, i)
            if record.partition not in part_set:
                raise ValidationError(
                    join(ep, "record/partition"),
                    f"分区 {record.partition!r} 未在 /partitions 声明",
                )
            key = (record.partition, record.generation)
            if key in upsert_gens:
                raise ValidationError(
                    join(ep, "record/generation"),
                    f"代次 {record.generation!r} 在分区内已被事件 "
                    f"{raw_events[upsert_gens[key]]['id']!r} 使用，代次不得复用",
                )
            upsert_gens[key] = i
            if record.name:
                distinct_names.add(record.name)
            if record.kind == "alias":
                distinct_names.add(record.value)  # type: ignore[arg-type]
        elif etype == "revoke":
            require_fields(obj, ("partition", "generation"), ep)
            rev_partition = expect_str(obj["partition"], join(ep, "partition"), "partition")
            rev_generation = expect_str(
                obj["generation"], join(ep, "generation"), "generation"
            )
            if rev_partition not in part_set:
                raise ValidationError(join(ep, "partition"), "分区未在 /partitions 声明")
            if (rev_partition, rev_generation) not in upsert_gens:
                raise ValidationError(
                    join(ep, "generation"),
                    "撤销目标代次在该分区的 upsert 事件中不存在",
                )
        elif etype == "trust_add":
            scope = _parse_scope(obj, ep, slot, i)
            if scope.partition not in part_set:
                raise ValidationError(
                    join(ep, "scope/partition"), "分区未在 /partitions 声明"
                )
            key = (scope.partition, scope.generation)
            if key in scope_gens:
                raise ValidationError(
                    join(ep, "scope/generation"), "信任范围代次在分区内重复"
                )
            scope_gens[key] = i
        elif etype == "trust_remove":
            require_fields(obj, ("partition", "generation"), ep)
            rp_part = expect_str(obj["partition"], join(ep, "partition"), "partition")
            remove_generation = expect_str(
                obj["generation"], join(ep, "generation"), "generation"
            )
            if rp_part not in part_set:
                raise ValidationError(join(ep, "partition"), "分区未在 /partitions 声明")
            if (rp_part, remove_generation) not in scope_gens:
                raise ValidationError(
                    join(ep, "generation"), "待移除的信任范围代次不存在"
                )
            rev_partition = rp_part
        elif etype == "admission_add":
            admission = _parse_admission(obj, ep, slot, i)
            if admission.partition not in part_set:
                raise ValidationError(
                    join(ep, "admission/partition"), "分区未在 /partitions 声明"
                )
            if admission.admission_id in admission_ids:
                raise ValidationError(
                    join(ep, "admission/admission_id"), "授权 id 重复"
                )
            admission_ids[admission.admission_id] = i
            akey = (admission.partition, admission.generation)
            if akey in admission_gens:
                raise ValidationError(
                    join(ep, "admission/generation"), "授权代次在分区内重复"
                )
            admission_gens[akey] = i
        elif etype == "admission_remove":
            require_fields(obj, ("admission_id",), ep)
            aid = expect_str(
                obj["admission_id"], join(ep, "admission_id"), "admission_id"
            )
            if aid not in admission_ids:
                raise ValidationError(join(ep, "admission_id"), "待移除的授权 id 不存在")
            remove_generation = aid
        elif etype in ("failure_begin", "failure_end"):
            require_fields(obj, ("service",), ep)
            service = expect_str(obj["service"], join(ep, "service"), "service")
            if etype == "failure_begin":
                if service in open_failures:
                    raise ValidationError(
                        join(ep, "service"), f"服务 {service!r} 的故障窗口未闭合又开启"
                    )
                open_failures[service] = i
            else:
                if service not in open_failures:
                    raise ValidationError(
                        join(ep, "service"), f"服务 {service!r} 没有匹配的 failure_begin"
                    )
                begin_i = open_failures.pop(service)
                if slot <= raw_events[begin_i]["slot"]:
                    raise ValidationError(
                        join(ep, "slot"), "failure_end 的 slot 必须晚于 failure_begin"
                    )
        else:  # request
            request = _parse_request(obj, ep, i, mode)
            if request.partition not in part_set:
                raise ValidationError(
                    join(ep, "request/partition"), "起始分区未在 /partitions 声明"
                )
            distinct_names.add(request.name)

        events.append(
            Event(
                id=ev_id,
                index=i,
                slot=slot,
                etype=etype,
                after=after,
                record=record,
                rev_partition=rev_partition,
                rev_generation=rev_generation,
                scope=scope,
                remove_generation=remove_generation,
                admission=admission,
                service=service,
                request=request,
            )
        )

    if open_failures:
        first = next(iter(open_failures.values()))
        raise ValidationError(
            join("/events", first),
            f"服务 {raw_events[first]['service']!r} 的故障窗口缺少 failure_end",
        )

    # after 引用完整性 + 时序方向。
    id_to_event = {ev.id: ev for ev in events}
    for ev in events:
        for ref in ev.after:
            if ref not in id_to_event:
                raise ValidationError(
                    join("/events", ev.index), f"after 引用了不存在的事件 {ref!r}"
                )
            if ref == ev.id:
                raise ValidationError(
                    join("/events", ev.index), "事件不能把自身列入 after"
                )
            if id_to_event[ref].slot > ev.slot:
                raise ValidationError(
                    join("/events", ev.index),
                    f"after 依赖 {ref!r} 的 slot 更晚，逻辑时间不允许倒流",
                )

    # 名称表核对。
    if names_registry is not None:
        registry_set = set(names_registry)
        for name in sorted(distinct_names):
            if name not in registry_set:
                raise ValidationError(
                    "/names", f"事件使用的名称 {name!r} 未在名称表登记"
                )
    elif len(distinct_names) > MAX_NAMES:
        raise ValidationError("/events", f"涉及不同名称数超过上限 {MAX_NAMES}")

    # simulate 固定时间线：slot 必须非递减且至少有一个请求。
    has_request = any(ev.etype == "request" for ev in events)
    if mode == "simulate":
        prev = -1
        for ev in events:
            if ev.slot < prev:
                raise ValidationError(
                    join("/events", ev.index),
                    "simulate 时间线的 slot 必须非递减",
                )
            prev = ev.slot
        if not has_request:
            raise ValidationError("/events", "simulate 至少需要一个 request 事件")

    compare_fields = COMPARE_FIELDS
    cache_a = cache_b = None
    # 默认预算覆盖典型偏序（绝大多数实际交错远小于此）；极端高分支偏序
    # （接近 2^N 个独立理想）在纯 CPython 下枚举成本随理想数线性增长，
    # 用户可用 limits.max_states 显式调高。截断时 truncated=true 且不误报等价。
    max_states = 200_000
    if "limits" in doc and doc["limits"] is not None:
        limits = expect_object(doc["limits"], "/limits", "limits")
        if "max_states" in limits and limits["max_states"] is not None:
            max_states = expect_int(
                limits["max_states"], "/limits/max_states", "max_states"
            )
            if max_states <= 0:
                raise ValidationError("/limits/max_states", "max_states 必须为正数")
    if mode == "compare":
        if "compare_fields" in doc and doc["compare_fields"] is not None:
            raw_fields = expect_list(
                doc["compare_fields"], "/compare_fields", "比较字段"
            )
            chosen: list[str] = []
            for i, item in enumerate(raw_fields):
                text = expect_str(item, join("/compare_fields", i), "比较字段")
                if text not in COMPARE_FIELDS:
                    raise ValidationError(
                        join("/compare_fields", i),
                        f"比较字段必须是 {COMPARE_FIELDS} 之一",
                    )
                if text not in chosen:
                    chosen.append(text)
            if not chosen:
                raise ValidationError("/compare_fields", "比较字段集合不能为空")
            compare_fields = tuple(chosen)
        for side in ("a", "b"):
            key = f"cache_{side}"
            if key not in doc:
                raise ValidationError("/" + key, f"compare 缺少初始缓存依据 {key}")
            entries = _parse_cache(doc[key], "/" + key)
            for j, entry in enumerate(entries):
                p = join(f"/{key}/entries", j)
                if entry.partition not in part_set:
                    raise ValidationError(join(p, "partition"), "分区未在 /partitions 声明")
                gen_key = (entry.partition, entry.generation)
                if gen_key not in upsert_gens:
                    raise ValidationError(
                        join(p, "generation"), "缓存绑定的代次在事件中不存在"
                    )
                # 缓存键是请求起始名；代次内记录可能是该名称的正/负项，
                # 也可能是链上的别名，因此这里只核对记录种类的兼容性。
                src_event = events[upsert_gens[gen_key]]
                rec = src_event.record
                if rec is None:
                    raise ValidationError(
                        join(p, "generation"), "绑定代次的事件不是 upsert"
                    )
                if entry.kind == "negative" and rec.kind != "negative":
                    raise ValidationError(
                        join(p, "kind"), "否定缓存必须绑定否定记录代次"
                    )
                if entry.kind == "positive" and rec.kind == "negative":
                    raise ValidationError(
                        join(p, "kind"), "正项缓存不能绑定否定记录代次"
                    )
            if side == "a":
                cache_a = entries
            else:
                cache_b = entries
        if not has_request:
            raise ValidationError("/events", "compare 至少需要一个 request 事件")

    return Case(
        mode=mode,
        partitions=tuple(partitions),
        names=names_registry,
        events=tuple(events),
        compare_fields=compare_fields,
        cache_a=cache_a,
        cache_b=cache_b,
        max_states=max_states,
    )
