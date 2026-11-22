"""离线解析引擎。

决策码（``decision``）：

``resolved``
    正项链终点 endpoint 且在该分区本轮获批。
``negative_denied``
    被覆盖性否定记录命中（已扣除同分区更具体的可信存在子树的交叠部分）。
``untrusted``
    名称在起始分区没有任何覆盖它的活动信任范围。
``no_record``
    受信任但目录中没有活动记录，或活记录代次已被撤销。
``unadmitted``
    正项终点 endpoint 未在该分区本轮获批。
``alias_cycle``
    多级别名形成闭环，返回最短闭环。

每个决策都带 ``source``：``live`` / ``cache`` / ``stale``。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .cache import Cache, CacheEntry
from .model import (
    Admission,
    Record,
    RequestSpec,
    is_suffix,
)
from .view import View

# 无显式 expires 的记录视为远未来截止；输出稳定的有限整数而非无限。
FAR_FUTURE = 2**31 - 1


@dataclass
class LiveResult:
    decision: str
    source: str
    partition: str
    name: str
    slot: int
    chain: list[str] = field(default_factory=list)
    endpoint: str | None = None
    deadline: int | None = None
    generation: str | None = None
    admission_id: str | None = None
    negative_suffix: str | None = None
    negative_generation: str | None = None
    proof: str | None = None
    remaining_suffix: str | None = None
    subtracted: list[str] = field(default_factory=list)
    cycle: list[str] = field(default_factory=list)
    cache_write: CacheEntry | None = None

    @property
    def cycle_length(self) -> int:
        return len(self.cycle)


class Engine:
    """绑定一个目录视图与一个缓存的解析器。"""

    def __init__(self, view: View, cache: Cache) -> None:
        self.view = view
        self.cache = cache

    def snapshot(self) -> "Engine":
        return Engine(self.view, self.cache.copy())

    # ============================================================== 否定覆盖

    def negative_cover(
        self, partition: str, name: str, slot: int
    ) -> tuple[Record, list[str]] | None:
        """返回命中名称的最具体否定记录，以及被扣减的存在子树列表。

        规则：覆盖性否定遇到同分区更具体的可信存在子树时，仅扣除交叠子树；
        若名称本身落在某个存在子树中（即被完全扣掉），该否定不命中，
        继续考虑更宽的否定；全部否定都被避开则返回 None。
        """

        for neg in self.view.covering_negatives(partition, name, slot):
            subtrees = self.view.existence_subtrees(partition, neg.name, slot)
            covering = [sub for sub in subtrees if is_suffix(sub, name)]
            if covering:
                # 名称被某个更具体的存在子树覆盖，此否定对该名称失效。
                continue
            return neg, subtrees
        return None

    # ============================================================== 活目录

    def live_resolve(self, req: RequestSpec, slot: int) -> LiveResult:
        # 1) 外层服务身份与起始分区的信息访问复核。
        if not self.view.trust_visible(req.partition, req.name, slot):
            return LiveResult(
                decision="untrusted",
                source="live",
                partition=req.partition,
                name=req.name,
                slot=slot,
            )

        # 2) 覆盖性否定（先于条目命中；存在子树已按规则扣减）。
        neg_hit = self.negative_cover(req.partition, req.name, slot)
        if neg_hit is not None:
            neg, subtrees = neg_hit
            result = LiveResult(
                decision="negative_denied",
                source="live",
                partition=req.partition,
                name=req.name,
                slot=slot,
                negative_suffix=neg.name,
                negative_generation=neg.generation,
                proof=neg.proof,
                remaining_suffix=neg.name,
                subtracted=subtrees,
                generation=neg.generation,
                cache_write=CacheEntry(
                    partition=req.partition,
                    name=req.name,
                    kind="negative",
                    generation=neg.generation,
                    # 否定缓存的实际截止：否定记录自身的有效期截止。
                    deadline=neg.expires if neg.expires is not None else FAR_FUTURE,
                    proof=neg.proof,
                ),
            )
            return result

        # 3) 跟随别名链；每一跳都必须在起始分区可见。
        chain: list[str] = []
        seen: dict[str, int] = {}
        current = req.name
        current_rec: Record | None = None
        while True:
            if current in seen:
                cycle = chain[seen[current]:] + [current]
                return LiveResult(
                    decision="alias_cycle",
                    source="live",
                    partition=req.partition,
                    name=req.name,
                    slot=slot,
                    chain=list(chain),
                    cycle=cycle,
                )
            seen[current] = len(chain)
            chain.append(current)
            if not self.view.trust_visible(req.partition, current, slot):
                return LiveResult(
                    decision="untrusted",
                    source="live",
                    partition=req.partition,
                    name=req.name,
                    slot=slot,
                    chain=list(chain),
                )
            rec = self.view.active_record(req.partition, current, slot)
            if rec is None:
                return LiveResult(
                    decision="no_record",
                    source="live",
                    partition=req.partition,
                    name=req.name,
                    slot=slot,
                    chain=list(chain),
                )
            current_rec = rec
            if rec.kind == "negative":
                # 直接命中的否定条目（名称完全相等），同样做存在扣减复核。
                neg_hit = self.negative_cover(req.partition, current, slot)
                if neg_hit is None:
                    return LiveResult(
                        decision="no_record",
                        source="live",
                        partition=req.partition,
                        name=req.name,
                        slot=slot,
                        chain=list(chain),
                    )
                neg, subtrees = neg_hit
                return LiveResult(
                    decision="negative_denied",
                    source="live",
                    partition=req.partition,
                    name=req.name,
                    slot=slot,
                    chain=list(chain),
                    negative_suffix=neg.name,
                    negative_generation=neg.generation,
                    proof=neg.proof,
                    remaining_suffix=neg.name,
                    subtracted=subtrees,
                    generation=neg.generation,
                    cache_write=CacheEntry(
                        partition=req.partition,
                        name=req.name,
                        kind="negative",
                        generation=neg.generation,
                        deadline=neg.expires if neg.expires is not None else FAR_FUTURE,
                        proof=neg.proof,
                    ),
                )
            if rec.kind == "positive":
                break
            # alias -> 继续解析下一跳。
            current = rec.value  # type: ignore[assignment]

        # 4) 正项终点只能交回本分区本轮获批的 endpoint。
        assert current_rec is not None
        endpoint = current_rec.value
        assert endpoint is not None
        admission = self.view.active_admission(req.partition, endpoint, slot)
        if admission is None:
            return LiveResult(
                decision="unadmitted",
                source="live",
                partition=req.partition,
                name=req.name,
                slot=slot,
                chain=list(chain),
                endpoint=endpoint,
                generation=current_rec.generation,
            )

        # 5) 有效期取整条链与授权的最早截止。
        deadline = self._chain_deadline(req.partition, chain, admission)
        return LiveResult(
            decision="resolved",
            source="live",
            partition=req.partition,
            name=req.name,
            slot=slot,
            chain=list(chain),
            endpoint=endpoint,
            deadline=deadline,
            generation=current_rec.generation,
            admission_id=admission.admission_id,
            cache_write=CacheEntry(
                partition=req.partition,
                name=req.name,
                kind="positive",
                generation=current_rec.generation,
                deadline=deadline,
                endpoint=endpoint,
            ),
        )

    def _chain_deadline(
        self,
        partition: str,
        chain: list[str],
        admission: Admission,
    ) -> int:
        """整条别名链与授权的最早截止；无截止时用协议远未来常量。"""

        deadlines: list[int] = []
        for hop in chain:
            rec = self.view.latest_record(partition, hop)
            if rec is not None and rec.expires is not None:
                deadlines.append(rec.expires)
        if admission.expires is not None:
            deadlines.append(admission.expires)
        if not deadlines:
            return FAR_FUTURE
        return min(deadlines)

    # ============================================================== 缓存路径

    def _positive_cache_valid(
        self, entry: CacheEntry, req: RequestSpec, slot: int
    ) -> tuple[bool, Admission | None]:
        """正项缓存当前是否仍可直接交付（撤销/信任/准入/截止逐项复核）。"""

        if self.view.record_generation_dead(entry.partition, entry.generation):
            return False, None
        if not self.view.trust_visible(entry.partition, entry.name, slot):
            return False, None
        if entry.endpoint is None:
            return False, None
        admission = self.view.active_admission(entry.partition, entry.endpoint, slot)
        if admission is None:
            return False, None
        if slot >= entry.deadline:
            return False, admission
        return True, admission

    def _negative_cache_valid(self, entry: CacheEntry, req: RequestSpec, slot: int) -> LiveResult | None:
        """否定缓存复核；返回可直接交付的结果，或 None 表示缓存已失效。"""

        if self.view.record_generation_dead(entry.partition, entry.generation):
            return None
        if not self.view.trust_visible(entry.partition, entry.name, slot):
            return None
        rec = self.view.record_of_generation(entry.partition, entry.generation)
        if rec is None or rec.kind != "negative" or not rec.is_live_at(slot):
            return None
        if slot >= entry.deadline:
            return None
        # 现行否定与存在子树都可能变化：重新计算扣减。
        neg_hit = self.negative_cover(entry.partition, entry.name, slot)
        if neg_hit is None:
            return None
        neg, subtrees = neg_hit
        if neg.generation != entry.generation:
            return None
        return LiveResult(
            decision="negative_denied",
            source="cache",
            partition=req.partition,
            name=req.name,
            slot=slot,
            negative_suffix=neg.name,
            negative_generation=neg.generation,
            proof=entry.proof,
            remaining_suffix=neg.name,
            subtracted=subtrees,
            generation=neg.generation,
        )

    def _stale_result(
        self, entry: CacheEntry, req: RequestSpec, slot: int
    ) -> LiveResult | None:
        """故障期间的限时旧正项兜底。"""

        stale_cfg = req.stale
        if stale_cfg is None or not stale_cfg.enabled:
            return None
        # 现行否定始终禁止兜底。
        if self.negative_cover(req.partition, req.name, slot) is not None:
            return None
        # 撤销始终禁止兜底。
        if self.view.record_generation_dead(entry.partition, entry.generation):
            return None
        if entry.endpoint is None:
            return None
        # 原链的当前信任范围仍有效：起始名与终点都可见。
        if not self.view.trust_visible(entry.partition, entry.name, slot):
            return None
        admission = self.view.active_admission(entry.partition, entry.endpoint, slot)
        if admission is None:
            return None
        # 必须处于该服务的故障窗口，且旧正项仍在限时宽限内。
        if not self.view.service_in_failure(req.service):
            return None
        if slot > entry.deadline + stale_cfg.extra_slots:
            return None
        return LiveResult(
            decision="resolved",
            source="stale",
            partition=req.partition,
            name=req.name,
            slot=slot,
            chain=[entry.name],
            endpoint=entry.endpoint,
            deadline=entry.deadline + stale_cfg.extra_slots,
            generation=entry.generation,
            admission_id=admission.admission_id,
        )

    def query(self, req: RequestSpec, slot: int, use_cache: bool = True) -> LiveResult:
        """执行一次请求：先缓存，再活目录，必要时按故障规则走旧正项兜底。"""

        entry = self.cache.get(req.partition, req.name) if use_cache else None

        if entry is not None and entry.kind == "positive":
            valid, admission = self._positive_cache_valid(entry, req, slot)
            if valid:
                assert admission is not None and entry.endpoint is not None
                return LiveResult(
                    decision="resolved",
                    source="cache",
                    partition=req.partition,
                    name=req.name,
                    slot=slot,
                    chain=[entry.name],
                    endpoint=entry.endpoint,
                    deadline=entry.deadline,
                    generation=entry.generation,
                    admission_id=admission.admission_id,
                )
            # 缓存不可直接交付：先跑活目录，明确不可用时再评估限时旧正项。
            live_fallback = self.live_resolve(req, slot)
            if live_fallback.decision != "resolved":
                stale = self._stale_result(entry, req, slot)
                if stale is not None:
                    # 兜底只限时放行，不重写缓存。
                    return stale
            self._commit(live_fallback)
            return live_fallback

        if entry is not None and entry.kind == "negative":
            cached = self._negative_cache_valid(entry, req, slot)
            if cached is not None:
                return cached
            # 现行否定及撤销始终禁止兜底：否定缓存失效即删除，转活目录。
            self.cache.remove(entry.partition, entry.name)

        result = self.live_resolve(req, slot)
        self._commit(result)
        return result

    # ------------------------------------------------------------------ 内部

    def _commit(self, result: LiveResult) -> None:
        if result.cache_write is not None:
            self.cache.put(result.cache_write)
