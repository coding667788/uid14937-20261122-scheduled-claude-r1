"""事件溯源的目录视图。

视图只消费合成事件，不做任何真实查询：

* upsert 记录按 ``(分区, 名称)`` 保存最新代次的活动条目；
* revoke 按 ``(分区, 代次)`` 杀掉该代次的记录及信任范围；
* 信任范围以 ``(分区, 后缀, 代次)`` 绑定，按最长后缀选择；
* 准入表按授权 id 维护本轮获批 endpoint；
* 故障窗口按服务身份记录开闭区间。
"""

from __future__ import annotations

from .model import Admission, Event, Record, TrustScope, is_suffix, specificity


class View:
    def __init__(self, partitions: tuple[str, ...]) -> None:
        self.partitions = set(partitions)
        # (partition, name) -> Record（同键仅最新代次存活）
        self.records: dict[tuple[str, str], Record] = {}
        # (partition, name) -> Record（含已失效历史，用于代次溯源）
        self.generations: dict[tuple[str, str], Record] = {}
        # 死亡代次集合 (partition, generation)
        self.dead_generations: set[tuple[str, str]] = set()
        # 信任范围 (partition, suffix, generation) -> TrustScope
        self.scopes: dict[tuple[str, str, str], TrustScope] = {}
        # 已移除/撤销的信任范围代次
        self.dead_scope_generations: set[tuple[str, str]] = set()
        # 授权 id -> Admission
        self.admissions: dict[str, Admission] = {}
        # 打开中的故障窗口 service -> begin_slot
        self.failures: dict[str, int] = {}

    def apply_event(self, event: Event) -> None:
        et = event.etype
        if et == "upsert":
            rec = event.record
            assert rec is not None
            key = (rec.partition, rec.name)
            self.generations[(rec.partition, rec.generation)] = rec
            self.records[key] = rec
        elif et == "revoke":
            assert event.rev_partition is not None and event.rev_generation is not None
            pkey = (event.rev_partition, event.rev_generation)
            self.dead_generations.add(pkey)
            # 若当前正条目属于该代次，撤下正表（历史代次记录保留在 generations）。
            # 信任范围代次是独立命名空间，由 trust_remove 单独管理。
            for key, rec in list(self.records.items()):
                if rec.partition == event.rev_partition and rec.generation == event.rev_generation:
                    del self.records[key]
        elif et == "trust_add":
            scope = event.scope
            assert scope is not None
            self.scopes[(scope.partition, scope.suffix, scope.generation)] = scope
        elif et == "trust_remove":
            assert event.rev_partition is not None and event.remove_generation is not None
            self.dead_scope_generations.add(
                (event.rev_partition, event.remove_generation)
            )
        elif et == "admission_add":
            adm = event.admission
            assert adm is not None
            self.admissions[adm.admission_id] = adm
        elif et == "admission_remove":
            assert event.remove_generation is not None
            self.admissions.pop(event.remove_generation, None)
        elif et == "failure_begin":
            assert event.service is not None
            self.failures[event.service] = event.slot
        elif et == "failure_end":
            assert event.service is not None
            self.failures.pop(event.service, None)
        # request 事件不改变目录视图。

    # ------------------------------------------------------------------ 查询

    def record_generation_dead(self, partition: str, generation: str) -> bool:
        return (partition, generation) in self.dead_generations

    def active_record(self, partition: str, name: str, slot: int) -> Record | None:
        """同分区内查同键的活动记录；不存在、过期或已撤销均返回 None。"""

        rec = self.records.get((partition, name))
        if rec is None:
            return None
        if not rec.is_live_at(slot):
            return None
        if self.record_generation_dead(rec.partition, rec.generation):
            return None
        return rec

    def record_of_generation(
        self, partition: str, generation: str
    ) -> Record | None:
        return self.generations.get((partition, generation))

    def latest_record(self, partition: str, name: str) -> Record | None:
        """同键最新 upsert 的记录（不检查存活/撤销），用于链有效期溯源。"""

        return self.records.get((partition, name))

    def trust_visible(self, partition: str, name: str, slot: int) -> bool:
        """名称在该分区是否存在覆盖它的、活动且未撤销的信任范围。

        取覆盖名称的最长后缀；同长按 order（输入优先级）处理。
        """

        best: TrustScope | None = None
        for (part, suffix, gen), scope in self.scopes.items():
            if part != partition:
                continue
            if (part, gen) in self.dead_scope_generations:
                continue
            if not scope.is_live_at(slot):
                continue
            if not is_suffix(suffix, name):
                continue
            if best is None:
                best = scope
                continue
            cur = specificity(suffix)
            old = specificity(best.suffix)
            if cur > old or (cur == old and scope.order < best.order):
                best = scope
        return best is not None

    def covering_negatives(self, partition: str, name: str, slot: int) -> list[Record]:
        """同分区内覆盖名称的活动否定记录，按后缀具体度降序、同长按输入顺序。"""

        found: list[Record] = []
        for (part, rec_name), rec in self.records.items():
            if part != partition or rec.kind != "negative":
                continue
            if not rec.is_live_at(slot):
                continue
            if self.record_generation_dead(rec.partition, rec.generation):
                continue
            if is_suffix(rec_name, name):
                found.append(rec)
        found.sort(
            key=lambda r: (-specificity(r.name), r.order)
        )
        return found

    def existence_subtrees(
        self, partition: str, suffix: str, slot: int
    ) -> list[str]:
        """同分区内、落在 ``suffix`` 子树中的可信存在证据后缀。

        存在证据 = 活动的 positive/alias 条目名称本身（每个名称代表一个存在点，
        以点分后缀形式参与扣减）。仅统计当前仍被信任范围覆盖的存在点。
        """

        subtrees: list[str] = []
        for (part, name), rec in self.records.items():
            if part != partition or rec.kind not in ("positive", "alias"):
                continue
            if not rec.is_live_at(slot):
                continue
            if self.record_generation_dead(rec.partition, rec.generation):
                continue
            if not is_suffix(suffix, name):
                continue
            if not self.trust_visible(partition, name, slot):
                continue
            subtrees.append(name)
        subtrees.sort()
        return subtrees

    def active_admission(
        self, partition: str, endpoint: str, slot: int
    ) -> Admission | None:
        """终点是否在该分区本轮获批；同长按输入顺序取第一条。"""

        matches = [
            adm
            for adm in self.admissions.values()
            if adm.partition == partition
            and adm.endpoint == endpoint
            and adm.is_live_at(slot)
        ]
        if not matches:
            return None
        matches.sort(key=lambda a: a.order)
        return matches[0]

    def service_in_failure(self, service: str) -> bool:
        return service in self.failures

    def failure_begin_slot(self, service: str) -> int | None:
        return self.failures.get(service)

    def copy(self) -> "View":
        """深拷贝全部事件溯源状态（BFS 每边转移用）。"""

        clone = View(tuple(self.partitions))
        clone.records = dict(self.records)
        clone.generations = dict(self.generations)
        clone.dead_generations = set(self.dead_generations)
        clone.scopes = dict(self.scopes)
        clone.dead_scope_generations = set(self.dead_scope_generations)
        clone.admissions = dict(self.admissions)
        clone.failures = dict(self.failures)
        return clone
