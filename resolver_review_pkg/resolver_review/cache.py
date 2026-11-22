"""缓存条目与缓存容器。

缓存键固定为 ``(起始分区, 名称)``：信息访问以“外层请求的服务身份和起始分区”
复核，因此正项与否定项都不得跨分区命中。每个键至多保留一条条目，
新写入覆盖旧条目（绑定代次随之更换，天然禁止复用旧代次）。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CacheEntry:
    partition: str
    name: str
    kind: str  # 'positive' | 'negative'
    generation: str
    deadline: int
    proof: str | None = None
    endpoint: str | None = None

    def to_dict(self) -> dict:
        data = {
            "partition": self.partition,
            "name": self.name,
            "kind": self.kind,
            "generation": self.generation,
            "deadline": self.deadline,
        }
        if self.proof is not None:
            data["proof"] = self.proof
        if self.endpoint is not None:
            data["endpoint"] = self.endpoint
        return data


class Cache:
    """按 (partition, name) 键控的可复制缓存。"""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], CacheEntry] = {}

    @classmethod
    def from_entries(cls, entries: tuple[CacheEntry, ...] | list[CacheEntry]) -> "Cache":
        cache = cls()
        for entry in entries:
            cache.put(entry)
        return cache

    def get(self, partition: str, name: str) -> CacheEntry | None:
        return self._entries.get((partition, name))

    def remove(self, partition: str, name: str) -> None:
        self._entries.pop((partition, name), None)

    def put(self, entry: CacheEntry) -> None:
        self._entries[(entry.partition, entry.name)] = entry

    def invalidate_generation(self, partition: str, generation: str) -> int:
        """撤销生效：删除该分区该代次绑定的全部缓存（正项与否定项）。"""

        dead = [
            key
            for key, entry in self._entries.items()
            if entry.partition == partition and entry.generation == generation
        ]
        for key in dead:
            del self._entries[key]
        return len(dead)

    def copy(self) -> "Cache":
        clone = Cache()
        clone._entries = dict(self._entries)
        return clone

    def snapshot(self) -> list[dict]:
        return [
            self._entries[key].to_dict()
            for key in sorted(self._entries, key=lambda k: (k[0], k[1]))
        ]

    def state_key(self) -> tuple:
        return tuple(
            (p, n, e.kind, e.generation, e.deadline, e.proof or "", e.endpoint or "")
            for (p, n), e in sorted(self._entries.items())
        )

    def immutable_key(self) -> frozenset:
        """可哈希的增量键：条目本身是 frozen dataclass，可直接入 frozenset。

        相比 state_key 省去每次排序，适合 BFS 中每状态一次的高频去重。
        """

        return frozenset(self._entries.values())

    def __len__(self) -> int:
        return len(self._entries)
