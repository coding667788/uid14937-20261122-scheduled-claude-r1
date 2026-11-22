"""名称/后缀代数与不可变事件数据模型。

名称是点分小写标签序列（如 ``db.internal``）。后缀 ``s`` 覆盖名称 ``n``
当且仅当 ``s`` 为根（空串）、``s == n`` 或 ``n`` 以 ``.s`` 结尾。
更长的后缀匹配更具体；同长度且同时覆盖同一名称的两个后缀必为同一字符串，
因此“同长按输入优先级”只可能在显式 scope/准入等并列字段中出现，由 order 决定。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_LABEL_RE = re.compile(r"^[a-z0-9_-]+$")
ROOT_SUFFIX = ""


def normalize_label(value: str) -> str:
    """规范化标签：仅小写、点分、每段非空且只含 [a-z0-9_-]。"""

    if value != value.strip():
        raise ValueError("标签首尾不允许空白")
    lowered = value.lower()
    if lowered == ROOT_SUFFIX:
        return ROOT_SUFFIX
    segments = lowered.split(".")
    for segment in segments:
        if not segment:
            raise ValueError(f"标签含空段: {value!r}")
        if not _LABEL_RE.match(segment):
            raise ValueError(f"标签含非法字符: {value!r}")
    return lowered


def split_label(value: str) -> tuple[str, ...]:
    if value == ROOT_SUFFIX:
        return ()
    return tuple(value.split("."))


def is_suffix(suffix: str, name: str) -> bool:
    """``suffix`` 是否覆盖 ``name``（根后缀覆盖一切）。"""

    if suffix == ROOT_SUFFIX:
        return True
    return suffix == name or name.endswith("." + suffix)


def specificity(suffix: str) -> int:
    """后缀的标签深度；根为 0，值越大越具体。"""

    return len(split_label(suffix))


@dataclass(frozen=True)
class Record:
    """upsert 产生的目录条目（正项 / 别名 / 带证明否定项）。"""

    kind: str  # 'positive' | 'alias' | 'negative'
    partition: str
    name: str
    generation: str
    order: int
    expires: int | None = None
    value: str | None = None  # positive: endpoint；alias: 下一名称
    proof: str | None = None  # negative: 证明标识

    def is_live_at(self, slot: int) -> bool:
        return self.expires is None or slot < self.expires


@dataclass(frozen=True)
class TrustScope:
    """信任范围条目：分区 + 名称后缀 + 目录代次绑定。"""

    partition: str
    suffix: str
    generation: str
    order: int
    expires: int | None = None
    active: bool = True

    def is_live_at(self, slot: int) -> bool:
        return self.active and (self.expires is None or slot < self.expires)


@dataclass(frozen=True)
class Admission:
    """本轮获批 endpoint 的授权依据。"""

    admission_id: str
    endpoint: str
    partition: str
    generation: str
    order: int
    expires: int | None = None
    active: bool = True

    def is_live_at(self, slot: int) -> bool:
        return self.active and (self.expires is None or slot < self.expires)


@dataclass(frozen=True)
class StaleConfig:
    """故障期间限时旧正项兜底参数（挂在请求上）。"""

    extra_slots: int
    enabled: bool = True


@dataclass(frozen=True)
class RequestSpec:
    """一次解析请求（外层服务身份 + 起始分区 + 起始名称）。"""

    name: str
    service: str
    partition: str
    order: int
    lo: int | None = None      # 仅 compare 窗口使用
    hi: int | None = None      # 仅 compare 窗口使用
    stale: StaleConfig | None = None


@dataclass(frozen=True)
class Event:
    """逻辑事件序列中的一个事件。

    etype 取值：
      upsert / revoke / trust_add / trust_remove /
      admission_add / admission_remove /
      failure_begin / failure_end / request
    """

    id: str
    index: int
    slot: int
    etype: str
    after: tuple[str, ...] = field(default_factory=tuple)
    record: Record | None = None
    rev_partition: str | None = None
    rev_generation: str | None = None
    scope: TrustScope | None = None
    remove_generation: str | None = None
    admission: Admission | None = None
    service: str | None = None
    request: RequestSpec | None = None
