"""输入校验错误模型。

每个错误都携带一个 RFC 6901 风格的 JSON Pointer（相对 CASE 根），
使输入结构错误可以被精确定位到字段。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationError(Exception):
    """结构化输入错误。``pointer`` 形如 ``/events/3/after/2``。"""

    pointer: str
    message: str

    def __str__(self) -> str:  # pragma: no cover - 仅用于未包装的兜底显示
        return f"{self.pointer}: {self.message}"

    def to_dict(self) -> dict:
        return {"pointer": self.pointer, "message": self.message}


def join(pointer: str, segment: object) -> str:
    """在 JSON Pointer 后追加一个段（正确转义 ``~`` 与 ``/``）。"""

    text = str(segment)
    text = text.replace("~", "~0").replace("/", "~1")
    return f"{pointer}/{text}"


def type_name(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def expect_object(value: object, pointer: str, what: str = "对象") -> dict:
    if not isinstance(value, dict):
        raise ValidationError(
            pointer, f"{what}必须是 object，实际为 {type_name(value)}"
        )
    return value


def require_fields(obj: dict, fields: tuple[str, ...], pointer: str) -> None:
    for field in fields:
        if field not in obj:
            raise ValidationError(join(pointer, field), "缺少必填字段")


def expect_int(value: object, pointer: str, what: str = "字段") -> int:
    # bool 是 int 的子类，显式拒绝。
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(pointer, f"{what}必须是整数，实际为 {type_name(value)}")
    return value


def expect_str(value: object, pointer: str, what: str = "字段") -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(pointer, f"{what}必须是非空字符串，实际为 {type_name(value)}")
    return value


def expect_bool(value: object, pointer: str, what: str = "字段") -> bool:
    if not isinstance(value, bool):
        raise ValidationError(pointer, f"{what}必须是布尔值，实际为 {type_name(value)}")
    return value


def expect_list(value: object, pointer: str, what: str = "字段") -> list:
    if not isinstance(value, list):
        raise ValidationError(pointer, f"{what}必须是数组，实际为 {type_name(value)}")
    return value
