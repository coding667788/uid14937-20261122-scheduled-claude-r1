"""确定性 UTF-8 JSON 读写与命令行入口。"""

from __future__ import annotations

import json
import os
import sys

from .errors import ValidationError
from .validator import parse_case


def load_json(path: str) -> object:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise ValidationError("", f"输入文件不存在: {path}") from exc
    except json.JSONDecodeError as exc:
        pointer = ""
        if exc.doc:
            # 给出行列定位，弥补 JSON 语法阶段没有 JSON Pointer 的问题。
            pointer = f"第 {exc.lineno} 行第 {exc.colno} 列"
        raise ValidationError(pointer, f"JSON 语法错误: {exc.msg}") from exc
    except UnicodeDecodeError as exc:
        raise ValidationError("", f"输入不是合法 UTF-8: {exc}") from exc


def dump_json(payload: object) -> str:
    # sort_keys + 固定分隔符保证可复现；ensure_ascii=False 保留中文可读。
    return json.dumps(
        payload, ensure_ascii=False, indent=2, sort_keys=True, separators=(",", ": ")
    )


USAGE = (
    "用法: python -m resolver_review <simulate|compare> CASE.json [OUT.json]\n"
    "  simulate 按固定逻辑事件序列重放并输出解析路径\n"
    "  compare  验证两套缓存依据在全部允许的事件交错下是否等价\n"
    "  省略 OUT.json 时结果写到标准输出（UTF-8）"
)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) < 2 or args[0] not in ("simulate", "compare"):
        sys.stderr.write(USAGE + "\n")
        return 2
    mode, case_path = args[0], args[1]
    out_path = args[2] if len(args) > 2 else None

    try:
        doc = load_json(case_path)
        case = parse_case(doc, mode)
        if mode == "simulate":
            from .simulate import run_simulate

            payload = run_simulate(case)
        else:
            from .compare import run_compare

            payload = run_compare(case)
    except ValidationError as exc:
        error_payload = {
            "ok": False,
            "error": {"pointer": exc.pointer, "message": exc.message},
        }
        # 显式 UTF-8，避免 Windows 控制台默认代码页导致中文乱码。
        sys.stderr.buffer.write((dump_json(error_payload) + "\n").encode("utf-8"))
        return 1

    text = dump_json({"ok": True, "result": payload})
    if out_path:
        parent = os.path.dirname(os.path.abspath(out_path))
        os.makedirs(parent, exist_ok=True)
        with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text + "\n")
    else:
        sys.stdout.buffer.write(text.encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
