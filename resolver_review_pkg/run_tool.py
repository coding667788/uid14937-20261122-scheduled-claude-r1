"""隔离模式启动器。

以 ``python -I run_tool.py <simulate|compare> CASE.json [OUT.json]`` 运行。
``-I``（隔离模式）下解释器不读取 PYTHONPATH、用户站点包或当前目录，
避免数据目录中被植入的 ``json.py`` 等模块被意外导入；本脚本把**受信任的
包目录**（脚本自身所在目录）显式插入 sys.path 后再调用 CLI，数据文件
始终以路径参数传入，不会进入模块搜索路径。
"""

from __future__ import annotations

import os
import sys

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
if _PACKAGE_DIR not in sys.path:
    sys.path.insert(0, _PACKAGE_DIR)

from resolver_review.jsonio import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
