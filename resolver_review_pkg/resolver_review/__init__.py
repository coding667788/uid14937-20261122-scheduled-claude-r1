"""resolver_review

离线内网分区目录解析复核工具（纯标准库实现）。

子模块：
  model      名称后缀代数与不可变数据模型
  validator  带 JSON Pointer 的输入校验
  view       目录视图（代次、信任范围、准入、故障窗口）
  cache      缓存条目模型
  resolve    单步解析引擎（活目录 / 缓存 / 限时旧正项兜底）
  simulate   固定逻辑时间线模拟
  compare    偏序事件理想（ideal）位掩码 BFS 对比
  jsonio     确定性 UTF-8 JSON 读写
"""

__version__ = "1.0.0"
