"""取证证据接收系统（Evidence Intake）。

分模块说明：

* ``config``    —— 运行配置（数据目录、大小上限等）
* ``errors``    —— 领域错误类型
* ``security``  —— 路径校验与安全分块解压
* ``manifest``  —— JSON 清单解析
* ``storage``   —— SQLite 持久化与原子版本发布
* ``samples``   —— 页面演示用正常/恶意样例
* ``main``      —— FastAPI 入口
"""
