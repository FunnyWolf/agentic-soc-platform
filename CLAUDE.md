- python 可以使用 .venv/Script/python.exe

项目架构:
├── ASP/                  # Django 项目配置
│   ├── settings.py       # 全局配置
│   ├── urls.py           # 路由定义
│   ├── wsgi.py           # WSGI 入口
│   └── asgi.py           # ASGI 入口
├── Core/                 # Django 应用: 用户认证
│   ├── bootstrap.py      # 启动初始化
│   ├── models.py         # 数据模型
│   ├── views.py          # 视图
│   └── Handle/           # 认证处理器
│       ├── baseauth.py   # 基础认证
│       ├── currentuser.py # 当前用户
│       └── user.py       # 用户管理
├── Lib/                  # 核心框架库
│   ├── basemodule.py     # Module 基类, 包含 Correlation 关联逻辑
│   ├── baseplaybook.py   # Playbook 基类, 继承 BaseAPI
│   ├── baseapi.py        # API 抽象基类, 提供模块名获取等通用方法
│   ├── baseview.py       # DRF ViewSet 基类, 封装 CRUD 操作
│   ├── moduleengine.py   # Module 执行引擎, 负责加载与运行 Module
│   ├── playbookloader.py # Playbook 加载器, 动态发现与加载 Playbook 类
│   ├── threadmodulemanager.py # 线程管理器, 管理 Module/Playbook 线程生命周期
│   ├── configs.py        # 全局配置常量 (Redis consumer group 等)
│   ├── log.py            # 日志配置
│   ├── monitor.py        # MainMonitor, 监听 Playbook 任务完成事件
│   ├── analysis.py       # 分析数据模型 (AffectedAsset, AttackChainStep 等)
│   ├── api.py            # 工具函数 (时间戳转换等)
│   ├── customexception.py # 自定义异常 (LLMModuleException 等) 及异常处理器
│   └── xcache.py         # Xcache 缓存封装 (SIRP 字段/Token 缓存)
├── MODULES/              # 安全检测模块 (告警消费与聚合)
│   ├── Cloud-01-AWS-IAM-Privilege-Escalation-via-AttachUserPolicy.py
│   ├── EDR-01-HOST-Vssadmin-Delete-Shadows.py
│   └── Mail-01-User-Report-Phishing-Mail.py
├── PLAYBOOKS/            # 调查剧本 (一键执行)
│   ├── Investigation.py  # 案件调查
│   ├── Knowledge_Extraction.py # 知识提取
│   └── Threat_Intelligence_Enrichment.py # 威胁情报补充
├── PLUGINS/              # 集成插件
│   ├── AlienVaultOTX/    # AlienVault OTX 威胁情报
│   │   └── alienvaultotx.py
│   ├── CMDB/             # CMDB 资产管理
│   │   └── tools.py
│   ├── ELK/              # Elasticsearch 集成
│   │   ├── client.py     # ES 客户端
│   │   └── index_action.py # 索引操作
│   ├── Forwarder/        # 告警转发
│   │   ├── main.py       # 转发逻辑
│   │   └── models.py     # 数据模型
│   ├── LLM/              # LLM 大模型集成
│   │   └── llmapi.py     # LLM API 调用
│   ├── MCP/              # MCP 服务器
│   │   ├── mcpserver.py  # MCP 服务端
│   │   └── llmfunc.py    # LLM 函数绑定
│   ├── Mock/             # Mock 测试用
│   ├── Redis/            # Redis 客户端
│   │   ├── redis_client.py # Redis 连接
│   │   └── redis_stream_api.py # Stream API
│   ├── SIEM/             # 统一 SIEM 接口 (ELK/Splunk)
│   │   ├── backends.py   # 后端实现
│   │   ├── query_builders.py # 查询构建
│   │   ├── data_extractors.py # 数据提取
│   │   ├── tools.py      # 工具函数
│   │   ├── models.py     # 数据模型
│   │   ├── registry.py   # 后端注册
│   │   ├── response.py   # 响应处理
│   │   └── time_utils.py # 时间工具
│   ├── SIRP/             # SIRP 安全编排平台
│   │   ├── sirpapi.py    # SIRP API
│   │   ├── nocolyapi.py  # Nocoly API
│   │   └── *model.py     # 数据模型组
│   ├── Splunk/           # Splunk 集成
│   │   └── client.py     # Splunk 客户端
│   └── ThreatIntelligence/ # 威胁情报聚合
│       ├── tools.py      # TI 工具
│       └── models.py     # 数据模型
├── Docker/               # Docker 配置与资源
│   ├── DB/               # SQLite 数据库
│   ├── IMG/              # 文档图片
│   ├── Log/              # 日志文件
│   ├── Ollama/           # Ollama 本地 LLM 配置
│   ├── RedisStack/       # Redis docker-compose
│   ├── SIRP/             # SIRP 配置
│   └── Uvicorn/          # Uvicorn ASGI 配置
├── DATA/                 # 数据文件
├── manage.py             # Django 入口
└── pyproject.toml        # 项目依赖 (uv)
