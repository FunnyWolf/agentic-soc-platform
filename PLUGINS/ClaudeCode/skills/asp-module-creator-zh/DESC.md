skill是用来创建 ASP module 的工具,ASP的module是一个独立的python脚本,放在ASP的MODULES目录下
可以参考 `MODULES/Cloud-01-AWS-IAM-Privilege-Escalation-via-AttachUserPolicy.py` 这个模块的实现,来创建你自己的模块
ArtifactModel/AlertModel//CaseModel等数据模型在 `PLUGINS/SIRP/sirpcoremodel.py`
硬性限制:

脚本中必须满足如下框架

```python


from Lib.basemodule import BaseModule


class Module(BaseModule):
    def __init__(self):
        super().__init__()

    def run(self):
        # 获取原始告警JSON
        raw_alert = self.read_message()

        # 自定义处理逻辑
        ...
        return True
```

及必须定义名为Module的类,该类必须继承自BaseModule,并且必须实现run方法,run方法是模块的入口,当模块被调用时,会执行run方法中的逻辑.
模块通过self.read_message()方法从以模块名称为stream_name的redis stream中获取读取一条dict格式原始告警(例如样例模块就是从"
Cloud-01-AWS-IAM-Privilege-Escalation-via-AttachUserPolicy"的stream中读取)

读取到原始告警后通常使用如下步骤进行处理:

- 对原始告警进行解析,尽量提取出有用的字段
- 在原始告警数据中提取artifact,articat作为最小实体,是后续调查的基础,数据模型参考ArtifactModel
- 计算correlation_uid,相同correlation_uid的告警会聚合成一个case

```python
        correlation_uid = Correlation.generate_correlation_uid(
            rule_id=self.module_name,
            time_window="24h",
            keys=[principal_user, target_user, account_id],
            timestamp=event_time_formatted
        )
```
如上代码所示,correlation_uid的生成需要提供rule_id(通常使用模块名称),time_window(通常使用24h),keys(一个列表,包含一些字符串,相同的keys会被聚合到一起),timestamp(一个时间戳,通常是事件发生的时间).
通过correlation_uid即可将Cloud-01-AWS-IAM-Privilege-Escalation-via-AttachUserPolicy规则产生的告警,拥有相同 principal_user, target_user, account_id,24h之内的告警聚合到一个Case中

- 组装 AlertModel ,将从原始告警中提取到的字段尽可能的映射到AlertModel中,如果AlertModel中有字段缺失,可以尝试是否可以通过原始告警中的字段计算或者转换得到,如果前两部仍然有AlertModel字段缺失,则使用默认值.没有特殊情况AlertModel.raw_data存储原始告警的json格式内容,AlertModel.unmapped字段存储没有mapping到ArtifactModel,AlertModel的内容
- 将artifacts挂载到AlertModel.artifacts,调用Alert.create创建告警,函数会自动创建artifacts记录,并获取到的row_id列表赋值给AlertModel.artifacts,然后再创建alert记录
- 创建case,使用correlation_uid搜索是否已有case,有的话将alert的row_id挂载到case的alerts上,然后更新case