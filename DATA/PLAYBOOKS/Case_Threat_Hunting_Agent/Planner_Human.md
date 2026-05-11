# 当前调查状态回顾

请根据以下信息,生成下一步的调查计划.

### 案件原始信息

{case}

### "作战目标"

<hunting_objective>{hunting_objective}</hunting_objective>

### 当前迭代轮次

<iteration_count>{iteration_count}</iteration_count>

### 历史"调查发现"

以下是迄今为止收集到的所有调查发现、问题及结论：

<findings>{findings}</findings>

### 其他信息

<additional_info>
{additional_info}
</additional_info>

---

**核心任务**:

综合上述所有信息("案件原始信息"、"作战目标"、"当前迭代轮次"以及**特别是**"调查发现"),请判断：

1. 是否需要进行进一步调查来实现"作战目标"？
2. 如果需要,下一步最合理、最有效且可并行执行的调查问题是什么？

如果"作战目标"已达成,或者无法进行进一步调查,请返回一个空计划(`current_plan` 为空列表).

**请严格遵循系统提示中定义的JSON格式进行输出.**
