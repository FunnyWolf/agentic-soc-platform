from datetime import datetime, timedelta

from models import AdaptiveQueryInput, SchemaExplorerInput
from tools import SIEMToolKit


def get_recent_time_range(minutes=5):
    """获取最近N分钟的时间范围，返回ISO 8601格式的字符串"""
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(minutes=minutes)
    return start_time.strftime("%Y-%m-%dT%H:%M:%SZ"), end_time.strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    toolkit = SIEMToolKit()
    all = toolkit.explore_schema()
    print(all)
    all = toolkit.explore_schema(SchemaExplorerInput(target_index="siem-aws-cloudtrail"))
    print(all)

    # 获取最近5分钟的时间范围
    time_range_start, time_range_end = get_recent_time_range(5)

    query_input = AdaptiveQueryInput(
        index_name="siem-aws-cloudtrail",
        time_field="@timestamp",  # 这里可以改成任意 Date 类型字段，如 "event.created"
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        filters={
            "event.outcome": "success",
            "user.name": "user_002"
        }
    )

    result = toolkit.execute_adaptive_query(query_input)
    print(f"Using time field: {query_input.time_field}")
    print(f"Status: {result.status}")
    print(f"Total Hits: {result.total_hits}")

    if result.records:
        # 验证返回数据
        print(f"Sample: {result.records[0]}")

    query_input = AdaptiveQueryInput(
        index_name="siem-network-traffic",
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        filters={
            "event.dataset": "network",
            "destination.ip": "104.21.11.22",
            "event.action": "deny"
        }
    )

    result = toolkit.execute_adaptive_query(query_input)
    print(f"Using time field: {query_input.time_field}")
    print(f"Status: {result.status}")
    print(f"Total Hits: {result.total_hits}")

    if result.records:
        # 验证返回数据
        print(f"Sample: {result.records[0]}")


if __name__ == "__main__":
    main()
