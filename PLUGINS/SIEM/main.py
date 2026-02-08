from datetime import datetime, timedelta

from models import AdaptiveQueryInput, SchemaExplorerInput, KeywordSearchInput, KeywordSearchOutput
from tools import SIEMToolKit


def get_recent_time_range(minutes=5):
    """获取最近N分钟的时间范围，返回ISO 8601格式的字符串"""
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(minutes=minutes)
    return start_time.strftime("%Y-%m-%dT%H:%M:%SZ"), end_time.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_explore_schema():
    toolkit = SIEMToolKit()
    all = toolkit.explore_schema()
    print(all)
    all = toolkit.explore_schema(SchemaExplorerInput(target_index="siem-network-traffic"))
    print(all)


def test_adaptive_query():
    # 获取最近5分钟的时间范围
    toolkit = SIEMToolKit()
    time_range_start, time_range_end = get_recent_time_range(5)

    query_input = AdaptiveQueryInput(
        index_name="siem-network-traffic",
        time_field="@timestamp",  # 这里可以改成任意 Date 类型字段，如 "event.created"
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        filters={
            # "source.ip": "192.168.1.150",
            "host.name": "srv-db-master",
            # "destination.service": "ssh"
        }
    )

    result = toolkit.execute_adaptive_query(query_input)
    print(f"Status: {result.status}")
    print(f"Total Hits: {result.total_hits}")
    print(result.model_dump())
    if result.records:
        # 验证返回数据
        print(f"Sample: {result.records[0]}")

    # query_input = AdaptiveQueryInput(
    #     index_name="siem-network-traffic",
    #     time_range_start=time_range_start,
    #     time_range_end=time_range_end,
    #     filters={
    #         "event.dataset": "network",
    #         "destination.ip": "104.21.11.22",
    #         "event.action": "deny"
    #     }
    # )
    #
    # result = toolkit.execute_adaptive_query(query_input)
    # print(f"Using time field: {query_input.time_field}")
    # print(f"Status: {result.status}")
    # print(f"Total Hits: {result.total_hits}")
    #
    # if result.records:
    #     # 验证返回数据
    #     print(f"Sample: {result.records[0]}")


def test_keyword_search():
    toolkit = SIEMToolKit()
    time_range_start, time_range_end = get_recent_time_range(10)

    input_data = KeywordSearchInput(
        keyword="srv-db-master",
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        # aggregation_fields=["event.action", "source.ip"]
    )
    result: KeywordSearchOutput = toolkit.keyword_search(input_data)
    print(f"Status: {result.status}")
    print(f"Total Hits: {result.total_hits}")

    if result.records:
        # 验证返回数据
        print(f"Sample: {result.records[0]}")


if __name__ == "__main__":
    test_keyword_search()
    # test_adaptive_query()
