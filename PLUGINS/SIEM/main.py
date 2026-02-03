from models import AdaptiveQueryInput
from tools import SIEMToolKit


def main():
    toolkit = SIEMToolKit()

    print("\n--- Testing Adaptive Query with Custom Time Field ---")

    # 场景：假设我们要过滤 'event.ingested' 字段 (前提是 ES 里有这个 Date 类型的字段)
    # 如果 ES 里没有这个字段，Total Hits 将会是 0
    query_input = AdaptiveQueryInput(
        index_name="siem-aws-cloudtrail",
        time_field="@timestamp",  # 这里可以改成任意 Date 类型字段，如 "event.created"
        time_range_start="2026-02-03T06:00:00Z",
        time_range_end="2026-02-05T07:00:00Z",
        filters={"event.outcome": "success"}
    )

    try:
        result = toolkit.execute_adaptive_query(query_input)
        print(f"Using time field: {query_input.time_field}")
        print(f"Status: {result.status}")
        print(f"Total Hits: {result.total_hits}")

        if result.records:
            # 验证返回数据
            print(f"Sample Timestamp: {result.records[0].get('@timestamp')}")

    except Exception as e:
        print(f"Error: {str(e)}")

    query_input = AdaptiveQueryInput(
        index_name="siem-network-traffic",
        time_range_start="2026-02-03T06:00:00Z",
        time_range_end="2026-02-05T07:00:00Z",
        filters={"event.dataset": "network"}
    )

    result = toolkit.execute_adaptive_query(query_input)
    print(f"Using time field: {query_input.time_field}")
    print(f"Status: {result.status}")
    print(f"Total Hits: {result.total_hits}")

    if result.records:
        # 验证返回数据
        print(f"Sample Timestamp: {result.records[0].get('@timestamp')}")


if __name__ == "__main__":
    main()
