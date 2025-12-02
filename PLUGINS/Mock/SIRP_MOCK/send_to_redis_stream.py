from Docker.mock.SIRP_MOCK.alert import get_mock_alerts
from Lib.api import generate_four_random_timestamps
from Lib.redis_stream_api import RedisStreamAPI

if __name__ == "__main__":

    alert_list = get_mock_alerts()

    for alert in alert_list:
        default_times = generate_four_random_timestamps()
        alert_date = default_times["alert_date"]
        created_date = default_times["created_date"]
        acknowledged_date = default_times["acknowledged_date"]
        closed_date = default_times["closed_date"]
        alert["alert_date"] = alert_date
        alert_name = alert.get("rule_id", "default_stream")
        redis_stream_api = RedisStreamAPI()
        redis_stream_api.send_message(alert_name, alert)
