import atexit
import json
import logging
from datetime import datetime, timedelta, UTC
from typing import Dict, Any

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from PLUGINS.ELK.CONFIG import ACTION_INDEX_NAME, POLL_INTERVAL_MINUTES
from PLUGINS.ELK.client import ELKClient
from PLUGINS.Redis.redis_stream_api import RedisStreamAPI

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SIEMAlertProcessor:
    def __init__(self):
        self.elk_client = ELKClient.get_client()
        self.redis_stream_api = RedisStreamAPI()
        self.scheduler = BackgroundScheduler()
        self.last_check_time = None

    def start_monitoring(self):
        trigger = IntervalTrigger(minutes=POLL_INTERVAL_MINUTES)
        self.scheduler.add_job(
            func=self.process_alerts,
            trigger=trigger,
            id='siem_alert_processor',
            name='Process SIEM alerts every minute',
            replace_existing=True
        )
        self.scheduler.start()
        logger.info("SIEM Alert monitoring started - checking every 1 minute")
        atexit.register(lambda: self.scheduler.shutdown())

    def process_alerts(self):
        try:
            current_time = datetime.now(UTC)
            if self.last_check_time is None:
                self.last_check_time = current_time - timedelta(minutes=POLL_INTERVAL_MINUTES)

            start_time = self.last_check_time.replace(microsecond=0).isoformat().replace('+00:00', 'Z')
            end_time = current_time.replace(microsecond=0).isoformat().replace('+00:00', 'Z')

            query_body = {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time,
                                    "lt": end_time
                                }
                            }
                        }
                    ]
                }
            }

            response = self.elk_client.search(
                index=ACTION_INDEX_NAME,
                query=query_body,
                size=1000,
                sort=[{"@timestamp": {"order": "asc"}}]
            )

            alerts = response.get("hits", {}).get("hits", [])
            processed_count = 0

            for alert_hit in alerts:
                alert_data = alert_hit.get("_source", {})
                if self._process_single_alert(alert_data):
                    processed_count += 1

            if processed_count > 0:
                logger.info(f"Processed {processed_count} alerts from siem_alert index")

            self.last_check_time = current_time

        except Exception as e:
            logger.exception(f"Error processing alerts: {e}")

    def _process_single_alert(self, alert_data: Dict[str, Any]) -> bool:
        try:
            rule_name = alert_data.get("rule", {}).get("name")
            hits = alert_data.get("context", {}).get("hits", [])
            hits = json.loads(hits)
            if not rule_name:
                logger.warning("Alert missing rule name, skipping")
                return False

            if not hits:
                logger.warning(f"Alert {rule_name} has no hits, skipping")
                return False

            for hit in hits:
                if isinstance(hit, dict):
                    _source = hit.pop('_source', {}) if '_source' in hit else hit
                    logger.debug(f"Processing hit for rule: {rule_name}")
                    self.redis_stream_api.send_message(rule_name, _source)
                    logger.debug("Message sent to Redis stream")

            return True

        except Exception as e:
            logger.exception(f"Error processing single alert: {e}")
            return False

    def stop_monitoring(self):
        if self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("SIEM Alert monitoring stopped")


processor = None


def start_alert_processor():
    global processor
    if processor is None:
        processor = SIEMAlertProcessor()
        processor.start_monitoring()
    return processor


def stop_alert_processor():
    global processor
    if processor is not None:
        processor.stop_monitoring()
        processor = None


if __name__ == "__main__":
    processor = start_alert_processor()
    try:
        import time

        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        stop_alert_processor()
        logger.info("Alert processor stopped by user")
