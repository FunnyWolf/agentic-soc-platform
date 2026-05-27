import logging
from typing import Any, Dict

from fastapi import FastAPI, Request

from PLUGINS.Forwarder.models import SplunkPayload, KibanaPayload
from PLUGINS.Redis.redis_stream_api import RedisStreamAPI

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI()


def _normalize_hit_value(value):
    if isinstance(value, dict):
        if set(value.keys()) == {"keyword"}:
            return _normalize_hit_value(value.get("keyword"))
        return {k: _normalize_hit_value(v) for k, v in value.items() if not k.endswith(".keyword")}
    if isinstance(value, list):
        return [_normalize_hit_value(item) for item in value]
    return value


def _extract_source(hit: Dict[str, Any]) -> Dict[str, Any]:
    source = hit.get('_source') if isinstance(hit.get('_source'), dict) else hit
    source = _normalize_hit_value(source)
    return source if isinstance(source, dict) else {}


@app.get("/")
async def root():
    return {"message": "Webhook Forwarder is running"}


@app.post("/api/v1/webhook/splunk")
async def webhook_splunk(request: Request):
    """
    Receives a webhook from Splunk, sends the 'result' to a Redis stream
    named after the 'search_name'.
    """
    try:
        body = await request.json()
        logging.debug(f"Splunk webhook raw payload: {body}")
        payload = SplunkPayload.model_validate(body)
        redis_stream_api = RedisStreamAPI()
        redis_stream_api.send_message(payload.search_name, payload.result)
        logging.debug("Message sent to Redis stream")
        return {"status": "success", "message": "Message sent to Redis stream"}
    except Exception as e:
        logging.exception(e)
        return {"status": "error", "message": str(e)}


@app.post("/api/v1/webhook/kibana")
async def webhook_kibana(request: Request):
    """
    Receives a webhook from Kibana, iterates through hits, and sends
    each '_source' to a Redis stream named after the rule name.
    """
    try:
        body = await request.json()
        logging.debug(f"Kibana webhook raw payload: {body}")
        payload = KibanaPayload.model_validate(body)
        rule_name = payload.rule.name
        hits = payload.context.hits
        logging.debug(f"Kibana webhook received for rule: {rule_name}, with {len(hits)} hits")
        redis_stream_api = RedisStreamAPI()
        for hit in hits:
            _source = _extract_source(hit)
            logging.debug(f"Processing hit for rule: {rule_name}")
            redis_stream_api.send_message(rule_name, _source)
            logging.debug("Message sent to Redis stream")
        return {"status": "success", "message": f"{len(hits)} messages sent to Redis stream"}
    except Exception as e:
        logging.exception(e)
        return {"status": "error", "message": str(e)}
