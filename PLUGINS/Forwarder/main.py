import logging

from fastapi import FastAPI, Request

from PLUGINS.Forwarder import CONFIG
from PLUGINS.Forwarder.models import SplunkPayload, KibanaPayload
from PLUGINS.Redis.redis_stream_api import RedisStreamAPI

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Webhook Forwarder is running"}


@app.post("/api/v1/webhook/splunk")
async def webhook_splunk(payload: SplunkPayload):
    """
    Receives a webhook from Splunk, sends the 'result' to a Redis stream
    named after the 'search_name'.
    """
    try:
        logging.debug(f"Splunk webhook received for search_name: {payload.search_name}")
        redis_stream_api = RedisStreamAPI()
        redis_stream_api.send_message(payload.search_name, payload.result)
        logging.debug("Message sent to Redis stream")
        return {"status": "success", "message": "Message sent to Redis stream"}
    except Exception as e:
        logging.exception(e)
        return {"status": "error", "message": str(e)}


@app.post("/api/v1/webhook/kibana")
async def webhook_kibana(payload: KibanaPayload):
    """
    Receives a webhook from Kibana, iterates through hits, and sends
    each '_source' to a Redis stream named after the rule name.
    """
    try:
        rule_name = payload.rule.name
        hits = payload.context.hits
        logging.debug(f"Kibana webhook received for rule: {rule_name}, with {len(hits)} hits")
        redis_stream_api = RedisStreamAPI()
        for hit in hits:
            _source = hit.pop('_source', {})
            logging.debug(f"Processing hit for rule: {rule_name}")
            redis_stream_api.send_message(rule_name, _source)
            logging.debug("Message sent to Redis stream")
        return {"status": "success", "message": f"{len(hits)} messages sent to Redis stream"}
    except Exception as e:
        logging.exception(e)
        return {"status": "error", "message": str(e)}


@app.post("/api/v1/webhook/nocolymail")
async def webhook_nocolymail(request: Request):
    """
    Receives a webhook from NocolyMail and logs the data.
    """
    try:
        data = await request.json()
        logging.info(f"NocolyMail webhook received: {data}")
        # Currently, this endpoint only logs the data.
        # If sending to Redis is needed in the future, the logic can be added here.
        # For example:
        # redis_stream_api = RedisStreamAPI()
        # stream_name = "nocolymail_events" # Or derive from data
        # redis_stream_api.send_message(stream_name, data)
        return {"status": "success", "message": "Data logged"}
    except Exception as e:
        logging.exception(e)
        return {"status": "error", "message": str(e)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=CONFIG.APP_HOST, port=CONFIG.APP_PORT)
