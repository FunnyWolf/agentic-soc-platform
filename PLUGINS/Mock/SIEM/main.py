import json
import random
import time

import httpx

import config as secrets
import settings
from generator import NetworkGenerator, HostGenerator, CloudGenerator
from scenarios import BruteForceScenario, SqlInjectionScenario, RansomwareScenario, CloudPrivilegeEscalationScenario


# --- 发送器类 (同步版本) ---
class ELKSender:
    def __init__(self):
        self.url = f"{secrets.ELK_HOST}/_bulk"
        self.auth = (secrets.ELK_USER, secrets.ELK_PASS)

    def send(self, batch, index_name):
        payload = ""
        for doc in batch:
            payload += json.dumps({"index": {"_index": index_name}}) + "\n"
            payload += json.dumps(doc) + "\n"

        with httpx.Client(verify=False) as client:
            resp = client.post(
                self.url,
                content=payload,
                auth=self.auth,
                headers={"Content-Type": "application/x-ndjson"}
            )
            if resp.status_code >= 400:
                raise Exception(f"ELK Error: {resp.text}")


class SplunkSender:
    def __init__(self):
        self.url = secrets.SPLUNK_HEC_URL
        self.headers = {"Authorization": f"Splunk {secrets.SPLUNK_TOKEN}"}

    def send(self, batch, index_name):
        payload = "".join([json.dumps({"event": doc, "index": index_name}) for doc in batch])
        with httpx.Client(verify=False) as client:
            resp = client.post(self.url, content=payload, headers=self.headers)
            if resp.status_code >= 400:
                raise Exception(f"Splunk Error: {resp.text}")


# --- 核心引擎 ---
def run_engine(generators, senders, scenario_list=None):
    """
    generators: dict { index_name: generator_instance }
    senders: list [sender_instances]
    scenario_list: list [scenario_classes]
    """
    print(f"Simulation engine started. Targets: {[s.__class__.__name__ for s in senders]}")

    while True:
        for index_name, gen in generators.items():
            # 1. 生成基础批次
            batch = [gen.generate() for _ in range(settings.BATCH_SIZE)]

            # 2. 注入异常场景 (可选)
            if scenario_list and random.random() < 0.05:
                scenario_class = random.choice(scenario_list)
                scenario_instance = scenario_class()
                batch.extend(scenario_instance.get_logs())

            # 3. 同步发送到所有目标
            for s in senders:
                s.send(batch, index_name)

        # 控制频率 (简单 Sleep)
        time.sleep(settings.BATCH_SIZE / settings.EPS)


# --- 入口控制 ---
if __name__ == "__main__":
    # 1. 定义你想要使用的生成器和对应的 Index
    my_generators = {
        settings.NET_INDEX: NetworkGenerator(),
        settings.HOST_INDEX: HostGenerator(),
        settings.CLOUD_INDEX: CloudGenerator()
    }

    # 2. 定义你想启用的发送器
    my_senders = []
    if secrets.ELK_ENABLED:
        my_senders.append(ELKSender())
    if secrets.SPLUNK_ENABLED:
        my_senders.append(SplunkSender())

    # 3. 定义你想注入的攻击场景
    my_scenarios = [BruteForceScenario, SqlInjectionScenario, RansomwareScenario, CloudPrivilegeEscalationScenario]

    # 4. 启动引擎 (完全通过传参控制)
    if not my_senders:
        raise Exception("No senders configured. Please check secret_config.py")

    run_engine(
        generators=my_generators,
        senders=my_senders,
        scenario_list=my_scenarios
    )
