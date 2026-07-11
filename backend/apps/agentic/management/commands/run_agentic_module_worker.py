from django.core.management.base import BaseCommand

from apps.agentic.runtime.module import run_all_modules_once
from apps.common.worker_runner import SLEEP_WHEN_IDLE, add_worker_arguments, run_worker

DEFAULT_INTERVAL_SECONDS = 3.0


class Command(BaseCommand):
    help = "Run the Agentic SOC module worker."

    def add_arguments(self, parser):
        add_worker_arguments(parser, interval_help="Seconds to sleep when no module stream message is available.")

    def handle(self, *args, **options):
        run_worker(
            self,
            options=options,
            worker_name="agentic module",
            run_once=run_all_modules_once,
            default_interval=DEFAULT_INTERVAL_SECONDS,
            sleep_policy=SLEEP_WHEN_IDLE,
            log_role="agentic-module-worker",
        )
