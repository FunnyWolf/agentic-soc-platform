from django.apps import AppConfig


class CoreConfig(AppConfig):
    name = 'Core'

    def ready(self):
        from Core.bootstrap import get_or_start_background_services

        get_or_start_background_services()
