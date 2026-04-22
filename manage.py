#!/usr/bin/env python
import os
import sys

if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ASP.settings')
    if len(sys.argv) > 1 and sys.argv[1] == 'runserver':
        os.environ['ASP_START_BACKGROUND_SERVICES'] = '1'
        os.environ['ASP_BACKGROUND_SERVICES_SOURCE'] = 'manage.py runserver'
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)
