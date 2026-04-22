"""
WSGI config for BlackPost project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/2.1/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ASP.settings')
os.environ.setdefault('ASP_START_BACKGROUND_SERVICES', '1')
os.environ.setdefault('ASP_BACKGROUND_SERVICES_SOURCE', 'wsgi')

application = get_wsgi_application()
