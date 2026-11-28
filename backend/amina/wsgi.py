"""
WSGI config for the amina project.
"""
import os

from django.core.wsgi import get_wsgi_application

if os.environ.get("IAMINA_PHYSICAL_E2E"):
    # Dedicated preview settings reject every other project/target at startup.
    os.environ["DJANGO_SETTINGS_MODULE"] = "amina.physical_lab_settings"
elif os.environ.get("VERCEL") == "1":
    os.environ["DJANGO_SETTINGS_MODULE"] = "amina.vercel_settings"
else:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "amina.settings")

application = get_wsgi_application()
