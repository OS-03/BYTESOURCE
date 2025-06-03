import os
from django.core.wsgi import get_wsgi_application
from whitenoise import WhiteNoise
from pathlib import Path

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'online_test.settings')

application = get_wsgi_application()
static_root = Path(__file__).resolve().parent.parent / 'staticfiles'
application = WhiteNoise(application, root=str(static_root))

