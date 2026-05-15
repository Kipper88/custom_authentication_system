SECRET_KEY = "demo-only"
DEBUG = True
ROOT_URLCONF = "apps.drf_app.urls"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
INSTALLED_APPS = ["django.contrib.contenttypes", "rest_framework"]
MIDDLEWARE = []
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
REST_FRAMEWORK = {
    "UNAUTHENTICATED_USER": None,
}
