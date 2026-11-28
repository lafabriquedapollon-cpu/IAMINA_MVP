"""Dedicated Vercel Preview settings: no product apps, routes or accounts."""
import os
import re
from urllib.parse import parse_qs, urlsplit, unquote
import dj_database_url

def require(ok):
    if not ok:
        raise ValueError("Physical lab configuration refused")

require(os.environ.get("VERCEL")=="1" and os.environ.get("VERCEL_ENV")=="preview"
        and os.environ.get("VERCEL_PROJECT_ID")=="prj_hnlWE6QdXtWvYVfwe2JVAqIKPUiP"
        and os.environ.get("IAMINA_PHYSICAL_E2E")=="synthetic-v1"
        and os.environ.get("IAMINA_D1_SAFARI_LAB_ONLY")=="synthetic-preview-v1"
        and os.environ.get("IAMINA_ENV")=="development")
host=os.environ.get("VERCEL_URL","")
# Exact deployment-name pattern observed in the existing project, no custom alias.
require(re.fullmatch(r"iamina-d1-6-safari-django-preview-20261113-[a-z0-9]{9}(?:-achraf-benmoussa-s-projects)?\.vercel\.app",host))
PHYSICAL_LAB_ORIGIN="https://"+host
PHYSICAL_LAB_OPERATOR_HASH=os.environ.get("IAMINA_PHYSICAL_OPERATOR_SHA256","")
PHYSICAL_LAB_ISSUER=os.environ.get("IAMINA_PHYSICAL_ISSUER_PKCS8","")
require(re.fullmatch(r"[0-9a-f]{64}",PHYSICAL_LAB_OPERATOR_HASH) and
        re.fullmatch(r"[A-Za-z0-9_-]{100,512}",PHYSICAL_LAB_ISSUER))
SECRET_KEY=os.environ.get("SECRET_KEY","")
require(len(SECRET_KEY)>=32)
url=os.environ.get("DATABASE_URL","")
parsed=urlsplit(url)
params=parse_qs(parsed.query,keep_blank_values=True)
require(parsed.scheme in ("postgres","postgresql") and
        parsed.hostname=="ep-frosty-tooth-b921hjv8-pooler.c-7.eu-central-1.aws.neon.tech"
        and parsed.port in (None,5432) and parsed.path=="/iamina925_empty"
        and unquote(parsed.username or "")=="d1_safari_runtime"
        and params.get("sslmode")==["verify-full"]
        and set(params)<=set(("sslmode","sslrootcert","channel_binding"))
        and params.get("sslrootcert")==["system"])
DATABASES={"default":dj_database_url.parse(url,conn_max_age=0)}
DEBUG=False
ALLOWED_HOSTS=[host]
ROOT_URLCONF="core.d1_physical_lab_web"
INSTALLED_APPS=[]
MIDDLEWARE=["django.middleware.security.SecurityMiddleware"]
SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO","https")
SECURE_SSL_REDIRECT=True
SECURE_HSTS_SECONDS=31536000
SECURE_CONTENT_TYPE_NOSNIFF=True
USE_TZ=True
DEFAULT_AUTO_FIELD="django.db.models.BigAutoField"
