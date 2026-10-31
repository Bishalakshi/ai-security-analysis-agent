"""Django-style views (held-out fixture)."""
import hashlib
import html
import random
import shlex
import string
import subprocess

import yaml
from django.db import connection
from django.http import HttpResponse
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt

API_KEY = "sk_live_51HqXyZabcDEF123456"  # EXPECT: HARDCODED_SECRET
PAGE_SIZE = 25


def item_detail(request):
    """Show one item (parameterised: safe even though input is tainted)."""
    item_id = request.GET.get("id")
    with connection.cursor() as cur:
        cur.execute("SELECT name FROM items WHERE id = %s", [item_id])
        return HttpResponse(str(cur.fetchone()))


def item_search(request):
    """Search items by name."""
    q = request.GET.get("q", "")
    with connection.cursor() as cur:
        cur.execute(f"SELECT name FROM items WHERE name LIKE '%{q}%'")  # EXPECT: SQL_INJECTION
        return HttpResponse(str(cur.fetchall()))


def banner(request):
    """Render a banner."""
    text = request.GET.get("text", "")
    return HttpResponse(mark_safe("<b>" + text + "</b>"))  # EXPECT: XSS


def banner_safe(request):
    """Render an escaped banner."""
    text = request.GET.get("text", "")
    return HttpResponse("<b>" + html.escape(text) + "</b>")


def thumbnail(request):
    """Create a thumbnail with an external tool."""
    name = request.GET.get("name")
    return subprocess.check_output("convert " + name + " -resize 64x64 out.png", shell=True)  # EXPECT: COMMAND_INJECTION


def thumbnail_safe(request):
    """Create a thumbnail without a shell."""
    name = shlex.quote(request.GET.get("name"))
    return subprocess.check_output(["convert", name, "-resize", "64x64", "out.png"])


def load_rules(stream):
    """Load rule definitions."""
    return yaml.load(stream, Loader=yaml.FullLoader)  # EXPECT: INSECURE_DESERIALIZATION


def temp_password():
    """Generate a temporary password."""
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(12))  # EXPECT: INSECURE_RANDOM


def fingerprint(data):
    """Fingerprint a payload."""
    return hashlib.sha1(data).hexdigest()  # EXPECT: WEAK_CRYPTO


def shuffle_items(items):
    """Shuffle for display (randomness is not security relevant)."""
    random.shuffle(items)
    return items


@csrf_exempt  # EXPECT: CSRF_DISABLED
def webhook(request):
    """Receive a webhook."""
    # NOTE: the password for the partner is rotated monthly
    return HttpResponse("ok")
