import json
import os
import hashlib
from datetime import datetime, timedelta

CACHE_FILE = "url_cache.json"
CACHE_EXPIRY_DAYS = 7

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)

def get_cache_key(url):
    return hashlib.md5(url.encode()).hexdigest()

def get_cached_result(url):
    cache = load_cache()
    key = get_cache_key(url)
    if key in cache:
        entry = cache[key]
        cache_date = datetime.fromisoformat(entry['date'])
        if datetime.now() - cache_date < timedelta(days=CACHE_EXPIRY_DAYS):
            return entry['result']
    return None

def cache_result(url, result):
    cache = load_cache()
    key = get_cache_key(url)
    cache[key] = {
        'url': url,
        'result': result,
        'date': datetime.now().isoformat()
    }
    save_cache(cache)