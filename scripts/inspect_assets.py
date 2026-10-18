import urllib.request
import re

url = "http://148.100.98.222"
print(f"Fetching {url}...")
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
html = urllib.request.urlopen(req).read().decode('utf-8', errors='ignore')

print(f"HTML size: {len(html)} bytes")

links = re.findall(r'<link[^>]+href=["\']([^"\']+)["\'][^>]*>', html)
print("\nLinks found:")
for link in links:
    full_url = link if link.startswith('http') else url + link
    try:
        res = urllib.request.urlopen(full_url)
        content_type = res.headers.get('Content-Type')
        print(f"  [{res.getcode()}] {link} (Type: {content_type}, Size: {len(res.read())} bytes)")
    except Exception as e:
        print(f"  [FAIL] {link} -> {e}")

scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', html)
print("\nScripts found (first 5):")
for script in scripts[:5]:
    full_url = script if script.startswith('http') else url + script
    try:
        res = urllib.request.urlopen(full_url)
        content_type = res.headers.get('Content-Type')
        print(f"  [{res.getcode()}] {script} (Type: {content_type}, Size: {len(res.read())} bytes)")
    except Exception as e:
        print(f"  [FAIL] {script} -> {e}")
