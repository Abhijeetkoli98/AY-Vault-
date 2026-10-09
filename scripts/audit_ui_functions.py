import re

html = open("web/templates/index.html", encoding="utf-8").read()
js = open("web/static/js/app.js", encoding="utf-8").read()
clicks = set(re.findall(r'onclick=[\"\']([a-zA-Z0-9_]+)', html))

print("Total onclick functions found in HTML:", len(clicks))
missing = []
for fn in sorted(clicks):
    if f"function {fn}" not in js and f"{fn} =" not in js and f"{fn}=" not in js:
        missing.append(fn)

print("MISSING FUNCTIONS IN app.js:", missing)

# Check all modals referenced in openModal or closeModal
modals_in_html = set(re.findall(r'id=[\"\'](modal-[a-zA-Z0-9_-]+)[\"\']', html))
modals_called = set(re.findall(r'(?:openModal|closeModal)\([\'\"]([a-zA-Z0-9_-]+)[\'\"]\)', html + js))
print("Modals in HTML:", modals_in_html)
print("Modals called in code:", modals_called)
missing_modals = modals_called - modals_in_html
print("MISSING MODALS IN HTML:", missing_modals)
