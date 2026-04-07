"""
botwall — Identify bot protection systems and rate bypass difficulty.

Detects Cloudflare, DataDome, Akamai Bot Manager, PerimeterX (HUMAN),
Incapsula/Imperva, and generic WAF/CAPTCHA patterns by inspecting HTTP
response headers, cookies, and body content.
"""
