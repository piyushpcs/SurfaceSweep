"""
SurfaceSweep modules package.

Architecture:
    extraction/   — Core JS content extraction (regex, AST, browser, deobfuscation)
    discovery/    — Expand attack surface (SPA routes, Wayback Machine)
    analysis/     — Analyze findings (endpoint validation, library/CVE detection)
    recon/        — Target reconnaissance (WAF detection)
    reporting/    — Output generation (JSON, HTML, Burp/ZAP CSV)
    cors/         — Phase 2: CORS misconfiguration scanner
    jwt_analyzer.py — Phase 3: JWT security analyzer (complete)
"""
