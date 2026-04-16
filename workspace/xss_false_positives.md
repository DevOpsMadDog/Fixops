# XSS False Positives Tracking

## XSS-VULN-05: Report Builder Template Name Field

**Vulnerability ID:** XSS-VULN-05  
**Status:** POTENTIAL (Inaccessible — Router Not Registered)

**What was attempted:**
- POST /api/v1/report-builder/templates with various request body formats
- GET /api/v1/report-builder/templates
- All HTTP methods (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD)
- Checked /api/v1/report-builder/meta/section-types and /api/v1/report-builder/stats

**Why classified as POTENTIAL rather than FALSE POSITIVE:**
The `report_builder_router.py` source file confirms the vulnerability exists:
- `report_builder.py:597-603` uses Python f-strings to construct `<title>{report.template_name}</title>` and `<h1>{report.template_name}</h1>` without html.escape()
- The router code is correct and would be vulnerable if deployed

The blocking factor is operational (router not registered in app.py), NOT a security implementation designed to prevent XSS.

**Why not included in main report as EXPLOITED:**
The POST /api/v1/report-builder/templates endpoint returns 405 Method Not Allowed for all request bodies tested. Source code analysis confirmed that `report_builder_router.py` is NOT imported or included in the main FastAPI application (`suite-api/apps/api/app.py`). All other report-builder sub-paths return 404, confirming the router is not registered.

**Classification:** POTENTIAL — operational constraint (not deployed), not a security defense.
