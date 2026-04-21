# API Test Report — Batch C Routers
**Date**: 2026-04-22
**Base URL**: http://localhost:8000
**Auth**: Bearer token (fixops_ent_...)
**Org**: default


## cache_router.py — /api/v1/cache
| Method | Path | Status | Time | Result |
|--------|------|--------|------|--------|
| GET    | /api/v1/cache/stats?org_id=default                                          |  |    0ms | FAIL |
| POST   | /api/v1/cache/clear                                                         |  |    0ms | FAIL |
| POST   | /api/v1/cache/clear/findings                                                |  |    0ms | FAIL |

## casb_router.py — /api/v1/casb
| Method | Path | Status | Time | Result |
|--------|------|--------|------|--------|
| GET    | /api/v1/casb/apps?org_id=default                                            |  |    0ms | FAIL |
| POST   | /api/v1/casb/apps                                                           |  |    0ms | FAIL |
| POST   | /api/v1/casb/apps/1/sanction                                                |  |    0ms | FAIL |
| POST   | /api/v1/casb/apps/1/unsanction                                              |  |    0ms | FAIL |
| GET    | /api/v1/casb/data-activities?org_id=default                                 |  |    0ms | FAIL |
| POST   | /api/v1/casb/data-activities                                                |  |    0ms | FAIL |
| GET    | /api/v1/casb/policies?org_id=default                                        |  |    0ms | FAIL |
| POST   | /api/v1/casb/policies                                                       |  |    0ms | FAIL |
| GET    | /api/v1/casb/violations?org_id=default                                      |  |    0ms | FAIL |
| POST   | /api/v1/casb/violations                                                     |  |    0ms | FAIL |
| GET    | /api/v1/casb/shadow-it-report?org_id=default                                |  |    0ms | FAIL |
| GET    | /api/v1/casb/stats?org_id=default                                           |  |    0ms | FAIL |

## ccm_router.py — /api/v1/ccm
| Method | Path | Status | Time | Result |
|--------|------|--------|------|--------|
| POST   | /api/v1/ccm/orgs/default/controls                                           |  |    0ms | FAIL |
| GET    | /api/v1/ccm/orgs/default/controls                                           |  |    0ms | FAIL |
| POST   | /api/v1/ccm/orgs/default/controls/1/tests                                   |  |    0ms | FAIL |
| POST   | /api/v1/ccm/orgs/default/tests/1/run                                        |  |    0ms | FAIL |
| GET    | /api/v1/ccm/orgs/default/tests                                              |  |    0ms | FAIL |
| POST   | /api/v1/ccm/orgs/default/failures                                           |  |    0ms | FAIL |
| POST   | /api/v1/ccm/orgs/default/failures/1/remediate                               |  |    0ms | FAIL |
| GET    | /api/v1/ccm/orgs/default/failures                                           |  |    0ms | FAIL |
| GET    | /api/v1/ccm/orgs/default/coverage                                           |  |    0ms | FAIL |
| GET    | /api/v1/ccm/orgs/default/stats                                              |  |    0ms | FAIL |

## cert_router.py — /api/v1/certificates
| Method | Path | Status | Time | Result |
|--------|------|--------|------|--------|
| GET    | /api/v1/certificates/?org_id=default                                        |  |    0ms | FAIL |
| POST   | /api/v1/certificates/                                                       |  |    0ms | FAIL |
| GET    | /api/v1/certificates/alerts/expiry?org_id=default                           |  |    0ms | FAIL |
| GET    | /api/v1/certificates/weak?org_id=default                                    |  |    0ms | FAIL |
| GET    | /api/v1/certificates/stats?org_id=default                                   |  |    0ms | FAIL |
| POST   | /api/v1/certificates/check                                                  |  |    0ms | FAIL |
| GET    | /api/v1/certificates/1?org_id=default                                       |  |    0ms | FAIL |
| PUT    | /api/v1/certificates/1                                                      |  |    0ms | FAIL |
| DELETE | /api/v1/certificates/1?org_id=default                                       |  |    0ms | FAIL |

## change_management_router.py — /api/v1/changes
| Method | Path | Status | Time | Result |
|--------|------|--------|------|--------|
| GET    | /api/v1/changes?org_id=default                                              |  |    0ms | FAIL |
| POST   | /api/v1/changes                                                             |  |    0ms | FAIL |
| GET    | /api/v1/changes/1?org_id=default                                            |  |    0ms | FAIL |
| POST   | /api/v1/changes/1/submit                                                    |  |    0ms | FAIL |
| POST   | /api/v1/changes/1/approve                                                   |  |    0ms | FAIL |
| POST   | /api/v1/changes/1/reject                                                    |  |    0ms | FAIL |
| POST   | /api/v1/changes/1/implement                                                 |  |    0ms | FAIL |
| POST   | /api/v1/changes/1/complete                                                  |  |    0ms | FAIL |
| POST   | /api/v1/changes/1/rollback                                                  |  |    0ms | FAIL |
| POST   | /api/v1/changes/1/impact                                                    |  |    0ms | FAIL |
| POST   | /api/v1/changes/1/risk-override                                             |  |    0ms | FAIL |
| GET    | /api/v1/changes/1/audit?org_id=default                                      |  |    0ms | FAIL |
| GET    | /api/v1/changes/1/conflicts?org_id=default                                  |  |    0ms | FAIL |
| GET    | /api/v1/changes/calendar/windows?org_id=default                             |  |    0ms | FAIL |
| POST   | /api/v1/changes/calendar/windows                                            |  |    0ms | FAIL |
| GET    | /api/v1/changes/calendar/freezes?org_id=default                             |  |    0ms | FAIL |
| POST   | /api/v1/changes/calendar/freezes                                            |  |    0ms | FAIL |
| GET    | /api/v1/changes/metrics/summary?org_id=default                              |  |    0ms | FAIL |
| POST   | /api/v1/changes/admin/expire-stale                                          |  |    0ms | FAIL |

## change_tracker_router.py — /api/v1/change-tracker
| Method | Path | Status | Time | Result |
|--------|------|--------|------|--------|
| POST   | /api/v1/change-tracker/                                                     |  |    0ms | FAIL |
| POST   | /api/v1/change-tracker/1/assess-risk                                        |  |    0ms | FAIL |
| POST   | /api/v1/change-tracker/1/approve                                            |  |    0ms | FAIL |
| POST   | /api/v1/change-tracker/1/reject                                             |  |    0ms | FAIL |
| GET    | /api/v1/change-tracker/pending?org_id=default                               |  |    0ms | FAIL |
| GET    | /api/v1/change-tracker/high-risk?org_id=default                             |  |    0ms | FAIL |
| GET    | /api/v1/change-tracker/velocity?org_id=default                              |  |    0ms | FAIL |
| GET    | /api/v1/change-tracker/stats?org_id=default                                 |  |    0ms | FAIL |
| GET    | /api/v1/change-tracker/correlate-incidents?org_id=default                   |  |    0ms | FAIL |
| GET    | /api/v1/change-tracker/1?org_id=default                                     |  |    0ms | FAIL |
