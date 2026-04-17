# US-0287: Threat Feed Subscription

## Sub-Epic: AI Intelligence
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Nina Patel (Threat Intel Analyst)**, I need to manage threat feed subscriptions
so that the platform delivers enterprise-grade ai intelligence capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Threat Feed Subscription replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone AI Intelligence tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/feed-subscriptions"]
    API --> Auth["api_key_auth"]
    Auth --> Router["threat_feed_subscription_router.py"]
    Router --> Engine["ThreatFeedSubscriptionEngine"]
    Engine --> DB[(SQLite: {org_id}_threat_feed_subscription.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `create_subscription()` — Create a new feed subscription. api_key is stored as SHA-256 hash. (line 153)
- ✅ `update_subscription_status()` — Update subscription status. (line 193)
- ✅ `record_ingestion()` — Log an ingestion run and update subscription counters. (line 214)
- ✅ `create_delivery()` — Create a delivery channel for a subscription. (line 256)
- ✅ `record_delivery()` — Increment delivery_count and update last_delivered timestamp. (line 299)
- ✅ `get_subscription()` — Get a subscription with the last 10 ingestion log entries. (line 318)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/threat_feed_subscription_engine.py` — 428 lines)
- `ThreatFeedSubscriptionEngine.create_subscription()` — Create a new feed subscription. api_key is stored as SHA-256 hash. (line 153)
- `ThreatFeedSubscriptionEngine.update_subscription_status()` — Update subscription status. (line 193)
- `ThreatFeedSubscriptionEngine.record_ingestion()` — Log an ingestion run and update subscription counters. (line 214)
- `ThreatFeedSubscriptionEngine.create_delivery()` — Create a delivery channel for a subscription. (line 256)
- `ThreatFeedSubscriptionEngine.record_delivery()` — Increment delivery_count and update last_delivered timestamp. (line 299)
- `ThreatFeedSubscriptionEngine.get_subscription()` — Get a subscription with the last 10 ingestion log entries. (line 318)
- `ThreatFeedSubscriptionEngine.list_subscriptions()` — List subscriptions with optional status/feed_type filters. (line 338)
- `ThreatFeedSubscriptionEngine.get_due_subscriptions()` — Return active subscriptions that are due for a fetch. (line 358)

## Dependencies
- **Depends on**: standalone
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/threat_feed_subscription_engine.py` (428 lines)
- **Router file**: `suite-api/apps/api/threat_feed_subscription_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/feed-subscriptions/subscriptions` | create subscription |
| GET | `/api/v1/feed-subscriptions/subscriptions` | list subscriptions |
| GET | `/api/v1/feed-subscriptions/subscriptions/{subscription_id}` | get subscription |
| PATCH | `/api/v1/feed-subscriptions/subscriptions/{subscription_id}/status` | update status |
| POST | `/api/v1/feed-subscriptions/subscriptions/{subscription_id}/ingestion` | record ingestion |
| POST | `/api/v1/feed-subscriptions/subscriptions/{subscription_id}/deliveries` | create delivery |
| POST | `/api/v1/feed-subscriptions/subscriptions/{subscription_id}/deliveries/{delivery_id}/record` | record delivery |
| GET | `/api/v1/feed-subscriptions/due` | get due |
| GET | `/api/v1/feed-subscriptions/stats` | get stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Nina Patel (Threat Intel Analyst) can access /api/v1/feed-subscriptions and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 34+ tests passing in `tests/test_threat_feed_subscription_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 51 (est. April 27-29, 2026)

## Test Coverage
- **Test file**: `tests/test_threat_feed_subscription_engine.py`
- **Tests**: 34 tests
- **Status**: Passing
