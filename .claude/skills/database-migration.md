# Skill: Database Migration — sqlite3/PersistentDict → DatabaseManager

> How to migrate any code from raw SQLite or PersistentDict to the enterprise DatabaseManager with async sessions, connection pooling, and PostgreSQL support.

## Current State (2026-03-17)
- 185 `sqlite3.connect` calls across production code
- 42 `PersistentDict` usages
- 37 `DatabaseManager` usages (the target pattern)
- 100 `.db` files on disk
- Enterprise DB session: `suite-core/core/db/enterprise/session.py`
- Settings: `suite-core/config/enterprise/settings.py` (DATABASE_URL, pool config)
- Migrations: `suite-core/core/db/enterprise/migrations/versions/`

## The Target Pattern — DatabaseManager

```python
# suite-core/core/db/enterprise/session.py provides:
from core.db.enterprise.session import DatabaseManager

# Initialize once at startup (in app.py lifespan):
await DatabaseManager.initialize()

# Use in any endpoint:
async with DatabaseManager.get_session() as session:
    result = await session.execute(select(Finding).where(Finding.org_id == org_id))
    findings = result.scalars().all()
```

## Migration Recipe: sqlite3.connect → DatabaseManager

### Step 1: Identify the call site
```bash
grep -n "sqlite3.connect" path/to/file.py
```

### Step 2: Understand what it does
Look for the pattern:
```python
# BEFORE (anti-pattern):
import sqlite3
conn = sqlite3.connect("data/some_domain.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS items (...)")
cursor.execute("SELECT * FROM items WHERE status = ?", (status,))
rows = cursor.fetchall()
conn.close()
```

### Step 3: Create SQLAlchemy model (if not exists)
```python
# suite-core/core/models/enterprise/DOMAIN.py
from sqlalchemy import Column, String, DateTime, Text, Integer, Boolean, JSON
from core.models.enterprise.base_sqlite import BaseModel, AuditMixin, SoftDeleteMixin

class Item(BaseModel, AuditMixin, SoftDeleteMixin):
    __tablename__ = "items"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = Column(String(36), nullable=False, index=True)  # ALWAYS include org_id
    status = Column(String(50), nullable=False, default="open")
    title = Column(String(500), nullable=False)
    details = Column(JSON, nullable=True)
    # AuditMixin adds: created_at, updated_at, created_by, updated_by
    # SoftDeleteMixin adds: deleted_at, is_deleted
```

### Step 4: Create Alembic migration
```bash
cd suite-core && alembic -c core/db/enterprise/alembic.ini revision --autogenerate -m "add_items_table"
```

Or manually:
```python
# suite-core/core/db/enterprise/migrations/versions/003_add_items.py
from alembic import op
import sqlalchemy as sa

def upgrade():
    op.create_table(
        "items",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False, index=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="open"),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("details", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, onupdate=sa.func.now()),
        sa.Column("deleted_at", sa.DateTime, nullable=True),
        sa.Column("is_deleted", sa.Boolean, server_default="false"),
    )

def downgrade():
    op.drop_table("items")
```

### Step 5: Replace the code
```python
# AFTER (correct pattern):
from sqlalchemy import select
from core.db.enterprise.session import DatabaseManager
from core.models.enterprise.domain import Item

async def get_items(org_id: str, status: str = None):
    async with DatabaseManager.get_session() as session:
        query = select(Item).where(Item.org_id == org_id, Item.is_deleted == False)
        if status:
            query = query.where(Item.status == status)
        result = await session.execute(query)
        return result.scalars().all()

async def create_item(org_id: str, title: str, details: dict = None):
    async with DatabaseManager.get_session() as session:
        item = Item(org_id=org_id, title=title, details=details)
        session.add(item)
        await session.commit()
        await session.refresh(item)
        return item
```

### Step 6: Verify
```bash
# Check no sqlite3 remains in the file:
grep -n "sqlite3" path/to/file.py
# Run tests:
python -m pytest tests/test_DOMAIN.py -v --timeout=10
```

## Migration Recipe: PersistentDict → SQLAlchemy

PersistentDict stores key-value pairs in SQLite. Replace with a proper model:

```python
# BEFORE:
from core.persistent_store import PersistentDict
store = PersistentDict("domain_cache")
store["key"] = {"some": "data"}
value = store.get("key")

# AFTER:
from core.db.enterprise.session import DatabaseManager
from core.models.enterprise.domain import DomainSetting

async def get_setting(org_id: str, key: str):
    async with DatabaseManager.get_session() as session:
        result = await session.execute(
            select(DomainSetting).where(
                DomainSetting.org_id == org_id,
                DomainSetting.key == key
            )
        )
        row = result.scalar_one_or_none()
        return row.value if row else None
```

## Critical Rules

1. **Always include `org_id`** on every new model and every query
2. **Always use `async with DatabaseManager.get_session()`** — never create raw connections
3. **Always create both upgrade() and downgrade()** in migrations
4. **Test on both SQLite and PostgreSQL** — avoid PostgreSQL-only features in migrations
5. **Never delete .db files** until the migration is verified working
6. **Batch migrate** — convert one domain at a time (findings, evidence, scans, etc.), test, commit

## Validation Commands

```bash
# Count remaining sqlite3 calls:
grep -rn "sqlite3.connect" suite-api/ suite-core/ suite-attack/ suite-feeds/ suite-evidence-risk/ suite-integrations/ --include="*.py" | grep -v __pycache__ | wc -l

# Count remaining PersistentDict:
grep -rn "PersistentDict" suite-api/ suite-core/ suite-attack/ suite-feeds/ suite-evidence-risk/ suite-integrations/ --include="*.py" | grep -v __pycache__ | wc -l

# Count DatabaseManager usage (should be growing):
grep -rn "DatabaseManager" suite-api/ suite-core/ suite-attack/ suite-feeds/ suite-evidence-risk/ suite-integrations/ --include="*.py" | grep -v __pycache__ | wc -l

# Run migrations:
cd suite-core && alembic -c core/db/enterprise/alembic.ini upgrade head

# Target: 0 sqlite3.connect, 0 PersistentDict in production paths
```
