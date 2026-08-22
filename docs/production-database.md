# PostgreSQL and Alembic deployment

SQLite is the default local-development store. Use PostgreSQL for the final demo/deployment so variable event metadata, features, evidence, and baselines are stored as JSONB.

## Configure SEC-SRV

Install the PostgreSQL dependency and configure environment values before starting the API:

```powershell
cd C:\HyperProtection\backend
py -m pip install -e ".[postgres]"
$env:HYPERPROTECTION_DATABASE_URL = "postgresql+psycopg://hp_app:replace-me@SEC-SRV:5432/hyperprotection"
$env:HYPERPROTECTION_AUTO_CREATE_SCHEMA = "false"
$env:HYPERPROTECTION_SEED_DEMO_DATA = "false"
$env:HYPERPROTECTION_PSEUDONYMIZATION_SECRET = "replace-with-a-long-random-secret"
py -m alembic upgrade head
py -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

`AUTO_CREATE_SCHEMA=false` makes the service depend on the Alembic revision rather than calling `create_all`. The first revision creates all required tables and uses JSONB on PostgreSQL. Do not use a superuser connection for the application role.

## Verify

```powershell
py -m alembic current
```

Expected revision: `0001_initial_schema (head)`.

For local migration verification without PostgreSQL:

```powershell
$env:HYPERPROTECTION_DATABASE_URL = "sqlite:///C:/temp/hyperprotection-migration-test.db"
py -m alembic upgrade head
```

This validates migration ordering, but it cannot replace a PostgreSQL integration test. PostgreSQL-specific compilation is covered in the test suite; a real final-demo environment should also run `alembic upgrade head` against a disposable PostgreSQL instance before release.
