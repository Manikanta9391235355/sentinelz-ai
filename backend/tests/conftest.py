import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app import database as db_module
from backend.app import main as main_module
from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.services.seeder import seed_database
from backend.app.core.security import create_access_token
from backend.app.models.all_models import User

# Use a file-based temporary or isolated test database
TEST_DB_PATH = "test_sentinelz.db"
TEST_DATABASE_URL = f"sqlite:///{TEST_DB_PATH}"

engine_test = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine_test)

# Point main application's engine to test engine
db_module.engine = engine_test
db_module.SessionLocal = TestingSessionLocal
main_module.engine = engine_test
main_module.SessionLocal = TestingSessionLocal

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine_test)
    db = TestingSessionLocal()
    seed_database(db, force=True)
    db.close()
    yield
    Base.metadata.drop_all(bind=engine_test)
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception:
            pass

@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

@pytest.fixture
def admin_headers(db_session):
    admin = db_session.query(User).filter(User.role == "security_admin").first()
    token = create_access_token(admin.id, admin.role)
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def analyst_headers(db_session):
    analyst = db_session.query(User).filter(User.role == "security_analyst").first()
    token = create_access_token(analyst.id, analyst.role)
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def viewer_headers(db_session):
    viewer = db_session.query(User).filter(User.role == "viewer").first()
    token = create_access_token(viewer.id, viewer.role)
    return {"Authorization": f"Bearer {token}"}
