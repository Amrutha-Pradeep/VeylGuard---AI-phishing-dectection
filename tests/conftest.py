"""
Shared pytest fixtures for VeylGuard integration tests.

Each test function gets a fresh Flask test client backed by a temporary
SQLite database file that is deleted after the test session.
"""

import os
import tempfile

import pytest

from app import create_app
from app.database import clear_history, init_db


@pytest.fixture(scope="session")
def app():
    """
    Create a Flask test application once per test session.

    A temporary SQLite file is used so tests are isolated from the
    production database in instance/.
    """
    db_fd, db_path = tempfile.mkstemp(suffix=".sqlite3")

    flask_app = create_app({
        "TESTING": True,
        "DATABASE": db_path,
    })

    yield flask_app

    os.close(db_fd)
    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest.fixture
def client(app):
    """Return a Flask test client."""
    return app.test_client()


@pytest.fixture(autouse=False)
def clean_db(app):
    """
    Clear scan history before and after a test.

    Use this fixture in tests that write to the database so they don't
    interfere with one another.
    """
    with app.app_context():
        clear_history()
    yield
    with app.app_context():
        clear_history()
