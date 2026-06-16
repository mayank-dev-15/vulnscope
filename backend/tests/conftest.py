import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

@pytest.fixture
def app():
    from main import app
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()
