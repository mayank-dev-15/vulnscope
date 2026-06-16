import pytest

def test_import_models():
    from models import Base
    assert Base is not None

def test_import_database():
    from database import engine
    assert engine is not None
