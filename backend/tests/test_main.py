import pytest, json

def test_health_check(client):
    response = client.get('/health')
    assert response.status_code == 200

def test_api_cves_get(client):
    response = client.get('/api/cves')
    assert response.status_code == 200

def test_404_handler(client):
    response = client.get('/nonexistent-endpoint-xyz')
    assert response.status_code == 404
