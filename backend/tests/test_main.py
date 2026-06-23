import pytest


@pytest.mark.anyio
async def test_health_check(client):
    response = await client.get('/api/v1/health')
    assert response.status_code == 200
    data = response.json()
    assert data['status'] == 'healthy'


@pytest.mark.anyio
async def test_api_cves_get(client):
    response = await client.get('/api/v1/cves')
    assert response.status_code == 200


@pytest.mark.anyio
async def test_404_handler(client):
    response = await client.get('/nonexistent-endpoint-xyz')
    assert response.status_code == 404
