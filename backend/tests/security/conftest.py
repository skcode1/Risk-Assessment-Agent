#import asyncio

import pytest

# @pytest.fixture(scope="session")
# def event_loop():
#     """Force a single shared event loop for all tests in this module."""
#     loop = asyncio.new_event_loop()
#     asyncio.set_event_loop(loop)
#     yield loop
#     loop.close()
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.fixture
def security_client():
    transport = ASGITransport(app=app)
    client = AsyncClient(transport=transport, base_url="http://testserver")
    yield client