from quart import Quart
from quart_jwt_extended import (
    JWTManager,
    jwt_required,
    fresh_jwt_required,
    jwt_refresh_token_required,
)
import pytest


@pytest.fixture(scope="function")
def app():
    app = Quart(__name__)
    app.config["JWT_SECRET_KEY"] = "secret"
    JWTManager(app)

    @app.route("/jwt_required", methods=["GET", "OPTIONS"])
    @jwt_required
    async def jwt_required_endpoint():
        return b"ok"

    @app.route("/fresh_jwt_required", methods=["GET", "OPTIONS"])
    @fresh_jwt_required
    async def fresh_jwt_required_endpoint():
        return b"ok"

    @app.route("/jwt_refresh_token_required", methods=["GET", "OPTIONS"])
    @jwt_refresh_token_required
    async def jwt_refresh_token_required_endpoint():
        return b"ok"

    return app


@pytest.mark.asyncio
async def test_access_jwt_required_enpoint(app):
    res = await app.test_client().options("/jwt_required")
    assert res.status_code == 200
    assert await res.get_data() == b"ok"


@pytest.mark.asyncio
async def test_access_jwt_refresh_token_required_enpoint(app):
    res = await app.test_client().options("/jwt_refresh_token_required")
    assert res.status_code == 200
    assert await res.get_data() == b"ok"


@pytest.mark.asyncio
async def test_access_fresh_jwt_required_enpoint(app):
    res = await app.test_client().options("/fresh_jwt_required")
    assert res.status_code == 200
    assert await res.get_data() == b"ok"
