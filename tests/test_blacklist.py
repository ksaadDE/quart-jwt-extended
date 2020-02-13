import pytest
from quart import Quart, jsonify

from quart_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    jwt_refresh_token_required,
    create_refresh_token
)
from tests.utils import get_jwt_manager, make_headers


@pytest.fixture(scope='function')
def app():
    app = Quart(__name__)
    app.config['JWT_SECRET_KEY'] = 'foobarbaz'
    app.config['JWT_BLACKLIST_ENABLED'] = True
    JWTManager(app)

    @app.route('/protected', methods=['GET'])
    @jwt_required
    async def access_protected():
        return jsonify(foo='bar')

    @app.route('/refresh_protected', methods=['GET'])
    @jwt_refresh_token_required
    async def refresh_protected():
        return jsonify(foo='bar')

    return app


@pytest.mark.parametrize("blacklist_type", [['access'], ['refresh', 'access']])
@pytest.mark.asyncio
async def test_non_blacklisted_access_token(app, blacklist_type):
    jwt = get_jwt_manager(app)
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = blacklist_type

    @jwt.token_in_blacklist_loader
    def check_blacklisted(decrypted_token):
        return False

    async with app.test_request_context("/protected"):
        access_token = create_access_token('username')

    test_client = app.test_client()
    response = await test_client.get('/protected', headers=make_headers(access_token))
    assert await response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.parametrize("blacklist_type", [['access'], ['refresh', 'access']])
@pytest.mark.asyncio
async def test_blacklisted_access_token(app, blacklist_type):
    jwt = get_jwt_manager(app)
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = blacklist_type

    @jwt.token_in_blacklist_loader
    def check_blacklisted(decrypted_token):
        return True

    async with app.test_request_context("/protected"):
        access_token = create_access_token('username')

    test_client = app.test_client()
    response = await test_client.get('/protected', headers=make_headers(access_token))
    assert await response.get_json() == {'msg': 'Token has been revoked'}
    assert response.status_code == 401


@pytest.mark.parametrize("blacklist_type", [['refresh'], ['refresh', 'access']])
@pytest.mark.asyncio
async def test_non_blacklisted_refresh_token(app, blacklist_type):
    jwt = get_jwt_manager(app)
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = blacklist_type

    @jwt.token_in_blacklist_loader
    def check_blacklisted(decrypted_token):
        return False

    async with app.test_request_context("/protected"):
        refresh_token = create_refresh_token('username')

    test_client = app.test_client()
    response = await test_client.get('/refresh_protected', headers=make_headers(refresh_token))
    assert await response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.parametrize("blacklist_type", [['refresh'], ['refresh', 'access']])
@pytest.mark.asyncio
async def test_blacklisted_refresh_token(app, blacklist_type):
    jwt = get_jwt_manager(app)
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = blacklist_type

    @jwt.token_in_blacklist_loader
    def check_blacklisted(decrypted_token):
        return True

    async with app.test_request_context("/protected"):
        refresh_token = create_refresh_token('username')

    test_client = app.test_client()
    response = await test_client.get('/refresh_protected', headers=make_headers(refresh_token))
    assert await response.get_json() == {'msg': 'Token has been revoked'}
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_no_blacklist_callback_method_provided(app):
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']

    async with app.test_request_context("/protected"):
        access_token = create_access_token('username')

    test_client = app.test_client()
    response = await test_client.get('/protected', headers=make_headers(access_token))
    assert response.status_code == 500


@pytest.mark.asyncio
async def test_revoked_token_of_different_type(app):
    jwt = get_jwt_manager(app)
    test_client = app.test_client()

    @jwt.token_in_blacklist_loader
    def check_blacklisted(decrypted_token):
        return True

    async with app.test_request_context("/protected"):
        access_token = create_access_token('username')
        refresh_token = create_refresh_token('username')

    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']
    response = await test_client.get('/refresh_protected', headers=make_headers(refresh_token))
    assert await response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200

    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['refresh']
    response = await test_client.get('/protected', headers=make_headers(access_token))
    assert await response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_custom_blacklisted_message(app):
    jwt = get_jwt_manager(app)

    @jwt.token_in_blacklist_loader
    def check_blacklisted(decrypted_token):
        return True

    @jwt.revoked_token_loader
    def custom_error():
        return jsonify(baz='foo'), 404

    async with app.test_request_context("/protected"):
        access_token = create_access_token('username')

    test_client = app.test_client()
    response = await test_client.get('/protected', headers=make_headers(access_token))
    assert await response.get_json() == {'baz': 'foo'}
    assert response.status_code == 404
