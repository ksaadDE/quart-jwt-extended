import pytest
from quart import Quart, jsonify

from quart_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_claims,
    decode_token, jwt_refresh_token_required, create_refresh_token
)
from tests.utils import get_jwt_manager, make_headers


@pytest.fixture(scope='function')
def app():
    app = Quart(__name__)
    app.config['JWT_SECRET_KEY'] = 'foobarbaz'
    JWTManager(app)

    @app.route('/protected', methods=['GET'])
    @jwt_required
    async def get_claims():
        return jsonify(get_jwt_claims())

    @app.route('/protected2', methods=['GET'])
    @jwt_refresh_token_required
    async def get_refresh_claims():
        return jsonify(get_jwt_claims())

    return app


@pytest.mark.asyncio
async def test_user_claim_in_access_token(app):
    jwt = get_jwt_manager(app)

    @jwt.user_claims_loader
    def add_claims(identity):
        return {'foo': 'bar'}

    async with app.test_request_context("/protected"):
        access_token = create_access_token('username')

    test_client = app.test_client()
    response = await test_client.get('/protected', headers=make_headers(access_token))
    assert await response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_non_serializable_user_claims(app):
    jwt = get_jwt_manager(app)

    @jwt.user_claims_loader
    def add_claims(identity):
        return app

    with pytest.raises(TypeError):
        async with app.test_request_context("/protected"):
            create_access_token('username')


@pytest.mark.asyncio
async def test_token_from_complex_object(app):
    class TestObject:
        def __init__(self, username):
            self.username = username

    jwt = get_jwt_manager(app)

    @jwt.user_claims_loader
    def add_claims(test_obj):
        return {'username': test_obj.username}

    @jwt.user_identity_loader
    def add_claims(test_obj):
        return test_obj.username

    async with app.test_request_context("/protected"):
        access_token = create_access_token(TestObject('username'))

        # Make sure the changes appear in the token
        decoded_token = decode_token(access_token)
        assert decoded_token['identity'] == 'username'
        assert decoded_token['user_claims'] == {'username': 'username'}

    test_client = app.test_client()
    response = await test_client.get('/protected', headers=make_headers(access_token))
    assert await response.get_json() == {'username': 'username'}
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_user_claims_with_different_name(app):
    jwt = get_jwt_manager(app)
    app.config['JWT_USER_CLAIMS'] = 'banana'

    @jwt.user_claims_loader
    def add_claims(identity):
        return {'foo': 'bar'}

    async with app.test_request_context("/protected"):
        access_token = create_access_token('username')

        # Make sure the name is actually different in the token
        decoded_token = decode_token(access_token)
        assert decoded_token['banana'] == {'foo': 'bar'}

    # Make sure the correct data is returned to us from the full call
    test_client = app.test_client()
    response = await test_client.get('/protected', headers=make_headers(access_token))
    assert await response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_user_claim_not_in_refresh_token(app):
    jwt = get_jwt_manager(app)

    @jwt.user_claims_loader
    def add_claims(identity):
        return {'foo': 'bar'}

    async with app.test_request_context("/protected"):
        refresh_token = create_refresh_token('username')

    test_client = app.test_client()
    response = await test_client.get('/protected2', headers=make_headers(refresh_token))
    assert await response.get_json() == {}
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_user_claim_in_refresh_token(app):
    app.config['JWT_CLAIMS_IN_REFRESH_TOKEN'] = True
    jwt = get_jwt_manager(app)

    @jwt.user_claims_loader
    def add_claims(identity):
        return {'foo': 'bar'}

    async with app.test_request_context("/protected"):
        refresh_token = create_refresh_token('username')

    test_client = app.test_client()
    response = await test_client.get('/protected2', headers=make_headers(refresh_token))
    assert await response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_user_claim_in_refresh_token_specified_at_creation(app):
    app.config['JWT_CLAIMS_IN_REFRESH_TOKEN'] = True

    async with app.test_request_context("/protected"):
        refresh_token = create_refresh_token('username', user_claims={'foo': 'bar'})

    test_client = app.test_client()
    response = await test_client.get('/protected2', headers=make_headers(refresh_token))
    assert await response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_user_claims_in_access_token_specified_at_creation(app):
    async with app.test_request_context("/protected"):
        access_token = create_access_token('username', user_claims={'foo': 'bar'})

    test_client = app.test_client()
    response = await test_client.get('/protected', headers=make_headers(access_token))
    assert await response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_user_claims_in_access_token_specified_at_creation_override(app):
    jwt = get_jwt_manager(app)

    @jwt.user_claims_loader
    def add_claims(identity):
        return {'default': 'value'}

    async with app.test_request_context("/protected"):
        access_token = create_access_token('username', user_claims={'foo': 'bar'})

    test_client = app.test_client()
    response = await test_client.get('/protected', headers=make_headers(access_token))
    assert await response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200
