import jwt

from quart_jwt_extended.config import config


async def encode_token(app, token_data, headers=None):
    async with app.test_request_context("/protected"):
        token = jwt.encode(
            token_data,
            config.decode_key,
            algorithm=config.algorithm,
            json_encoder=config.json_encoder,
            headers=headers
        )
        return token.decode('utf-8')


def get_jwt_manager(app):
    return app.extensions['quart-jwt-extended']


def make_headers(jwt):
    return {'Authorization': 'Bearer {}'.format(jwt)}
