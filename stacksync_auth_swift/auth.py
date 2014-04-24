from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from stacksync_oauth.provider import AuthProvider
from stacksync_oauth.validator import AuthValidator
from swift.common.middleware.acl import clean_acl
from swift.common.swob import HTTPForbidden, HTTPUnauthorized, HTTPBadRequest
from swift.common.utils import get_logger


class StackSyncAuth(object):
    def __init__(self, app, conf):
        self.app = app
        self.host = conf.get('psql_host', 'localhost').lower()
        self.port = conf.get('psql_port', 5432)
        self.dbname = conf.get('psql_dbname', 'stacksync')
        self.user = conf.get('psql_user', 'postgres')
        self.password = conf.get('psql_password', 'postgres')
        self.logger = get_logger(conf, log_route='stacksync_auth')

        dbsession = scoped_session(sessionmaker())
        engine = create_engine("postgresql://%s:%s@%s/%s", self.user, self.password, self.host, self.dbname)
        dbsession.configure(bind=engine, autoflush=False, expire_on_commit=False)
        #Base.metadata.drop_all(engine)
        #Base.metadata.create_all(engine)
        validator = AuthValidator(dbsession)
        self.provider = AuthProvider(validator)

        self.logger.info('StackSync Auth: __init__: OK')

    def __call__(self, environ, start_response):

        self.logger.info('StackSync Auth: __call__: %r', environ)

        if environ.get('STACKSYNC_API'):
            # Handle anonymous access to accounts I'm the definitive
            # auth for.
            environ['swift.authorize_override'] = True
            environ['swift.authorize'] = self.authorize
            environ['swift.clean_acl'] = clean_acl

        return self.app(environ, start_response)

    def authorize(self, req):

        self.logger.info('StackSync Auth: authorize: split path: %r', req.split_path)

        h, b, s = self.provider.create_request_token_response(req.url, http_method=req.method, body=req.body,
                                                              headers=req.headers)

        self.logger.info('StackSync Auth: authorize: request token: h=%s, b=%s, s=%s', h, b, s)

        if s == 400:
            return HTTPBadRequest(body=b, headers=h)
        elif s == 401:
            return HTTPUnauthorized(body=b, headers=h)

        return None

    def denied_response(self, req):
        """Deny WSGI Response.

        Returns a standard WSGI response callable with the status of 403 or 401
        depending on whether the REMOTE_USER is set or not.
        """
        if req.remote_user:
            return HTTPForbidden(request=req)
        else:
            return HTTPUnauthorized(request=req)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return StackSyncAuth(app, conf)

    return auth_filter