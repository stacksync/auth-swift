import os
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from stacksync_oauth.provider import AuthProvider
from stacksync_oauth.validator import AuthValidator
from swift.common.middleware.acl import clean_acl
from swift.common.swob import HTTPForbidden, HTTPUnauthorized, HTTPBadRequest, HTTPOk, Response, HTTPMethodNotAllowed
from swift.common.utils import get_logger
import jinja2


class StackSyncAuth(object):

    def __init__(self, app, conf):
        self.app = app
        self.host = conf.get('psql_host', 'localhost').lower()
        self.port = conf.get('psql_port', 5432)
        self.dbname = conf.get('psql_dbname', 'stacksync')
        self.user = conf.get('psql_user', 'postgres')
        self.password = conf.get('psql_password', 'postgres')
        self.logger = get_logger(conf, log_route='stacksync_auth')
        self.templates_path = conf.get('templates_path', '')

        if not os.path.isdir(self.templates_path):
            raise Exception('Templates path does not exists')

        template_loader = jinja2.FileSystemLoader(searchpath=self.templates_path)
        self.template_env = jinja2.Environment(loader=template_loader)

        dbsession = scoped_session(sessionmaker())
        engine = create_engine("postgresql://%s:%s@%s/%s" % (self.user, self.password, self.host, self.dbname))

        # Try to connect, it will raise an exception if not possible
        connection = engine.connect()
        connection.close()

        dbsession.configure(bind=engine, autoflush=False, expire_on_commit=False)
        #Base.metadata.drop_all(engine)
        #Base.metadata.create_all(engine)
        validator = AuthValidator(dbsession)
        self.provider = AuthProvider(validator)

        self.logger.info('StackSync Auth: __init__: OK')

    def __call__(self, environ, start_response):

        self.logger.info('StackSync Auth: __call__: %r', environ)

        if environ.get('HTTP_STACKSYNC_API'):
            self.logger.info('StackSync Auth: __call__: STACKSYNC-API ON')
            # Handle anonymous access to accounts I'm the definitive
            # auth for.
            environ['swift.authorize_override'] = True
            environ['swift.authorize'] = self.authorize
            environ['swift.clean_acl'] = clean_acl

        return self.app(environ, start_response)

    def authorize(self, req):

        self.logger.info('StackSync Auth: authorize: path info: %s', req.path_info)

        if req.path_info == '/request_token':
            response = self.__request_token(req)
        elif req.path_info == '/access_token':
            response = self.__access_token(req)
        elif req.path_info == '/authorize':
            response = self.__authorize(req)
        else:
            response = self.__protected_resource(req)

        return response

    def __request_token(self, req):
        self.logger.info('StackSync Auth: authorize: request token request')
        h, b, s = self.provider.create_request_token_response(req.url, http_method=req.method, body=req.body,
                                                              headers=req.headers)
        return Response(body=b, status=s, headers=h)

    def __access_token(self, req):
        self.logger.info('StackSync Auth: authorize: access token request')
        credentials = {'user_id': '1'}
        h, b, s = self.provider.create_request_token_response(req.url, http_method=req.method, body=req.body,
                                                              headers=req.headers, credentials=credentials)
        return Response(body=b, status=s, headers=h)

    def __authorize(self, req):
        self.logger.info('StackSync Auth: authorize: authorize request')

        if req.method == 'GET':
            template_file = "authorize.jinja"
            template = self.template_env.get_template(template_file)
            template_vars = {"application_title": "Titulo de la app",
                             "application_descr": "Descripcion de la app.... bla bla bla..."}

            body = template.render(template_vars)
            return HTTPOk(body=body)

        elif req.method == 'POST':
            b = 'Authorize page'
            return HTTPOk(body=b)
        else:
            return HTTPMethodNotAllowed()

    def __protected_resource(self, req):
        self.logger.info('StackSync Auth: authorize: protected resource request')
        valid, _ = self.provider.validate_protected_resource_request(req.url, http_method=req.method, body=req.body,
                                                                     headers=req.headers)
        if valid:
            return None
        return HTTPUnauthorized()

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
