import os
import random
import urllib
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from stacksync_oauth.provider import AuthProvider
from stacksync_oauth.validator import AuthValidator
from swift.common.middleware.acl import clean_acl
from swift.common.swob import HTTPUnauthorized, HTTPBadRequest, HTTPOk, Response, HTTPMethodNotAllowed, \
    HTTPInternalServerError, HTTPMovedPermanently
from swift.common.utils import get_logger
from oauthlib.common import urldecode
from keystoneclient.v2_0 import client as client_v2
from keystoneclient.v3 import client as client_v3
import jinja2


class StackSyncAuth(object):
    def __init__(self, app, conf):
        self.app = app
        self.host = conf.get('psql_host', 'localhost').lower()
        self.port = conf.get('psql_port', 5432)
        self.dbname = conf.get('psql_dbname', 'stacksync')
        self.user = conf.get('psql_user', 'postgres')
        self.password = conf.get('psql_password', 'postgres')
        self.tenant = conf.get('tenant', 'stacksync')
        self.keystone_host = conf.get('keystone_host', 'localhost').lower()
        self.keystone_port = conf.get('keystone_port', 5000)
        self.keystone_version = conf.get('keystone_version', '2.0')
        self.templates_path = conf.get('templates_path', '')
        self.logger = get_logger(conf, log_route='stacksync_auth')

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

        if environ.get('HTTP_STACKSYNC_API') or environ.get('PATH_INFO') == '/oauth/authorize':
            self.logger.info('StackSync Auth: __call__: STACKSYNC-API ON')
            # Handle anonymous access to accounts I'm the definitive
            # auth for.
            environ['swift.authorize_override'] = True
            environ['swift.authorize'] = self.authorize
            environ['swift.clean_acl'] = clean_acl

        return self.app(environ, start_response)

    def authorize(self, req):

        self.logger.info('StackSync Auth: authorize: path info: %s', req.path_info)

        if req.path_info.endswith("/request_token"):
            response = self.__request_token(req)
        elif req.path_info.endswith("/access_token"):
            response = self.__access_token(req)
        elif req.path_info.endswith("/authorize"):
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
        h, b, s = self.provider.create_access_token_response(req.url, http_method=req.method, body=req.body,
                                                             headers=req.headers)
        return Response(body=b, status=s, headers=h)

    def __authorize(self, req):
        self.logger.info('StackSync Auth: authorize: authorize request')
        headers = {}
        if 'Cookie' not in req.headers:
            self.logger.info('StackSync Auth: Cookie not found. Creating one...')
            session_id = '%032x' % random.getrandbits(128)
            headers['Set-Cookie'] = 'ssid=%s' % session_id
        else:
            headers['Cookie'] = req.headers['Cookie']

        self.logger.info('StackSync Auth: authorize: params: %r' % req.params)

        if 'oauth_token' not in req.params:
            return HTTPBadRequest(body='Missing oauth token')

        token = req.params['oauth_token']
        result = self.provider.verify_authorize_request(token)
        if not result:
            return HTTPBadRequest(body='Invalid oauth token')

        request_token, consumer = result

        if req.method == 'GET':
            body = self.__render_authorize_page(consumer.application_title, consumer.application_description,
                                                request_token.request_token)
            return HTTPOk(body=body, headers=headers)

        elif req.method == 'POST':

            try:
                self.logger.info('StackSync Auth: body: %s ' % (req.body, ))
                email, password, permission = self.__get_authorize_params(req)

                result = self.provider.verify_authorize_submission(request_token.request_token, email)

                if not result:
                    self.logger.info('StackSync Auth: request token or email not found')
                    body = self.__render_authorize_page(consumer.application_title, consumer.application_description,
                                                        request_token.request_token, error='Invalid user or password')
                    return HTTPOk(body=body, headers=headers)

                user, token, consumer = result
                self.logger.info('StackSync Auth: request token and email successfully verified')

                if self.keystone_version == '2' or '2.0':
                    logged_in = self.__login_keystone_v2(user.swift_user, password)
                elif self.keystone_version == '3':
                    logged_in = self.__login_keystone_v3(user.swift_user, password)
                else:
                    return HTTPInternalServerError('Keystone version %s not implemented' % self.keystone_version)

                if not logged_in:
                    self.logger.info('StackSync Auth: login failed')
                    body = self.__render_authorize_page(consumer.application_title, consumer.application_description,
                                                        request_token.request_token, error='Invalid user or password')
                    return HTTPOk(body=body, headers=headers)

                self.logger.info('StackSync Auth: successfully logged in')

                if permission != 'allow':
                    #TODO: inform the consumer about the rejection
                    self.logger.info('StackSync Auth: user rejected authorization')
                    return HTTPOk('Authorization rejected by user')

                self.logger.info('StackSync Auth: user granted authorization')
                verifier = self.provider.authorize_request_token(request_token.request_token, user.id)

                if not verifier:
                    self.logger.info('StackSync Auth: could not create verifier')
                    body = self.__render_authorize_page(consumer.application_title, consumer.application_description,
                                                        request_token.request_token,
                                                        error='Could not generate verifier, please contact an administrator')
                    return HTTPOk(body=body, headers=headers)

                self.logger.info('StackSync Auth: verifier created successfully')

                url_params = {'token': request_token.request_token, 'verifier': verifier}
                encoded_params = urllib.urlencode(url_params)

                if request_token.redirect_uri == 'oob':
                    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                    return HTTPOk(encoded_params, headers=headers)
                else:
                    redirect_url = request_token.redirect_uri + "?" + encoded_params
                    headers = {'Location': redirect_url}
                    return HTTPMovedPermanently(headers=headers)

            except AttributeError as inst:
                self.logger.info('StackSync Auth: authorization failure: %s' % inst)
                return HTTPBadRequest(body=inst)
        else:
            return HTTPMethodNotAllowed()

    def __render_authorize_page(self, app_title, app_description, oauth_token, error=None):
        template_file = "authorize.jinja"
        template = self.template_env.get_template(template_file)
        template_vars = {"application_title": app_title,
                         "application_descr": app_description,
                         "oauth_token": oauth_token,
                         "error": error}
        body = template.render(template_vars)
        return body

    def __get_authorize_params(self, req):
        form_params_list = urldecode(req.body)
        form_params = dict(form_params_list)

        if 'email' not in form_params:
            raise AttributeError('email not found')
        if 'password' not in form_params:
            raise AttributeError('password not found')
        if 'permission' not in form_params:
            raise AttributeError('permission not found')

        return form_params['email'], form_params['password'], form_params['permission']

    def __login_keystone_v2(self, username, password):
        try:
            url = 'http://%s:%s/v2.0' % (self.keystone_host, self.keystone_port)
            client_v2.Client(username=username, password=password, tenant_name=self.tenant, auth_url=url)
            return True
        except:
            return False

    def __login_keystone_v3(self, username, password):
        try:
            url = 'http://%s:%s/v3' % (self.keystone_host, self.keystone_port)
            client_v3.Client(username=username, password=password, tenant_name=self.tenant, auth_url=url)
            return True
        except:
            return False

    def __protected_resource(self, req):
        self.logger.info('StackSync Auth: authorize: protected resource request')
        valid, oauth_info = self.provider.validate_protected_resource_request(req.url, http_method=req.method,
                                                                              body=req.body,
                                                                              headers=req.headers)
        if valid:
            req.environ['stacksync_user_id'] = oauth_info.user.id
            req.environ['stacksync_user_account'] = oauth_info.user.swift_account
            self.logger.info('StackSync Auth: authorize: Valid request')
            return None
        self.logger.info('StackSync Auth: authorize: Invalid request')
        return HTTPUnauthorized('Could not authorize request')


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return StackSyncAuth(app, conf)

    return auth_filter
