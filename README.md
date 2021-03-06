StackSync auth middleware for Swift
===================================


## Requirements

Before installing the StackSync authentication middleware you first need to install some requirements. Although they are included in the setup.py, we show you how to install them one by one.

#### PostgreSQL client library

First, you have to install the PostgreSQL client library to communicate with the database backend.

    apt-get install libpq-dev python-dev

Now, you have to install the psycopg2 Python package.

    easy_install psycopg2 

#### SQLAlchemy

SQLAlchemy is used to map Python objects to the database.

    easy_install sqlalchemy

#### Jinja2

Jinja2 is used to render the OAuth's authorization page so that the user can grant or deny permissions to applications.

    easy_install Jinja2

#### StackSync OAuth Python library

Please, refer to the [StackSync Auth project](https://github.com/stacksync/auth) to install it.

## Installation

To install the StackSync authentication middleware for Swift you first need to install the Python package.

    python setup.py install

This will install the package after checking that the previous requirements are satisfied.

Depending on your Python installation you may also need to update other Python packages.

    pip install -U

Now we need to modify the proxy configuration. First, we add the filter to tell the proxy that the middleware should be loaded. Be sure you set up the database with the correct parameters.

    [filter:stacksync-auth-swift]
    use = egg:stacksync-auth-swift#stacksync_auth_swift
    psql_host = localhost
    psql_port = 5432
    psql_dbname = stacksync
    psql_user = stacksync_user
    psql_password = stacksync
    tenant = stacksync
    keystone_host = localhost
    keystone_post = 5000
    keystone_version = 2.0
    templates_path = /home/swift/stacksync-auth-swift/templates/

Next, we have to add the middleware to the proxy's pipeline.

    pipeline = catch_errors healthcheck proxy-logging cache bulk slo ratelimit crossdomain authtoken keystoneauth stacksync-auth-swift staticweb container-quotas account-quotas proxy-logging proxy-server

Finally, if you use Keystone, you have to delay the auth decision so that it does not interfere with the StackSync auth middleware.

    [filter:authtoken]
    paste.filter_factory = keystoneclient.middleware.auth_token:filter_factory
    ...
    delay_auth_decision = true

Now you can restart the proxy.

    swift-init proxy restart
    
