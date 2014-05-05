from setuptools import setup
import stacksync_auth_swift

setup(name='stacksync_auth_swift',
      version=stacksync_auth_swift.__version__,
      description='StackSync Authentication middleware for Swift',
      author='StackSync Team',
      author_email='info@stacksync.org',
      url='http://stacksync.org',
      packages=['stacksync_auth_swift'],
      install_requires=['stacksync_oauth>=1.0.6', 'swift>=1.4', 'sqlalchemy>=0.9.4', 'psycopg2>=2.5.0',
                        'Jinja2>=2.7.2', 'requests>=2.2.1'],
      entry_points={'paste.filter_factory': ['stacksync_auth_swift=stacksync_auth_swift.auth:filter_factory']}
)
