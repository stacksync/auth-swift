from setuptools import setup
import stacksync_auth_swift

setup(name='stacksync_auth_swift',
      version=stacksync_auth_swift.__version__,
      description='StackSync Authentication middleware for Swift',
      author='StackSync Team',
      author_email='info@stacksync_oauth.com',
      url='http://stacksync.org',
      packages=['stacksync_auth_swift'],
      install_requires=['stacksync_oauth>=1.0.5', 'swift>=1.4', 'sqlalchemy>=0.9.4'],
)
