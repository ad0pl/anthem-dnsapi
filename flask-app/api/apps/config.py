import os

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Set environment variables if configuration.env exists.
config_path = os.path.join(basedir, 'apps/config.env')

# Assert environment configuration file exists
assert os.path.exists(config_path), "%s required." % config_path
for line in open(config_path):
    if line[0] != '#':
        var = line.strip().split('=')
        if len(var) == 2:
            os.environ[var[0]] = var[1].replace("\"", "")

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'SECRET_KEY_ENV_VAR_NOT_SET'
    PROJECT = "anthem-dnspai"
    BASE_DIR = basedir

class DevelopmentConfig(Config):
    # Flask
    ENV = 'development'
    DEBUG = True

    # Logging - https://docs.python.org/2/library/logging.html
    LOG_FILE = '/var/log/anthem-dnsapi.log'

class TestingConfig(Config):
    # Flask
    ENV = 'testing'
    DEBUG = True
    TESTING = True

    # Logging - https://docs.python.org/2/library/logging.html
    LOG_FILE = '/var/log/anthem-dnsapi.log'

class StagingConfig(Config):
    # Flask
    ENV = 'staging'

    # Logging - https://docs.python.org/2/library/logging.html
    LOG_FILE = '/var/log/anthem-dnsapi.log'

class ProductionConfig(Config):
    # Flask
    ENV = 'production'

    # Logging - https://docs.python.org/2/library/logging.html
    LOG_FILE = '/var/log/anthem-dnsapi.log'

def config_options(option):
    # Validate configuration option.
    if option not in ('develop', 'test', 'stage', 'prod'):
        raise NotImplementedError("Invalid configuration choice. Options include ('base', 'develop', 'test', 'prod')")

    return {
        'develop': DevelopmentConfig,
        'test': TestingConfig,
        'stage': StagingConfig,
        'prod': ProductionConfig,
    }[option]

