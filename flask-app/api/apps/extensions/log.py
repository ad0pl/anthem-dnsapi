import logging
from logging.handlers import RotatingFileHandler


def configure_logging(app):
    """
    Utility function to set Flask instance logging with configuration context specific levels.
    Arguments:
        app (Flask instance):
    Returns:
        (None)
    """
    # pass
    # Set base logging config based on Flask application debug mode.
    if app.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.ERROR)

    # Initialize file handler at Flask application config log file location.
    file_handler = RotatingFileHandler(app.config['LOG_FILE'], maxBytes=1000, backupCount=0)

    file_handler.setFormatter(
        logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s '
            '[in %(pathname)s:%(lineno)d]'
        )
    )

    console = logging.StreamHandler()

    if app.debug:
        file_handler.setLevel(logging.DEBUG)
        console.setLevel(logging.DEBUG)
    else:
        file_handler.setLevel(logging.ERROR)
        console.setLevel(logging.ERROR)

    # Add file handler to Flask application and various extensions.
    # TODO - configure for all extensions.
    app.logger.addHandler(file_handler)

    app_logger = logging.getLogger('api.apps')
    app_logger.setLevel(logging.INFO)
    app_logger.addHandler(file_handler)
