import datetime
import os

from api.apps import create_app

app = create_app(os.getenv('FLASK_CONFIG') or 'develop')

