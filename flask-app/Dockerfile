FROM python:3
MAINTAINER Eddie Bugg "Ralph.Bugg@anthem.com"

#RUN apt-get update -y
#RUN apt-get install -y python3 python3-dev python3-pip nginx
#RUN apt-get install -y nginx

ENV APP_DIR /app

# Create a config directory and copy the ini file there to launch
COPY . $APP_DIR
WORKDIR $APP_DIR

# The port uWSGI will listen on
EXPOSE 5000

RUN pip install --trusted-host files.pythonhosted.org --trusted-host pypi.org --trusted-host pypi.python.org -r requirements.txt

CMD ["uwsgi", "--ini", "app.ini"]

