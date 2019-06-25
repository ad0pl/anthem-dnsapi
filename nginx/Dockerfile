# Dockerfile-nginx
FROM nginx:latest

# Nginx will listen on this port
EXPOSE 80

# Remove the default config file that
# /etc/nginx/nginx.conf includes
RUN rm /etc/nginx/conf.d/default.conf

# We copy the requirements file in order to install
# Python dependencies
COPY app.conf /etc/nginx/conf.d
COPY testcert.crt /etc/nginx/certs/cert.pem
COPY testcert.key /etc/nginx/certs/cert.key

RUN touch /usr/share/nginx/html/favicon.ico
COPY html2/index.html /usr/share/nginx/html/
COPY anthem-dnsapi-v1.0.json /usr/share/nginx/html/
COPY anthem-dnsapi-v1.0.yaml /usr/share/nginx/html/
