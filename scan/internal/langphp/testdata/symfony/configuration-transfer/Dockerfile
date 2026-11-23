FROM scratch
WORKDIR /srv/app
COPY . /srv/app
COPY nginx/site.conf /etc/nginx/conf.d/site.conf
RUN set -eu; chmod 777 /srv/app/jobs/report.sh; chown -R web /srv/app/tasks
RUN crontab /srv/app/schedule/crontab
