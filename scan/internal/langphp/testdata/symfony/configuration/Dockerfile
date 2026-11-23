FROM scratch
WORKDIR /srv/site
COPY . /srv/site
COPY deploy/site.conf /etc/apache2/conf-enabled/site.conf
COPY deploy/env.stage /srv/site/.env.local
RUN chown web:web /srv/site/tools/job.php
RUN echo "*/5 * * * * root cd /srv/site && sh tools/tick.sh" > /etc/cron.d/site
