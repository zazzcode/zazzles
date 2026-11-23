FROM scratch
RUN echo "*/5 * * * * root cd /srv/site && sh tools/tick.sh" > /etc/cron.d/site
