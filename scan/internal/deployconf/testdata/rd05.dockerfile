FROM scratch
WORKDIR /srv/site
COPY . /srv/site
COPY deploy/env.prod /srv/site/.env.local
