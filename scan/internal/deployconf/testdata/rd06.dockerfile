FROM scratch
RUN a && \
    chown -R web:web /srv/site/tools
