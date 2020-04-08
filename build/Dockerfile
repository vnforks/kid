FROM alpine:3.11

# Some ENV variables
ENV PATH="/kid/bin:${PATH}"
ARG PUID=2000
ARG PGID=2000
ARG K_PACKAGE="https://releases.mattermost.com/5.18.1/mattermost-5.18.1-linux-amd64.tar.gz"


# Install some needed packages
RUN apk add --no-cache \
  ca-certificates \
  curl \
  libc6-compat \
  libffi-dev \
  linux-headers \
  mailcap \
  netcat-openbsd \
  xmlsec-dev \
  tzdata \
  && rm -rf /tmp/*

# Get Mattermost
RUN mkdir -p /kid/data \
  && if [ ! -z "$K_PACKAGE" ]; then curl $K_PACKAGE | tar -xvz ; \
  else echo "please set the K_PACKAGE" ; fi \
  && addgroup -g ${PGID} kid \
  && adduser -D -u ${PUID} -G kid -h /kid -D kid \
  && chown -R kid:kid /kid

USER kid

#Healthcheck to make sure container is ready
HEALTHCHECK --interval=5m --timeout=3s \
  CMD curl -f http://localhost:8065/api/v4/system/ping || exit 1


# Configure entrypoint and command
COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
WORKDIR /kid
CMD ["kid"]

EXPOSE 8065 8067 8074 8075

# Declare volumes for mount point directories
VOLUME ["/kid/data", "/kid/logs", "/kid/config"]
