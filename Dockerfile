# The binary is copied in rather than compiled here, so the image ships the
# exact artifact the release archives contain.
#
# GoReleaser lays the build context out as <os>/<arch>/yrfy and buildx sets
# TARGETPLATFORM to match, which is how one Dockerfile serves both platforms.
#
# The base image is pinned so a rebuild of an old tag produces the same image,
# and so Dependabot can propose the upgrade rather than it arriving unannounced.
FROM alpine:3.24
RUN apk add --no-cache ca-certificates && \
    adduser -D -g '' appuser

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/yrfy /yrfy

USER appuser
ENTRYPOINT ["/yrfy"]
