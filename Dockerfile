FROM alpine:latest
RUN apk add --no-cache ca-certificates && \
    adduser -D -g '' appuser
COPY yrfy /yrfy
USER appuser
ENTRYPOINT ["/yrfy"]
