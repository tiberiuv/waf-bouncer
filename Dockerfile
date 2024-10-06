FROM gcr.io/distroless/base
ARG REPOSTIORY
ENV REPOSITORY=$REPOSTIORY
LABEL org.opencontainers.image.source=https://github.com/${REPOSITORY}

COPY --chown=nonroot:nonroot ./waf-bouncer /app/
USER 1000
ENTRYPOINT ["/app/waf-bouncer"]
