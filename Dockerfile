FROM clux/muslrust:stable AS planner
RUN cargo install cargo-chef
COPY . .
RUN cargo chef prepare --recipe-path recipe.json


FROM clux/muslrust:stable AS cacher
RUN cargo install cargo-chef
COPY --from=planner /volume/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json


FROM clux/muslrust:stable AS builder
COPY . .
COPY --from=cacher /volume/target target
COPY --from=cacher /root/.cargo /root/.cargo
RUN cargo build --bin waf-bouncer --release --target x86_64-unknown-linux-musl


# Need cacerts
FROM gcr.io/distroless/static:nonroot
ARG REPOSTIORY
ENV REPOSITORY=$REPOSTIORY
LABEL org.opencontainers.image.source=https://github.com/${REPOSITORY}
COPY --from=builder --chown=nonroot:nonroot /volume/target/x86_64-unknown-linux-musl/release/waf-bouncer /app/waf-bouncer
ENTRYPOINT ["/app/waf-bouncer"]
