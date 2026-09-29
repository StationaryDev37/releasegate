FROM rust:1.90-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home releasegate && mkdir -p /data && chown releasegate:releasegate /data
USER releasegate
WORKDIR /data
COPY --from=build /src/target/release/releasegate /usr/local/bin/releasegate
ENV RELEASEGATE_BIND=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/releasegate"]
