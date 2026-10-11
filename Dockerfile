# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p rex-cli --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/rex /usr/local/bin/rex
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/rex"]
CMD ["--help"]
