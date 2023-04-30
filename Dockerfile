FROM rust as builder
WORKDIR /usr/src/nestedsocks
COPY . .
RUN cargo install --path .

FROM debian:bullseye-slim
COPY --from=builder /usr/local/cargo/bin/nestedsocks /usr/local/bin/nestedsocks

EXPOSE 5000
CMD ["nestedsocks", "--listen-addr", "0.0.0.0:5000"]
