FROM rust:1.73-bullseye as builder
RUN apt-get update
RUN apt-get install -y libssl-dev libudev-dev pkg-config zlib1g-dev llvm clang cmake make libprotobuf-dev protobuf-compiler
WORKDIR /solana-build
COPY . .
RUN cargo build --release

FROM debian:bullseye-20230522 as runtime
RUN apt-get update
RUN apt-get install -y bzip2
COPY --from=builder --chmod=700 /solana-build/target/release /usr/local/bin

WORKDIR /solana
ENTRYPOINT ["solana-test-validator"]
