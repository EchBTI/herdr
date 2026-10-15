# Opt-in disposable test image. Build from the repository root:
# docker build -f scripts/shared-access-test.Dockerfile -t herdr-shared-test .
# docker run --rm -e HERDR_SHARED_TEST_DISPOSABLE=1 herdr-shared-test
FROM rust:1.96.1-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl xz-utils pkg-config clang python3 procps \
    && rm -rf /var/lib/apt/lists/*
# Zig archive checksums verified against https://ziglang.org/download/index.json
# Version and architecture are explicit; never accept an unverified archive.
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      arm64) zig_arch=aarch64; zig_sha=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17 ;; \
      amd64) zig_arch=x86_64; zig_sha=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00 ;; \
      *) echo 'Unsupported qualification architecture' >&2; exit 1 ;; \
    esac; \
    curl --fail --location --retry 3 \
      "https://ziglang.org/download/0.16.0/zig-${zig_arch}-linux-0.16.0.tar.xz" \
      -o /tmp/zig.tar.xz; \
    echo "${zig_sha}  /tmp/zig.tar.xz" | sha256sum -c -; \
    mkdir /opt/zig; \
    tar -xJf /tmp/zig.tar.xz --strip-components=1 -C /opt/zig; \
    rm -f /tmp/zig.tar.xz
ENV PATH="/opt/zig:${PATH}"
WORKDIR /work
COPY . /work
RUN cargo build --locked --bin herdr
ENV HERDR_SHARED_TEST_BINARY=/work/target/debug/herdr
# Qualify the scoped broker and the normal native Herdr TUI under real OS UIDs.
CMD ["sh", "-c", "python3 scripts/test_shared_access.py && python3 scripts/test_shared_access_native.py"]
