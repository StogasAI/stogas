# The same compiler image is used by local rebuilds and GitHub builds.
FROM ghcr.io/rust-cross/cargo-zigbuild:0.23.4@sha256:d8313491ec5798de0633fdc1c5753761bff79967bea69076020dc78121b2cca8 AS zig
FROM node:24.14.1-bookworm-slim@sha256:b506e7321f176aae77317f99d67a24b272c1f09f1d10f1761f2773447d8da26c AS node
FROM ghcr.io/rust-cross/cargo-xwin:0.23.1@sha256:9856b895265d4966f212228ba64802cf89337e2a2a537aa2533c1b8784cbc81b AS common
COPY --from=zig /usr/local/zig-x86_64-linux-0.16.0 /usr/local/zig-x86_64-linux-0.16.0
COPY --from=zig /usr/local/cargo/bin/cargo-zigbuild /usr/local/cargo/bin/cargo-zigbuild
RUN ln -s /usr/local/zig-x86_64-linux-0.16.0/zig /usr/local/bin/zig
RUN rustup set auto-self-update disable && rustup toolchain install 1.97.1 --profile minimal --component llvm-tools-preview && rustup default 1.97.1
RUN curl --fail --location --silent --show-error \
    https://files.pythonhosted.org/packages/fe/91/b495e19e2f5c503b540452b2039115e7b2363867e8c5ad4179eb752fa92c/maturin-1.15.0-py3-none-manylinux_2_12_x86_64.manylinux2010_x86_64.musllinux_1_1_x86_64.whl \
    --output /tmp/maturin.whl && \
    echo '653020a63525bb224e5ab0adf02e17a2e08bc86dbea7fc1399c9a56d7529b99e  /tmp/maturin.whl' | sha256sum --check && \
    python3 -c 'import zipfile; z=zipfile.ZipFile("/tmp/maturin.whl"); p=next(p for p in z.namelist() if p.endswith(".data/scripts/maturin")); open("/usr/local/bin/maturin", "wb").write(z.read(p))' && \
    chmod 755 /usr/local/bin/maturin && rm /tmp/maturin.whl
ENV TZ=UTC LC_ALL=C.UTF-8 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4
WORKDIR /build/source
ENTRYPOINT ["python3", "release/build_native.py"]

FROM common AS linux
RUN rustup target add --toolchain 1.97.1 \
    x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
    x86_64-unknown-linux-musl aarch64-unknown-linux-musl

FROM common AS windows
ADD --checksum=sha256:87336eba53b4acfe917424ab5d500d2b0054d9f5148d35c2273ccf2cfb712f0d https://www.nasm.us/pub/nasm/releasebuilds/3.02/nasm-3.02.tar.xz /tmp/nasm.tar.xz
RUN tar -xJf /tmp/nasm.tar.xz -C /tmp && cd /tmp/nasm-3.02 && \
    ./configure && make -j4 nasm && install -m755 nasm /usr/local/bin/nasm && \
    rm -rf /tmp/nasm-3.02 /tmp/nasm.tar.xz
RUN rustup target add --toolchain 1.97.1 \
    x86_64-pc-windows-msvc aarch64-pc-windows-msvc \
    x86_64-pc-windows-gnullvm aarch64-pc-windows-gnullvm
ENV XWIN_VERSION=17 XWIN_SDK_VERSION=10.0.26100 XWIN_CRT_VERSION=14.44.17.14 XWIN_ARCH=x86_64,aarch64 XWIN_CACHE_DIR=/opt/xwin
RUN cargo xwin cache xwin
ADD --checksum=sha256:5f9c6ed95b2d4bdb2869a488c5fd5857fbdabcf288a0aa3eb1da43f6a08d8ab4 https://github.com/mstorsjo/llvm-mingw/releases/download/20261006/llvm-mingw-20261006-ucrt-ubuntu-22.04-x86_64.tar.xz /tmp/llvm-mingw.tar.xz
RUN mkdir /opt/llvm-mingw && tar -xJf /tmp/llvm-mingw.tar.xz --strip-components=1 -C /opt/llvm-mingw && rm /tmp/llvm-mingw.tar.xz

FROM common AS android
RUN rustup target add --toolchain 1.97.1 aarch64-linux-android x86_64-linux-android
RUN cargo install cargo-ndk --version 4.1.2 --locked
ADD --checksum=sha256:753611f410d002cfcd3f3dc2ef49aad532089d3180b436c060a90bf0fcb64df2 https://dl.google.com/android/repository/android-ndk-r30-linux.zip /tmp/ndk.zip
RUN unzip -q /tmp/ndk.zip -d /opt && rm /tmp/ndk.zip
ENV ANDROID_NDK_HOME=/opt/android-ndk-r30

FROM common AS portable
COPY --from=node /usr/local/ /usr/local/
RUN rustup target add --toolchain 1.97.1 wasm32-unknown-unknown
RUN cargo install wasm-bindgen-cli --version 0.2.129 --locked
ENTRYPOINT ["python3", "release/build_portable.py"]
