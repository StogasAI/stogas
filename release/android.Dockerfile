FROM ghcr.io/rust-cross/cargo-xwin:0.23.1@sha256:9856b895265d4966f212228ba64802cf89337e2a2a537aa2533c1b8784cbc81b AS sdk
ADD --checksum=sha256:bbaeb2fef8710818cf0e261201dab964c572f92b942812df0c3620d62a529a01 https://services.gradle.org/distributions/gradle-9.6.0-bin.zip /tmp/gradle.zip
ADD --checksum=sha256:37607369a28c5b640b3a7998868d45898ebcb777565a0e85f9acf36f29631d2e https://dl.google.com/android/repository/platform-36_r02.zip /tmp/platform.zip
ADD --checksum=sha256:5d9ac77fb6ff43d9da518a337b4fcf8f9097113df531d99ccefe80ef7ce8250b https://dl.google.com/android/repository/build-tools_r36_linux.zip /tmp/build-tools.zip
RUN unzip -q /tmp/gradle.zip -d /opt && \
    mkdir -p /opt/android-sdk/platforms /opt/android-sdk/build-tools && \
    unzip -q /tmp/platform.zip -d /opt/android-sdk/platforms && \
    unzip -q /tmp/build-tools.zip -d /opt/android-sdk/build-tools && \
    mv /opt/android-sdk/build-tools/android-16 /opt/android-sdk/build-tools/36.0.0 && \
    rm /tmp/gradle.zip /tmp/platform.zip /tmp/build-tools.zip
FROM maven:3.9.11-eclipse-temurin-17@sha256:e4a7ace3dc0d645ed97f8d9ad0b0d3f0b14fa8d150138f27f116d7105a639b82
COPY --from=sdk /opt/android-sdk /opt/android-sdk
COPY --from=sdk /opt/gradle-9.6.0 /opt/gradle-9.6.0
ENV ANDROID_HOME=/opt/android-sdk GRADLE_USER_HOME=/build/.gradle
ENV PATH=/opt/gradle-9.6.0/bin:$PATH
