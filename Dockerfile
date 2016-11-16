FROM ubuntu:15.10

RUN apt-get update && apt-get install -y \
  ca-certificates \
  g++ \
  python \
  libevent-dev \
  libglib2.0-0 \
  libicu-dev \
  libssl-dev

RUN mkdir subzone
COPY . subzone

WORKDIR /subzone
RUN third_party/depot_tools/download_from_google_storage --bucket chromium-gn \
  -s build/tools/gn.sha1
RUN build/tools/gn gen out && third_party/depot_tools/ninja -C out
RUN out/crypto_test
