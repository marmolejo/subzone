Clone this repository with:

```git clone --recursive```

to pull all dependencies as well. If you already have cloned this repository
non recursively, just do a:

```git submodule update --init --recursive```

### Tests
Note that the only supported platform is Ubuntu 14.10 on x86_64. First, you
need to install libevent-dev and libicu-dev:

```sudo apt-get install libevent-dev libicu-dev```

To build the tests, first download GN, then build the system.

```
cd subzone/
third_party/depot_tools/download_from_google_storage \
  --bucket chromium-gn -s build/tools/gn.sha1
build/tools/gn gen out
third_party/depot_tools/ninja -C out
```

This will generate a binary file **out/crypto_test**, which contain all tests.
