Clone this repository with:

```git clone --recursive https://github.com/marmolejo/subzone```

to pull all dependencies as well. If you already have cloned this repository
non recursively, just do a:

```git submodule update --init --recursive```

### Tests
The best way to run the tests is inside a Docker container, so once installed,
run:

```docker build .```

It will automatically run the crypto tests
