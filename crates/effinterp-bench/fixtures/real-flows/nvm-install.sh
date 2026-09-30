#!/usr/bin/env bash

nvm_download() {
  command curl --fail --compressed -q "$@"
}

install_nvm() {
  nvm_download -s https://github.com/nvm-sh/nvm/archive/v0.40.3.tar.gz -o /tmp/nvm.tar.gz
}

install_nvm
