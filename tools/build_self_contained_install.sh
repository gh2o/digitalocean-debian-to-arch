#!/bin/bash

set -eu
set -o pipefail

cd "$(dirname "${0}")"
cd ..

. aur/PKGBUILD

cat components/base-install.sh
tar -Jch -C aur PKGBUILD "${source[@]}" \
    --format=ustar --sort=name --mtime=@0 --owner=:0 --group=:0 | base64
