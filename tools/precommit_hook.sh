#!/bin/bash

set -eu
set -o pipefail

cd "$(dirname "${0}")"
while [ ! -e PKGBUILD ]; do cd ..; done
exec >&2

check_sha256sums() {
    local expected
    local calculated
    echo -n ">>> Checking PKGBUILD sha256sums ... "
    (
        . PKGBUILD

        if [ ${#source[@]} -ne ${#sha256sums[@]} ]; then
            echo "!!! Wrong number of sha256sums!"
            exit 1
        fi

        for i in $(eval "echo {1..${#source[@]}}"); do
            (( i-- ))
            expected=${sha256sums[$i]}
            calculated=$(sha256sum ${source[$i]} | cut -d' ' -f1)
            if [ $expected != $calculated ]; then
                echo "!!! Wrong checksum on ${source[$i]}!"
                exit 1
            fi
        done
    )
    echo "OK!"
}

check_install_sh() {
    echo -n ">>> Generating install.sh ... "
    ./tools/build_self_contained_install.sh > install.sh
    git add install.sh
    echo "OK!"
}

echo ">>> PRECOMMIT CHECK"

check_sha256sums
check_install_sh

echo ">>> PRECOMMIT OK"
