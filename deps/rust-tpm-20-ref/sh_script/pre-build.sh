#!/bin/bash

patch_mstpm20ref() {
    # apply the patch set for ms-tpm-20-ref
    pushd ms-tpm-20-ref
    git reset --hard d638536
    git clean -f -d
    patch -p 1 -i ../patches/nv.diff
    popd
}

patch_mstpm20ref
