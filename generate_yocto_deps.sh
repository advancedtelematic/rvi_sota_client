#!/bin/sh

cat Cargo.lock | sed -e '1,/metadata/ d' Cargo.lock | awk '{print "crate://crates.io/"$2 "/" $3"\\"}'
