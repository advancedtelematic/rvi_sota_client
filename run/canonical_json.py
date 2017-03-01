#!/usr/bin/env python

import canonicaljson
import os
import sys

if __name__ == '__main__':
    with os.fdopen(sys.stdin.fileno(), 'rb') as f:
        bytes_in = fd.read()

    bytes_out = canonicaljson.encode_canonical_json(d)

    with os.fdopen(sys.stdout.fileno(), 'wb') as f:
        f.write(bytes_out)
        f.flush()
