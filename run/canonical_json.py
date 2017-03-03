#!/usr/bin/env python

import canonicaljson
import json
import os
import sys

if __name__ == '__main__':
    with os.fdopen(sys.stdin.fileno(), 'rb') as f:
        bytes_in = f.read()

    bytes_out = canonicaljson.encode_canonical_json(json.loads(bytes_in.decode('utf-8')))

    with os.fdopen(sys.stdout.fileno(), 'wb') as f:
        f.write(bytes_out)
        f.flush()
