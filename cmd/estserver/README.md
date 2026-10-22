# estserver

Application estserver is a basic EST server for testing purposes.

## Requiring a password to enroll

By default, estserver accepts enrollment requests without credentials. To
require HTTP Basic Authentication for `/simpleenroll`, with or without an
additional path segment, add an `enroll_basic_auth` section to the
configuration file:

    "enroll_basic_auth": {
        "username": "enroller",
        "password_file": "/path/to/enroll/password.txt"
    }

The password is read from the file when estserver starts, without trailing
CR and LF characters. No other endpoint is affected: `/simplereenroll` still
requires a TLS client certificate, and `/serverkeygen`, `/tpmenroll`,
`/csrattrs` and `/healthcheck` are unchanged.
