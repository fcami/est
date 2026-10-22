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

## Logging client authentication

For every request that reaches the Basic authentication check, estserver
logs a "Client authentication" line. These are the requests to
`/healthcheck` and to the EST POST endpoints (`/simpleenroll`,
`/simplereenroll`, `/serverkeygen` and `/tpmenroll`), with or without an
additional path segment, except those the server turns away earlier: with
the `allowed_hosts` list, the rate limit, routing (404 and 405) or a wrong
Content-Type. `/cacerts` and `/csrattrs` get no such line.

Its "Authorization Presented" field says whether the request had an
Authorization header, whatever its scheme or whether it could be decoded.
"Basic Auth User" holds the user name of HTTP Basic credentials, and is empty
if there were none or they could not be decoded. "Client Certificate" holds
the Subject of the TLS client certificate, if there was one. The password is
never logged. The user name is, whether or not authentication succeeds, so a
password typed into the user name field ends up in the log; treat the log as
sensitive. The line carries the same "HTTP Request ID" as the "HTTP request"
line of the same request, so a client's test suite can check from the log
that a re-enrollment authenticated with its certificate and sent no password.
