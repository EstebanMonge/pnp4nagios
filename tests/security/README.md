# Security test series

Black-box tests that run the real PNP4Nagios + vendored Kohana 2.3.4 under PHP
inside a throwaway container (no network, repo mounted read-only) and attack it
over HTTP.

    tests/security/run.sh        # PHP 8.4 (default)
    tests/security/run.sh 8.2    # any php:<version>-cli tag

Needs `podman` (and the php image, pulled once). Exit status is non-zero if any
test fails. Each test asserts the SECURE behaviour, so a FAIL is a real weakness
(or a regression once fixed). `control:` tests prove the XSS checks actually hit
a reflection point, so a pass is not vacuous.

Fixtures live in `fixtures/`: a legit host, a hostile-name host (stored XSS) and
a decoy XML outside the RRD base (path traversal). The server runs with
`display_errors=0` at start-up like a production PHP-FPM; `index.php` then
re-enables it itself, exactly as in a real install.
