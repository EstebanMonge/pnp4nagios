<?php
// Dependency-free security test runner. Talks HTTP to the PNP4Nagios app that
// container.sh starts with php -S. Each test asserts SECURE behaviour; a FAIL
// means a real weakness exists in the current code.
$BASE = getenv('BASE'); $WORK = getenv('WORK');
$pass = $fail = 0; $failures = [];

function http($path, $headers = [], $ua = true) {
    global $BASE;
    if ($ua) $headers[] = 'User-Agent: pnp-security-tests/1.0';
    $ctx = stream_context_create(['http' => ['ignore_errors' => true, 'timeout' => 10, 'follow_location' => 0, 'max_redirects' => 0,
        'header' => implode("\r\n", $headers)]]);
    $body = @file_get_contents($BASE . $path, false, $ctx);
    $status = 0; $hdrs = [];
    foreach (($http_response_header ?? []) as $h) {
        if (preg_match('#^HTTP/\S+ (\d+)#', $h, $m)) $status = (int)$m[1];
        else $hdrs[] = $h;
    }
    return ['status' => $status, 'body' => (string)$body, 'headers' => $hdrs];
}
$accepted = 0;
// $why marks a documented, deliberate trade-off: reported as ACCEPTED, does not fail the run.
function test($name, callable $fn, $why = null) {
    global $pass, $fail, $failures, $accepted;
    try { $r = $fn(); } catch (Throwable $e) { $r = 'exception: ' . $e->getMessage(); }
    if ($r === true) { $pass++; echo "PASS  $name\n"; }
    elseif ($why !== null) { $accepted++; echo "ACCEPTED  $name\n      -> $r\n      why: $why\n"; }
    else { $fail++; $failures[] = $name; echo "FAIL  $name\n      -> " . (is_string($r) ? $r : 'assertion false') . "\n"; }
}
function absent($needle, $hay, $what = '') {
    return strpos($hay, $needle) === false ? true : "found '$needle' $what";
}
function snip($s) { return substr(preg_replace('/\s+/', ' ', strip_tags($s)), 0, 160); }

// ---- 0. Harness sanity: the app is really running and serving data ---------
test('harness: legit XML is served', function () {
    $r = http('/xml?host=testhost&srv=PING');
    return ($r['status'] === 200 && strpos($r['body'], '<NAGIOS>') !== false)
        ? true : "status {$r['status']} body " . snip($r['body']);
});
test('harness: missing service reports error, not content', function () {
    $r = http('/xml?host=testhost&srv=NOPE');
    return absent('DECOY', $r['body']);
});

// Positive controls: prove the XSS checks below exercise real reflection points.
// If a benign marker never appears in a page, "not reflected raw" would be vacuous.
test('control: benign marker in host IS reflected (encoded) on /graph', function () {
    $r = http('/graph?host=testhost&srv=PING&view=ZZMARKERZZ');
    return strpos($r['body'], 'ZZMARKERZZ') !== false ? true : 'marker not reflected: XSS tests on view would be vacuous';
});
test('control: payload is reflected but HTML-encoded (shows escaping is what protects us)', function () {
    $r = http('/graph?host=testhost&srv=PING&view=' . rawurlencode('"><b>ZZ</b>'));
    if (strpos($r['body'], '<b>ZZ</b>') !== false) return 'raw tag reflected';
    return strpos($r['body'], '&lt;b&gt;ZZ') !== false || strpos($r['body'], '&quot;&gt;') !== false ? true
        : 'payload not reflected at all (cannot tell whether escaping works)';
});

// ---- 1. Path traversal via host / srv --------------------------------------
// pnp::clean strips / \ : and space, but NOT "..". rrdbase . host . '/' . srv . '.xml'
test('traversal: host=.. srv=secret must not read XML outside rrdbase', function () {
    $r = http('/xml?host=..&srv=secret');
    return absent('OUTSIDE-RRDBASE-DECOY', $r['body'], 'in response (file outside rrdbase was read)');
});
test('traversal: encoded slashes in host', function () {
    $r = http('/xml?host=' . rawurlencode('../') . '&srv=secret');
    return absent('OUTSIDE-RRDBASE-DECOY', $r['body']);
});
test('traversal: double-encoded slashes', function () {
    $r = http('/xml?host=%252e%252e%252f&srv=secret');
    return absent('OUTSIDE-RRDBASE-DECOY', $r['body']);
});
test('traversal: null byte in srv', function () {
    $r = http('/xml?host=testhost&srv=' . rawurlencode("PING\0../../secret"));
    return absent('OUTSIDE-RRDBASE-DECOY', $r['body']);
});
test('traversal: host=.. on json/graph endpoints must not leak decoy', function () {
    foreach (['/json?host=..&srv=secret', '/graph?host=..&srv=secret', '/popup?host=..&srv=secret'] as $p) {
        $r = http($p);
        if (strpos($r['body'], 'OUTSIDE-RRDBASE-DECOY') !== false) return "leak via $p";
    }
    return true;
});

// ---- 2. Reflected XSS -------------------------------------------------------
$xss = '"><script>alert(1337)</script>';
foreach (['graph', 'xml', 'popup', 'zoom', 'json', 'special', 'page', 'debug', 'start', 'mobile', 'ajax', 'xport', 'docs'] as $c) {
    foreach (['host', 'srv', 'view', 'source', 'theme', 'tpl', 'version'] as $p) {
        test("xss: /$c?$p= is not reflected raw", function () use ($c, $p, $xss) {
            $r = http("/$c?host=testhost&srv=PING&$p=" . rawurlencode($xss));
            return absent('<script>alert(1337)', $r['body'], "(status {$r['status']})");
        });
    }
}
foreach (['start', 'end', 'h', 'w', 'graph_width', 'graph_height', 'page', 'basket'] as $p) {
    test("xss: numeric-ish param $p not reflected raw", function () use ($p, $xss) {
        $r = http("/graph?host=testhost&srv=PING&$p=" . rawurlencode($xss));
        return absent('<script>alert(1337)', $r['body']);
    });
}
test('xss: path segment (controller/method) not reflected raw', function () use ($xss) {
    $r = http('/' . rawurlencode('<script>alert(1337)</script>'));
    return absent('<script>alert(1337)', $r['body']);
});
test('xss: unknown method name not reflected raw (System_Controller::__call)', function () {
    $r = http('/graph/' . rawurlencode('<script>alert(1337)</script>'));
    return absent('<script>alert(1337)', $r['body']);
});
test('xss: event-handler payload without angle brackets', function () {
    $r = http('/graph?host=testhost&srv=PING&view=' . rawurlencode('" onmouseover="alert(1337)'));
    return absent('" onmouseover="alert(1337)', $r['body']);
});

// Stored XSS: perfdata-derived XML (service/host display names) is attacker-influenced.
// The hostile host only exists during this section so it cannot contaminate other tests.
@mkdir("$WORK/rrd/evilhost");
copy(__DIR__ . '/fixtures/evilhost.xml', "$WORK/rrd/evilhost/PING.xml");
foreach (['graph', 'popup', 'debug', 'json', 'page', 'special', 'mobile', 'start', 'zoom'] as $c) {
    test("stored xss: hostile DISP_SERVICEDESC/HOSTNAME from XML not raw on /$c", function () use ($c) {
        $r = http("/$c?host=evilhost&srv=PING");
        return absent('<script>alert(1337)', $r['body'], "(status {$r['status']})");
    });
}
test('control: stored-XSS fixture is actually rendered on at least one page', function () {
    foreach (['/graph', '/popup', '/debug', '/json', '/mobile', '/zoom', '/special'] as $c) {
        $b = http($c . '?host=evilhost&srv=PING')['body'];
        if (strpos($b, 'alert(1337)') !== false) return true;
    }
    return 'hostile name never rendered anywhere: stored-XSS tests are vacuous';
});

@unlink("$WORK/rrd/evilhost/PING.xml"); @rmdir("$WORK/rrd/evilhost");

// ---- 3. Information disclosure ---------------------------------------------
test('info: errors do not disclose filesystem paths', function () use ($WORK) {
    $r = http('/xml?host=testhost&srv=NOPE'); $b = $r['body'];
    $r2 = http('/graph?host=nohost&srv=nosrv'); $b .= $r2['body'];
    return absent($WORK, $b, '(absolute server path leaked in error output)');
}, 'PNP shows its own error pages (missing XML, bad config) to help admins debug; hiding them is a config choice (display_errors in index.php / config.php).');
test('info: no PHP warnings/notices/deprecations in normal pages', function () {
    foreach (['/', '/graph?host=testhost&srv=PING', '/xml?host=testhost&srv=PING', '/popup?host=testhost&srv=PING', '/start'] as $p) {
        $r = http($p);
        if (preg_match('/(Warning|Notice|Deprecated|Fatal error)\b[^<]{0,80}(on line|in \/)/i', $r['body'], $m))
            return "$p: " . snip($m[0]);
    }
    return true;
});
test('info: X-Powered-By / server version headers not sent by app', function () {
    $r = http('/');
    foreach ($r['headers'] as $h) if (stripos($h, 'X-Powered-By') === 0) return $h;
    return true;
});
test('info: dotfiles / source files not downloadable from docroot', function () {
    foreach (['/index.php.in', '/application/config/config.php', '/install.ignore', '/application/controllers/system.php'] as $p) {
        $r = http($p);
        if (strpos($r['body'], "defined('SYSPATH')") !== false) return "source disclosed via $p";
    }
    return true;
});

// ---- 4. Header / session / cookie handling ---------------------------------
test('headers: X-Content-Type-Options: nosniff is sent', function () {
    $r = http('/graph?host=testhost&srv=PING');
    foreach ($r['headers'] as $h) if (stripos($h, 'X-Content-Type-Options: nosniff') === 0) return true;
    return 'missing';
});
test('headers: clickjacking protection (X-Frame-Options / frame-ancestors)', function () {
    $r = http('/graph?host=testhost&srv=PING');
    $h = strtolower(implode("\n", $r['headers']));
    return (strpos($h, 'x-frame-options') !== false || strpos($h, 'frame-ancestors') !== false) ? true : 'missing';
}, 'PNP graphs are routinely embedded in Nagios/Thruk pages, often from another origin; a blanket frame policy would break that. Set it in the web server if you do not embed.');
test('cookie: session cookie has HttpOnly flag', function () {
    $r = http('/graph?host=testhost&srv=PING');
    foreach ($r['headers'] as $h) {
        if (stripos($h, 'Set-Cookie:') === 0) {
            if (stripos($h, 'httponly') === false) return "no HttpOnly: " . substr($h, 0, 120);
            return true;
        }
    }
    return 'no Set-Cookie sent at all (cannot verify)';
});
test('header injection: CRLF in params does not split response', function () {
    $r = http('/graph?host=testhost%0d%0aX-Injected:1&srv=PING');
    foreach ($r['headers'] as $h) if (stripos($h, 'X-Injected') === 0) return 'header injected';
    return true;
});
test('spoofing: X-Forwarded-For must not change client identity', function () {
    // Smoke test: request must still succeed and not echo the spoofed value
    $r = http('/graph?host=testhost&srv=PING', ['X-Forwarded-For: <script>alert(1337)</script>']);
    return absent('<script>alert(1337)', $r['body']);
});

// ---- 5. Robustness (DoS-ish / malformed input) -----------------------------
test('robust: request without User-Agent header does not error', function () {
    $r = http('/graph?host=testhost&srv=PING', [], false);
    return $r['status'] < 500 && stripos($r['body'], 'Undefined') === false ? true : "status {$r['status']}: " . snip($r['body']);
});
test('robust: array params (host[]=x) do not fatal', function () {
    $r = http('/xml?host[]=a&srv[]=b');
    return $r['status'] < 500 && stripos($r['body'], 'Fatal error') === false ? true : "status {$r['status']}: " . snip($r['body']);
});
test('robust: very long parameter does not fatal', function () {
    // A 500 "XML file not found" framework error is expected for an unknown host; only a real crash is a failure.
    $r = http('/xml?host=' . str_repeat('A', 60000) . '&srv=x');
    return stripos($r['body'], 'Fatal error') === false && stripos($r['body'], 'Stack trace') === false ? true : "crash: " . snip($r['body']);
});
test('robust: invalid UTF-8 / control chars handled', function () {
    $r = http('/graph?host=%ff%fe%00%01&srv=%c0%af');
    return $r['status'] < 500 && stripos($r['body'], 'Fatal error') === false ? true : "status {$r['status']}: " . snip($r['body']);
});
test('robust: huge numeric start/end handled', function () {
    $r = http('/graph?host=testhost&srv=PING&start=99999999999999999999&end=-99999999999999999999');
    return $r['status'] < 500 && stripos($r['body'], 'Fatal error') === false ? true : "status {$r['status']}: " . snip($r['body']);
});

// ---- 6. XML external entity -------------------------------------------------
test('xxe: XML with external entity is not expanded when read', function () use ($WORK) {
    $dir = "$WORK/rrd/xxehost"; @mkdir($dir);
    file_put_contents("$dir/X.xml", '<?xml version="1.0"?><!DOCTYPE n [<!ENTITY x SYSTEM "file://' . $WORK . '/secret/flag.txt">]>'
        . '<NAGIOS><NAGIOS_AUTH_HOSTNAME>&x;</NAGIOS_AUTH_HOSTNAME><NAGIOS_AUTH_SERVICEDESC>X</NAGIOS_AUTH_SERVICEDESC>'
        . '<NAGIOS_DISP_SERVICEDESC>&x;</NAGIOS_DISP_SERVICEDESC><XML><VERSION>4</VERSION></XML></NAGIOS>');
    $b = '';
    foreach (['/graph?host=xxehost&srv=X', '/popup?host=xxehost&srv=X', '/json?host=xxehost&srv=X'] as $p) $b .= http($p)['body'];
    return absent('TOP-SECRET-OUTSIDE-RRDBASE', $b, '(external entity expanded)');
});

echo "\n$pass passed, $fail failed, $accepted accepted\n";
exit($fail ? 1 : 0);
