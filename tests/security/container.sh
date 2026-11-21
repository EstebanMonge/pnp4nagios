#!/bin/sh
# Runs INSIDE the container. Repo is mounted read-only at /repo.
set -eu
W=/tmp/pnp
rm -rf $W && mkdir -p $W/app $W/etc $W/rrd $W/secret $W/cache $W/templates
cp -r /repo/share/pnp/. $W/app/

# Generate index.php the way ./configure would
sed -e "s#@PACKAGE_NAME@#pnp4nagios#g" -e "s#@PACKAGE_VERSION@#test#g" \
    -e "s#@PKG_REL_DATE@#test#g" -e "s#@pkgsysconfdir@#$W/etc#g" \
    -e "s#@PNP_LOGDIR@#$W/log#g" -e "s#@CACHE_DIR@#$W/cache#g" \
    -e "s#@XML_STRUCTURE_VERSION@#4#g" -e "s#@KOHANA_SYSTEM@#/repo/lib/kohana/system#g" \
    /repo/share/pnp/index.php.in > $W/app/index.php
# keep the installer out of the way
touch $W/app/install.ignore

# Config as ./configure would produce it
sed -e "s#@RRDTOOL@#/bin/false#g" -e "s#@PERFDATA_DIR@#$W/rrd#g" \
    -e "s#@pkgsysconfdir@#$W/etc#g" -e "s#@datarootdir@#$W/app#g" \
    -e "s#@PAPERSIZE@#A4#g" -e "s#@PACKAGE_NAME@#pnp4nagios#g" -e "s#@PACKAGE_VERSION@#test#g" \
    /repo/sample-config/config_samples/config.php.in > $W/etc/config.php

# Fixtures: a legit host/service, and a decoy XML OUTSIDE the rrd base
cp -r /repo/tests/security/fixtures/rrd/. $W/rrd/
cp /repo/tests/security/fixtures/secret.xml $W/secret.xml
echo "TOP-SECRET-OUTSIDE-RRDBASE" > $W/secret/flag.txt

export PNP_CONFIG_FILE=$W/etc/config
php -d display_errors=0 -S 127.0.0.1:8080 -t $W/app $W/app/index.php >$W/server.log 2>&1 &
SRV=$!
sleep 1
export BASE=http://127.0.0.1:8080 WORK=$W
php /repo/tests/security/run_tests.php
RC=$?
kill $SRV 2>/dev/null || true
exit $RC
