#!/bin/sh

# ------------------------------------
# Function:
# - Testsuite.
#
# Version:
# - 0.1.0 - 2018/09/22 initial release
# - 0.2.0 - 2018/09/27 added: some domains
#
# Usage:
# - sh testsuite.sh >testsuite.out
# ------------------------------------

# set -o xtrace
set -o verbose

# define application name
appname=./certstate

# define separator (for better readability)
separator="\n------------------------------------------------------------------------------------------------------------\n"

# reference websites
# ------------------------------------
$appname example.com:443
echo "$separator"

# top 50 websites World (de.wikipedia.org/wiki/Liste_der_meistaufgerufenen_Websites, 2018/09/21)
# ------------------------------------
$appname google.com:443
echo "$separator"
$appname youtube.com:443
echo "$separator"
$appname facebook.com:443
echo "$separator"
$appname baidu.com:443
echo "$separator"
$appname wikipedia.org:443
echo "$separator"
$appname yahoo.com:443
echo "$separator"
$appname google.co.in:443
echo "$separator"
$appname reddit.com:443
# website has no https support
# $appname qq.com:443
# echo "$separator"
$appname amazon.com:443
echo "$separator"
$appname taobao.com:443
echo "$separator"
$appname tmall.com:443
echo "$separator"
$appname twitter.com:443
echo "$separator"
$appname vk.com:443
echo "$separator"
$appname live.com:443
echo "$separator"
$appname sohu.com:443
echo "$separator"
$appname instagram.com:443
echo "$separator"
$appname google.co.jp:443
echo "$separator"
$appname sina.com.cn:443
echo "$separator"
$appname jd.com:443
echo "$separator"
$appname weibo.com:443
echo "$separator"
$appname 360.cn:443
echo "$separator"
$appname google.de:443
echo "$separator"
$appname google.co.uk:443
echo "$separator"
$appname google.com.br:443
echo "$separator"
$appname list.tmall.com:443
echo "$separator"
$appname google.fr:443
echo "$separator"
$appname google.ru:443
echo "$separator"
$appname yandex.ru:443
echo "$separator"
$appname linkedin.com:443
echo "$separator"
$appname netflix.com:443
echo "$separator"
$appname google.it:443
echo "$separator"
$appname google.com.hk:443
echo "$separator"
$appname google.es:443
echo "$separator"
$appname t.co:443
echo "$separator"
$appname pornhub.com:443
echo "$separator"
$appname ebay.com:443
echo "$separator"
$appname www.alipay.com:443
echo "$separator"
$appname google.com.mx:443
echo "$separator"
$appname google.ca:443
echo "$separator"
$appname yahoo.co.jp:443
echo "$separator"
$appname twitch.tv:443
echo "$separator"
$appname xvideos.com:443
echo "$separator"
$appname bing.com:443
echo "$separator"
$appname microsoft.com:443
echo "$separator"
$appname ok.ru:443
echo "$separator"
$appname imgur.com:443
echo "$separator"
$appname aliexpress.com:443
echo "$separator"
$appname mail.ru:443
echo "$separator"
$appname office.com:443
echo "$separator"

# top 50 websites Germany (de.wikipedia.org/wiki/Liste_der_meistaufgerufenen_Websites, 2018/09/21)
# ------------------------------------
$appname google.de:443
echo "$separator"
$appname youtube.com:443
echo "$separator"
$appname google.com:443
echo "$separator"
$appname amazon.de:443
echo "$separator"
$appname facebook.com:443
echo "$separator"
$appname ebay.de:443
echo "$separator"
$appname wikipedia.org:443
echo "$separator"
$appname vk.com:443
echo "$separator"
$appname ebay-kleinanzeigen.de:443
echo "$separator"
$appname web.de:443
echo "$separator"
$appname ok.ru:443
echo "$separator"
$appname gmx.net:443
echo "$separator"
$appname yahoo.com:443
echo "$separator"
$appname t-online.de:443
echo "$separator"
$appname livejasmin.com:443
echo "$separator"
$appname reddit.com:443
echo "$separator"
$appname mail.ru:443
echo "$separator"
$appname paypal.com:443
echo "$separator"
$appname instagram.com:443
echo "$separator"
$appname google.com.ua:443
echo "$separator"
$appname twitter.com:443
echo "$separator"
$appname xhamster.com:443
echo "$separator"
$appname chip.de:443
echo "$separator"
$appname spiegel.de:443
echo "$separator"
$appname bing.com:443
echo "$separator"
$appname bild.de:443
echo "$separator"
$appname live.com:443
echo "$separator"
$appname yandex.ru:443
echo "$separator"
$appname google.ru:443
echo "$separator"
$appname pornhub.com:443
echo "$separator"
$appname twitch.tv:443
echo "$separator"
$appname otto.de:443
echo "$separator"
$appname netflix.com:443
echo "$separator"
$appname whatsapp.com:443
echo "$separator"
$appname dhl.de:443
echo "$separator"
$appname focus.de:443
echo "$separator"
$appname txxx.com:443
echo "$separator"
$appname idealo.de:443
echo "$separator"
$appname postbank.de:443
echo "$separator"
$appname telekom.com:443
echo "$separator"
$appname welt.de:443
echo "$separator"
$appname microsoft.com:443
echo "$separator"
$appname amazon.com:443
echo "$separator"
$appname xvideos.com:443
echo "$separator"
$appname tumblr.com:443
echo "$separator"
$appname linkedin.com:443
echo "$separator"
$appname pinterest.de:443
echo "$separator"
$appname bahn.de:443
echo "$separator"
$appname wordpress.com:443
echo "$separator"
$appname mobile.de:443
echo "$separator"

# top 50 websites Switzerland (de.wikipedia.org/wiki/Liste_der_meistaufgerufenen_Websites, 2018/09/21)
# ------------------------------------
$appname google.ch:443
echo "$separator"
$appname youtube.com:443
echo "$separator"
$appname google.com:443
echo "$separator"
$appname facebook.com:443
echo "$separator"
$appname wikipedia.org:443
echo "$separator"
$appname bluewin.ch:443
echo "$separator"
$appname livejasmin.com:443
echo "$separator"
$appname reddit.com:443
echo "$separator"
$appname yahoo.com:443
echo "$separator"
$appname live.com:443
echo "$separator"
$appname 20min.ch:443
echo "$separator"
$appname blick.ch:443
echo "$separator"
$appname amazon.de:443
echo "$separator"
$appname twitter.com:443
echo "$separator"
$appname srf.ch:443
echo "$separator"
$appname google.de:443
echo "$separator"
$appname instagram.com:443
echo "$separator"
$appname ricardo.ch:443
echo "$separator"
$appname bongacams.com:443
echo "$separator"
$appname sbb.ch:443
echo "$separator"
$appname pornhub.com:443
echo "$separator"
$appname postfinance.ch:443
echo "$separator"
$appname digitec.ch:443
echo "$separator"
$appname xhamster.com:443
echo "$separator"
$appname vk.com:443
echo "$separator"
$appname gmx.net:443
echo "$separator"
$appname gmx.ch:443
echo "$separator"
$appname www.ubs.com:443
echo "$separator"
$appname admin.ch:443
echo "$separator"
$appname xvideos.com:443
echo "$separator"
$appname whatsapp.com:443
echo "$separator"
$appname swisscom.ch:443
echo "$separator"
$appname Search.ch:443
echo "$separator"
$appname netflix.com:443
echo "$separator"
$appname aliexpress.com:443
echo "$separator"
$appname amazon.com:443
echo "$separator"
$appname apple.com:443
echo "$separator"
$appname tagesanzeiger.ch:443
echo "$separator"
$appname microsoft.com:443
echo "$separator"
$appname tutti.ch:443
echo "$separator"
$appname paypal.com:443
echo "$separator"
$appname twitch.tv:443
echo "$separator"
$appname dropbox.ch:443
echo "$separator"
$appname stackoverflow.com:443
echo "$separator"
$appname wordpress.com:443
echo "$separator"
$appname txxx.com:443
echo "$separator"
$appname raiffeisen.ch:443
echo "$separator"
$appname xnxx.com:443
echo "$separator"
$appname github.com:443
echo "$separator"

# special websites
# ------------------------------------
$appname porsche.com:443
echo "$separator"
$appname highway.porsche.com:443
echo "$separator"
$appname freizeitkarte-osm.de:443
echo "$separator"
$appname vb-ascheberg-herbern.de:443
echo "$separator"
$appname www.volksbank-muenster.de:443
echo "$separator"
$appname dkb.de:443
echo "$separator"
$appname uni-leipzig.de:443
echo "$separator"

# IPv4 addresses
# ------------------------------------
# example.com, 93.184.216.34
$appname 93.184.216.34:443
echo "$separator"

# freizeitkarte-osm.de, 138.201.250.238
$appname 138.201.250.238:443
echo "$separator"

# 'bad ssl' (badssl.com)
# ------------------------------------
# general
$appname badssl.com:443
echo "$separator"

# not secure
$appname expired.badssl.com:443
echo "$separator"
$appname wrong.host.badssl.com:443
echo "$separator"
$appname self-signed.badssl.com:443
echo "$separator"
$appname untrusted-root.badssl.com:443
echo "$separator"
$appname sha1-intermediate.badssl.com:443
echo "$separator"
$appname rc4.badssl.com:443
echo "$separator"
$appname rc4-md5.badssl.com:443
echo "$separator"
$appname dh480.badssl.com:443
echo "$separator"
$appname dh512.badssl.com:443
echo "$separator"
$appname dh1024.badssl.com:443
echo "$separator"
$appname superfish.badssl.com:443
echo "$separator"
$appname edellroot.badssl.com:443
echo "$separator"
$appname dsdtestprovider.badssl.com:443
echo "$separator"
$appname preact-cli.badssl.com:443
echo "$separator"
$appname webpack-dev-server.badssl.com:443
echo "$separator"
$appname null.badssl.com:443
echo "$separator"

# bad certificates
$appname revoked.badssl.com:443
echo "$separator"
$appname pinning-test.badssl.com:443
echo "$separator"
$appname invalid-expected-sct.badssl.com:443
echo "$separator"

# legacy
$appname tls-v1-0.badssl.com:443
echo "$separator"
$appname tls-v1-1.badssl.com:443
echo "$separator"
$appname cbc.badssl.com:443
echo "$separator"
$appname 3des.badssl.com:443
echo "$separator"

# secure
$appname tls-v1-2.badssl.com:443
echo "$separator"
$appname sha256.badssl.com:443
echo "$separator"
$appname sha384.badssl.com:443
echo "$separator"
$appname sha512.badssl.com:443
echo "$separator"
$appname rsa2048.badssl.com:443
echo "$separator"
$appname rsa4096.badssl.com:443
echo "$separator"
$appname extended-validation.badssl.com:443
echo "$separator"
$appname mozilla-modern.badssl.com:443
echo "$separator"

# secure but weird
$appname 1000-sans.badssl.com:443
echo "$separator"
$appname 10000-sans.badssl.com:443
echo "$separator"
$appname rsa8192.badssl.com:443
echo "$separator"
$appname no-subject.badssl.com:443
echo "$separator"
$appname no-common-name.badssl.com:443
echo "$separator"
$appname incomplete-chain.badssl.com:443
echo "$separator"

# ?
$appname ecc256.badssl.com:443
echo "$separator"
$appname ecc384.badssl.com:443
echo "$separator"
$appname dh2048.badssl.com:443
echo "$separator"
