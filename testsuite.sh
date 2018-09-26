#!/bin/sh

# ------------------------------------
# Function:
# - Testsuite.
#
# Version:
# - 0.1.0 - 2018/09/22
#
# Usage:
# - sh testsuite.sh >testsuite.out
# ------------------------------------

# set -o xtrace
set -o verbose

# define application name
appname=./certstate

# Referenz-Websites
# ------------------------------------
$appname example.com:443

# Liste der 50 meistaufgerufenen Websites (Welt, Wikipedia, 21.09.2018)
# ------------------------------------
$appname google.com:443
$appname youtube.com:443
$appname facebook.com:443
$appname baidu.com:443
$appname wikipedia.org:443
$appname yahoo.com:443
$appname google.co.in:443
$appname reddit.com:443
$appname qq.com:443
$appname amazon.com:443
$appname taobao.com:443
$appname tmall.com:443
$appname twitter.com:443
$appname vk.com:443
$appname live.com:443
$appname sohu.com:443
$appname instagram.com:443
$appname google.co.jp:443
$appname sina.com.cn:443
$appname jd.com:443
$appname weibo.com:443
$appname 360.cn:443
$appname google.de:443
$appname google.co.uk:443
$appname google.com.br:443
$appname list.tmall.com:443
$appname google.fr:443
$appname google.ru:443
$appname yandex.ru:443
$appname linkedin.com:443
$appname netflix.com:443
$appname google.it:443
$appname google.com.hk:443
$appname google.es:443
$appname t.co:443
$appname pornhub.com:443
$appname ebay.com:443
$appname alipay.com:443
$appname google.com.mx:443
$appname google.ca:443
$appname yahoo.co.jp:443
$appname twitch.tv:443
$appname xvideos.com:443
$appname bing.com:443
$appname microsoft.com:443
$appname ok.ru:443
$appname imgur.com:443
$appname aliexpress.com:443
$appname mail.ru:443
$appname office.com:443

# Liste der 50 meistaufgerufenen Websites (Deutschland, Wikipedia, Stand 21.09.2018)
# ------------------------------------
$appname google.de:443
$appname youtube.com:443
$appname google.com:443
$appname amazon.de:443
$appname facebook.com:443
$appname ebay.de:443
$appname wikipedia.org:443
$appname vk.com:443
$appname ebay-kleinanzeigen.de:443
$appname web.de:443
$appname ok.ru:443
$appname gmx.net:443
$appname yahoo.com:443
$appname t-online.de:443
$appname livejasmin.com:443
$appname reddit.com:443
$appname mail.ru:443
$appname paypal.com:443
$appname instagram.com:443
$appname google.com.ua:443
$appname twitter.com:443
$appname xhamster.com:443
$appname chip.de:443
$appname spiegel.de:443
$appname bing.com:443
$appname bild.de:443
$appname live.com:443
$appname yandex.ru:443
$appname google.ru:443
$appname pornhub.com:443
$appname twitch.tv:443
$appname otto.de:443
$appname netflix.com:443
$appname whatsapp.com:443
$appname dhl.de:443
$appname focus.de:443
$appname txxx.com:443
$appname idealo.de:443
$appname postbank.de:443
$appname telekom.com:443
$appname welt.de:443
$appname microsoft.com:443
$appname amazon.com:443
$appname xvideos.com:443
$appname tumblr.com:443
$appname linkedin.com:443
$appname pinterest.de:443
$appname bahn.de:443
$appname wordpress.com:443
$appname mobile.de:443

# Liste der 50 meistaufgerufenen Websites (Schweiz, Wikipedia, Stand 21.09.2018)
# ------------------------------------
$appname google.ch:443
$appname youtube.com:443
$appname google.com:443
$appname facebook.com:443
$appname wikipedia.org:443
$appname bluewin.ch:443
$appname livejasmin.com:443
$appname reddit.com:443
$appname yahoo.com:443
$appname live.com:443
$appname 20min.ch:443
$appname blick.ch:443
$appname amazon.de:443
$appname twitter.com:443
$appname srf.ch:443
$appname google.de:443
$appname instagram.com:443
$appname ricardo.ch:443
$appname bongacams.com:443
$appname sbb.ch:443
$appname pornhub.com:443
$appname postfinance.ch:443
$appname digitec.ch:443
$appname xhamster.com:443
$appname vk.com:443
$appname gmx.net:443
$appname gmx.ch:443
$appname ubs.com:443
$appname admin.ch:443
$appname xvideos.com:443
$appname whatsapp.com:443
$appname swisscom.ch:443
$appname Search.ch:443
$appname netflix.com:443
$appname aliexpress.com:443
$appname amazon.com:443
$appname apple.com:443
$appname tagesanzeiger.ch:443
$appname microsoft.com:443
$appname tutti.ch:443
$appname paypal.com:443
$appname twitch.tv:443
$appname dropbox.ch:443
$appname stackoverflow.com:443
$appname wordpress.com:443
$appname txxx.com:443
$appname raiffeisen.ch:443
$appname xnxx.com:443
$appname github.com:443

# Spezielle Websites
# ------------------------------------
$appname porsche.com:443
$appname highway.porsche.com:443
$appname freizeitkarte-osm.de:443
$appname vb-ascheberg-herbern.de:443
$appname www.volksbank-muenster.de:443
$appname dkb.de:443
$appname uni-leipzig.de:443

# IPv4 Addresses
# ------------------------------------
# example.com, 93.184.216.34
$appname 93.184.216.34:443
# freizeitkarte-osm.de, 138.201.250.238
$appname 138.201.250.238:443

# not working: IPv6 Addresses (syntax?, link: ip6.nl)
# ------------------------------------
# google.com, 2a00:1450:400e:809::200e
# $appname [2a00:1450:400e:809::200e]:443
