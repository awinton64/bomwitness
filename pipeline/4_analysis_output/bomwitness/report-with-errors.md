# BOMwitness report: openwrt-24.10.8-ath79-generic-tplink_archer-c7-v5-squashfs-sysupgrade.bin

Reference: OpenWrt 24.10.8 ath79/generic (mips_24kc), sha256sums signed by usign key d310c6f2833e97f7.
Evidence used: byte hashes on, version markers on, release manifest yes, sibling-image snapshots 1, file-path index no.

Trust of the reference: the signed checksum file is checked against pinned keys and pins the frozen package indexes, the release manifest and profiles.json; shared feed indexes carry their own signatures; packages are checked against their index hash when first fetched. Cached copies are trusted afterwards.
- snapshot file snapshot.json: local file, trusted as supplied; it records that it was made from an image with SHA-256 f4d55cb506f1b192..., which is listed as openwrt-24.10.8-ath79-generic-tplink_archer-a7-v5-squashfs-sysupgrade.bin in the signed profiles.json of 24.10.8 ath79/generic.

## Triage

| Outcome | Count | Meaning |
|---|---|---|
| Automatic pass | 139 | claim supported by grade A or B evidence |
| Automatic fail | 4 | claim contradicted by the bytes, or undeclared content found |
| Needs review | 0 | bytes or label differ from the reference and a person must decide |
| Unverifiable | 8 | nothing to compare against |

Files in the image: 629, accounted for by a declared component or reference package: 629. Executable files not accounted for: 0.

## SBOM findings

| Class | Component | Grade | Detail |
|---|---|---|---|
| wrong_version | busybox | A | declared 1.36.2-r3; actual 1.36.1-r3. bytes are the build that the feed index and the official sibling image both label 1.36.1-r3 |
| wrong_version | dropbear | A | declared 2022.82-6; actual 2024.86-r3. bytes are the reference build 2024.86-r3 from a feed that is frozen for this release |
| absent | tcpdump | A | none of the reference package's files exist in the firmware |
| undeclared_component | dnsmasq | A | 12 file(s) present, byte-identical to reference dnsmasq 2.93-r1 |

### Notes (not failures)

| Class | Component | Detail |
|---|---|---|
| stale | ca-bundle | firmware has 20260601-r1; the reference feed now ships 20260816-r2 |
| stale | libmbedtls21 | firmware has 3.6.6-r2; the reference feed now ships 3.6.7-r1 |
| stale | libucode20230711 | firmware has 2025.07.18~3f64c808-r1; the reference feed now ships 2025.07.18~3f64c808-r2 |
| stale | luci-app-firewall | firmware has 26.205.85413~cac97ed; the reference feed now ships 26.301.70438~aa4865e |
| stale | luci-app-package-manager | firmware has 26.205.85413~cac97ed; the reference feed now ships 26.301.70438~aa4865e |
| stale | luci-base | firmware has 26.205.85413~cac97ed; the reference feed now ships 26.301.70438~aa4865e |
| stale | luci-mod-network | firmware has 26.205.85413~cac97ed; the reference feed now ships 26.301.70438~aa4865e |
| stale | luci-mod-status | firmware has 26.205.85413~cac97ed; the reference feed now ships 26.301.70438~aa4865e |
| stale | luci-mod-system | firmware has 26.205.85413~cac97ed; the reference feed now ships 26.301.70438~aa4865e |
| stale | luci-proto-ipv6 | firmware has 26.205.85413~cac97ed; the reference feed now ships 26.301.70438~aa4865e |
| stale | luci-proto-ppp | firmware has 26.205.85413~cac97ed; the reference feed now ships 26.301.70438~aa4865e |
| stale | luci-theme-bootstrap | firmware has 26.205.85413~cac97ed; the reference feed now ships 26.301.70438~aa4865e |
| stale | ucode | firmware has 2025.07.18~3f64c808-r1; the reference feed now ships 2025.07.18~3f64c808-r2 |
| stale | ucode-mod-fs | firmware has 2025.07.18~3f64c808-r1; the reference feed now ships 2025.07.18~3f64c808-r2 |
| stale | ucode-mod-math | firmware has 2025.07.18~3f64c808-r1; the reference feed now ships 2025.07.18~3f64c808-r2 |
| stale | ucode-mod-nl80211 | firmware has 2025.07.18~3f64c808-r1; the reference feed now ships 2025.07.18~3f64c808-r2 |
| stale | ucode-mod-rtnl | firmware has 2025.07.18~3f64c808-r1; the reference feed now ships 2025.07.18~3f64c808-r2 |
| stale | ucode-mod-ubus | firmware has 2025.07.18~3f64c808-r1; the reference feed now ships 2025.07.18~3f64c808-r2 |
| stale | ucode-mod-uci | firmware has 2025.07.18~3f64c808-r1; the reference feed now ships 2025.07.18~3f64c808-r2 |
| stale | ucode-mod-uloop | firmware has 2025.07.18~3f64c808-r1; the reference feed now ships 2025.07.18~3f64c808-r2 |

## Device package database (grade C, self-reported)

150 packages listed. Disagreements:

| Class | Component | Detail |
|---|---|---|
| wrong_version | busybox | BOM declares 1.36.2-r3; the device database says 1.36.1-r3 |
| wrong_version | dropbear | BOM declares 2022.82-6; the device database says 2024.86-r3 |
| absent | tcpdump | declared in the BOM; the device database does not list it |
| undeclared_component | dnsmasq | the device database lists dnsmasq 2.93-r1; the BOM does not |

## CBOM findings

Found in the bytes: 121 certificates, 1 keys, 72 (component, algorithm) pairs.

| Class | Asset | Grade | Detail |
|---|---|---|---|
| undeclared_certificate | 018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05 | A | CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\, Inc.,C=US in etc/ssl/certs/ca-certificates.crt |
| provider_unverified | busybox | A | the CBOM says busybox provides MD5; the SBOM check of busybox ended in wrong_version |
| provider_unverified | dropbear | A | the CBOM says dropbear provides AES; the SBOM check of dropbear ended in wrong_version |
| algorithm_not_evidenced | ML-KEM@libmbedtls21 | B | no file of libmbedtls21 carries a name of ML-KEM |
| deprecated_algorithm | MD5@busybox | B | deprecated primitive named in bin/busybox |
| deprecated_algorithm | SHA-1@dropbear | B | deprecated primitive named in usr/sbin/dropbear |
| deprecated_algorithm | MD5@fstools | B | deprecated primitive named in lib/libfstools.so |
| deprecated_algorithm | TKIP@iw | B | deprecated primitive named in usr/sbin/iw |
| deprecated_algorithm | WEP@iw | B | deprecated primitive named in usr/sbin/iw |
| deprecated_algorithm | WEP@iwinfo | B | deprecated primitive named in usr/bin/iwinfo |
| deprecated_algorithm | WEP@kmod-cfg80211 | B | deprecated primitive named in lib/modules/6.6.144/cfg80211.ko |
| deprecated_algorithm | SHA-1@kmod-crypto-rng | B | deprecated primitive named in lib/modules/6.6.144/drbg.ko |
| deprecated_algorithm | RC4@kmod-mac80211 | B | deprecated primitive named in lib/modules/6.6.144/mac80211.ko |
| deprecated_algorithm | TKIP@kmod-mac80211 | B | deprecated primitive named in lib/modules/6.6.144/mac80211.ko |
| deprecated_algorithm | WEP@kmod-mac80211 | B | deprecated primitive named in lib/modules/6.6.144/mac80211.ko |
| deprecated_algorithm | TKIP@libiwinfo20230701 | B | deprecated primitive named in usr/lib/libiwinfo.so.20230701 |
| deprecated_algorithm | WEP@libiwinfo20230701 | B | deprecated primitive named in usr/lib/libiwinfo.so.20230701 |
| deprecated_algorithm | 3DES@libmbedtls21 | B | deprecated primitive named in usr/lib/libmbedcrypto.so.3.6.6 |
| deprecated_algorithm | MD5@libmbedtls21 | B | deprecated primitive named in usr/lib/libmbedcrypto.so.3.6.6 |
| deprecated_algorithm | SHA-1@libmbedtls21 | B | deprecated primitive named in usr/lib/libmbedcrypto.so.3.6.6 |
| deprecated_algorithm | MD5@libubox20240329 | B | deprecated primitive named in lib/libubox.so.20240329 |
| deprecated_algorithm | MD5@libuclient20201210 | B | deprecated primitive named in usr/lib/libuclient.so |
| deprecated_algorithm | MD5@mtd | B | deprecated primitive named in sbin/mtd |
| deprecated_algorithm | MD5@odhcp6c | B | deprecated primitive named in usr/sbin/odhcp6c |
| deprecated_algorithm | MD5@odhcpd-ipv6only | B | deprecated primitive named in usr/sbin/odhcpd |
| deprecated_algorithm | MD5@opkg | B | deprecated primitive named in bin/opkg |
| deprecated_algorithm | MD5@ppp | B | deprecated primitive named in usr/sbin/pppd |
| deprecated_algorithm | SHA-1@ppp | B | deprecated primitive named in usr/sbin/pppd |
| deprecated_algorithm | MD5@procd | B | deprecated primitive named in sbin/procd |
| deprecated_algorithm | MD5@rpcd-mod-file | B | deprecated primitive named in usr/lib/rpcd/file.so |
| deprecated_algorithm | MD5@uhttpd | B | deprecated primitive named in usr/sbin/uhttpd |
| deprecated_algorithm | RC4@wpad-basic-mbedtls | B | deprecated primitive named in usr/sbin/wpad |
| deprecated_algorithm | SHA-1@wpad-basic-mbedtls | B | deprecated primitive named in usr/sbin/wpad |
| deprecated_algorithm | TKIP@wpad-basic-mbedtls | B | deprecated primitive named in usr/sbin/wpad |
| deprecated_algorithm | WEP@wpad-basic-mbedtls | B | deprecated primitive named in usr/sbin/wpad |

## AI-BOM

Model files found by file header (for some formats, header plus file extension): 0.

No findings.

## Declared components

| Component | Declared version | Verdict | Evidence |
|---|---|---|---|
| ath10k-board-qca988x | 20241110-r2 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| ath10k-firmware-qca988x-ct | 2020.11.08-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| base-files | 1674~443ec4032a | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| busybox | 1.36.2-r3 | wrong version | bytes are the build that the feed index and the official sibling image both label 1.36.1-r3 |
| ca-bundle | 20260601-r1 | verified, files present are byte-identical to the publisher's build | 1 file(s) byte-identical to the build in the official sibling image (20260601-r1); the shared feed has since moved to 20260816-r2 |
| cgi-io | 2026.07.21~31cb3c89-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| dropbear | 2022.82-6 | wrong version | bytes are the reference build 2024.86-r3 from a feed that is frozen for this release |
| firewall4 | 2024.12.18~18fc0ead-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| fstools | 2024.07.14~408c2cc4-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| fwtool | 2019.11.12~8f7fe925-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| getrandom | 2024.04.26~85f10530-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| hostapd-common | 2024.09.15~5ace39b0-r3 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| iw | 6.9-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| iwinfo | 2024.10.20~b94f066e-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| jansson4 | 2.14-r3 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| jshn | 2025.07.23~49056d17-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| jsonfilter | 2025.04.18~8a86fb78-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kernel | 6.6.144~70248021204b78344d5fb62a0e7f5bea-r1 | verified by a version marker in the bytes | version marker 6.6.144 found in lib/modules/6.6.144/ath.ko |
| kmod-ath | 6.6.144.6.12.96-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-ath10k-ct | 6.6.144.2024.07.30~ac71b14d-r2 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-ath9k | 6.6.144.6.12.96-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-ath9k-common | 6.6.144.6.12.96-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-cfg80211 | 6.6.144.6.12.96-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-acompress | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-aead | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-ccm | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-cmac | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-crc32c | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-ctr | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-gcm | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-geniv | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-gf128 | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-ghash | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-hash | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-hmac | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-manager | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-null | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-rng | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-seqiv | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-sha3 | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-crypto-sha512 | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-gpio-button-hotplug | 6.6.144-r5 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-hwmon-core | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-lib-crc-ccitt | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-lib-crc32c | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-lib-lzo | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-mac80211 | 6.6.144.6.12.96-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-nf-conntrack | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-nf-conntrack6 | 6.6.144-r1 | unverifiable | metadata-only package with no files to check |
| kmod-nf-flow | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-nf-log | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-nf-log6 | 6.6.144-r1 | unverifiable | metadata-only package with no files to check |
| kmod-nf-nat | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-nf-reject | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-nf-reject6 | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-nfnetlink | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-nft-core | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-nft-fib | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-nft-nat | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-nft-offload | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-nls-base | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-phy-ath79-usb | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-ppp | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-pppoe | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-pppox | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-random-core | 6.6.144-r1 | unverifiable | metadata-only package with no files to check |
| kmod-slhc | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-usb-core | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-usb-ehci | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-usb-ledtrig-usbport | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| kmod-usb2 | 6.6.144-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libblobmsg-json20240329 | 2025.07.23~49056d17-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libc | 1.2.5-r4 | verified by a version marker in the bytes | version marker 1.2.5 found in lib/libc.so |
| libgcc1 | 13.3.0-r4 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libiwinfo-data | 2024.10.20~b94f066e-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libiwinfo20230701 | 2024.10.20~b94f066e-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libjson-c5 | 0.18-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libjson-script20240329 | 2025.07.23~49056d17-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| liblucihttp-ucode | 2023.03.15~9b5b683f-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| liblucihttp0 | 2023.03.15~9b5b683f-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libmbedtls21 | 3.6.6-r2 | verified, files present are byte-identical to the publisher's build | 3 file(s) byte-identical to the build in the official sibling image (3.6.6-r2); the shared feed has since moved to 3.6.7-r1 |
| libmnl0 | 1.0.5-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libnftnl11 | 1.2.8-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libnl-tiny1 | 2025.03.19~c0df580a-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libpthread | 1.2.5-r4 | unverifiable | metadata-only package with no files to check |
| libubox20240329 | 2025.07.23~49056d17-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libubus20250102 | 2025.10.17~60e04048-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libuci20250120 | 2025.01.20~16ff0bad-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libuclient20201210 | 2024.10.22~88ae8f20-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libucode20230711 | 2025.07.18~3f64c808-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package; the release manifest labels it 2025.07.18~3f64c808-r1 (the shared feed now labels the same bytes 2025.07.18~3f64c808-r2) |
| libudebug | 2025.08.24~edeb4d6d | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| libustream-mbedtls20201210 | 2024.07.28~99bd3d2b-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| logd | 2024.04.26~85f10530-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| luci | 26.205.85413~cac97ed | unverifiable | metadata-only package with no files to check |
| luci-app-firewall | 26.205.85413~cac97ed | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package; the release manifest labels it 26.205.85413~cac97ed (the shared feed now labels the same bytes 26.301.70438~aa4865e) |
| luci-app-package-manager | 26.205.85413~cac97ed | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package; the release manifest labels it 26.205.85413~cac97ed (the shared feed now labels the same bytes 26.301.70438~aa4865e) |
| luci-base | 26.205.85413~cac97ed | verified, files present are byte-identical to the publisher's build | 72 file(s) byte-identical to the build in the official sibling image (26.205.85413~cac97ed); the shared feed has since moved to 26.301.70438~aa4865e |
| luci-light | 26.205.85413~cac97ed | unverifiable | metadata-only package with no files to check |
| luci-mod-admin-full | 26.205.85413~cac97ed | unverifiable | metadata-only package with no files to check |
| luci-mod-network | 26.205.85413~cac97ed | verified, files present are byte-identical to the publisher's build | 16 file(s) byte-identical to the build in the official sibling image (26.205.85413~cac97ed); the shared feed has since moved to 26.301.70438~aa4865e |
| luci-mod-status | 26.205.85413~cac97ed | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package; the release manifest labels it 26.205.85413~cac97ed (the shared feed now labels the same bytes 26.301.70438~aa4865e) |
| luci-mod-system | 26.205.85413~cac97ed | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package; the release manifest labels it 26.205.85413~cac97ed (the shared feed now labels the same bytes 26.301.70438~aa4865e) |
| luci-proto-ipv6 | 26.205.85413~cac97ed | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package; the release manifest labels it 26.205.85413~cac97ed (the shared feed now labels the same bytes 26.301.70438~aa4865e) |
| luci-proto-ppp | 26.205.85413~cac97ed | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package; the release manifest labels it 26.205.85413~cac97ed (the shared feed now labels the same bytes 26.301.70438~aa4865e) |
| luci-ssl | 26.205.85413~cac97ed | unverifiable | metadata-only package with no files to check |
| luci-theme-bootstrap | 26.205.85413~cac97ed | verified, files present are byte-identical to the publisher's build | 10 file(s) byte-identical to the build in the official sibling image (26.205.85413~cac97ed); the shared feed has since moved to 26.301.70438~aa4865e |
| mtd | 26 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| netifd | 2025.05.23~7901e66c-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| nftables-json | 1.1.1-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| odhcp6c | 2024.09.25~b6ae9ffa-r2 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| odhcpd-ipv6only | 2025.10.02~b14cf98c-r3 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| openwrt-keyring | 2024.11.01~fbae29d7-r2 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| opkg | 2024.10.16~38eccbb1-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| ppp | 2.5.1-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| ppp-mod-pppoe | 2.5.1-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| procd | 2026.03.14~c59f2d80-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| procd-seccomp | 2026.03.14~c59f2d80-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| procd-ujail | 2026.03.14~c59f2d80-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| px5g-mbedtls | 11 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| rpcd | 2025.09.01~bba95191-r2 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| rpcd-mod-file | 2025.09.01~bba95191-r2 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| rpcd-mod-iwinfo | 2025.09.01~bba95191-r2 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| rpcd-mod-luci | 20240305-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| rpcd-mod-rrdns | 20170710 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| rpcd-mod-ucode | 2025.09.01~bba95191-r2 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| swconfig | 12 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| uboot-envtools | 2024.07-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| ubox | 2024.04.26~85f10530-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| ubus | 2025.10.17~60e04048-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| ubusd | 2025.10.17~60e04048-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| uci | 2025.01.20~16ff0bad-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| uclient-fetch | 2024.10.22~88ae8f20-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| ucode | 2025.07.18~3f64c808-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package; the release manifest labels it 2025.07.18~3f64c808-r1 (the shared feed now labels the same bytes 2025.07.18~3f64c808-r2) |
| ucode-mod-fs | 2025.07.18~3f64c808-r1 | verified, files present are byte-identical to the publisher's build | 1 file(s) byte-identical to the build in the official sibling image (2025.07.18~3f64c808-r1); the shared feed has since moved to 2025.07.18~3f64c808-r2 |
| ucode-mod-html | 1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| ucode-mod-math | 2025.07.18~3f64c808-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package; the release manifest labels it 2025.07.18~3f64c808-r1 (the shared feed now labels the same bytes 2025.07.18~3f64c808-r2) |
| ucode-mod-nl80211 | 2025.07.18~3f64c808-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package; the release manifest labels it 2025.07.18~3f64c808-r1 (the shared feed now labels the same bytes 2025.07.18~3f64c808-r2) |
| ucode-mod-rtnl | 2025.07.18~3f64c808-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package; the release manifest labels it 2025.07.18~3f64c808-r1 (the shared feed now labels the same bytes 2025.07.18~3f64c808-r2) |
| ucode-mod-ubus | 2025.07.18~3f64c808-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package; the release manifest labels it 2025.07.18~3f64c808-r1 (the shared feed now labels the same bytes 2025.07.18~3f64c808-r2) |
| ucode-mod-uci | 2025.07.18~3f64c808-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package; the release manifest labels it 2025.07.18~3f64c808-r1 (the shared feed now labels the same bytes 2025.07.18~3f64c808-r2) |
| ucode-mod-uloop | 2025.07.18~3f64c808-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package; the release manifest labels it 2025.07.18~3f64c808-r1 (the shared feed now labels the same bytes 2025.07.18~3f64c808-r2) |
| uhttpd | 2025.07.06~7e64e8ba-r5 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| uhttpd-mod-ubus | 2025.07.06~7e64e8ba-r5 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| urandom-seed | 3 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| urngd | 2023.11.01~44365eb1-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| usign | 2020.05.23~f1f65026-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| wifi-scripts | 1.0-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| wireless-regdb | 2026.05.30-r1 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| wpad-basic-mbedtls | 2024.09.15~5ace39b0-r3 | verified, files present are byte-identical to the publisher's build | every file byte-identical to the reference package |
| tcpdump | 4.99.5-r1 | absent from the firmware | none of the reference package's files exist in the firmware |

## What this report does not establish

- That any component is free of vulnerabilities or is used at run time.
- Anything about files outside the root filesystem (boot loader, kernel image, radio calibration data).
- That an `unverifiable` or `needs review` component is wrong. Those need a person or more reference data.
- Algorithm findings are string-level evidence (grade B), not proof of an implementation.
