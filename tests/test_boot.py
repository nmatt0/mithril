#!/usr/bin/env python3
"""Boot Security pass (--boot) regression.

Exercises the three artifact families, self-contained (no external tools):
  - U-Boot environment: moria's decoded uboot-env.txt (newline) and a raw env
    region (CRC header + NUL-separated key=value), leads classified by risk.
  - Device tree: /chosen bootargs analysis + hardware fingerprint.
  - FIT verified-boot posture: unsigned, signed-but-not-enforced, signed+required.

The device-tree / FIT blobs are dtc-built fixtures embedded as base64 (their
.its/.dts sources are in the comments); the env cases are built inline. Exit
nonzero on any failure.
"""
import base64
import json
import os
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
MITHRIL = os.path.join(HERE, "..", "build", "mithril")

# --- dtc-built device-tree / FIT fixtures (base64 of the compiled blobs) ------
# board.dts: model="Acme Router X1000", compatible="acme,x1000","acme,ipq8065",
#            /chosen bootargs="console=ttyS0,115200 root=/dev/mmcblk0p2 rootwait selinux=0"
BOARD_DTB = base64.b64decode(
    "0A3+7QAAAP4AAAA4AAAA5AAAACgAAAARAAAAEAAAAAAAAAAaAAAArAAAAAAAAAAAAAAAAAAAAAAA"
    "AAABAAAAAAAAAAMAAAASAAAAAEFjbWUgUm91dGVyIFgxMDAwAAAAAAAAAwAAABgAAAAGYWNtZSx4"
    "MTAwMABhY21lLGlwcTgwNjUAAAAAAWNob3NlbgAAAAAAAwAAADwAAAARY29uc29sZT10dHlTMCwx"
    "MTUyMDAgcm9vdD0vZGV2L21tY2JsazBwMiByb290d2FpdCBzZWxpbnV4PTAAAAAAAgAAAAIAAAAJ"
    "bW9kZWwAY29tcGF0aWJsZQBib290YXJncwA=")
# fit_unsigned.its: /images/{kernel-1,fdt-1} each with a hash-N, /configurations
#                   /conf-1 with no signature -> "no verified boot"
FIT_UNSIGNED = base64.b64decode(
    "0A3+7QAAAmcAAAA4AAACEAAAACgAAAARAAAAEAAAAAAAAABXAAAB2AAAAAAAAAAAAAAAAAAAAAAA"
    "AAABAAAAAAAAAAMAAAANAAAAAHVuc2lnbmVkIEZJVAAAAAAAAAADAAAABAAAAAwAAAABAAAAAWlt"
    "YWdlcwAAAAAAAWtlcm5lbC0xAAAAAAAAAAMAAAAEAAAAGxEiM0QAAAADAAAABwAAACBrZXJuZWwA"
    "AAAAAAMAAAAGAAAAJWFybTY0AAAAAAAAAwAAAAYAAAAqbGludXgAAAAAAAADAAAABQAAAC1nemlw"
    "AAAAAAAAAAFoYXNoLTEAAAAAAAMAAAAHAAAAOXNoYTI1NgAAAAAAAwAAAAQAAAA+3q2+7wAAAAIA"
    "AAACAAAAAWZkdC0xAAAAAAAAAwAAAAQAAAAbVWZ3iAAAAAMAAAAIAAAAIGZsYXRfZHQAAAAAAwAA"
    "AAYAAAAlYXJtNjQAAAAAAAABaGFzaC0xAAAAAAADAAAABgAAADljcmMzMgAAAAAAAAMAAAAEAAAA"
    "PgAAEjQAAAACAAAAAgAAAAIAAAABY29uZmlndXJhdGlvbnMAAAAAAAMAAAAHAAAARGNvbmYtMQAA"
    "AAAAAWNvbmYtMQAAAAAAAwAAAAkAAABMa2VybmVsLTEAAAAAAAAAAwAAAAYAAABTZmR0LTEAAAAA"
    "AAACAAAAAgAAAAIAAAAJZGVzY3JpcHRpb24AI2FkZHJlc3MtY2VsbHMAZGF0YQB0eXBlAGFyY2gA"
    "b3MAY29tcHJlc3Npb24AYWxnbwB2YWx1ZQBkZWZhdWx0AGtlcm5lbABmZHQA")
# fit_signed_noenf.its: config + image signature-1 nodes, /signature/key-devkey
#                       with NO `required` -> "not enforced"
FIT_SIGNED_NOENF = base64.b64decode(
    "0A3+7QAAAucAAAA4AAACiAAAACgAAAARAAAAEAAAAAAAAABfAAACUAAAAAAAAAAAAAAAAAAAAAAA"
    "AAABAAAAAAAAAAMAAAAXAAAAAHNpZ25lZCBGSVQgbm8gcmVxdWlyZWQAAAAAAAFpbWFnZXMAAAAA"
    "AAFrZXJuZWwtMQAAAAAAAAADAAAABAAAAAwRIjNEAAAAAwAAAAcAAAARa2VybmVsAAAAAAADAAAA"
    "BgAAABZhcm02NAAAAAAAAAMAAAAGAAAAG2xpbnV4AAAAAAAAAWhhc2gtMQAAAAAAAwAAAAcAAAAe"
    "c2hhMjU2AAAAAAADAAAABAAAACMAAACqAAAAAgAAAAFzaWduYXR1cmUtMQAAAAADAAAADwAAAB5z"
    "aGEyNTYscnNhMjA0OAAAAAAAAwAAAAcAAAApZGV2a2V5AAAAAAADAAAABAAAACMAAAC7AAAAAgAA"
    "AAIAAAACAAAAAWNvbmZpZ3VyYXRpb25zAAAAAAADAAAABwAAADdjb25mLTEAAAAAAAFjb25mLTEA"
    "AAAAAAMAAAAJAAAAP2tlcm5lbC0xAAAAAAAAAAFzaWduYXR1cmUtMQAAAAADAAAADwAAAB5zaGEy"
    "NTYscnNhMjA0OAAAAAAAAwAAAAcAAAApZGV2a2V5AAAAAAADAAAABwAAAEZrZXJuZWwAAAAAAAMA"
    "AAAEAAAAIwAAAMwAAAACAAAAAgAAAAIAAAABc2lnbmF0dXJlAAAAAAAAAWtleS1kZXZrZXkAAAAA"
    "AAMAAAAPAAAAHnNoYTI1Nixyc2EyMDQ4AAAAAAADAAAABwAAAClkZXZrZXkAAAAAAAMAAAAEAAAA"
    "UgAACAAAAAACAAAAAgAAAAIAAAAJZGVzY3JpcHRpb24AZGF0YQB0eXBlAGFyY2gAb3MAYWxnbwB2"
    "YWx1ZQBrZXktbmFtZS1oaW50AGRlZmF1bHQAa2VybmVsAHNpZ24taW1hZ2VzAHJzYSxudW0tYml0"
    "cwA=")
# fit_signed_enf.its: same but /signature/key-devkey has required="conf" -> enforced
FIT_SIGNED_ENF = base64.b64decode(
    "0A3+7QAAAwAAAAA4AAACmAAAACgAAAARAAAAEAAAAAAAAABoAAACYAAAAAAAAAAAAAAAAAAAAAAA"
    "AAABAAAAAAAAAAMAAAAUAAAAAHNpZ25lZCBGSVQgZW5mb3JjZWQAAAAAAWltYWdlcwAAAAAAAWtl"
    "cm5lbC0xAAAAAAAAAAMAAAAEAAAADBEiM0QAAAADAAAABwAAABFrZXJuZWwAAAAAAAMAAAAGAAAA"
    "FmFybTY0AAAAAAAAAwAAAAYAAAAbbGludXgAAAAAAAABaGFzaC0xAAAAAAADAAAABwAAAB5zaGEy"
    "NTYAAAAAAAMAAAAEAAAAIwAAAKoAAAACAAAAAXNpZ25hdHVyZS0xAAAAAAMAAAAPAAAAHnNoYTI1"
    "Nixyc2EyMDQ4AAAAAAADAAAABwAAAClkZXZrZXkAAAAAAAMAAAAEAAAAIwAAALsAAAACAAAAAgAA"
    "AAIAAAABY29uZmlndXJhdGlvbnMAAAAAAAMAAAAHAAAAN2NvbmYtMQAAAAAAAWNvbmYtMQAAAAAA"
    "AwAAAAkAAAA/a2VybmVsLTEAAAAAAAAAAXNpZ25hdHVyZS0xAAAAAAMAAAAPAAAAHnNoYTI1Nixy"
    "c2EyMDQ4AAAAAAADAAAABwAAAClkZXZrZXkAAAAAAAMAAAAHAAAARmtlcm5lbAAAAAAAAwAAAAQA"
    "AAAjAAAAzAAAAAIAAAACAAAAAgAAAAFzaWduYXR1cmUAAAAAAAABa2V5LWRldmtleQAAAAAAAwAA"
    "AA8AAAAec2hhMjU2LHJzYTIwNDgAAAAAAAMAAAAHAAAAKWRldmtleQAAAAAAAwAAAAQAAABSAAAI"
    "AAAAAAMAAAAFAAAAX2NvbmYAAAAAAAAAAgAAAAIAAAACAAAACWRlc2NyaXB0aW9uAGRhdGEAdHlw"
    "ZQBhcmNoAG9zAGFsZ28AdmFsdWUAa2V5LW5hbWUtaGludABkZWZhdWx0AGtlcm5lbABzaWduLWlt"
    "YWdlcwByc2EsbnVtLWJpdHMAcmVxdWlyZWQA")

ENV_VARS = [
    b"bootcmd=run bootargs; bootm 0x82000000",
    b"bootargs=console=ttyS0,115200 root=/dev/mtdblock3 init=/bin/sh",
    b"baudrate=115200",
    b"ethaddr=00:11:22:33:44:55",
    b"ipaddr=192.168.1.1",
    b"bootdelay=2",
    b"security_password=SuperSecret123",
]


# --- synthesized AVB vbmeta (no avbtool needed) -------------------------------
def _pad8(b):
    return b + b"\x00" * ((-len(b)) % 8)


def _descriptor(tag, payload):
    payload = _pad8(payload)
    return struct.pack(">QQ", tag, len(payload)) + payload


def desc_hashtree(part=b"system", algo=b"sha256"):
    fixed = struct.pack(">IQQQIIIQQ32sIIiI60s",
                        1, 0x40000, 0x40000, 0x1000, 4096, 4096, 0, 0, 0,
                        algo, len(part), 0, 0, 0, b"")
    return _descriptor(1, fixed + part)


def desc_kernel_cmdline(cmd):
    fixed = struct.pack(">II60s", 0, len(cmd), b"")
    return _descriptor(3, fixed + cmd)


def desc_chain(part=b"vendor", ril=2, pubkey=b"\x00" * 8):
    fixed = struct.pack(">IIII60s", ril, len(part), len(pubkey), 0, b"")
    return _descriptor(4, fixed + part + pubkey)


# The real AOSP AVB test public-key blob (external/avb/test/data/testkey_rsa2048.pem,
# via `avbtool extract_public_key`); its fingerprint is in mithril's corpus, so a
# vbmeta carrying it must be flagged avb-test-key (the private key is public).
AOSP_TEST_PUBKEY = base64.b64decode(
    "AAAIAMnYfXvGVVHdMiSi4A68fv29olOAWGl+9UpAh5WQVFk9Vcr/NjQa+uHgkCoaMmhb89+tC/mx0Pfqq0cfdr4"
    "bmEtno2L63+a1+O5zFl+4sYLeSYnVPdeoQpmBdcjYhHu9VKgiZES8NAYQPInC0fMsA2WRsaDRyCFWFZlIICd07wF"
    "6dqULa/3j+u0N+Q96Qfp2BTdJ/jRPSwFJ5Jj3iY7NNqo5Hal9XWtaUtF1aajffN4cG/nZGVu3R0y5cC6t5daIfO"
    "2SbkYIELV2Az4JrE22LM0SAL3UpwPTG5EIIzZbEf6vWWmzPIgkNy1husWZURiX+SNClp+HLs2yTV+pJPJF2uJlJi"
    "ZNHvo7U6vF03lTL2a4IZRmmpNvNSZDjI+Wuf+szfQAbr62c1SEUIVGU9XdQ/6yanhAeVafhvPTgTs9QJA1MppRf/"
    "jDS8fWocow+xv9Jwq4ZEE0wRfeoXaa688MUNkT9Q0LLJkky7W0+MYK0CaxW/1NRGadsHaqeZ3AXDuUNsGP/snSWm"
    "qgRuGiiy9RYVGjNpGDtPvNqUA0RpiKGpHf2Sw6v1c6RkYg8vC8MV4p/liQMlxml5majhUj66lH02PGGLuO0iCfeK"
    "9xsy4IiaHxfbEwoOYbvW7I9jPh2rC9FkH+B29ul4tqM9LXgANqTecFgigf72qpdX7hTuKVW0/m3AO5gQ==")


def vbmeta(descriptors=b"", algorithm=1, flags=0, rollback=0, pubkey=b"AVBKEY" + bytes(range(32))):
    aux = _pad8(pubkey)
    desc_off = len(aux)
    aux = _pad8(aux + descriptors)
    auth = _pad8(b"\x11" * 32 + (b"\x22" * 256 if algorithm else b""))
    hdr = struct.pack(
        ">4sIIQQIQQQQQQQQQQQII48s80s",
        b"AVB0", 1, 0, len(auth), len(aux), algorithm,
        0, 32 if algorithm else 0, 32 if algorithm else 0, 256 if algorithm else 0,
        0, len(pubkey), 0, 0,
        desc_off, len(descriptors),
        rollback, flags, 0, b"avbtool 1.2.0", b"")
    return hdr + auth + aux


# --- synthesized UEFI Secure Boot variable store (FV + authenticated store) ---
_GLOBAL = bytes([0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11,
                 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C])
_IMGSEC = bytes([0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45,
                 0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F])
_AVSTORE = bytes([0x78, 0x2C, 0xF3, 0xAA, 0x7B, 0x94, 0x9A, 0x43,
                  0xA1, 0x80, 0x2E, 0x14, 0x4E, 0xC3, 0x77, 0x92])
_NVDATA = bytes([0x8D, 0x2B, 0xF1, 0xFF, 0x96, 0x76, 0x8B, 0x4C,
                 0xA9, 0x85, 0x27, 0x47, 0x07, 0x5B, 0x4F, 0x50])


def _uvar(name, guid, data):
    nm = name.encode("utf-16-le") + b"\x00\x00"
    h = struct.pack("<HBBIQ16sIII16s", 0x55AA, 0x3F, 0, 7, 0, b"\x00" * 16, 0, len(nm), len(data), guid)
    b = h + nm + data
    return b + b"\x00" * ((-len(b)) % 4)


def uefi_vars(variables):
    body = b"".join(_uvar(n, g, d) for (n, g, d) in variables)
    store = _AVSTORE + struct.pack("<IBBHI", 28 + len(body), 0x5A, 0xFE, 0, 0) + body
    hlen = 0x48
    h = bytearray(hlen)
    h[16:32] = _NVDATA
    struct.pack_into("<Q", h, 32, hlen + len(store))
    h[40:44] = b"_FVH"
    struct.pack_into("<I", h, 44, 0x4FE)
    struct.pack_into("<H", h, 48, hlen)
    h[55] = 2
    s = sum(struct.unpack_from("<%dH" % (hlen // 2), h))
    struct.pack_into("<H", h, 50, (-s) & 0xFFFF)
    return bytes(h) + store


# CERT/CC PKfail AMI "DO NOT TRUST" test PK (AmiTestPk00.p7, PKCS#7) and the AOSP
# platform signing test cert (build/make .../security/platform.x509.pem). Both
# public; their fingerprints are in mithril's compiled-in corpus.
AMI_P7 = base64.b64decode(
    "MIIEvwIBATEPMA0GCWCGSAFlAwQCAQUAMAsGCSqGSIb3DQEHAaCCAzIwggMuMIICFqADAgECAhBV+++HgSMAhEcXC7PNhzr0"
    "MA0GCSqGSIb3DQEBCwUAMCUxIzAhBgNVBAMTGkRPIE5PVCBUUlVTVCAtIEFNSSBUZXN0IFBLMB4XDTE3MTEwODIzMzI1M1oX"
    "DTIxMTEwODIzMzI1MlowJTEjMCEGA1UEAxMaRE8gTk9UIFRSVVNUIC0gQU1JIFRlc3QgUEswggEiMA0GCSqGSIb3DQEBAQUA"
    "A4IBDwAwggEKAoIBAQDnNnsgkrp/qqP2DkkIh/UcETO6XfibXO3HkOTzQQIGQfkXHlKqmRq0ilpW7lvvd1kHEG6Rb/eRYU36"
    "MPVnSfWArXVUDaTcaK3hY4ofWSOwnvkZ9qDofTvB2bEf1pWWEroI/SB1vn2qhC6j0RNLxrrgzrjN4fAnIUZWQTVh94Hl25z3"
    "ROtpehmlahnZdX8/ysaOfrcFrAHhb0bPlPjh32aNH5hBQM8HwG5TbmPvqtFB7buHkB9ghKbQpqSulVGZiGQhSWLI6fyJKBL0"
    "cws9GWxS/DT98vy0T8pzSRpu+Tfyx1Ft/711h0b7bbX4DtA4N+eRIXLv4jMEPqHGf5YN62NZAgMBAAGjWjBYMFYGA1UdAQRP"
    "ME2AEAEnXPoS4sZrHbLwpPtj+n2hJzAlMSMwIQYDVQQDExpETyBOT1QgVFJVU1QgLSBBTUkgVGVzdCBQS4IQVfvvh4EjAIRH"
    "FwuzzYc69DANBgkqhkiG9w0BAQsFAAOCAQEAS4BTo5WFyB0gZznzY+aDeXXASbKFLUmBo6WC6D+J+4NheJ+mlN8jq/tbNYuL"
    "NuMc4PbkeWbHDalo54j4dkclzVWr0mQjVj1Y6Awn8nZdWWZ3VLNnDnlg6rbKhG79pBnaojdLjt+NQEh34qzadskAtogB67oo"
    "Kgi6/r2u+XKDd7kMIDZ8/j0d/uXUSg9o4OxTa5Zyd1DM6kCl2U3ryrrGbEupi1R7AaMg5/OiVF2S4rnpFwfM+6Joc5YQnswq"
    "5VlNVmO/AD4xnGS6DqYrvfCRNLm1qGzPyT2v/aYqWBJ1Yj130W1LnDcfy17LxUWv9/3/SEn5GhOHeaWb3Qg1sS01BjGCAWQw"
    "ggFgAgEBMDkwJTEjMCEGA1UEAxMaRE8gTk9UIFRSVVNUIC0gQU1JIFRlc3QgUEsCEFX774eBIwCERxcLs82HOvQwDQYJYIZI"
    "AWUDBAIBBQAwDQYJKoZIhvcNAQEBBQAEggEAigaDnxd6oomjpRDo2iTnAVV+NT/xLIPZDN0ueGKSjlLmHxM56BMD/2a3xQPk"
    "l6Z/Qji93aVn/Ch7GAWIAx3dJ1tHLCo4UT6TL67lEAbU0rTUQWynWO5RiquCoJhoYJIy5AYGBa4CiE2LL3Z+kxZDAWSb60Hg"
    "3Lr3DKfFdMx2lme2U/YKm8LqZI8ddhzn1cyRO6gwX0fGZ2MxvzKQ5PW1iC0mwGnaQGXHgM18auxFlCrcDI5oawGVz62R9T+s"
    "M789PrtmGinq0uTc6bQjYoDGWfM41Y/Ku7ufdMJwzu/PL+hKtzGpSCywfCGRw4+vqQwLTdzFIcfwvESAiS6xfAsWTg==")
AOSP_PLATFORM_PEM = base64.b64decode(
    "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVxRENDQTVDZ0F3SUJBZ0lKQUxPWmdJYlFWcy82TUEwR0NTcUdTSWIz"
    "RFFFQkJBVUFNSUdVTVFzd0NRWUQKVlFRR0V3SlZVekVUTUJFR0ExVUVDQk1LUTJGc2FXWnZjbTVwWVRFV01CUUdBMVVFQnhN"
    "TlRXOTFiblJoYVc0ZwpWbWxsZHpFUU1BNEdBMVVFQ2hNSFFXNWtjbTlwWkRFUU1BNEdBMVVFQ3hNSFFXNWtjbTlwWkRFUU1B"
    "NEdBMVVFCkF4TUhRVzVrY205cFpERWlNQ0FHQ1NxR1NJYjNEUUVKQVJZVFlXNWtjbTlwWkVCaGJtUnliMmxrTG1OdmJUQWUK"
    "Rncwd09EQTBNVFV5TWpRd05UQmFGdzB6TlRBNU1ERXlNalF3TlRCYU1JR1VNUXN3Q1FZRFZRUUdFd0pWVXpFVApNQkVHQTFV"
    "RUNCTUtRMkZzYVdadmNtNXBZVEVXTUJRR0ExVUVCeE1OVFc5MWJuUmhhVzRnVm1sbGR6RVFNQTRHCkExVUVDaE1IUVc1a2Nt"
    "OXBaREVRTUE0R0ExVUVDeE1IUVc1a2NtOXBaREVRTUE0R0ExVUVBeE1IUVc1a2NtOXAKWkRFaU1DQUdDU3FHU0liM0RRRUpB"
    "UllUWVc1a2NtOXBaRUJoYm1SeWIybGtMbU52YlRDQ0FTQXdEUVlKS29aSQpodmNOQVFFQkJRQURnZ0VOQURDQ0FRZ0NnZ0VC"
    "QUp4NEJaS3NEVjA0SE42cVpleklwZ0J1TmtnTWJYSUhzU0FSCnZsQ0dPcXZpdFYwQW10OXhSdGJ5SUNLQXg4MU5lOXNtSkR1"
    "S2dHd21zMHNUZFNPa2ttZ2lTUVRjQVVrK2ZBclAKR2dYSWRQYWJBM3RnTUoyUWROSkNnT0ZyclNxSE5EWVpVZXIzS2tndENi"
    "SUVzWWRlRXF5WXdhcDNQV2dBdWVyOQo1VzFZdnRqbzJoYjVvMkFKbkRlb05LYmY3YmUydEVvRW5nZWlhZnpQTEZTVzhzODIx"
    "azM1Q2p1Tmp6U2p1cXRNCjlUTnhxeWR4bXp1bGgxU3RERlA4Rk9IYlJkVWVJMCs3NlR5YnBPMzV6bFFtRTFEc1UxWUh2Mm1p"
    "LzBxZ2ZiWDMKNmlBTkNhYkJ0SjRoUUMrSjdSR1FpVHFyV3BHQThWTG9MNFdrVjFQUFg4R1FjY1h1eUNjQ0FRT2pnZnd3Z2Zr"
    "dwpIUVlEVlIwT0JCWUVGRS9rb0xQZG5Mb3A5eDF5aDhUbnc0OGdoc0taTUlISkJnTlZIU01FZ2NFd2diNkFGRS9rCm9MUGRu"
    "TG9wOXgxeWg4VG53NDhnaHNLWm9ZR2FwSUdYTUlHVU1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUUKQ0JNS1EyRnNhV1p2"
    "Y201cFlURVdNQlFHQTFVRUJ4TU5UVzkxYm5SaGFXNGdWbWxsZHpFUU1BNEdBMVVFQ2hNSApRVzVrY205cFpERVFNQTRHQTFV"
    "RUN4TUhRVzVrY205cFpERVFNQTRHQTFVRUF4TUhRVzVrY205cFpERWlNQ0FHCkNTcUdTSWIzRFFFSkFSWVRZVzVrY205cFpF"
    "QmhibVJ5YjJsa0xtTnZiWUlKQUxPWmdJYlFWcy82TUF3R0ExVWQKRXdRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFRUJRQURn"
    "Z0VCQUZjbFVialpPaDl6M2c5dFJwK0cydFp3RkFBcApQSWlnelh6WGVMYzlyOHdaZjZ0MjVpRXVWc0hIWWMvRUw5Y3ozbExG"
    "Q3VDSUZNNzhDanRhR2tOR0JVMkNueDJDCnRDc2dTTCtJdGRGSktlK0Y5ZzdkRXRjdFZXVitJdVBvWFFUSU1kWVQwWms0dTRt"
    "Q0pIK2pJU1Zyb1MwZGFvK1MKNmgyeHczTXhlNkRBTi9EUnIvWkZydklrbDUrNmJub1V2QUpjY2JtQk9NN3ozZndGbGhmUEpJ"
    "UmM5N1FOWTRMMwpKMTdYT0VsYXR1V1RHNVFoZGx4SkczTDdhT0NBMjl0WXdnS2ROSHlMTW96a1B2YW9zVlV6N2Z2cGliMXFT"
    "TjFMCklDN2FsTWFyamRXNE9aSUQycTR1MUVZakxrL3B2WllUbE1Zd0RsRTQ0OC9TaGViazVJTlRqTGl4czFjPQotLS0tLUVO"
    "RCBDRVJUSUZJQ0FURS0tLS0tCg==")
X509GUID = bytes([0xA1, 0x59, 0xC0, 0xA5, 0xE4, 0x94, 0xA7, 0x4A,
                  0x87, 0xB5, 0xAB, 0x15, 0x5C, 0x2B, 0xF0, 0x72])


def _cert_from_p7(d):
    def tlv(d, i):
        t = d[i]; j = i + 1; l = d[j]; j += 1
        if l & 0x80:
            n = l & 0x7F; l = int.from_bytes(d[j:j + n], "big"); j += n
        return t, j, l, j + l
    _, cs, _, e = tlv(d, 0); i = cs
    while i < e:
        t, c, _, end = tlv(d, i)
        if t == 0xA0:
            ct, _, _, ce = tlv(d, c)
            return d[c:ce] if ct == 0x30 else None
        i = end
    return None


def efi_sig_list(cert):
    sigsize = 16 + len(cert)
    return X509GUID + struct.pack("<III", 28 + sigsize, 0, sigsize) + b"\x00" * 16 + cert


SHA256GUID = bytes([0x26, 0x16, 0xC4, 0xC1, 0x4C, 0x50, 0x92, 0x40,
                    0xAC, 0xA9, 0x41, 0xF9, 0x36, 0x93, 0x43, 0x28])


def sha256_siglist(n):
    sigsize = 16 + 32  # owner GUID + SHA-256 hash
    entries = b"".join(b"\x00" * 16 + bytes([i & 0xFF]) * 32 for i in range(n))
    return SHA256GUID + struct.pack("<III", 28 + len(entries), 0, sigsize) + entries


def _fv(body):
    """Wrap a body in a minimal UEFI firmware volume (so the FV branch dispatches)."""
    hlen = 0x48
    h = bytearray(hlen)
    h[16:32] = _NVDATA
    struct.pack_into("<Q", h, 32, hlen + len(body))
    h[40:44] = b"_FVH"
    struct.pack_into("<I", h, 44, 0x4FE)
    struct.pack_into("<H", h, 48, hlen)
    h[55] = 2
    s = sum(struct.unpack_from("<%dH" % (hlen // 2), h))
    struct.pack_into("<H", h, 50, (-s) & 0xFFFF)
    return bytes(h) + body


def _nvar_entry(name, data, attr=0x82):
    # AMI NVAR: 'NVAR' size(u16) next(3) attr(u8), then 1-byte GUID index (attr&4==0),
    # ASCII name + NUL (attr&2), then data. attr 0x82 = VALID|ASCII_NAME.
    body = b"\x00" + name.encode() + b"\x00" + data
    size = 10 + len(body)
    return b"NVAR" + struct.pack("<H", size) + b"\xff\xff\xff" + bytes([attr]) + body


def nvar_store(variables):
    """A synthetic AMI NVAR variable store in an FV. variables: [(name, data)]."""
    return _fv(b"".join(_nvar_entry(n, d) for (n, d) in variables))


def env_text():
    return b"\n".join(ENV_VARS) + b"\n"


def env_raw(size=0x2000):
    data = b"\x00".join(ENV_VARS) + b"\x00\x00"
    data = data.ljust(size - 4, b"\x00")[: size - 4]
    return struct.pack("<I", zlib.crc32(data) & 0xFFFFFFFF) + data


def run(name, blob, extra_env_txt=False):
    with tempfile.TemporaryDirectory() as td:
        # uboot-env.txt basename triggers the line-based env parse.
        fn = "uboot-env.txt" if extra_env_txt else name
        p = os.path.join(td, fn)
        with open(p, "wb") as f:
            f.write(blob)
        out = subprocess.run([MITHRIL, "--boot", "-j", p], capture_output=True, text=True).stdout
        return json.loads(out).get("boot_security", [])


def types(hits):
    return {h["type"] for h in hits}


def sev(hits, t):
    for h in hits:
        if h["type"] == t:
            return h["evidence"].split("]")[0].lstrip("[")
    return None


def main():
    fails = []

    def check(cond, msg):
        print(("  PASS  " if cond else "  FAIL  ") + msg)
        if not cond:
            fails.append(msg)

    # --- U-Boot env (text, moria-extracted) ---
    h = run("uboot-env.txt", env_text(), extra_env_txt=True)
    t = types(h)
    check("cmdline-init-shell" in t and sev(h, "cmdline-init-shell") == "high",
          "env-txt: init=/bin/sh flagged high")
    check("uboot-env-secret" in t and sev(h, "uboot-env-secret") == "high",
          "env-txt: password var flagged high")
    check("uboot-console-interruptible" in t, "env-txt: bootdelay>=0 interruptible console")
    check("uboot-env-mac" in t and "uboot-env-network" in t, "env-txt: mac + network leads")

    # --- U-Boot env (raw region with CRC header) ---
    h = run("env.bin", env_raw())
    check("cmdline-init-shell" in types(h) and "uboot-env-secret" in types(h),
          "env-raw: NUL-separated env parsed, leads found")

    # --- device tree: bootargs + fingerprint ---
    h = run("board.dtb", BOARD_DTB)
    t = types(h)
    check("cmdline-selinux-off" in t and sev(h, "cmdline-selinux-off") == "medium",
          "dtb: selinux=0 flagged medium")
    check("hardware-model" in t and "hardware-compatible" in t, "dtb: hardware fingerprint")

    # --- FIT verified-boot posture ---
    h = run("fit.itb", FIT_UNSIGNED)
    check("fit-unsigned" in types(h) and sev(h, "fit-unsigned") == "medium",
          "fit-unsigned: no verified boot flagged medium")

    h = run("fit.itb", FIT_SIGNED_NOENF)
    t = types(h)
    check("fit-signed" in t, "fit-signed-noenf: signature nodes detected")
    check("fit-signature-not-enforced" in t and sev(h, "fit-signature-not-enforced") == "medium",
          "fit-signed-noenf: not-enforced flagged medium")
    check("fit-signing-key" in t, "fit-signed-noenf: embedded pubkey surfaced")

    h = run("fit.itb", FIT_SIGNED_ENF)
    t = types(h)
    check("fit-signed" in t and "fit-signature-not-enforced" not in t,
          "fit-signed-enf: enforced (required=conf), no not-enforced warning")

    # --- AVB vbmeta: verification posture ---
    h = run("vbmeta.img", vbmeta(algorithm=0, flags=0x2))
    t = types(h)
    check("avb-verification-disabled" in t and sev(h, "avb-verification-disabled") == "high",
          "avb: VERIFICATION_DISABLED flag flagged high")
    check("avb-unsigned" in t, "avb: algorithm NONE flagged unsigned")

    h = run("vbmeta.img", vbmeta(algorithm=1, flags=0x1))
    check("avb-hashtree-disabled" in types(h) and sev(h, "avb-hashtree-disabled") == "high",
          "avb: HASHTREE_DISABLED flag flagged high")

    # signed vbmeta with descriptors: dm-verity, chain partition, injected cmdline
    descs = (desc_hashtree(b"system", b"sha256")
             + desc_kernel_cmdline(b"console=ttyMSM0 init=/bin/sh androidboot.selinux=permissive")
             + desc_chain(b"vendor", 2))
    h = run("vbmeta.img", vbmeta(descriptors=descs, algorithm=1, rollback=3))
    t = types(h)
    check("avb-signed" in t and "avb-signing-key" in t, "avb: signed + key fingerprint")
    check("avb-dm-verity" in t, "avb: dm-verity hashtree descriptor (system)")
    check("avb-chain-partition" in t, "avb: chain-partition descriptor (vendor)")
    check("cmdline-init-shell" in t, "avb: injected kernel cmdline analyzed (init=/bin/sh)")
    check("cmdline-androidboot-permissive" in t, "avb: injected cmdline androidboot permissive")

    # signed with the real AOSP AVB test key -> corpus match (private key is public)
    h = run("vbmeta.img", vbmeta(algorithm=1, pubkey=AOSP_TEST_PUBKEY))
    check("avb-test-key" in types(h) and sev(h, "avb-test-key") == "high",
          "avb: AOSP test key detected (private key public -> forgeable)")

    # --- U-Boot weak/default password ---
    env2 = b"bootcmd=x\nbootargs=y\nbaudrate=1\nipaddr=1.2.3.4\npassword=admin\n"
    h = run("uboot-env.txt", env2, extra_env_txt=True)
    check("uboot-env-weak-password" in types(h) and sev(h, "uboot-env-weak-password") == "high",
          "env: weak/default password flagged high")

    # --- UEFI Secure Boot posture ---
    enrolled = uefi_vars([("SecureBoot", _GLOBAL, b"\x01"), ("SetupMode", _GLOBAL, b"\x00"),
                          ("PK", _GLOBAL, b"PKCERT" * 40), ("KEK", _GLOBAL, b"KEK" * 30),
                          ("db", _IMGSEC, b"DB" * 300), ("dbx", _IMGSEC, b"")])
    h = run("OVMF_VARS.fd", enrolled)
    t = types(h)
    check("uefi-secureboot-on" in t, "uefi: Secure Boot on with PK")
    check("uefi-platform-key" in t, "uefi: platform key fingerprinted")
    check("uefi-dbx-empty" in t and sev(h, "uefi-dbx-empty") == "medium",
          "uefi: empty dbx flagged medium")

    off = uefi_vars([("SecureBoot", _GLOBAL, b"\x00"), ("PK", _GLOBAL, b"PK" * 40)])
    check("uefi-secureboot-off" in types(run("OVMF_VARS.fd", off)) and
          sev(run("OVMF_VARS.fd", off), "uefi-secureboot-off") == "high",
          "uefi: Secure Boot disabled flagged high")

    setup = uefi_vars([("SecureBoot", _GLOBAL, b"\x00"), ("SetupMode", _GLOBAL, b"\x01")])
    check("uefi-setup-mode" in types(run("OVMF_VARS.fd", setup)),
          "uefi: setup mode / no PK flagged")

    # --- PKFAIL: UEFI PK = the AMI "DO NOT TRUST" test cert (B5 corpus) ---
    ami_cert = _cert_from_p7(AMI_P7)
    pkfail = uefi_vars([("PK", _GLOBAL, efi_sig_list(ami_cert)), ("SecureBoot", _GLOBAL, b"\x01")])
    h = run("OVMF_VARS.fd", pkfail)
    check("uefi-test-platform-key" in types(h) and sev(h, "uefi-test-platform-key") == "high",
          "pkfail: AMI test PK detected in UEFI PK (Secure Boot forgeable)")

    # --- AOSP signing test cert (PEM) + OTA CERT.RSA (PKCS#7) ---
    h = run("platform.x509.pem", AOSP_PLATFORM_PEM)
    check("apk-test-signing-cert" in types(h) and sev(h, "apk-test-signing-cert") == "high",
          "apk: AOSP platform test cert (PEM) detected")
    h = run("CERT.RSA", AMI_P7)
    check("apk-test-signing-cert" in types(h), "apk: PKCS#7 signature block cert matched")

    # --- AMI NVAR variable store (the format most vendor BIOSes use) ---
    ami_cert = _cert_from_p7(AMI_P7)
    nv = nvar_store([("SecureBoot", b"\x01"), ("SetupMode", b"\x00"),
                     ("PK", b"PKCERT" * 40), ("KEK", b"KEK" * 30),
                     ("db", b"DB" * 300), ("dbx", sha256_siglist(5))])
    h = run("bios.bin", nv)
    check("uefi-platform-key" in types(h), "nvar: PK recovered from AMI NVAR store")
    check("uefi-secureboot-on" in types(h), "nvar: SecureBoot/PK posture from NVAR")
    dbxh = [x for x in h if x["type"] == "uefi-dbx"]
    check(bool(dbxh) and "5 revocation" in dbxh[0]["label"],
          "nvar+dbx: dbx revocations enumerated (5)")

    # A full-flash SPI dump: the firmware volume sits at a nonzero offset (the low
    # region is 0xFF pad), so "_FVH" is not at offset 40. The pass must still find
    # it — this is how a real desktop BIOS image is laid out.
    padded = b"\xff" * 0x4000 + nvar_store([("SecureBoot", b"\x01"), ("PK", b"PKCERT" * 40)])
    ph = run("flash.bin", padded)
    check("uefi-platform-key" in types(ph) and "uefi-secureboot-on" in types(ph),
          "nvar: FV at a nonzero offset (full-flash dump) still analyzed")

    # A variable store extracted on its own (a chipsec/UEFITool artifact) has no FV
    # wrapper, so no "_FVH" signature. It must still be analyzed -- the raw AMI store
    # begins with an "NVAR" entry. A large defaults-container entry ("StdDefaults")
    # sits up front, as on a real BIOS; the top-level PK/dbx after it are still
    # recovered. Regression: without the store-start trigger this was silently
    # skipped, so an extracted NVAR store reported nothing.
    raw = b"".join(_nvar_entry(n, d) for (n, d) in
                   [("StdDefaults", b"\x00" * 200), ("PK", b"PKCERT" * 40),
                    ("KEK", b"KEK" * 30), ("db", b"DB" * 300), ("dbx", sha256_siglist(5)),
                    ("SecureBoot", b"\x01")])
    check(raw[:4] == b"NVAR", "nvar: standalone store begins with an NVAR entry (no FV)")
    rh = run("varstore.bin", raw)
    check("uefi-platform-key" in types(rh) and "uefi-secureboot-on" in types(rh),
          "nvar: standalone extracted store (no FV wrapper) is analyzed")
    rdbx = [x for x in rh if x["type"] == "uefi-dbx"]
    check(bool(rdbx) and "5 revocation" in rdbx[0]["label"],
          "nvar: standalone store dbx enumerated past a leading container entry")

    # PKFAIL through the NVAR store: PK is the AMI "DO NOT TRUST" test key.
    nvpk = nvar_store([("PK", efi_sig_list(ami_cert)), ("SecureBoot", b"\x01")])
    check("uefi-test-platform-key" in types(run("bios.bin", nvpk)),
          "nvar+pkfail: AMI test PK detected via the NVAR store")

    # --- standalone EFI_SIGNATURE_LIST (an extracted PK/KEK/db/dbx variable) ---
    sl = run("PK.bin", efi_sig_list(ami_cert))
    check("uefi-siglist" in types(sl) and "1 X.509 cert" in sl[0]["label"],
          "siglist: standalone X.509 signature list inventoried")
    check("uefi-test-key" in types(sl), "siglist: test/default key matched in a standalone list")
    dbxsl = run("dbx.bin", sha256_siglist(371))
    slh = [x for x in dbxsl if x["type"] == "uefi-siglist"]
    check(bool(slh) and "371 SHA-256 hashes" in slh[0]["label"],
          "siglist: SHA-256 revocation list counted (371)")

    # --- FP guards ---
    h = run("app.conf", b"A=1\nB=2\nC=3\nD=4\nE=5\n")
    check(len(h) == 0, "fp: newline .conf (not uboot-env.txt) -> no boot findings")
    h = run("bad.img", b"AVB0" + os.urandom(300))
    check(len(h) == 0, "fp: AVB0 + random header -> no boot findings")
    h = run("junk.x509.pem", b"-----BEGIN CERTIFICATE-----\nnot base64!!!\n-----END CERTIFICATE-----\n")
    check(len(h) == 0, "fp: non-cert .pem -> no boot findings")

    # --- human view: identical (type,value) findings collapse with a count ---
    with tempfile.TemporaryDirectory() as td:
        for i in range(3):
            with open(os.path.join(td, "fdt%d.dtb" % i), "wb") as f:
                f.write(BOARD_DTB)
        human = subprocess.run([MITHRIL, "--boot", td], capture_output=True, text=True).stdout
        check("unique)" in human and "(×3)" in human and "+2 more" in human,
              "human: identical findings across files collapse to one row (×N)")

    if fails:
        print(f"\nFAIL: {len(fails)} check(s) failed")
        return 1
    print("\nPASS: boot pass (U-Boot env + device tree + FIT posture)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
