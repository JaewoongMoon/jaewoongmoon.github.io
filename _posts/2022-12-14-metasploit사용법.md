---
layout: post
title: "Metasploit 프레임워크 설치 및 사용법"
categories: [보안, 취약점스캐너]
tags: [취약점, 스캐너, metasploit]
toc: true
last_modified_at: 2023-08-09 17:02:00 +0900
---

# Metasploit 설치 및 셋업
- 터미널을 통한 설치를 진행한다. 아래 커맨드를 실행하면 설치된다. 

```sh
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
```

- 아래 명령어를 실행해서 DB 셋업에 들어간다. 
- yes를 입력해서 새로운 DB를 만든다. 
- webservice는 선택이다. no를 선택했다. 

```sh
/opt/metasploit-framework/bin/msfconsole

 ** Welcome to Metasploit Framework Initial Setup **
    Please answer a few questions to get started.


Would you like to use and setup a new database (recommended)? yes
[?] Would you like to init the webservice? (Not Required) [no]: no
```

- DB설정이 완료되면 다음과 같이 메타스플로잇 프레임워크 6 (msf6) 콘솔에 접속한 상태가 된다. 

```sh
 _                                                    _
/ \    /\         __                         _   __  /_/ __
| |\  / | _____   \ \           ___   _____ | | /  \ _   \ \
| | \/| | | ___\ |- -|   /\    / __\ | -__/ | || | || | |- -|
|_|   | | | _|__  | |_  / -\ __\ \   | |    | | \__/| |  | |_
      |/  |____/  \___\/ /\ \\___/   \/     \__|    |_\  \___\


       =[ metasploit v6.2.31-dev-                         ]
+ -- --=[ 2272 exploits - 1191 auxiliary - 405 post       ]
+ -- --=[ 948 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Adapter names can be used for IP params
set LHOST eth0
Metasploit Documentation: https://docs.metasploit.com/

```

- 다음 커맨드를 실행한다. 
- Connected to msf. Connection type: postgresql. 같은 메세지가 나오면 설치 성공이다!
- exit 를 입력하고 빠져나온다. 

```
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.
msf6 > 
 ```

- 메타스플로잇 프레임워크는 /opt/metasploit-framework/ 에 설치되어 있다. 
- DB 데이터는 ~/.msf4/db 에 있다. 

 # 사용법
 ## 메타스플로잇 콘솔 접속
 ```sh
 msfconsole
 ```

 ## 메타스플로잇 DB 검색
```sh
search -h 
```

검색 커맨드 예제

```sh
search cve:2022 platform:linux type:exploit
search aka:heartbleed
search name:openssl 
search type:exploit -s date # exploit을 공개일을 기준으로 정렬한다. 
search type:exploit -s date -r # exploit을공개일을 기준으로 역순으로 정렬한다.  
search cve:2019 1458 # cve-2019-1458 을 찾는다. 
```

## 검색한 DB 사용하기
- use 커맨드를 사용한다. 
- 다음은 heartbleed 스캐너를 사용하는 예이다. 

```sh
use auxiliary/scanner/ssl/openssl_heartbleed
```

- use 커맨드를 사용하면 다음과 같이 프롬프트가 변경된다. 

```sh
msf6 auxiliary(scanner/ssl/openssl_heartbleed) >
```

- 어떤 옵션이 사용가능한지 보기위해 show options를 사용한다. 
- 또는 info 커맨드를 사용해도 된다. 
- Required 필드는 필수로 설정해야 하는 값이다 (입력하지 않으면 기본값이 사용되는 것 같다).

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

## 검색한 모듈의 코드 보기
edit명령으로 exploit 코드를 볼 수 있다. 

```sh
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > edit
```

## 해당 모듈에서 사용가능한 페이로드 확인하기
show payloads 명령으로 사용가능한 페이로드를 볼 수 있다. 

```sh
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > show payloads
```

## 해당 모듈이 스캔(또는 공격)가능한 시스템 종류 확인하기
- show targets 명령으로 어떤 시스템을 스캔(또는 공격)가능한지 볼 수 있다. 
- exploit모듈에서만 지원하는 기능으로 보인다. 

```sh
msf6 exploit(windows/smb/ms08_067_netapi) > show targets
```

## 취약한지 체크하기
- check 커맨드로 취약한지 체크할 수 있다. (exploit까지는 실행하지 않는다.)
- 모듈에서 check 옵션을 지원하는 경우에 사용가능하다. 

```sh
set RHOSTS xxx.com 
set RPORT 443
check 
```

## exploit(공격) 수행하기
- set 명령으로 필요한 설정값을 설정한 후에 exploit 명령으로 스캔을 수행한다. 

```sh
set RHOSTS xxx.com 
set RPORT 443
exploit
```

## 되돌아가기
DB를 사용한 후에 다시 콘솔 메인으로 돌아가고 싶을 때 사용한다. 

```sh
msf auxiliary(ms09_001_write) > back
msf >
```

## DB 업데이트하기

```sh
msfupdate 
```


# 메타스플로잇 개념
## 익스플로잇
공격자나 테스터가 시스템, 어플리케이션, 서비스 내의 결함을 교묘하게 이용하는 것을 의미한다. 

## 페이로드 
페이로드는 타겟 시스템에게 실행시키고 싶은 코드를 의미한다. 예를들면 리버스 셸같은 것이다. 

## Stager


# 참고 
- https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/
- https://t-okk.tistory.com/187
- https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/