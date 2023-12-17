---
layout: post
title: "Metasploit DB 사용법"
categories: [보안, 취약점스캐너]
tags: [취약점, 스캐너, metasploit]
toc: true
last_modified_at: 2023-12-06 17:02:00 +0900
---

#  개요
metasploit에서 DB에 접속하거나 DB관련 트러블 슈팅하는 방법을 정리해둔다. 

# 초기화작업
1. Metasploit에서 DB를 사용하려면 postgresql 서버를 구동해야한다. 

```sh
root@kali:~# systemctl start postgresql
```

2. postgresql서를 구동한 후에는 `msfdb init` 커맨드를 사용해서 초기화한다. 

```sh
$ sudo msfdb init
[sudo] password for kali: 
[i] Database already started
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating databases 'msf_test'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema
                                 
```

3. msfconsole에서 상태를 확인한다. 문제가 없다면 다음과 같이 출력된다. 

```sh
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.
msf6 > 

```

※ `msfdb init`을 실행하지 않은 상태에서 msfconsole에서 확인하면 다음과 같이 출력된다. 


```sh
msf6 > db_status
[*] postgresql selected, no connection
msf6 > 

```


# 참고
- https://www.offsec.com/metasploit-unleashed/using-databases/