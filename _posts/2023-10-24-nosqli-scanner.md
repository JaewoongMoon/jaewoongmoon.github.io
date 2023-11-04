---
layout: post
title: "Burp Crawling 사양 정리"
categories: [취약점스캐너, Burp Suite]
tags: [취약점스캐너, Burp Suite]
toc: true
last_modified_at: 2023-10-25 09:15:00 +0900
---

# 개요
- 2023년 10월 25일 기준, Burp Suite의 기본 스캐너로는 NoSQL 인젝션을 탐지하지 못한다.
- Burp Suite 확장 프로그램인 NoSQL 인젝션 스캐너 "Burp NoSQLi Scanner"를 사용해보고 사용법과 결과등을 정리해둔다. 
- 스캔대상은 [여기]()에서 구축했던 서버를 대상으로 한다. 

# 설치 
BApp 스토어에서 설치하면 된다. 

![Burp NoSQLi Scanner설치](/images/nosqli-practice-install-nosqli-scanner.png)

# 사용법
- 공식 사이트에는 사용법이 따로 적혀있지 않다. 
- 예전에 Log4Shell 스캐너 확장 프로그램을 사용했을 때의 경험을 바탕으로 동일한 순서로 스캔해주었더니 스캔이 되었다. 
- scan launcher의 Scan Configuration 메뉴에서 Select from library를 선택하고, Audit checks - extensions only를 선택해주면 된다. 이렇게 하면 확장 프로그램에서 제공하는 스캔 기능만을 사용해서 스캔할 수 있다. 

![Configuration선택하기](/images/nosqli-practice-nosqli-scanner-configuration.png)

# 스캔 결과 
스캔 결과는 다음과 같다. NoSQL인젝션이 되는 것을 검출해주었다. 

![스캔 결과1](/images/nosqli-practice-nosqli-scanner-result-1.png)

![스캔 결과2](/images/nosqli-practice-nosqli-scanner-result-2.png)


# NoSQLMap
## 소스코드 내려받기 

```sh
git pull https://github.com/codingo/NoSQLMap.git
cd NoSQLMap/docker
```

## Dockerfile수정 
다음과 같이 수정한다. 

- certifi를 제거하고 2018.10.15버전을 명시하도록 수정하였다. (이렇게 하지 않으면 실행시에 파이썬에러가 발생한다.)

```sh
FROM python:2.7-alpine

RUN echo 'http://dl-cdn.alpinelinux.org/alpine/v3.9/main' >> /etc/apk/repositories
RUN echo 'http://dl-cdn.alpinelinux.org/alpine/v3.9/community' >> /etc/apk/repositories
RUN apk update && apk add mongodb git

RUN git clone https://github.com/codingo/NoSQLMap.git /root/NoSqlMap

WORKDIR /root/NoSqlMap

RUN python setup.py install
RUN pip2 uninstall -y certifi
RUN pip2 install certifi==2018.10.15

COPY entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh

ENTRYPOINT ["/tmp/entrypoint.sh"]

```

## 설치 

```sh
docker build -t nosqlmap .
```

## 실행 
docker-compose 혹은 docker run 을 사용해서 툴을 실행할 수 있다. 

```sh
docker-compose run nosqlmap 
```

```sh
docker run --net=host --rm -it nosqlmap
```

localhost
username,moon,password,test

## 파라메터를 주어 실행하기 
실행시에 파라메터를 주는 것은 어째서인지 제대로 동작하지 않았다. 

```sh
docker-compose run nosqlmap --attack 2 --victim localhost --webPort 3001 --uri /login --httpMethod POST --postData username,test,password,qwerty --savePath output.log
```

```sh
docker run --net=host --rm -it nosqlmap --attack 2 --victim localhost --webPort 3001 --uri /login --httpMethod POST --postData username,test,password,qwerty --savePath output.log
```

## 실행 결과 및 소감
- 일일히 옵션을 설정해줘야 하는게 귀찮다. 
- 서버측에서 에러 응답을 회신하면 바로 툴이 멈춰버린다. 
- 실행시에 파라메터를 주는 것도 제대로 동작하지 않는다. 
- 결론, 제대로 쓰기는 힘든 툴로 생각된다. 

```sh
_  _     ___  ___  _    __  __
| \| |___/ __|/ _ \| |  |  \/  |__ _ _ __
| .` / _ \__ \ (_) | |__| |\/| / _` | '_ \
|_|\_\___/___/\__\_\____|_|  |_\__,_| .__/
 v0.7 codingo@protonmail.com        |_|
 
 
1-Set options
2-NoSQL DB Access Attacks
3-NoSQL Web App attacks
4-Scan for Anonymous MongoDB Access
5-Change Platform (Current: MongoDB)
x-Exit
Select an option: 1
 
 
 
Options
1-Set target host/IP (Current: Not Set)
2-Set web app port (Current: 80)
3-Set App Path (Current: Not Set)
4-Toggle HTTPS (Current: OFF)
5-Set MongoDB Port (Current : 27017)
6-Set HTTP Request Method (GET/POST) (Current: GET)
7-Set my local MongoDB/Shell IP (Current: Not Set)
8-Set shell listener port (Current: Not Set)
9-Toggle Verbose Mode: (Current: OFF)
0-Load options file
a-Load options from saved Burp request
b-Save options file
h-Set headers
x-Back to main menu
Select an option: 1
Enter the host IP/DNS name: localhost
 
Target set to localhost
 
 
 
 
Options
1-Set target host/IP (Current: localhost)
2-Set web app port (Current: 80)
3-Set App Path (Current: Not Set)
4-Toggle HTTPS (Current: OFF)
5-Set MongoDB Port (Current : 27017)
6-Set HTTP Request Method (GET/POST) (Current: GET)
7-Set my local MongoDB/Shell IP (Current: Not Set)
8-Set shell listener port (Current: Not Set)
9-Toggle Verbose Mode: (Current: OFF)
0-Load options file
a-Load options from saved Burp request
b-Save options file
h-Set headers
x-Back to main menu
Select an option: 2
Enter the HTTP port for web apps: 3001
 
HTTP port set to 3001
 
 
 
 
Options
1-Set target host/IP (Current: localhost)
2-Set web app port (Current: 3001)
3-Set App Path (Current: Not Set)
4-Toggle HTTPS (Current: OFF)
5-Set MongoDB Port (Current : 27017)
6-Set HTTP Request Method (GET/POST) (Current: GET)
7-Set my local MongoDB/Shell IP (Current: Not Set)
8-Set shell listener port (Current: Not Set)
9-Toggle Verbose Mode: (Current: OFF)
0-Load options file
a-Load options from saved Burp request
b-Save options file
h-Set headers
x-Back to main menu
Select an option: 3
Enter URI Path (Press enter for no URI): login
 
 _  _     ___  ___  _    __  __
| \| |___/ __|/ _ \| |  |  \/  |__ _ _ __
| .` / _ \__ \ (_) | |__| |\/| / _` | '_ \
|_|\_\___/___/\__\_\____|_|  |_\__,_| .__/
 v0.7 codingo@protonmail.com        |_|
 
 
1-Set options
2-NoSQL DB Access Attacks
3-NoSQL Web App attacks
4-Scan for Anonymous MongoDB Access
5-Change Platform (Current: MongoDB)
x-Exit
Select an option: 3
Web App Attacks (POST)
===============
Checking to see if site at localhost:3001/login is up...
App is up!
List of parameters:
1-username
2-password
Which parameter should we inject? 2
Injecting the password parameter...
Baseline test-Enter random string size: 7
What format should the random string take?
1-Alphanumeric
2-Letters only
3-Numbers only
4-Email address
Select an option: 1
Using yJmq8le for injection testing.
 
Sending random parameter value...
Got response length of 25.
No change in response size injecting a random parameter..
 
Test 1: PHP/ExpressJS != associative array injection
Injection failed.
 
 
Test 2:  PHP/ExpressJS > Undefined Injection
Injection failed.
Test 3: $where injection (string escape)
Injection failed.
 
 
Test 4: $where injection (integer escape)
Injection failed.
 
 
Test 5: $where injection string escape (single record)
Injection failed.
 
 
Test 6: $where injection integer escape (single record)
Injection failed.
 
 
Test 7: This != injection (string escape)
Injection failed.
 
 
Test 8:  This != injection (integer escape)
Injection failed.
 
 
Start timing based tests (y/n)? y
Starting Javascript string escape time based injection...
Traceback (most recent call last):
  File "nosqlmap.py", line 544, in <module>
    main(args)
  File "nosqlmap.py", line 47, in main
    mainMenu()
  File "nosqlmap.py", line 103, in mainMenu
    nsmweb.postApps(victim,webPort,uri,https,verb,postData,requestHeaders)
  File "/root/NoSqlMap/nsmweb.py", line 691, in postApps
    conn = urllib2.urlopen(req,body)
  File "/usr/local/lib/python2.7/urllib2.py", line 154, in urlopen
    return opener.open(url, data, timeout)
  File "/usr/local/lib/python2.7/urllib2.py", line 435, in open
    response = meth(req, response)
  File "/usr/local/lib/python2.7/urllib2.py", line 548, in http_response
    'http', request, response, code, msg, hdrs)
  File "/usr/local/lib/python2.7/urllib2.py", line 473, in error
    return self._call_chain(*args)
  File "/usr/local/lib/python2.7/urllib2.py", line 407, in _call_chain
    result = func(*args)
  File "/usr/local/lib/python2.7/urllib2.py", line 556, in http_error_default
    raise HTTPError(req.get_full_url(), code, msg, hdrs, fp)
urllib2.HTTPError: HTTP Error 400: Bad Request
```

# 참고 
- https://github.com/matrix/Burp-NoSQLiScanner
- https://github.com/matrix/Burp-NoSQLiScanner/blob/main/src/burp/BurpExtender.java
- https://github.com/codingo/NoSQLMap