---
layout: post
title: "파이썬 대량 HTTP요청 라이브러리 - grequests 사용법"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, JWT취약점]
toc: true
---

# 개요
파이썬에서 대량의 HTTP요청을 보내고 싶을 경우에 사용하는 grequests 라이브러리의 사용법을 정리해둔다. 

# 설치 
```
sudo pip3 install grequests
```

## 설치 트러블 슈팅
### src/greenlet/greenlet.cpp:16:20: fatal error: Python.h: No such file or directory 에러 발생시

```
src/greenlet/greenlet.cpp:16:20: fatal error: Python.h: No such file or directory
```

[여기](https://stackoverflow.com/questions/21530577/fatal-error-python-h-no-such-file-or-directory)를 보고 해결했다. 

`python3-devel`이라는 패키지가 설치되어 있지 않아서 생기는 문제였다. 

내 경우엔 python3-devel이 아니라 python36-devel이었다. 파이썬3에도 여러 세부 버전이 있어서 세부버전정보까지 지정해야 설치가 됐다. 

```sh
sudo yum install python36-devel 
```

### 파이썬 의존 라이브러리 greenlet 설치시에 gcc에러 발생시 
greenlet은 멀티프로세싱에 필요한 코루틴을 처리하기 위한 라이브러리라고 한다.   
grequest를 설치하면 greenlet도 같이 설치가 되는데 설치도중 다음과 같은 에러가 발생했다. 

```
/usr/include/c++/4.8.5/bits/c++0x_warning.h:32:2: error: #error This file requires compiler and library support for the ISO C++ 2011 standard. This support is currently experimental, and must be enabled with the -std=c++11 or -std=gnu++11 compiler options.
``` 

메세지를 분석해보면 gcc를 사용해서 빌드하려고 하는데 std 버전을 11이상인 것으로 지정해야 한다는 것 같다. 인터넷을 검색해보니 gcc 버전이 낮은 것이 원인인 것 같다. 내 경우엔 설치되어 있는 gcc 버전이 4.8.5였다. yum list 로 확인해보니 gcc64버전도 설치가능한 것을 알 수 있었다. gcc64를 설치한 후에 다시 grequests 설치를 시도하자 이상없이 설치가 완료되었다. 

```
sudo yum list | grep gcc
sudo yum install gcc64*
gcc -v
```

# 사용법 
- 사용법은 다음과 같이 간단하다. 
- urls에 확인하고자 하는 url목록을 입력하고 실행한다. 
- 결과가 urls의 입력 순서와 동일한 순서대로 출력된다는 점이 포인트다(뒤죽박죽이 되지 않는다).

```py
import grequests

urls = [
    'http://www.heroku.com',
    'http://tablib.org',
    'http://httpbin.org',
    'http://python-requests.org',
    'http://kennethreitz.com'
]

rs = (grequests.get(u) for u in urls)

res_list = grequests.map(rs)
# urls의 순서와 동일한 순서대로 출력된다.
# res.url: url에 접근한 결과 리다이렉트되는 경우, 리다이렉트된 곳의 url이 출력된다. 
for res in res_list:
    # 응답을 얻지 못한 경우에는 None 타입이 된다. 
    if res:
        print(f"{res.url} => {res.status_code}")
```

# 참고링크
- https://pypi.org/project/grequests/