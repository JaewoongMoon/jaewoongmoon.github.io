---
layout: post
title: "Python으로 Zap API실행하기"
categories: [스캐너, Zap]
tags: [스캐너, Zap]
toc: true
last_modified_at: 2025-03-03 21:55:00 +0900
---

# 개요
Zap과 Burp Suite를 비교해봤을 때, 강점이라고 할 수 있는 부분이 **API를 통한 조작기능**을 무료로 사용할 수 있다는 점이다. Zap이 제공하는 API를 통해서 스캔을 실시하거나 결과를 얻어내거나 하는 과정을 자동화할 수 있는 것이다. 따라서 **진단 엔지니어가 자신의 작업을 자동화하는 목적으로** 사용하기에 좋다. 또한 DevSecOps와도 궁합도 좋다. 이 문서에서는 API를 수행하기 위한 과정을 정리해둔다. 

# 미리 해두어야 하는 것 
## Zap 서버 증명서 신뢰 설정 
Zap의 서버증명서를 신뢰하는 Root인증국으로 등록한다. 

## (사내에서 사용하는 경우) 업스트림 프록시 설정
- 또한 회사내부 등, upstream 프록시가 존재하는 경우는 해당 프록시를 설정해주어야 한다. (Tools > Options > Network > Local Servers/Proxies에서 설정가능하다.)

## API 키 확인
API 키는 Zap의 Tools > Options에 들어가면 API항목에서 확인할 수 있다. 이 API 키의 값을 복사해서 curl이나 Python 스크립트에서 사용하면 된다. 

## 라이브러리 설치
- 각 프로그래밍 언어별로 Zap의 API를 구현한 라이브러리가 존재한다. 
- 파이썬에서는 `zaproxy` 프로젝트다. 다음 커맨드로 설치한다. 

```sh
pip install zaproxy
```


# 스캔 대상 앱을 탐색하기 (Exploring the App)
스캔 대상 사이트에 어떤 패스나 파라메터가 있는지 조사하는 기능이다. (Burp Suite에서는 크롤링이라고 부른다.) Zap 에서 제공하는 앱 탐색 기능은 다음 네 가지가 있다. 

1. Traditional Spider (Crawler): 이 방법을 사용하면 웹 애플리케이션에서 HTML 리소스(하이퍼링크 등)를 크롤링할 수 있다. 
2. Ajax Spider: 애플리케이션이 Ajax 호출에 크게 의존하는 경우 이 기능을 사용한다. 
3. Proxy Regression / Unit Tests: 보안 리스레션 테스트에 권장되는 접근 방식이다. 이미 Test suite나 단위 테스트가 있는 경우 이 접근 방식을 사용하여 앱을 탐색한다. 
4. OpenAPI/SOAP Definition : 잘 정의된 OpenAPI 정의가 있는 경우 이 접근 방식을 사용한다. OpenAPI 플러그인은 마켓플레이스를 통해 다운로드할 수 있다. 

 
## 1. Spider (기본 Crwaler)사용하기 
- 다음 코드를 사용한다. 
- `https://public-firing-range.appspot.com`는 테스트 목적으로 제공하는 URL이다. 스캔 대상으로 사용해도 된다. 
- akiKey 변수를 변경한다. 

```py
#!/usr/bin/env python
import time
from zapv2 import ZAPv2

# The URL of the application to be tested
target = 'https://public-firing-range.appspot.com'
# Change to match the API key set in ZAP, or use None if the API key is disabled
apiKey = 'changeMe'

# By default ZAP API client will connect to port 8080
zap = ZAPv2(apikey=apiKey)
# Use the line below if ZAP is not listening on port 8080, for example, if listening on port 8090
# zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})

print('Spidering target {}'.format(target))
# The scan returns a scan id to support concurrent scanning
scanID = zap.spider.scan(target)
while int(zap.spider.status(scanID)) < 100:
    # Poll the status until it completes
    print('Spider progress %: {}'.format(zap.spider.status(scanID)))
    time.sleep(1)

print('Spider has completed!')
# Prints the URLs the spider has crawled
print('\n'.join(map(str, zap.spider.results(scanID))))
# If required post process the spider results

# TODO: Explore the Application more with Ajax Spider or Start scanning the application for vulnerabilities
```

결과는 다음과 같다. 진척률과 탐색된 URL이 표시된다. 

![](/images/zap-spider-result.png)

동시에 Zap UI 화면도 실시간으로 갱신된다. 

![](/images/zap-spider-result2.png)

또한, Spider 결과는 별도의 results API를 통해 얻을 수도 있다. 


# 참고 
- ZAP API 문서: https://www.zaproxy.org/docs/api/
- zaproxy 라이브러리 문서: https://github.com/zaproxy/zap-api-python
