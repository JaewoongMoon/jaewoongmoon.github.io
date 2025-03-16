---
layout: post
title: "Burp Academy-XXE 취약점: Exploiting XInclude to retrieve files"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XXE injection]
toc: true
last_modified_at: 2024-08-15 21:00:00 +0900
---


# 개요
- 문제 주소: https://portswigger.net/web-security/xxe/lab-xinclude-attack
- 취약점 설명: https://portswigger.net/web-security/xxe#finding-hidden-attack-surface-for-xxe-injection
- 난이도: PRACTITIONER (중간)


# XXE 주입을 위한 숨겨진 공격 표면 찾기(Finding hidden attack surface for XXE injection)
XXE 주입 취약성에 대한 공격 표면은 많은 경우 명백하다. 애플리케이션의 일반 HTTP 트래픽에 XML 형식의 데이터가 포함된 요청이 포함되기 때문이다. 다른 경우에는 공격 표면이 덜 눈에 띄기도 한다. 그러나 올바른 곳을 살펴보면 XML이 전혀 포함되지 않은 요청에서 XXE 공격 표면을 찾을 수 있다.

# 취약점 설명: XInclude attacks
일부 애플리케이션은 클라이언트가 제출한 데이터를 수신하여 서버 측에서 XML 문서에 임베드한 다음 문서를 구문 분석한다. 이에 대한 한 가지 예는 클라이언트가 제출한 데이터가 백엔드 SOAP 요청에 배치된 다음 백엔드 SOAP 서비스에서 처리되는 경우이다.

이 상황에서는 전체 XML 문서를 제어하지 못하므로 DOCTYPE 요소를 정의하거나 수정할 수 없으므로 클래식 XXE 공격을 수행할 수 없다. 그러나 대신 `XInclude`를 사용할 수 있는 경우가 있다. XInclude는 XML 문서를 하위 문서(sub-document)에서 빌드할 수 있도록 하는 XML 사양의 일부이다. XML 문서의 어떤 데이터 값에도 XInclude 공격을 배치할 수 있다. 따라서 공격자는 서버 측에서 처리되는 XML 문서 중 데이터를 제어가능한 상황에서 이 테크닉을 사용할 수 있다. 

XInclude 공격을 수행하려면 XInclude 네임스페이스를 참조하고 포함하려는 파일의 경로를 제공해야 한다. 예를 들면 다음과 같다. 

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```


# 랩 개요
- 이전 문제들과 마찬가지로 "Check stock" 기능을 통해 XML 을 삽입할 수 있다.
- 당신은 XML 문서를 제어할 수 없기 때문에 클래식 XXE공격을 수행할 수 있는 DTD를 정의할 수 없다. 
- 문제를 풀려면 XInclude 스테이트먼트를 삽입해서 /etc/passwd 파일의 내용을 얻어내라. 
- 힌트: 기본적으로 XInclude는 포함된 문서를 XML로 구문 분석하려고 한다. /etc/passwd가 유효한 XML이 아니므로 이 동작을 변경하려면 XInclude 지시문에 어떤 속성을 추가해야 한다.


```
This lab has a "Check stock" feature that embeds the user input inside a server-side XML document that is subsequently parsed.

Because you don't control the entire XML document you can't define a DTD to launch a classic XXE attack.

To solve the lab, inject an XInclude statement to retrieve the contents of the /etc/passwd file.

Hint: By default, XInclude will try to parse the included document as XML. Since /etc/passwd isn't valid XML, you will need to add an extra attribute to the XInclude directive to change this behavior.
```

# 도전 

## 살펴보기 

1. 이전 문제들과는 다르게 재고를 확인하는 요청에서 어떤 XML도 보이지 않는다. 파라메터인 productId와 storeId는 일반적인 POST요청에서 사용되는 파라메터다. 어떻게 XML을 삽입할 수 있을까? 

![](/images/burp-academy-xxe-7-1.png)

2. 취약점 설명에서 XInclude는 공격자가 데이터를 컨트롤할 수 있을 때 사용할 수 있다고 했다. 이 요청에서 컨트롤할 수 있는 것은 파라메터의 값이다. 파라메터의 값에 XInclude 공격 페이로드를 지정해서 요청을 보내본다. 다음과 같다. 

```xml
productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=2
```

![](/images/burp-academy-xxe-7-3.png)

3. 그러자 다음과 같이 400응답과 함께 /etc/passwd의 내용이 응답에 회신된다! 

![](/images/burp-academy-xxe-7-4.png)

4. 문제가 풀렸다는 메세지가 출력된다. 

![](/images/burp-academy-xxe-7-success.png)