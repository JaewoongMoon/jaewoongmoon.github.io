---
layout: post
title: "Burp Academy-안전하지 않은 역직렬화(Insecure Deserialization) 관련 취약점: Exploiting Java deserialization with Apache Commons"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Insecure Deserialization]
toc: true
last_modified_at: 2024-06-19 21:00:00 +0900
---


# 개요
- 안전하지 않은 역직렬화(Insecure Deserialization) 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons
- 취약점 설명페이지: https://portswigger.net/web-security/deserialization/exploiting
- 난이도: PRACTITIONER (보통)

# 취약점 개요: 개짓체인(Gadget Chain)
- "Gadget"(개짓)이란 어플리케이션 내부에 존재하는 공격자의 목적을 수행하도록 도와주는 코드 조각이다. 
- 개짓은 일반적인 유저의 입력에 대해서는 어떠한 해로운 동작도 하지 않는다. 
- 그러나 공격자의 목적은 단순히 다른 개짓을 부르는 (invoke) 것일 수 있다. 
- 복수의 개짓을 연결하는 것(Chaining)으로, 공격자는 자신의 입력을 데미지를 최대화할 수 있는 위험한 싱크 개짓(sink gadget)으로 전달할 수 있다. 
- 다른 타입의 exploit과는 다르게, 공격을 수행할 수 있는 일종의 장비가 이미 웹 사이트에 존재하고 있다는 점을 이해하는게 중요하다. 
- 공격자는 주로 역직렬화 과정에서 자동으로 호출되는 매직 메서드로 자신의 인풋데이터를 넘긴다. 이 매직 메서드는 "kick-off gadget" 이라고 불리기도 한다. 
- 현실에서 많은 역직렬화 취약점이 개짓체인을 통해서만 수행된다.  
- 이는 때때로 간단한 1단계 또는 2단계 체인일 수 있지만 심각도가 높은 공격을 구성하려면 보다 정교한 개체 인스턴스화 및 메서드 호출 순서가 필요할 수 있다. 따라서 가젯 체인을 구성하는 것은 안전하지 않은 역직렬화를 성공적으로 수행하기 위한 핵심적인 부분이다. 

## 미리 만들어진 개짓체인을 활용하기(Working with pre-built gadget chains)
- 수동으로 개짓체인을 만드는 것은 매우 고된 일이다. 또한 소스코드에 접근할 수 없으면 거의 불가능하다. 
- 다행히도 미리 만들어진(발견된) 개짓 체인을 사용하도록 도와주는 툴들이 있다. 
- 많은 웹 사이트들이 대부분 동일한 라이브러리를 사용하므로 유용하다. 

## ysoserial
- 이 툴들중에 하나는 `ysoserial`이다. 
- 이를 통해 대상 애플리케이션이 사용하고 있다고 생각되는 라이브러리에 대해 제공된 개짓 체인 중 하나를 선택한 다음 실행하려는 명령을 전달할 수 있다. 
- 그러면 선택한 체인을 기반으로 적절하게 직렬화된 개체를 생성해준다. 
- 여기에는 여전히 어느 정도의 시행착오가 수반되지만, 수동으로 개짓 체인을 직접 구성하는 것보다 훨씬 더 효율적이다. 
- Java 16이상에서는 ysoserial을 실행하기 위해 다음과 같은 몇 개의 커맨드라인 매개변수가 필요하다. 

```bash
java -jar ysoserial-all.jar \
   --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
   --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
   --add-opens=java.base/java.net=ALL-UNNAMED \
   --add-opens=java.base/java.util=ALL-UNNAMED \
   [payload] '[command]'
```


# 문제 개요
- 이 랩은 직렬화 베이스의 세션 관리 메커니즘을 사용하고 있고, Apache Commons Collections를 로드한다. 
- 소스코드에 접근할 수는 없지만, 미리 빌드된 개짓체인을 사용해서 exploit을 수행할 수 있다. 
- 랩을 풀려면 리모트 코드 실행을 수행하는 악의적인 직렬화 오브젝트를 만들어주는 서드파티 툴을 사용한다. 
- 생성한 오브젝트를 웹 사이트에 삽입하여 calros 유저의 홈디렉토리에 있는 morale.txt를 삭제하면 랩이 풀린다. 
- wiener:peter 크레덴셜로 로그인할 수 있다. 

```
This lab uses a serialization-based session mechanism and loads the Apache Commons Collections library. Although you don't have source code access, you can still exploit this lab using pre-built gadget chains.

To solve the lab, use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the morale.txt file from Carlos's home directory.

You can log in to your own account using the following credentials: wiener:peter
```

# 도전 
1. 주어진 크레덴셜로 로그인한 후에 세션쿠키를 base64으로 디코딩해보면 자바 베이스인 것을 알 수 있다. 

![](/images/burp-academy-serial-5-1.png)

2. ysoserial 을 사용해서 페이로드를 만든다. 내 PC에 설치된 자바 버전은 11이다. 자바 버전 15이하에서는 다음 커맨드로 페이로드를 만들 수 있다. 
base64에서 -w 옵션을 0으로 줌으로써 개행없이 이어지는 페이로드를 만들 수 있다. 

Cygwin 을 구동하고 ysoserial이 위치한 곳으로 이동한 후에 커맨드를 실행해본다. 

```sh
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w 0
```

3. 그러면 ysoserial이 다음과 같은 base64 인코딩된 페이로드를 만들어 준다. 

![](/images/burp-academy-serial-5-2.png)


4. 페이로드를 복사해서 Burp Repeater에서 세션쿠키 값을 이 페이로드로 바꿔준다. 요청을 보내보면 에러 메세지가 돌아온다. 

![](/images/burp-academy-serial-5-3.png)

5. 페이로드를 URL인코딩한 후에 다시 보내본다. 그러면 서버에서 500응답이 돌아오지만 곧 이어 문제풀이에 성공했다는 메세지가 출력된다. 

![](/images/burp-academy-serial-5-4.png)

![](/images/burp-academy-serial-5-success.png)

# 참고 
- https://github.com/frohoff/ysoserial