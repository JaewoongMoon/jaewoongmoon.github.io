---
layout: post
title: "Burp Academy-LLM 관련 취약점: Exploiting LLM APIs with excessive agency"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, LLM]
toc: true
last_modified_at: 2024-04-10 21:00:00 +0900
---

# 개요
- LLM(Large Language Model) 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/llm-attacks/lab-exploiting-llm-apis-with-excessive-agency
- 취약점 설명페이지: https://portswigger.net/web-security/llm-attacks
- 난이도: APPRENTICE (쉬움)

# 취약점 개요
- LLM은 Firewall로 나뉜 경계 안쪽에서 실행된다. 
- LLM은 유저는 직접사용할 수 없는 API를 실행가능한 경우가 많다. 
- LLM에게 이 API들을 실행하도록 만든다는 점에서 Web LLM 공격은 SSRF와 유사하다.  

![](/images/llm_image1.png)
*출처: https://portswigger.net/web-security/llm-attacks*


- 많은 Web LLM 공격은 프롬프트 인젝션(prompt injection) 테크닉에 기반한다. 이는 LLM의 아웃풋을 조작하기 위해 사용하는 프롬프트(인풋)이다. 이를 이용해서 AI가 본래의 의도와는 관계없는 일을 수행하도록 만든다. 

# 문제 개요
LLM에게 유저 carlos를 삭제하도록 시키면 랩이 풀린다. 

```
To solve the lab, use the LLM to delete the user carlos.
```


# 풀이 
1. 문제 서버를 살펴보면 Livechat 기능이 있다. 여기에 LLM이 사용되고 있을 가능성이 높다. 어떤 API를 실행할 수 있는지 물어보면 몇 가지 API를 사용할 수 있다고 알려준다. 이 중 SQL 쿼리를 실행할 수 있는기능 `debug_sql`이 눈에 띈다. 

![](/images/burp-academy-llm-1-1.png)

2. 또한 랩 서버에는 AI 실행 로그를 볼 수 있는 기능도 있다. 다른 질문들도 던져보면서 실행 로그를 살펴본다. 그러면 AI가 답변으로는 실행할 수 없다고 하면서도 실제로는 실행가능한지 시도해보고 있는 것을 알 수 있다. 

3. carlos 유저의 id를 알려줄 수 있냐는 질문을 하면 로그에서 유저 테이블과 username 컬럼의 존재를 확인할 수 있다. 

![](/images/burp-academy-llm-1-2.png)

4. carlos 유저를 삭제하는 쿼리를 실행할 수 있냐고 물어보면 쿼리를 실행했다고 알려준다. 

![](/images/burp-academy-llm-1-3.png)

5. 그리고 문제가 풀렸다는 메세지가 확인된다. 

![](/images/burp-academy-llm-1-success.png)