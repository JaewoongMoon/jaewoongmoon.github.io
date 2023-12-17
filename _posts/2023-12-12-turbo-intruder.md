---
layout: post
title: "Burp Suite - Turbo Intruder정리"
categories: [Burp Suite]
tags: [Burp Suite, Turbo Intruder]
toc: true
last_modified_at: 2023-12-11 09:50:00 +0900
---

# 알게된 것 
- 터보 인트루더는 아마 파이썬 2.x 버전으로 쓰여진 것으로 보인다. 
- Python3에서 자주 쓰이는 f-string을 사용할 수 없다. (사용하려고 하면 SyntaxError "no viable alternative at input ...) 에러가 발생한다. 
- Content-Length 헤더의 값은 자동으로 업데이트 해준다. 


# 참고 URL
- https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack