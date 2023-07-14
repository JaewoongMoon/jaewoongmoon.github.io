---
layout: post
title: "로컬 스토리지 vs 쿠키"
categories: [웹보안, 로컬스토리지, 쿠키]
tags: [웹보안, 로컬스토리지, 쿠키]
toc: true
last_modified_at: 2023-07-04 09:04:00 +0900
---

# 로컬 스토리지 vs 쿠키
- 보안관점에서 봤을 때 어느 쪽이 안전할까?
- 기본적으로 쿠키가 훨씬 안전하다. 
- 로컬 스토리지와 쿠키 모두 Same Origin Policy 에 의해 보호된다. 
- 그러나 쿠키에는 쿠키사용을 특정 패스(path)로 제한하는 기능이 있다. 
- 또한 쿠키는 httponly 속성을 붙여서 Javascript에서 접근하는 것을 막을 수 있다. XSS에 대한 꽤 유효한 방어책이 된다. 
- 로컬 스토리지에는 민감한 정보(sensitive info)는 저장하지 않는 것이 좋다.
- 쿠키는 저장용량이 최대 4KB까지지만 로컬 스토리지는 최소 5MB공간을 제공한다. 
- 또한, 로컬스토리지에 접근하는 과정은 동기적(syncronous)으로 동작한다. 브라우저가 로컬스토리지에 접근하는 동안은 해당 사이트의 다른 모든 처리가 멈춘다는 뜻이다. 다라서 로컬 스토리지 접근이 많으면 퍼포먼스 저하가 발생할 수 있다. 
- 로컬 스토리지는 민감하지 않은 데이터를 캐시하는 용도에 적합하다. 


# 궁금점: 로컬스토리지를 사용하는 경우는 CSRF 공격에 안전한가? (CSRF공격이 불가능한가?) 
- https://teratail.com/questions/323480 를 보면 CSRF자체가 성립하지 않는다고 한다. 
- CSRF가 성립하려면 특정 링크로 접근시킬 때 동시에 인증정보 같은 것이 전송되어야 한다. 쿠키가 이렇게 동작한다. 로컬스토리지라면 (별도 스크립트가 동작하지 않는한) 링크에 접근시키는 것 자체로는 CSRF가 불가능할 것으로 보인다. 


# 참고 
- https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#storage-apis
- https://climbtheladder.com/8-local-storage-best-practices/
- https://dev.to/rdegges/please-stop-using-local-storage-1i04