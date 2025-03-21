---
layout: post
title: "CERT Top 10 Secure Coding Practices 정리"
categories: [웹 보안, CSP헤더]
tags: [웹 보안, CSP헤더]
toc: true
last_modified_at: 2024-09-04 14:55:00 +0900
---


# 개요
- 보안 프로그래밍의 원칙으로 유명한 "CERT Top 10 Secure Coding Practices"(미국 카네기멜론대학교(CMU) 소프트웨어공학연구소(SEI)의 보안 코딩 원칙)이 있다. 이 것을 정리해본다. 
- 설계 및 구현 단계에서 적용할 수 있는 원칙이다. 

# 1. 입력 검증하기 (Valid Input)
모든 신뢰할 수 없는 데이터 소스의 입력을 확인한다. 적절한 입력 검증은 많은 소프트웨어의 취약성을 완화시킬 수 있다.  명령줄 인수, 네트워크 인터페이스, 환경 변수, 사용자 제어 파일을 포함한 대부분의 외부 데이터 소스는 의심하라. 

# 2. 컴파일러 경고에 귀 기울이기(Heed compiler warnings)
컴파일러 경고에 주의를 기울여야 한다.컴파일러는 프로그램 코드에 대하여 반드시 행해지는 첫번째 조사 행위이다. 컴파일러에서 사용 가능한 가장 높은 경고 수준을 사용하여 코드를 컴파일하고 코드를 수정하여 경고를 제거하라. 

# 3. 보안 정책 실현을 위한 설계 및 아키텍트(Architect and design for security policies)
각 애플리케이션이나 시스템에서 결정한 "보안 정책"에 따라 소프트웨어 아키텍처를 만들고 구현하며, 그 정책을 적용하는 소프트웨어를 설계한다. 지켜야 할 것을 식별하고 그것을 지키기 위해 하는 것이지, 모든 것을 똑같이 지키도록 하는 것은 아니다. 

# 4. 간단한 설계를 유지하기(Keep it simple)
설계를 가능한 한 간단하고 작게 유지한다. 복잡한 설계는 구현, 구성 및 사용에서 오류가 발생할 가능성을 높인다. 또한 보안 메커니즘이 더 복잡해짐에 따라 적절한 수준의 보증을 달성하는 데 필요한 노력이 극적으로 증가한다. 

# 5. 접근 거부를 기본값으로 설정하기(Default deny)
거부를 기본값으로 설정한다. 허가 기반이 아닌 거부 기반으로 접근을 결정한다. '보안 프로그래밍 설계의 8가지 원칙'의 페일 세이프 디폴트와 동일하다. Order Allow,Deny 와 같은 화이트리스트 방식으로 표현되는 것과 같은 의도이다.

# 6. 최소 권한의 원칙을 준수하기(Adhere to the principle of minimum privilege)
모든 프로세스는 실행에 필요한 최소한의 권한으로 실행되어야 한다. 권한이 승격되는 시간을 최소화해야 한다.  이 접근 방식은 공격자가 승격된 권한으로 임의의 코드를 실행할 수 있는 기회를 줄인다. 

# 7. 다른 시스템으로 전송하는 데이터는 무해화하기(Sanitize data sent to other systems)
외부로 넘기는 데이터는 넘기는 곳에서 문제가 생기지 않도록 가공한다. 전달처에 따라 문제가 되는 조건이 다르기 때문에 그에 맞는 가공을 해야 한다. 예를 들어 데이터를 전달하는 곳이 웹 페이지로 출력하는 부분이라면 XSS 대책을 해야 하고, DBMS의 SQL이라면 SQL 인젝션 대책이 필요하다.

# 8. 다층방어를 구현하기(Practice defense in depth)
다층방어를 구현한다. 근본적인 대책뿐만 아니라 보험적인 대책까지 포함한 다양한 유형의 방어책을 마련하는 것이다. 즉, 하나의 대책이 불완전하거나 공격자에게 뚫린다고 해도 모든 것을 잃는 것이 아니라 피해를 어느 정도 제한할 수 있도록 하는 것이다. 예를 들어, 안전한 프로그래밍 기술과 안전한 런타임 환경을 결합하면 배포 시점에 코드에 남아 있는 취약성이 운영 환경에서 악용될 가능성이 줄어든다. 설계 원칙 5의 'Separation of privilege: 권한의 분리'와 같은 취지이기도 하다. 

# 9. 효과적인 품질 보증 기법 활용하기 (Use effective quality assurance techniques)
효과적인 품질 보증 기법을 사용한다. 좋은 품질 보증 기술은 취약점을 식별하고 제거하는 데에도 효과적이다.
퍼즈 테스트, 침투 테스트 및 소스 코드 감사는 모든 효과적인 품질 보증 프로그램의 일부로 포함되어야 한다. 독립적인 보안 검토는 보다 안전한 시스템으로 이어질 수 있다. 외부 검토자는 독립적인 관점을 제공합니다. 

# 10. 보안 코딩 표준 채택하기 (Adopt a secure coding standard)
보안 코딩 표준을 채택한다. 타겟 개발 언어 및 플랫폼에 대한 보안 코딩 표준을 적용하여 개발한다. 많은 보안 대책은 여러 곳에서 유사한 대책을 시행하게 된다. 표준을 채택하여 공통적으로 대응함으로써 효율적으로 대응할 수 있다. 만약 채택한 표준에서 대책이 미흡한 부분이 발견되더라도, 공통적으로 대응할 수 있기 때문에 비교적 쉽게 수정할 수 있다.


# 참고 
- https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices
- https://eva.fing.edu.uy/mod/page/view.php?id=77012
- https://www.ipa.go.jp/archive/security/vuln/programming/ps6vr70000012yp1-att/000059838.pdf