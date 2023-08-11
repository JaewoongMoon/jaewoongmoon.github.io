---
layout: post
title: "Metasploit-Meterpreter 스크립팅 조사"
categories: [보안, 취약점스캐너]
tags: [취약점, 스캐너, metasploit]
toc: true
last_modified_at: 2023-08-09 15:02:00 +0900
---

# 개요
- Meterpreter 스크립팅에 대해 조사한다. 
- Meterpreter는 Metasploit 프레임워크를 구성하는 한 컴포넌트(페이로드)이다. 
- Metasploit 의 기본CLI보다 더 다양한 기능을 제공한다. 
- 그리고 기능을 확장할 수도 있는 것 같다.
- Meterpreter 스크립트는 루비로 개발한다. 

# 구동하는 방법
- 조금 조사를 해보니 Meterpreter는 exploit 을 성공한 후에 작동시키는 셸인 것 같다. 
- 이미 존재하는 스크립트 (https://www.offsec.com/metasploit-unleashed/existing-scripts/)들을 살펴보면, exploit 후에 침입한 시스템의 정보를 조사한다던가 하는 그 후 작업을 자동화해주는 스크립트가 많아 보인다. 
- https://techofide.com/blogs/how-to-use-metasploit-meterpreter-reverse-shell-metasploit-tutorial/ 를 보면 exploit에 성공했을시, 자동으로 Meterpreter 세션이 시작되는 것으로 보인다. 


# 참고 
- https://www.offsec.com/metasploit-unleashed/meterpreter-scripting/
- https://www.offsec.com/metasploit-unleashed/writing-meterpreter-scripts/