---
layout: post
title: "Windows에서 로컬 통신을 캡쳐하는 법"
categories: [네트워크, 패킷캡처, Wireshark]
tags: [네트워크, 패킷캡처, Wireshark]
toc: true
---


# 개요
- Windows에서 로컬 통신을 캡쳐하는 법을 정리한다. 
- 디폴트로는 안되고 `npcap`을 설치해야 한다. 
- Wireshark 설치할 때 `npcap`을 설치할 것인지 물어보는데 이때 설치했다면 가능하다. 
- `npcap`은 추후에 설치하는 것도 가능하다. 

# npcap이 설치되었는지 확인하는 방법
- Wireshark에서 Help -> About Wireshark -> Wireshark 탭을 확인한다. 
- `with Npcap version 1.55, based on libpcap version 1.10.2-PRE-GIT`와 같은 문자열이 포함되어 있다면 npcap이 설치가 되어 있는 것이다.

# 캡쳐 방법
- Wireshark를 기동한 후에 `Adapter for loopbak traffic capture`를 선택하면 Windows에서 로컬통신을 캡쳐할 수 있다. 

# 참고 
- https://ask.wireshark.org/question/18822/how-do-you-know-that-npcap-is-installed/
- https://kcm.trellix.com/corporate/index?page=content&id=KB91433
- https://wiki.wireshark.org/CaptureSetup/Loopback