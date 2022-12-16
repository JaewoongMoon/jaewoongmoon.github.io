---
layout: post
title: "Commercial National Security Algorithm Suite 2.0 조사"
categories: [보안기준, 암호알고리즘]
tags: [보안기준, 암호, NSA]
---

# 개요
- 2022년9월7일에 NSA가 Commercial National Security Algorithm Suite 2.0 (상용 국가보안알고리즘스위트 2.0) 라는 문서(권고안)를 발표했다. (https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- 2022년10월12일에 일본의 IPA에서 이 문서의 일본어 번역본을 발표했다. (https://www.ipa.go.jp/files/000103027.pdf)
- 2022년12월13일 현재, 구글검색해본 결과 한국어 번역본은 없는 것 같다. 
- 영어원본과 IPA의 번역본을 읽어보고 대략적인 내용이나마 정리해두고자 한다. 
- 주로 양자컴퓨터 등장을 대비하여 양자컴퓨터 시대에도 안전하게 사용할 수 있는 암호 알고리즘을 알려주는 내용으로 보인다. 
- Commercial National Security Algorithm 를 줄여서 CNSA 라고 표현한다. 

# 소프트웨어 및 펌웨어서명을 위한 알고리즘
- CNSA 1.0 (현행) 에는 없는 두 알고리즘이 추가되었다. 
- Leighton-Micali Signature (LMS) : 모든 파라메터가 모든 분류 레벨에 대해 승인되었다. SHA-256/192가 추천된다. 
- Xtended Merkle Signature Scheme (XMSS) : 모든 파라메터가 모든 분류 레벨에 대해 승인되었다.
![CNSA 2.0 algorithms for software and firmware updates](/images/CNSA2.0-signing.png)

# 대칭키 알고리즘
- AES는 CNSA 1.0과 변함없이 256비트키를 추천
- SHA는 SHA-384 및 SHA-512를 추천 (CNSA 1.0과 비교하여 SHA-512가 목록에 추가된 것이 유일한 변경이다.)
![CNSA 2.0 symmetric-key algorithms](/images/CNSA2.0-symmetric.png)

# 공개키 알고리즘
- CRYSTALS-Kyber, CRYSTALS-Dilithium 라는 암호 알고리즘이 검토중으로 TBD(곧 결정될 것) 상태이다.
- RSA, Diffie-Hellman (DH), 타원 곡선 암호화 (ECDH, ECDSA)의 사용은 비추천된다. 
![CNSA 2.0 quantum-resistant public-key algorithms](/images/CNSA2.0-public-key.png)

# 이행 타이밍
- 이행타이밍은 표준화 기반 구현의 보급에 달려있으나 NSA는 2035년까지 완료될 것으로 기대하고 있다고 한다. 
