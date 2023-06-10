---
layout: post
title: "Burp Intruder Attack Types 정리"
categories: [취약점스캐너, Burp Suite]
tags: [취약점스캐너, Burp Suite, Burp Intruder, Attack Types]
toc: true
---


# 개요
- Burp Intruder에서 설정가능한 attack type 을 정리해둔다. 
- 이해해두면 두고두고 써먹을 수 있을 것이다.  

# Sniper (스나이퍼)
- 말그대로 스나이퍼처럼 한번에 하나씩 정확하게 쏜다. 
- 페이로드를 각 파라메터 포지션에 하나씩 지정해서 공격한다. 
- 따라서 총 요청수는 "페이로드수 x 파라메터 포지션 수" 이다. 

# Battering ram (공성추)
- Battering ram (공성추)은 중세시대 성문을 부시기 위해서 쓰던 무기이다. 
- 페이로드를 모든 파라메터 포지션에 지정해서 공격한다. 
- 따라서 총 요청수는 "페이로드 수"이다. 

# Pitchfork (쇠스랑)
- 여기서부터 좀 복잡하다. 
- 공식설명은 다음과 같다. 공식 설명을 봐도 처음엔 잘 이해가 가지 않는다.

```
This attack iterates through a different payload set for each defined position. Payloads are placed into each position simultaneously. For example, the first three requests would be:

Request one:

Position 1 = First payload from Set 1.
Position 2 = First payload from Set 2.
Request two:

Position 1 = Second payload from Set 1.
Position 2 = Second payload from Set 2.
Request three:

Position 1 = Third payload from Set 1.
Position 2 = Third payload from Set 2.
The total number of requests generated in the attack is the number of payloads in the smallest payload set.

The Pitchfork attack is useful where an attack requires different but related input to be inserted in multiple places within the request. For example, to place a username in one parameter, and a known ID number corresponding to that username in another parameter.
```

- 이 공격타입을 이해하려면 여러개의 페이로드 세트가 있다는 것을 전제하고 시작해야 한다. 
- 예를들어 이해해보자. 위의 설명에 맞추어 파라메터 포지션이 두 개가 있다고 생각하자. 예를 들어서 ID와 패스워드 필드가 있다고 하자. 
- 그리고 페이로드 세트는 두개가 있다. 페이로드세트1은 ID후보군을 저장해둔 세트다. moon, admin, tester 세개의 페이로드가 있다. 
- 페이로드세트2는 패스워드 후보군을 저장해두 세트다. 123456, password, 1q2w3e 세 개의 페이로드가 있다. 
- 그러면 이 것을 Intruder로 테스트한다고 생각해보자. ID필드에는 페이로드세트1의 페이로드를 지정하고, 패스워드 필드에는 페이로드세트2의 페이로드를 지정하고 싶을 것이다. 
- 이럴 때 Pitchfork를 사용하면 각 페이로드세트에서 하나씩 꺼내와서 ID와 패스워드 필드에 지정해준다. 
- 총 요청수는 "여러개의 페이로드 세트중에서 수가 적은 쪽의 페이로드 세트의 수"가 된다.
- 쇠스랑이란 이름이 붙은 것도 페이로드 세트라는 소 여물 모아둔 곳이 여러개 있을 때, 그 곳을 쇠스랑으로 긁어서 필요한 부분만 횡적으로 얻어오는 이미지에서 온 것이 아닌가 생각한다. 
- 참고로 Intruder에서 정의가능한 페이로드 세트수는 Positions탭에서 정의해둔 파라메터 포지션 수가 된다. (Position탭에서 포지션을 추가해두면 Payloads탭에서 Payload sets부분을 봤을 때 수가 늘어난다.)

![burp-intruder-payload-sets-count](/images/burp-intruder-payload-sets-count.png)

- 다수의 페이로드 세트를 지정할 수 있는 것은 Pitchfork나 Cluster bomb일 때이다. Sniper나 Battering ram은 그 특성상 다수의 페이로드 세트를 지정할 수 없다. 


# Cluster bomb (산탄식 폭탄)

공식 문서의 설명은 다음과 같다. 

```
This attack iterates through a different payload set for each defined position. Payloads are placed from each set in turn, so that all payload combinations are tested. For example, the first three requests would be:

Request one:

Position 1 = First payload from Set 1.
Position 2 = First payload from Set 2.
Request two:

Position 1 = First payload from Set 1.
Position 2 = Second payload from Set 2.
Request three:

Position 1 = First payload from Set 1.
Position 2 = Third payload from Set 2.
The total number of requests generated in the attack is the product of the number of payloads in all defined payload sets - this may be extremely large.

The Cluster bomb attack is useful where an attack requires unrelated or unknown input to be inserted in multiple places within the request. For example, when guessing both a username and password.
```

- 모든 조합을 테스트할 수 있다. (산탄 폭탄을 이미지해보자. 사방으로 파편이 흩어져서 모든 방향을 공격하는 이미지다.)
- 위의 쇠스랑에서의 예에 대입해서 생각해본다. 파라메터 포지션은 ID와 패스워드 두 개가 있다. 
- 페이로드 세트는 ID용 패스워용 두 개가 있고 각각에 세개의 페이로드가 있다. 
- 첫번째 ID를 고정한 후에 모든 패스워드를 테스트한다. 
- 그 후에 두번째 ID를 고정한 후에 모든 패스워드를 테스트한다. 
- 이를 마지막 ID까지 반복한다. 마지막까지 반복하면 모든 조합에 대해서 테스트가 완료된다. 

# 참고 
- https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/attack-types
- https://www.youtube.com/watch?v=ehGsDQbMXn8