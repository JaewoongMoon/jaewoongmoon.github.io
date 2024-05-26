---
layout: post
title: "Burp Academy-안전하지 않은 역직렬화(Insecure Deserialization) 관련 취약점: Modifying serialized data types"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Insecure Deserialization]
toc: true
last_modified_at: 2024-05-14 21:00:00 +0900
---


# 개요
- 안전하지 않은 역직렬화(Insecure Deserialization) 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types
- 취약점 설명페이지: https://portswigger.net/web-security/deserialization/exploiting
- 난이도: PRACTITIONER (보통)

# 취약점 개요: 직렬화된 데이터 타입을 변경하기 
- 데이터 타입을 변경해서도 데이터의 값을 변경한 것과 비슷한 효과를 낼 때가 있다. 
- 대표적으로 PHP와 같은 언어에 있는 느슨한 동등비교를 악용하는 경우다.
- PHP에는 `==` 기호가 느슨한 동등비교(loose comparison)을 의미한다. 서로 다른 타입의 데이터를 비교할 때 편하다. 예를들어 `5 == "5"` 는 `true`가 된다. 
- 이는 5뒤에 문자열이 있어도 동일한 결과가 된다. 즉, `5 == "5 of something"`도 `true`가 된다. 
- 정수값 0일 때를 살펴보면 더 이상해진다. `0 == "Example string"`의 평가 결과가 `true`가 되는 것이다. 이는 문자열에 숫자가 없기 때문 (0개)이다. PHP는 우변의 문자열을 정수 0으로 취급한다. 
- 이 기능이 악용될 수 있는 상황을 살펴보자. PHP에서 로그인 처리 코드가 다음과 같이 되어 있다고 생각해보자. 

```php
$login = unserialize($_COOKIE)
if ($login['password'] == $password) {
// log in successfully
}
```

- 공격자가 패스워드에 정수값 0을 포함시켰다고 해보자. 
- 실제 패스워드가 숫자로 시작하지 않는 한 느슨한 동등 비교 결과, 항상 `true`가 리턴된다!😱 그 결과 인증우회가 된다. 
- 또한, 이는 **역직렬화를 통해 데이터 타입이 보존되는 경우(즉, 정수형이 유지되는 경우)에 한해 가능하다**는 점에 주의한다. 만약 코드가 패스워드를 HTTP요청에서 직접적으로 가져오는 경우에는 0가 문자열로 변환되기 때문에 비교 결과가 `false`가 된다. 
- 또한 역직렬화할 때 타입 라벨과 길이를 나타내는 부분도 변경 후에 맞춰서 같이 수정해줘야 한다는 점을 기억하자. 그렇게 하지 않으면 역직렬화과정에서 에러가 발생한다. 

## 실제로 PHP에서 테스트해보기
- https://onlinephp.io/ 에 방문하면 PHP코드를 실행해볼 수 있다. 

다음 코드로 실행해보았다. 실제로 패스워드가 0이외의 숫자로 시작하는 경우를 제외하고는 `true`로 평가되는 것을 확인했다. 

```php
<?php
// Enter your code here, enjoy!

// echo 5 == "5"; //true
// echo 5 == "5 of something"; // true
// echo 0 == "Example string"; // true
// echo 0 == "Password1"; //true 
// echo 0 == "Password1SW@!!"; //true
// echo 0 == "1Password1SW@!!"; //false
echo 0 == "0Password1SW@!!"; //true
```

※ 참고: `Hackvertor` 라는 확장 프로그램을 이용하면 바이너리 타입의 직렬화된 데이터를 쉽게 변조할 수 있다. 


# 문제 개요
- 이 랩은 직렬화 베이스의 세션 관리 메커니즘을 사용하고 있고, 결과적으로 인증우회 취약점이 존재한다. 
- 랩을 풀려면 세션 쿠키 안에 있는 직렬화 오브젝트를 수정해서 관리자 권한을 얻어내어 carlos유저를 삭제하면 된다. 
- wiener:peter 크레덴셜로 로그인할 수 있다. 

```
This lab uses a serialization-based session mechanism and is vulnerable to authentication bypass as a result. To solve the lab, edit the serialized object in the session cookie to access the administrator account. Then, delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter
```

# 도전
1. 로그인 과정을 살펴본다. 로그인시의 파라메터는 일반적인 HTTP 요청 파라메터로 전달된다. 따라서 패스워드는 문자열로 처리되므로 정수를 지정해서 느슨한 동등비교를 우회하는 테크닉은 사용할 수 없어 보인다.  주어진 로그인 크레덴셜로 로그인한 후, 발행된 세션토큰을 수정하는 방법을 생각해보자. 로그인하면 세션토큰이 발행된다. 

![](/images/burp-academy-serial-2-1.png)

2. 세션토큰을 Base64 디코딩해본다. administrator와 같은 값이 없어졌다. 음... 이번에는 좀 더 어렵다. 

```json
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"ix2obzejai29hzp3a4doo8yln4ys8822";}%3d%3d
```

3. 억세스토큰을 바꿔본다. 억세스토큰의 가장 앞의 문자 i를 숫자 1로 바꿔보았다. 

![](/images/burp-academy-serial-2-2.png)

4. 변경한 세션토큰으로 접근하니 PHP에러가 발생했다. access_token값이 일치하지 않아서 발생한 것 같다. 일단 유저별로 억세스 토큰 값의 동등성 체크를 하고 있는 것으로 보인다. 

![](/images/burp-academy-serial-2-3.png)

5. 세션 토큰값을 다음과 같이 변조해본다. `s:32` (32바이트의 문자열 값) 였던 것을 `i` (정수)로 바꾼다. 그리고 억세스토큰값의 부분을 정수 `0`으로 바꾼다. 

![](/images/burp-academy-serial-2-5.png)

6. 바뀐 토큰을 세션토큰으로 지정해서 서버에 접속해본다. 그러면 관리자 패널에 접근하는데 성공한 것을 볼 수 있다! 😎 억세스 토큰에 정수 0을 지정한 것으로 인해 인증을 우회(느슨한 동등성 비교를 통한 값 비교를 우회)하는데 성공했다. 

![](/images/burp-academy-serial-2-4.png)

7. calors 유저를 삭제하는 요청을 보낸다. 

![](/images/burp-academy-serial-2-6.png)

![](/images/burp-academy-serial-2-7.png)

8. 유저삭제에 성공하고 랩이 풀렸다는 메세지가 출력된다. 

![](/images/burp-academy-serial-2-success.png)