---
layout: post
title: "CSP 헤더 - 해시 계산하는 방법"
categories: [CSP 헤더, XSS 방어]
tags: [CSP 헤더, XSS 방어, 해시]
toc: true
---

# 개요
- CSP 헤더 적용시 `unsafe-inline`설정을 하지 않고 인라인 스크립트를 사용하려면 해시를 사용해야 한다. 
- 이 때 적절한 해시를 계산하는 방법을 조사한다. 
- 동일한 sha256 알고리즘인데, 크롬이 제안하는 해시 값과, 기타 openssl 등으로 계산한 해시 값이 다른 경우가 있는 것 같기 때문에 조사해보기로 했다. 


# 해시 계산 방법
다음 세 가지 방법을 사용해서 각 해시 값을 비교해 본다. 

1. 크롬이 기대하는 해시값을 확인하는 방법(디버그 콘솔의 에러메세지로 확인가능)
2. node.js 코드 

```js
const fs = require('fs');
const crypto = require('crypto');
// test.js는 해시계산 대상 파일.  alert(1);이 적혀있다. 
const input = fs.readFileSync("./test.js"); 
hash_val = crypto.createHash("sha256").update(input).digest('base64');
console.log(hash_val);
```

3. openssl 로 계산

```sh
echo -n 'alert(1);' | openssl sha256 -binary | openssl base64
```

# 테스트 1. 가장 간단한 코드로 테스트 
## 해시 값 계산 대상 코드 
해시값을 만들기 위한 대상은 다음의 아주 간단한 코드이다. CSP에서 해시 계산시에는 script태그 부분은 무시된다. 

```js
<script type="text/javascript">
alert(1);
</script>
```


# 해시 값 계산 결과 
모두 동일한 결과가 나왔다. 어떤 방법을 써도 될 것 같다. 
- 크롬에서 제안한 값은 `5jFwrAK0UV47oFbVg/iCCBbxD8X1w+QvoOUepu4C2YA=`
- node.js 실행 결과는 `5jFwrAK0UV47oFbVg/iCCBbxD8X1w+QvoOUepu4C2YA=`
- openssl 실행 결과는 `5jFwrAK0UV47oFbVg/iCCBbxD8X1w+QvoOUepu4C2YA=`


주의점: \r\n 등과 같은 개행코드가 들어가면 해시값이 완전히 바뀌기 때문에 주의가 필요하다. 

# 테스트 2. 조금 더 복잡한 코드로 테스트 
## 대상코드 

```js
<script type="text/javascript">
alert($("#div-1").val());
</script>
```

## 해시 값 계산 결과 
다른 값이 나왔다. 딱히 개행문자가 들어가 있는 것도 아닌데 왜 크롬은 다르게 계산할걸까? 이유를 잘 모르겠다...
- chrome: xAKHjin+kq87UVqWpXuUJYDNEg45GHgx9i2KfSdt/t8=
- node.js: 4CKRt8TkJRxUJBhemwkMvoUgBfvFfcWScUKvw/Ht3EU=
- openssl: 4CKRt8TkJRxUJBhemwkMvoUgBfvFfcWScUKvw/Ht3EU=