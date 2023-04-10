---
layout: post
title: "Node.js 크롤러 라이브러리- simplecrwaler 사용법"
categories: [Node.js, 크롤러]
tags: [Node.js, 크롤러, simplecrwaler]
toc: true
---


# 개요
- node.js를 사용한 크롤러는 simplecrwaler, crawler, puppeteer-extra-plugin-stealth등이 유명한 것 같다. 
- 이중에서 simplecrwaler를 사용해본 결과를 정리해둔다. 

# 설치 
```sh
npm install --save simplecrawler
```

# 사용법
- URL을 파라메터로 지정하고 시작하면 된다. 
- 이것저것 옵션을 설정할 수 있다. 
- 가끔 아무런 결과없이 끝나는 경우가 있는데, 이건 첫 HTTP요청시에 크롤 대상 웹사이트가 302등 리다이렉트를 반환하기 때문이라고 한다. 그 외의 사이트에서는 잘 동작한다. 

```js
var Crawler = require("simplecrawler");
var crawler = new Crawler("http://www.example.com/");
// crawler.interval = 10000; // Ten seconds, defualt is 250 ms 
// crawler.maxConcurrency = 3; // default is 5 

// crawler.maxDepth = 1; // Only first page is fetched (with linked CSS & images)
// Or:
// crawler.maxDepth = 2; // First page and discovered links from it are fetched
// Or:
// crawler.maxDepth = 3; // Etc.
crawler.on("fetchcomplete", function(queueItem, responseBuffer, response) {
    console.log("I just received %s (%d bytes)", queueItem.url, responseBuffer.length);
    console.log("It was a resource of type %s", response.headers['content-type']);
});

crawler.start();

```

# 참고한 곳
- https://github.com/simplecrawler/simplecrawler
- https://openbase.com/js/simplecrawler
- https://stackoverflow.com/questions/50218402/nodejs-web-crawling-with-node-crawler-or-simplecrawler