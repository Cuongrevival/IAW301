**# FastAPI Authentication Demo: JWT và Session ID**

README này giải thích cơ chế **\*\*đăng nhập bằng Session ID và JWT\*\*** trong project FastAPI.

Mục tiêu là hiểu rõ:

\- Username/password được kiểm tra như thế nào.

\- Session ID hoạt động ra sao.

\- JWT hoạt động ra sao.

\- Browser lưu gì trong Cookie.

\- Server xác định user đã đăng nhập bằng cách nào.

\- Logout khác nhau thế nào giữa Session và JWT.

**---**

**## 1. Luồng đăng nhập chung**

Dù sử dụng **\*\*Session ID\*\*** hay **\*\*JWT\*\***, bước đầu tiên đều giống nhau:

\`\`\`text

User nhập Username + Password

            |

            v

      POST /login

            |

            v

     Server kiểm tra DB

            |

       +----+----+

       |         |

      Sai       Đúng

       |         |

       v         v

   Login fail   Tạo thông tin xác thực

\`\`\`

Ví dụ database:

\| Username | Password |

\|----------|----------|

\| admin | admin123 |

\| user | user123 |

\| staff | staff123 |

\> Trong project demo password đang được lưu dạng plaintext để dễ học.  

\> Trong hệ thống thực tế phải lưu **\*\*password hash\*\***, không lưu password trực tiếp.

**---**

**# 2. Session ID Authentication**

**## 2.1 Session ID là gì?**

Session ID là một chuỗi ngẫu nhiên đại diện cho một phiên đăng nhập.

Ví dụ:

\`\`\`text

session_id = "4FrK8xM9p..."

\`\`\`

Session ID **\*\*không cần chứa username hoặc role\*\***.

Server dùng Session ID để tìm thông tin user trong bộ nhớ hoặc database.

Ví dụ:

\`\`\`python

sessions = {

    "4FrK8xM9p...": {

        "username": "admin"

    }

}

\`\`\`

Có thể hiểu:

\`\`\`text

Session ID = mã vé

Server = nơi lưu thông tin thật

\`\`\`

**---**

**## 2.2 Luồng Login bằng Session ID**

Trong code:

\`\`\`text

Browser

   |

   | username + password

   v

POST /login

   |

   v

Check username/password trong SQLite

   |

   +------------------+

   |                  |

  Sai                Đúng

   |                  |

   v                  v

401 / Login Fail   create_session()

                      |

                      v

             Sinh Session ID random

                      |

                      v

          sessions[session_id] = user

                      |

                      v

       Gửi session_id về Cookie

\`\`\`

Ví dụ hàm tạo session:

\`\`\`python

def create_session(username):

    session_id = secrets.token_urlsafe(32)

    sessions[session_id] = {

        "username": username,

        "created_at": time.time()

    }

    return session_id

\`\`\`

\`secrets.token_urlsafe()\` tạo một chuỗi ngẫu nhiên khó đoán.

**---**

**## 2.3 Browser lưu Session ID như thế nào?**

Sau khi login thành công:

\`\`\`python

response.set_cookie(

    key="session_id",

    value=session_id,

    httponly=True,

    samesite="lax"

)

\`\`\`

Browser sẽ giữ Cookie:

\`\`\`text

session_id=4FrK8xM9p...

\`\`\`

Sau đó khi user truy cập:

\`\`\`text

GET /profile

\`\`\`

browser tự gửi Cookie:

\`\`\`http

Cookie: session_id=4FrK8xM9p...

\`\`\`

**---**

**## 2.4 Server xác định user bằng Session ID**

Server lấy Session ID từ Cookie:

\`\`\`python

session_id = request.cookies.get("session_id")

\`\`\`

Sau đó tìm trong:

\`\`\`python

sessions

\`\`\`

Ví dụ:

\`\`\`python

sessions = {

    "4FrK8xM9p...": {

        "username": "admin"

    }

}

\`\`\`

Nếu tìm thấy:

\`\`\`text

Session ID

    |

    v

sessions[session_id]

    |

    v

username = admin

\`\`\`

User được xem là đã đăng nhập.

**---**

**## 2.5 Logout với Session ID**

Logout Session rất trực tiếp.

\`\`\`python

sessions.pop(session_id, None)

\`\`\`

Server xóa session:

\`\`\`text

Trước:

sessions = {

    "ABC123": {

        "username": "admin"

    }

}

\`\`\`

Sau logout:

\`\`\`text

sessions = {}

\`\`\`

Sau đó xóa Cookie:

\`\`\`python

response.delete_cookie("session_id")

\`\`\`

Session ID cũ không còn sử dụng được.

**---**

**# 3. JWT Authentication**

**## 3.1 JWT là gì?**

JWT là viết tắt của:

\`\`\`text

JSON Web Token

\`\`\`

JWT thường có dạng:

\`\`\`text

xxxxx.yyyyy.zzzzz

\`\`\`

Bao gồm 3 phần:

\`\`\`text

HEADER.PAYLOAD.SIGNATURE

\`\`\`

Ví dụ:

\`\`\`text

eyJhbGciOiJIUzI1NiJ9.

eyJzdWIiOiJhZG1pbiJ9.

abc123signature

\`\`\`

**---**

**## 3.2 Header**

Header mô tả loại token và thuật toán ký.

Ví dụ:

\`\`\`json

{

    "alg": "HS256",

    "typ": "JWT"

}

\`\`\`

Trong project:

\`\`\`python

header = {

    "alg": "HS256",

    "typ": "JWT"

}

\`\`\`

**---**

**## 3.3 Payload**

Payload chứa thông tin của token.

Ví dụ:

\`\`\`json

{

    "sub": "admin",

    "iat": 1789970000,

    "exp": 1789973600

}

\`\`\`

Ý nghĩa:

\| Field | Ý nghĩa |

\|-------|---------|

\| \`sub\` | Subject, thường dùng để xác định user |

\| \`iat\` | Thời điểm token được tạo |

\| \`exp\` | Thời điểm token hết hạn |

Trong code:

\`\`\`python

payload = {

    "sub": username,

    "iat": int(time.time()),

    "exp": int(time.time()) + 3600

}

\`\`\`

Token này có thời hạn:

\`\`\`text

3600 giây = 1 giờ

\`\`\`

**---**

**## 3.4 Signature**

Signature dùng để kiểm tra JWT có bị sửa hay không.

Project sử dụng:

\`\`\`text

HMAC-SHA256

\`\`\`

Ví dụ:

\`\`\`python

signature = hmac.new(

    JWT_SECRET.encode(),

    message.encode(),

    hashlib.sha256

).digest()

\`\`\`

Có thể hình dung:

\`\`\`text

Header

   +

Payload

   +

Secret Key

   |

   v

HMAC-SHA256

   |

   v

Signature

\`\`\`

Nếu attacker thay đổi:

\`\`\`json

{

    "sub": "user"

}

\`\`\`

thành:

\`\`\`json

{

    "sub": "admin"

}

\`\`\`

thì Signature cũ không còn hợp lệ.

Server sẽ phát hiện JWT bị thay đổi.

**---**

**# 4. Luồng Login bằng JWT**

\`\`\`text

Browser

   |

   | username + password

   v

POST /jwt-login

   |

   v

Check username/password

   |

   +------------------+

   |                  |

  Sai                Đúng

   |                  |

   v                  v

401 Unauthorized   create_jwt()

                      |

                      v

          Header + Payload + Signature

                      |

                      v

               JWT được tạo

                      |

                      v

          JWT được lưu trong Cookie

\`\`\`

Ví dụ:

\`\`\`python

token = create_jwt(username)

\`\`\`

Sau đó:

\`\`\`python

response.set_cookie(

    key="access_token",

    value=token,

    httponly=True,

    samesite="lax"

)

\`\`\`

Browser sẽ giữ:

\`\`\`text

access_token=\<JWT>

\`\`\`

**---**

**# 5. Truy cập route được bảo vệ bằng JWT**

Khi user truy cập:

\`\`\`text

GET /jwt-profile

\`\`\`

browser gửi Cookie:

\`\`\`http

Cookie: access_token=\<JWT>

\`\`\`

Server lấy token:

\`\`\`python

token = request.cookies.get("access_token")

\`\`\`

Sau đó gọi:

\`\`\`python

payload = verify_jwt(token)

\`\`\`

Quá trình verify:

\`\`\`text

JWT

 |

 v

Tách Header.Payload.Signature

 |

 v

Tự tạo lại Signature bằng JWT_SECRET

 |

 v

So sánh Signature

 |

 +------------------+

 |                  |

Sai                Đúng

 |                  |

 v                  v

Reject          Check exp

                    |

               +----+----+

               |         |

             Hết hạn    Còn hạn

               |         |

               v         v

             Reject   Cho phép

\`\`\`

Sau khi hợp lệ:

\`\`\`python

username = payload["sub"]

\`\`\`

Server biết user hiện tại là ai.

**---**

**# 6. JWT không phải Encryption**

Điểm rất quan trọng:

\`\`\`text

JWT != Encryption

\`\`\`

Payload JWT thường chỉ được Base64URL encode.

Điều đó có nghĩa là payload có thể được decode và đọc.

Ví dụ:

\`\`\`json

{

    "sub": "admin",

    "role": "admin"

}

\`\`\`

Không nên đặt thông tin bí mật như:

\`\`\`text

password

credit card

private key

secret key

\`\`\`

vào JWT.

Signature chỉ giúp server xác định:

\`\`\`text

Token có bị chỉnh sửa hay không?

\`\`\`

**---**

**# 7. So sánh Session ID và JWT**

\| Đặc điểm | Session ID | JWT |

\|----------|------------|-----|

\| Client giữ | Session ID | JWT |

\| Thông tin user | Chủ yếu ở server | Có thể nằm trong token |

\| Server lưu trạng thái | Có | Không bắt buộc |

\| Loại | Stateful | Thường Stateless |

\| Logout | Dễ | Phức tạp hơn |

\| Revoke ngay lập tức | Dễ | Khó hơn nếu không có blacklist |

\| Token size | Nhỏ | Lớn hơn |

\| Thường dùng | Web truyền thống | API, mobile, microservices |

**---**

**# 8. Ví dụ dễ nhớ**

**## Session ID**

Hãy tưởng tượng Session ID giống **\*\*vé gửi xe\*\***.

Bạn nhận:

\`\`\`text

Vé số: 12345

\`\`\`

Thông tin thật nằm ở hệ thống:

\`\`\`text

12345 -> Xe của Admin

\`\`\`

Client chỉ giữ mã:

\`\`\`text

12345

\`\`\`

Server phải tra cứu.

**---**

**## JWT**

JWT giống một **\*\*thẻ có thông tin và chữ ký xác nhận\*\***:

\`\`\`text

Username: admin

Role: admin

Expires: 16:00

Signature: ...

\`\`\`

Server không nhất thiết phải tra session.

Server kiểm tra chữ ký:

\`\`\`text

Signature hợp lệ?

        |

       Yes

        |

        v

Tin dữ liệu trong token

\`\`\`

**---**

**# 9. Cookie HttpOnly**

Project sử dụng:

\`\`\`python

httponly=True

\`\`\`

Ví dụ:

\`\`\`python

response.set_cookie(

    key="session_id",

    value=session_id,

    httponly=True

)

\`\`\`

Hoặc:

\`\`\`python

response.set_cookie(

    key="access_token",

    value=token,

    httponly=True

)

\`\`\`

\`HttpOnly\` giúp ngăn JavaScript phía client đọc Cookie trực tiếp bằng:

\`\`\`javascript

document.cookie

\`\`\`

Điều này giúp giảm rủi ro token/session bị lấy trong một số tình huống XSS.

**---**

**# 10. Login Fail và Account Lock**

Có thể kết hợp cơ chế authentication với biến đếm số lần login sai.

Ví dụ:

\`\`\`python

MAX_LOGIN_FAIL = 3

count = {}

locked_users = set()

\`\`\`

Luồng:

\`\`\`text

Nhập username/password

        |

        v

Check username

        |

   +----+----+

   |         |

Không có    Có

   |         |

   v         v

404     Check account locked

             |

        +----+----+

        |         |

      Locked    Không

        |         |

        v         v

      423     Check password

                  |

             +----+----+

             |         |

            Sai       Đúng

             |         |

             v         v

         count += 1  count = 0

             |

             v

      count >= MAX?

             |

        +----+----+

        |         |

       Yes        No

        |         |

        v         v

      423       401

\`\`\`

HTTP Status có thể dùng trong bài lab:

\| Trường hợp | Status |

\|-----------|--------|

\| Username không tồn tại | \`404 Not Found\` |

\| Password sai | \`401 Unauthorized\` |

\| Account bị khóa | \`423 Locked\` |

\| Login thành công | \`200 OK\` hoặc redirect \`303\` |

\| Logout rồi redirect | \`303 See Other\` |

\> Lưu ý: hệ thống production thường không trả thông báo khác nhau giữa username sai và password sai vì có thể gây **\*\*username enumeration\*\***.

**---**

**# 11. Session trong project hiện tại có một hạn chế**

Nếu sử dụng:

\`\`\`python

sessions = {}

\`\`\`

thì Session đang được lưu trong RAM.

Khi restart FastAPI:

\`\`\`text

Server restart

     |

     v

sessions = {}

\`\`\`

Tất cả session cũ sẽ mất.

Trong project thực tế, session có thể được lưu trong:

\`\`\`text

Redis

Database

Distributed Cache

\`\`\`

**---**

**# 12. JWT Logout có điểm khác Session**

Với Session:

\`\`\`python

sessions.pop(session_id)

\`\`\`

server có thể vô hiệu Session ngay.

Với JWT:

\`\`\`python

response.delete_cookie("access_token")

\`\`\`

chỉ xóa token khỏi browser hiện tại.

Nếu một attacker đã copy JWT trước đó, token đó vẫn có thể hợp lệ cho tới:

\`\`\`text

exp

\`\`\`

trừ khi hệ thống triển khai:

\`\`\`text

Token blacklist

Token revocation

Short-lived Access Token

Refresh Token rotation

\`\`\`

**---**

**# 13. Tóm tắt**

**## Session ID**

\`\`\`text

Login

  |

  v

Server tạo Session ID

  |

  v

Server lưu Session

  |

  v

Browser giữ Session ID

  |

  v

Request tiếp theo gửi Session ID

  |

  v

Server tra Session

\`\`\`

Câu dễ nhớ:

\> **\*\*Session ID: "Đưa tôi mã phiên, tôi sẽ tra xem bạn là ai."\*\***

**---**

**## JWT**

\`\`\`text

Login

  |

  v

Server tạo JWT

  |

  v

JWT chứa Payload + Signature

  |

  v

Browser giữ JWT

  |

  v

Request tiếp theo gửi JWT

  |

  v

Server verify Signature

\`\`\`

Câu dễ nhớ:

\> **\*\*JWT: "Đưa tôi dữ liệu đã được ký, tôi kiểm tra chữ ký để xác định dữ liệu có đáng tin hay không."\*\***

**---**

**

---

# 15. Exponential Backoff

## 15.1 Exponential Backoff là gì?

Exponential Backoff là cơ chế làm cho thời gian chờ giữa các lần đăng nhập sai tăng dần.

Ví dụ:

```text
Sai lần 1 -> chờ 2 giây
Sai lần 2 -> chờ 4 giây
Sai lần 3 -> chờ 8 giây
Sai lần 4 -> chờ 16 giây
Sai lần 5 -> khóa tài khoản
```

Công thức:

```python
delay = BASE_DELAY * (2 ** (failed_attempts - 1))
```

Ví dụ cấu hình:

```python
BASE_DELAY = 2
MAX_DELAY = 60
```

Để tránh thời gian chờ tăng vô hạn:

```python
delay = min(delay, MAX_DELAY)
```

---

## 15.2 Các biến cần sử dụng

```python
MAX_LOGIN_FAIL = 5

BASE_DELAY = 2
MAX_DELAY = 60

count = {}
next_login_time = {}
locked_users = set()
```

| Biến | Chức năng |
|---|---|
| `count` | Đếm số lần login sai của từng username |
| `next_login_time` | Lưu thời điểm username được phép login lại |
| `locked_users` | Danh sách tài khoản đã bị khóa |
| `BASE_DELAY` | Thời gian chờ ban đầu |
| `MAX_DELAY` | Thời gian chờ tối đa |

---

## 15.3 Kiểm tra user đang bị Backoff

```python
current_time = time.time()

blocked_until = next_login_time.get(username, 0)

if current_time < blocked_until:
    retry_after = int(blocked_until - current_time) + 1

    return HTMLResponse(
        f"<h2>429 - Too Many Requests</h2>"
        f"<p>Please wait {retry_after} seconds before trying again.</p>",
        status_code=429,
        headers={
            "Retry-After": str(retry_after)
        }
    )
```

Luồng:

```text
POST /login
     |
     v
Check next_login_time
     |
     +---- Chưa hết thời gian ----> 429
     |
     +---- Đã hết thời gian ------> tiếp tục check password
```

---

## 15.4 Khi Password sai

```python
if password != database_password:

    if username not in count:
        count[username] = 0

    count[username] += 1

    failed_attempts = count[username]

    delay = BASE_DELAY * (
        2 ** (failed_attempts - 1)
    )

    delay = min(
        delay,
        MAX_DELAY
    )

    next_login_time[username] = (
        time.time() + delay
    )
```

Ví dụ:

```text
Sai lần 1 -> 2 giây
Sai lần 2 -> 4 giây
Sai lần 3 -> 8 giây
Sai lần 4 -> 16 giây
```

---

## 15.5 Khi Login thành công

```python
count[username] = 0

next_login_time.pop(
    username,
    None
)
```

Tức là:

```text
Login đúng
   |
   v
Reset failed count
   |
   v
Xóa backoff
```

---

# 16. Rate Limit

## 16.1 Rate Limit là gì?

Rate Limit giới hạn số lượng request mà một client được phép gửi trong một khoảng thời gian.

Ví dụ:

```text
5 request / 60 giây / IP
```

Nếu IP gửi quá nhiều request:

```text
Request 1 -> OK
Request 2 -> OK
Request 3 -> OK
Request 4 -> OK
Request 5 -> OK

Request 6
   |
   v
429 Too Many Requests
```

Khác với Exponential Backoff:

```text
Rate Limit
= giới hạn số request

Exponential Backoff
= tăng thời gian chờ sau mỗi lần login sai
```

---

## 16.2 Biến Rate Limit

```python
RATE_LIMIT_REQUESTS = 5
RATE_LIMIT_WINDOW = 60

rate_limit_store = {}
```

Ví dụ dữ liệu:

```python
rate_limit_store = {
    "127.0.0.1": [
        1789970001,
        1789970005,
        1789970010
    ]
}
```

---

## 16.3 Hàm kiểm tra Rate Limit

```python
def check_rate_limit(ip_address):

    current_time = time.time()

    if ip_address not in rate_limit_store:
        rate_limit_store[ip_address] = []

    requests = rate_limit_store[ip_address]

    requests = [
        request_time
        for request_time in requests
        if current_time - request_time < RATE_LIMIT_WINDOW
    ]

    rate_limit_store[ip_address] = requests

    if len(requests) >= RATE_LIMIT_REQUESTS:

        oldest_request = requests[0]

        retry_after = int(
            RATE_LIMIT_WINDOW
            - (current_time - oldest_request)
        ) + 1

        return False, retry_after

    requests.append(current_time)

    return True, 0
```

Đây là một dạng Sliding Window đơn giản.

---

## 16.4 Lấy IP của Client

Endpoint login cần nhận thêm:

```python
request: Request
```

Ví dụ:

```python
@app.post(
    "/login",
    response_class=HTMLResponse
)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
```

Lấy IP:

```python
client_ip = request.client.host
```

---

## 16.5 Kiểm tra Rate Limit ở đầu Endpoint

Rate Limit nên được kiểm tra trước khi query database.

```python
client_ip = request.client.host

allowed, retry_after = check_rate_limit(
    client_ip
)

if not allowed:

    return HTMLResponse(
        f"<h2>429 - Too Many Requests</h2>"
        f"<p>Try again after {retry_after} seconds.</p>",
        status_code=429,
        headers={
            "Retry-After": str(retry_after)
        }
    )
```

Luồng:

```text
Client
  |
  | POST /login
  v
Check Rate Limit
  |
  +------ Quá giới hạn ------> 429
  |
  +------ Cho phép
           |
           v
       Query Database
```

---

# 17. Kết hợp Rate Limit + Exponential Backoff + Account Lock

| Cơ chế | Bảo vệ khỏi |
|---|---|
| Rate Limit | Gửi quá nhiều request trong thời gian ngắn |
| Exponential Backoff | Thử password sai liên tục |
| Account Lock | Tiếp tục brute force một account quá nhiều lần |

Luồng login:

```text
POST /login
     |
     v
Rate Limit theo IP
     |
     +------ Block ------> 429
     |
     v
Check Username
     |
     +------ Không tồn tại ------> 404
     |
     v
Check Account Locked
     |
     +------ Locked ------> 423
     |
     v
Check Exponential Backoff
     |
     +------ Đang chờ ------> 429
     |
     v
Check Password
     |
     +----------+----------+
     |                     |
    Sai                   Đúng
     |                     |
     v                     v
count += 1             count = 0
     |                     |
     v                     v
Tính Backoff          Xóa Backoff
     |
     v
count >= MAX?
     |
 +---+---+
 |       |
Yes     No
 |       |
 v       v
423     401
```

---

# 18. Cấu hình hoàn chỉnh

```python
MAX_LOGIN_FAIL = 5

# Exponential Backoff
BASE_DELAY = 2
MAX_DELAY = 60

count = {}
next_login_time = {}
locked_users = set()


# Rate Limit
RATE_LIMIT_REQUESTS = 5
RATE_LIMIT_WINDOW = 60

rate_limit_store = {}
```

---

# 19. Lưu ý khi triển khai thực tế

Trong project demo có thể sử dụng:

```python
count = {}
next_login_time = {}
rate_limit_store = {}
locked_users = set()
```

Nhưng tất cả dữ liệu này đang nằm trong RAM.

Khi FastAPI restart, mọi trạng thái sẽ bị mất.

Trong production nên cân nhắc:

```text
Redis
Database
Distributed Cache
```

để nhiều server có thể dùng chung trạng thái Rate Limit và Login Failure.

Ngoài ra, production thường nên trả về thông báo chung:

```text
Invalid username or password
```

thay vì phân biệt:

```text
404 - User not found
401 - Wrong password
```

để giảm nguy cơ Username Enumeration.

---

# 20. Tóm tắt cơ chế bảo vệ Login

```text
                     Login Request
                          |
                          v
                  Rate Limit by IP
                          |
                   +------+------+
                   |             |
                 Block         Allow
                   |             |
                  429            v
                          Check Username
                                |
                          Check Account
                                |
                          Check Backoff
                                |
                          Check Password
                           /          \
                        Wrong         Correct
                          |              |
                     count += 1      Reset count
                          |              |
                    Calculate delay   Create Session
                          |
                    Account Lock?
                     /        \
                   Yes        No
                    |          |
                   423        401
```

Câu dễ nhớ:

```text
Rate Limit:
"Bạn gửi request quá nhanh."

Exponential Backoff:
"Bạn càng login sai, bạn càng phải chờ lâu."

Account Lock:
"Bạn sai quá nhiều lần, tài khoản bị khóa."
```

---

# 14. Khuyến nghị cho project tiếp theo**

Sau khi hiểu Session và JWT, có thể phát triển tiếp:

\`\`\`text

1\. Password Hash + Salt

2\. Login Fail Counter

3\. Account Lock

4\. Session Expiration

5\. JWT Expiration

6\. Role-Based Authorization

7\. CSRF Protection

8\. Access Token + Refresh Token

9\. Logout / Token Revocation

10\. Redis Session Store

\`\`\`

Đây là các thành phần giúp authentication demo tiến gần hơn tới một hệ thống thực tế.