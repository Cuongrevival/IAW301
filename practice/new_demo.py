from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
import uvicorn
import sqlite3
import json
import base64
import hmac
import hashlib
import time
import secrets


# =========================================================
# APP + DATABASE
# =========================================================

db_name = "database"

app = FastAPI(title="Authentication Security Demo")


def create_database():
    connect = sqlite3.connect(f"{db_name}.db")
    cursor = connect.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS customers(
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Demo only.
    # Production phải lưu password hash, không lưu plaintext.
    users = [
        ("admin", "admin123"),
        ("user", "user123"),
        ("staff", "staff123")
    ]

    for username, password in users:
        cursor.execute(
            """
            INSERT OR IGNORE INTO customers(username, password)
            VALUES(?, ?)
            """,
            (username, password)
        )

    connect.commit()
    connect.close()


create_database()


def find_user(username):
    connect = sqlite3.connect(f"{db_name}.db")
    cursor = connect.cursor()

    cursor.execute(
        """
        SELECT id, username, password
        FROM customers
        WHERE username = ?
        """,
        (username,)
    )

    user = cursor.fetchone()

    connect.close()

    return user


def authenticate_user(username, password):
    connect = sqlite3.connect(f"{db_name}.db")
    cursor = connect.cursor()

    cursor.execute(
        """
        SELECT id, username
        FROM customers
        WHERE username = ? AND password = ?
        """,
        (username, password)
    )

    user = cursor.fetchone()

    connect.close()

    return user


# =========================================================
# JWT
# =========================================================

JWT_SECRET = "super-secret-key-change-this"


def base64url_encode(data: bytes):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def base64url_decode(data: str):
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_jwt(username):
    header = {
        "alg": "HS256",
        "typ": "JWT"
    }

    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }

    header_encoded = base64url_encode(
        json.dumps(header).encode()
    )

    payload_encoded = base64url_encode(
        json.dumps(payload).encode()
    )

    message = f"{header_encoded}.{payload_encoded}"

    signature = hmac.new(
        JWT_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).digest()

    signature_encoded = base64url_encode(signature)

    return (
        f"{header_encoded}."
        f"{payload_encoded}."
        f"{signature_encoded}"
    )


def verify_jwt(token):
    try:
        header_encoded, payload_encoded, signature_encoded = token.split(".")

        message = f"{header_encoded}.{payload_encoded}"

        expected_signature = hmac.new(
            JWT_SECRET.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()

        received_signature = base64url_decode(
            signature_encoded
        )

        if not hmac.compare_digest(
            expected_signature,
            received_signature
        ):
            return None

        payload = json.loads(
            base64url_decode(payload_encoded)
        )

        if payload["exp"] < int(time.time()):
            return None

        return payload

    except Exception:
        return None


# =========================================================
# SESSION
# =========================================================

sessions = {}


def create_session(username):
    session_id = secrets.token_urlsafe(32)

    sessions[session_id] = {
        "username": username,
        "created_at": time.time()
    }

    return session_id


def get_session(request: Request):
    session_id = request.cookies.get("session_id")

    if not session_id:
        return None

    return sessions.get(session_id)


# =========================================================
# LOGIN SECURITY SETTINGS
# =========================================================

# Account Lock + Exponential Backoff
MAX_LOGIN_FAIL = 5
BASE_DELAY = 2
MAX_DELAY = 60

# username -> số lần password sai
count = {}

# username -> thời điểm được phép thử login tiếp
next_login_time = {}

# các username đã bị khóa
locked_users = set()


# Rate Limit
RATE_LIMIT_REQUESTS = 5
RATE_LIMIT_WINDOW = 60

# IP -> [request_time_1, request_time_2, ...]
rate_limit_store = {}


# =========================================================
# RATE LIMIT FUNCTIONS
# =========================================================

def cleanup_rate_limit(ip_address):
    current_time = time.time()

    requests = rate_limit_store.get(
        ip_address,
        []
    )

    active_requests = [
        request_time
        for request_time in requests
        if current_time - request_time < RATE_LIMIT_WINDOW
    ]

    rate_limit_store[ip_address] = active_requests

    return active_requests


def get_rate_limit_status(ip_address):
    requests = cleanup_rate_limit(ip_address)

    used = len(requests)

    remaining = max(
        RATE_LIMIT_REQUESTS - used,
        0
    )

    if requests:
        reset_after = max(
            int(
                RATE_LIMIT_WINDOW
                - (time.time() - requests[0])
            ) + 1,
            0
        )
    else:
        reset_after = 0

    return used, remaining, reset_after


def check_rate_limit(ip_address):
    requests = cleanup_rate_limit(ip_address)

    current_time = time.time()

    if len(requests) >= RATE_LIMIT_REQUESTS:
        oldest_request = requests[0]

        retry_after = int(
            RATE_LIMIT_WINDOW
            - (current_time - oldest_request)
        ) + 1

        return False, retry_after, len(requests)

    requests.append(current_time)

    return True, 0, len(requests)


# =========================================================
# EXPONENTIAL BACKOFF FUNCTIONS
# =========================================================

def get_backoff_status(username):
    failed_attempts = count.get(username, 0)

    blocked_until = next_login_time.get(
        username,
        0
    )

    retry_after = 0

    if time.time() < blocked_until:
        retry_after = int(
            blocked_until - time.time()
        ) + 1

    return failed_attempts, retry_after


def register_failed_login(username):
    if username not in count:
        count[username] = 0

    count[username] += 1

    failed_attempts = count[username]

    # Nếu quá số lần cho phép -> khóa account
    if failed_attempts >= MAX_LOGIN_FAIL:
        locked_users.add(username)
        next_login_time.pop(username, None)

        return {
            "locked": True,
            "failed_attempts": failed_attempts,
            "delay": 0,
            "remaining": 0
        }

    # Exponential Backoff:
    # 2, 4, 8, 16, ...
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

    remaining = (
        MAX_LOGIN_FAIL - failed_attempts
    )

    return {
        "locked": False,
        "failed_attempts": failed_attempts,
        "delay": delay,
        "remaining": remaining
    }


def reset_login_security(username):
    count[username] = 0
    next_login_time.pop(username, None)


# =========================================================
# HTML HELPERS
# =========================================================

def rate_limit_html(
    client_ip,
    used,
    remaining,
    reset_after,
    title="RATE LIMIT"
):
    reset_text = (
        f"{reset_after} seconds"
        if reset_after > 0
        else "No active window"
    )

    return f"""
    <fieldset>
        <legend>
            <strong>{title}</strong>
        </legend>

        <h3>Request Limiting Protection</h3>

        <p>
            <strong>Đây là khu vực Rate Limit.</strong>
        </p>

        <p>
            Rate Limit kiểm soát số request gửi từ một IP
            trong một khoảng thời gian.
        </p>

        <p>
            Client IP:
            <strong>{client_ip}</strong>
        </p>

        <p>
            Requests:
            <strong>
                {used} / {RATE_LIMIT_REQUESTS}
            </strong>
        </p>

        <p>
            Remaining Requests:
            <strong>{remaining}</strong>
        </p>

        <p>
            Time Window:
            <strong>{RATE_LIMIT_WINDOW} seconds</strong>
        </p>

        <p>
            Window Reset:
            <strong>{reset_text}</strong>
        </p>

        <pre>
Rate Limit:
{RATE_LIMIT_REQUESTS} requests / {RATE_LIMIT_WINDOW} seconds / IP

Request quá giới hạn
        |
        v
429 Too Many Requests
        </pre>
    </fieldset>
    """


def backoff_general_html():
    return f"""
    <fieldset>
        <legend>
            <strong>EXPONENTIAL BACKOFF</strong>
        </legend>

        <h3>Failed Login Delay Protection</h3>

        <p>
            <strong>
                Đây là khu vực Exponential Backoff.
            </strong>
        </p>

        <p>
            Exponential Backoff tăng thời gian chờ
            sau mỗi lần nhập sai password.
        </p>

        <p>
            Base Delay:
            <strong>{BASE_DELAY} seconds</strong>
        </p>

        <p>
            Maximum Delay:
            <strong>{MAX_DELAY} seconds</strong>
        </p>

        <p>
            Account Lock:
            <strong>{MAX_LOGIN_FAIL} failures</strong>
        </p>

        <pre>
Sai lần 1 -> Wait 2 seconds
Sai lần 2 -> Wait 4 seconds
Sai lần 3 -> Wait 8 seconds
Sai lần 4 -> Wait 16 seconds
Sai lần 5 -> Account Locked
        </pre>
    </fieldset>
    """


def backoff_status_html(
    username,
    failed_attempts,
    delay,
    remaining=None
):
    remaining_html = ""

    if remaining is not None:
        remaining_html = f"""
        <p>
            Remaining Attempts:
            <strong>{remaining}</strong>
        </p>
        """

    return f"""
    <fieldset>
        <legend>
            <strong>EXPONENTIAL BACKOFF</strong>
        </legend>

        <h3>Failed Login Delay Protection</h3>

        <p>
            <strong>
                Đây là khu vực Exponential Backoff.
            </strong>
        </p>

        <p>
            Username:
            <strong>{username}</strong>
        </p>

        <p>
            Failed Attempts:
            <strong>{failed_attempts}</strong>
        </p>

        {remaining_html}

        <p>
            Current / Remaining Delay:
            <strong>{delay} seconds</strong>
        </p>

        <pre>
Exponential Backoff:
2s -> 4s -> 8s -> 16s -> ...

Password càng sai nhiều lần
        |
        v
Thời gian chờ càng tăng
        </pre>
    </fieldset>
    """


def login_form_html(
    action,
    heading,
    client_ip
):
    used, remaining, reset_after = get_rate_limit_status(
        client_ip
    )

    return f"""
    <html>

        <head>
            <meta charset="utf-8">
            <title>{heading}</title>
        </head>

        <body>

            <h1>{heading}</h1>

            <p>
                Trang này dùng HTML thuần để demo rõ
                Rate Limit và Exponential Backoff.
            </p>

            <hr>

            <h2>Security Protection Status</h2>

            {rate_limit_html(
                client_ip,
                used,
                remaining,
                reset_after
            )}

            <br>

            {backoff_general_html()}

            <hr>

            <h2>Login Form</h2>

            <form
                action="{action}"
                method="post"
            >

                <label>Username</label>

                <br>

                <input
                    name="username"
                    type="text"
                    required
                >

                <br><br>

                <label>Password</label>

                <br>

                <input
                    name="password"
                    type="password"
                    required
                >

                <br><br>

                <button type="submit">
                    Login
                </button>

            </form>

            <br>

            <a href="/">
                Back to Home
            </a>

        </body>

    </html>
    """


def rate_limit_block_page(
    client_ip,
    retry_after,
    used
):
    remaining = 0

    return HTMLResponse(
        f"""
        <html>

            <head>
                <meta charset="utf-8">
                <title>Rate Limit Triggered</title>
            </head>

            <body>

                <h1>
                    429 - Too Many Requests
                </h1>

                {rate_limit_html(
                    client_ip,
                    used,
                    remaining,
                    retry_after,
                    title="RATE LIMIT - ACTIVE"
                )}

                <br>

                <fieldset>
                    <legend>
                        <strong>
                            EXPONENTIAL BACKOFF
                        </strong>
                    </legend>

                    <p>
                        Đây là khu vực Exponential Backoff.
                    </p>

                    <p>
                        Tuy nhiên request này đã bị
                        <strong>Rate Limit chặn trước</strong>,
                        nên hệ thống chưa cần kiểm tra
                        Exponential Backoff.
                    </p>
                </fieldset>

                <br>

                <a href="/login-form">
                    Session Login
                </a>

                <br><br>

                <a href="/jwt-login-form">
                    JWT Login
                </a>

            </body>

        </html>
        """,
        status_code=429,
        headers={
            "Retry-After": str(retry_after)
        }
    )


def backoff_block_page(
    username,
    retry_after,
    failed_attempts,
    client_ip,
    rate_used
):
    rate_remaining = max(
        RATE_LIMIT_REQUESTS - rate_used,
        0
    )

    _, _, reset_after = get_rate_limit_status(
        client_ip
    )

    return HTMLResponse(
        f"""
        <html>

            <head>
                <meta charset="utf-8">
                <title>Exponential Backoff Active</title>
            </head>

            <body>

                <h1>
                    Login Temporarily Delayed
                </h1>

                {backoff_status_html(
                    username,
                    failed_attempts,
                    retry_after
                )}

                <br>

                {rate_limit_html(
                    client_ip,
                    rate_used,
                    rate_remaining,
                    reset_after
                )}

                <br>

                <p>
                    <strong>Phân biệt:</strong>
                </p>

                <pre>
Exponential Backoff
= kiểm soát thời gian chờ theo username / login fail

Rate Limit
= kiểm soát số request theo IP
                </pre>

                <a href="/login-form">
                    Back to Session Login
                </a>

            </body>

        </html>
        """,
        status_code=429,
        headers={
            "Retry-After": str(retry_after)
        }
    )


def wrong_password_page(
    username,
    failed_attempts,
    remaining_attempts,
    delay,
    client_ip,
    rate_used
):
    rate_remaining = max(
        RATE_LIMIT_REQUESTS - rate_used,
        0
    )

    _, _, reset_after = get_rate_limit_status(
        client_ip
    )

    return HTMLResponse(
        f"""
        <html>

            <head>
                <meta charset="utf-8">
                <title>Login Failed</title>
            </head>

            <body>

                <h1>
                    401 - Unauthorized
                </h1>

                <p>
                    Incorrect password.
                </p>

                <hr>

                {backoff_status_html(
                    username,
                    failed_attempts,
                    delay,
                    remaining_attempts
                )}

                <br>

                {rate_limit_html(
                    client_ip,
                    rate_used,
                    rate_remaining,
                    reset_after
                )}

                <hr>

                <h2>
                    Hai cơ chế khác nhau như thế nào?
                </h2>

                <pre>
EXPONENTIAL BACKOFF
- Theo username / lần login sai
- Sai càng nhiều -> chờ càng lâu
- Ví dụ: 2s -> 4s -> 8s -> 16s


RATE LIMIT
- Theo IP / số request
- Gửi quá nhiều request -> bị chặn
- Ví dụ: 5 requests / 60 seconds
                </pre>

                <form
                    action="/login-form"
                    method="get"
                >
                    <button type="submit">
                        Try Again
                    </button>
                </form>

            </body>

        </html>
        """,
        status_code=401,
        headers={
            "Retry-After": str(delay)
        }
    )


def account_locked_page(
    username,
    failed_attempts,
    client_ip,
    rate_used
):
    rate_remaining = max(
        RATE_LIMIT_REQUESTS - rate_used,
        0
    )

    _, _, reset_after = get_rate_limit_status(
        client_ip
    )

    return HTMLResponse(
        f"""
        <html>

            <head>
                <meta charset="utf-8">
                <title>Account Locked</title>
            </head>

            <body>

                <h1>
                    423 - Account Locked
                </h1>

                <fieldset>
                    <legend>
                        <strong>
                            ACCOUNT LOCK
                        </strong>
                    </legend>

                    <p>
                        Username:
                        <strong>{username}</strong>
                    </p>

                    <p>
                        Failed Login Attempts:
                        <strong>{failed_attempts}</strong>
                    </p>

                    <p>
                        Tài khoản đã đạt giới hạn
                        {MAX_LOGIN_FAIL} lần login sai.
                    </p>
                </fieldset>

                <br>

                <fieldset>
                    <legend>
                        <strong>
                            EXPONENTIAL BACKOFF
                        </strong>
                    </legend>

                    <p>
                        Đây là khu vực Exponential Backoff.
                    </p>

                    <p>
                        Trước khi account bị khóa,
                        thời gian chờ đã tăng theo:
                    </p>

                    <pre>
2s -> 4s -> 8s -> 16s
                    </pre>
                </fieldset>

                <br>

                {rate_limit_html(
                    client_ip,
                    rate_used,
                    rate_remaining,
                    reset_after
                )}

            </body>

        </html>
        """,
        status_code=423
    )


# =========================================================
# SHARED LOGIN SECURITY PROCESS
# =========================================================

def process_login_security(
    request: Request,
    username: str,
    password: str
):
    client_ip = request.client.host

    # -----------------------------------------------------
    # STEP 1: RATE LIMIT
    # Rate Limit được kiểm tra đầu tiên.
    # -----------------------------------------------------

    allowed, retry_after, rate_used = check_rate_limit(
        client_ip
    )

    if not allowed:
        return {
            "success": False,
            "response": rate_limit_block_page(
                client_ip,
                retry_after,
                rate_used
            )
        }

    # -----------------------------------------------------
    # STEP 2: CHECK USER
    # -----------------------------------------------------

    customer = find_user(username)

    if customer is None:
        return {
            "success": False,
            "response": HTMLResponse(
                f"""
                <html>

                    <head>
                        <meta charset="utf-8">
                        <title>User Not Found</title>
                    </head>

                    <body>

                        <h1>
                            404 - User Not Found
                        </h1>

                        <p>
                            Username does not exist.
                        </p>

                        <hr>

                        <fieldset>
                            <legend>
                                <strong>
                                    RATE LIMIT
                                </strong>
                            </legend>

                            <p>
                                Request này vẫn được tính
                                vào Rate Limit theo IP.
                            </p>

                            <p>
                                Current Requests:
                                <strong>
                                    {rate_used}
                                    /
                                    {RATE_LIMIT_REQUESTS}
                                </strong>
                            </p>
                        </fieldset>

                        <br>

                        <fieldset>
                            <legend>
                                <strong>
                                    EXPONENTIAL BACKOFF
                                </strong>
                            </legend>

                            <p>
                                Backoff chưa được áp dụng
                                vì username không tồn tại.
                            </p>
                        </fieldset>

                        <br>

                        <a href="/login-form">
                            Try Again
                        </a>

                    </body>

                </html>
                """,
                status_code=404
            )
        }

    # -----------------------------------------------------
    # STEP 3: ACCOUNT LOCK
    # -----------------------------------------------------

    if username in locked_users:
        failed_attempts = count.get(
            username,
            MAX_LOGIN_FAIL
        )

        return {
            "success": False,
            "response": account_locked_page(
                username,
                failed_attempts,
                client_ip,
                rate_used
            )
        }

    # -----------------------------------------------------
    # STEP 4: EXPONENTIAL BACKOFF
    # -----------------------------------------------------

    failed_attempts, backoff_retry_after = (
        get_backoff_status(username)
    )

    if backoff_retry_after > 0:
        return {
            "success": False,
            "response": backoff_block_page(
                username,
                backoff_retry_after,
                failed_attempts,
                client_ip,
                rate_used
            )
        }

    # -----------------------------------------------------
    # STEP 5: CHECK PASSWORD
    # -----------------------------------------------------

    database_password = customer[2]

    if password != database_password:
        result = register_failed_login(
            username
        )

        if result["locked"]:
            return {
                "success": False,
                "response": account_locked_page(
                    username,
                    result["failed_attempts"],
                    client_ip,
                    rate_used
                )
            }

        return {
            "success": False,
            "response": wrong_password_page(
                username,
                result["failed_attempts"],
                result["remaining"],
                result["delay"],
                client_ip,
                rate_used
            )
        }

    # -----------------------------------------------------
    # STEP 6: LOGIN SUCCESS
    # -----------------------------------------------------

    reset_login_security(username)

    return {
        "success": True,
        "username": username,
        "client_ip": client_ip,
        "rate_used": rate_used
    }


# =========================================================
# HOME
# =========================================================

@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse("""
    <html>

        <head>
            <meta charset="utf-8">
            <title>Authentication Demo</title>
        </head>

        <body>

            <h1>
                Authentication Security Demo
            </h1>

            <p>
                Project demo:
            </p>

            <ul>
                <li>Session ID Authentication</li>
                <li>JWT Authentication</li>
                <li>Rate Limit</li>
                <li>Exponential Backoff</li>
                <li>Account Lock</li>
            </ul>

            <hr>

            <h2>
                Session Authentication
            </h2>

            <a href="/login-form">
                Login using Session
            </a>

            <br><br>

            <h2>
                JWT Authentication
            </h2>

            <a href="/jwt-login-form">
                Login using JWT
            </a>

        </body>

    </html>
    """)


# =========================================================
# SESSION LOGIN
# =========================================================

@app.get(
    "/login-form",
    response_class=HTMLResponse
)
def login_form(request: Request):
    client_ip = request.client.host

    return HTMLResponse(
        login_form_html(
            "/login",
            "Session Login",
            client_ip
        )
    )


@app.post(
    "/login",
    response_class=HTMLResponse
)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    result = process_login_security(
        request,
        username,
        password
    )

    if not result["success"]:
        return result["response"]

    session_id = create_session(username)

    response = RedirectResponse(
        url="/profile",
        status_code=303
    )

    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax"
    )

    return response


@app.get(
    "/profile",
    response_class=HTMLResponse
)
def profile(request: Request):
    session = get_session(request)

    if not session:
        return RedirectResponse(
            url="/login-form",
            status_code=303
        )

    username = session["username"]

    return HTMLResponse(
        f"""
        <html>

            <head>
                <meta charset="utf-8">
                <title>Session Profile</title>
            </head>

            <body>

                <h1>
                    Session Authentication
                </h1>

                <p>
                    Login success:
                    <strong>{username}</strong>
                </p>

                <p>
                    Exponential Backoff counter
                    đã được reset sau khi login thành công.
                </p>

                <p>
                    Rate Limit vẫn hoạt động theo IP
                    và time window.
                </p>

                <form
                    action="/logout"
                    method="post"
                >
                    <button type="submit">
                        Logout
                    </button>
                </form>

                <br>

                <a href="/">
                    Home
                </a>

            </body>

        </html>
        """
    )


@app.post("/logout")
def logout(request: Request):
    session_id = request.cookies.get(
        "session_id"
    )

    if session_id:
        sessions.pop(
            session_id,
            None
        )

    response = RedirectResponse(
        url="/login-form",
        status_code=303
    )

    response.delete_cookie(
        "session_id"
    )

    return response


# =========================================================
# JWT LOGIN
# =========================================================

@app.get(
    "/jwt-login-form",
    response_class=HTMLResponse
)
def jwt_login_form(request: Request):
    client_ip = request.client.host

    return HTMLResponse(
        login_form_html(
            "/jwt-login",
            "JWT Login",
            client_ip
        )
    )


@app.post("/jwt-login")
def jwt_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    result = process_login_security(
        request,
        username,
        password
    )

    if not result["success"]:
        return result["response"]

    token = create_jwt(username)

    response = RedirectResponse(
        url="/jwt-profile",
        status_code=303
    )

    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax"
    )

    return response


@app.get(
    "/jwt-profile",
    response_class=HTMLResponse
)
def jwt_profile(request: Request):
    token = request.cookies.get(
        "access_token"
    )

    if not token:
        return RedirectResponse(
            url="/jwt-login-form",
            status_code=303
        )

    payload = verify_jwt(token)

    if not payload:
        return RedirectResponse(
            url="/jwt-login-form",
            status_code=303
        )

    username = payload["sub"]

    return HTMLResponse(
        f"""
        <html>

            <head>
                <meta charset="utf-8">
                <title>JWT Profile</title>
            </head>

            <body>

                <h1>
                    JWT Authentication
                </h1>

                <p>
                    Login success:
                    <strong>{username}</strong>
                </p>

                <p>
                    JWT hợp lệ và chưa hết hạn.
                </p>

                <p>
                    Exponential Backoff counter
                    đã được reset sau khi login thành công.
                </p>

                <form
                    action="/jwt-logout"
                    method="post"
                >
                    <button type="submit">
                        Logout
                    </button>
                </form>

                <br>

                <a href="/">
                    Home
                </a>

            </body>

        </html>
        """
    )


@app.post("/jwt-logout")
def jwt_logout():
    response = RedirectResponse(
        url="/jwt-login-form",
        status_code=303
    )

    response.delete_cookie(
        "access_token"
    )

    return response


# =========================================================
# USER LIST
# =========================================================

@app.get(
    "/users",
    response_class=HTMLResponse
)
def user_list():
    connect = sqlite3.connect(
        f"{db_name}.db"
    )

    cursor = connect.cursor()

    cursor.execute("""
        SELECT id, username
        FROM customers
    """)

    users = cursor.fetchall()

    connect.close()

    rows = ""

    for user in users:
        rows += f"""
        <tr>
            <td>{user[0]}</td>
            <td>{user[1]}</td>
        </tr>
        """

    return HTMLResponse(
        f"""
        <html>

            <head>
                <meta charset="utf-8">
                <title>User List</title>
            </head>

            <body>

                <h1>
                    User List
                </h1>

                <table border="1">

                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                    </tr>

                    {rows}

                </table>

                <br>

                <a href="/">
                    Home
                </a>

            </body>

        </html>
        """
    )


# =========================================================
# RUN SERVER
# =========================================================

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000
    )
