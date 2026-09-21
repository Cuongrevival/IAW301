from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
import uvicorn
import sqlite3

# JWT
import json
import base64
import hmac
import hashlib
import time

# Session
import secrets


db_name = "database"

app = FastAPI(title="user_demo")


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

    users = [
        ("admin", "admin123"),
        ("user", "user123"),
        ("staff", "staff123")
    ]

    for username, password in users:
        cursor.execute("""
            INSERT OR IGNORE INTO customers(username, password)
            VALUES(?, ?)
        """, (username, password))

    connect.commit()
    connect.close()


create_database()


def authenticate_user(username, password):

    connect = sqlite3.connect(f"{db_name}.db")
    cursor = connect.cursor()

    cursor.execute("""
        SELECT id, username
        FROM customers
        WHERE username = ? AND password = ?
    """, (username, password))

    user = cursor.fetchone()

    connect.close()

    return user



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

    token = (
        f"{header_encoded}."
        f"{payload_encoded}."
        f"{signature_encoded}"
    )

    return token


def verify_jwt(token):

    try:

        header_encoded, payload_encoded, signature_encoded = token.split(".")

        message = f"{header_encoded}.{payload_encoded}"

        expected_signature = hmac.new(
            JWT_SECRET.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()

        received_signature = base64url_decode(signature_encoded)

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



@app.get("/", response_class=HTMLResponse)
def home():

    return HTMLResponse("""
    <html>
        <body>

            <h1>Authentication Demo</h1>

            <h2>Session Authentication</h2>

            <a href="/login-form">
                Login using Session
            </a>

            <br><br>

            <h2>JWT Authentication</h2>

            <a href="/jwt-login-form">
                Login using JWT
            </a>

        </body>
    </html>
    """)


@app.get("/login-form", response_class=HTMLResponse)
def login_form():

    return HTMLResponse("""
    <html>
        <body>

            <h1>Session Login</h1>

            <form action="/login" method="post">

                <label>Username</label>
                <br>

                <input
                    name="username"
                    type="text"
                    required
                >

                <br>

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

        </body>
    </html>
    """)
MAX_LOGIN_FAIL = 3

count = {}

locked_users = set()

@app.post("/login", response_class=HTMLResponse)
def login(
    username: str = Form(...),
    password: str = Form(...)
):
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

    customer = cursor.fetchone()

    connect.close()

    if customer is None:

        return HTMLResponse(
            """
            <html>
                <body>

                    <h2>404 - User not found</h2>

                    <form action="/login-form" method="get">
                        <button type="submit">
                            Try again
                        </button>
                    </form>

                </body>
            </html>
            """,
            status_code=404
        )

    if username in locked_users:

        return HTMLResponse(
            """
            <html>
                <body>

                    <h2>423 - Account Locked</h2>

                    <p>
                        Your account has been locked
                        because of too many failed login attempts.
                    </p>

                </body>
            </html>
            """,
            status_code=423
        )

    database_password = customer[2]

    if password != database_password:

        # Nếu user chưa có trong count
        if username not in count:
            count[username] = 0

        # Tăng số lần login sai
        count[username] += 1

        remaining = MAX_LOGIN_FAIL - count[username]


        if count[username] >= MAX_LOGIN_FAIL:

            locked_users.add(username)

            return HTMLResponse(
                f"""
                <html>
                    <body>

                        <h2>423 - Account Locked</h2>

                        <p>
                            Failed login attempts:
                            {count[username]}
                        </p>

                        <p>
                            Account {username}
                            has been locked.
                        </p>

                    </body>
                </html>
                """,
                status_code=423
            )

        # Password sai nhưng chưa bị lock
        return HTMLResponse(
            f"""
            <html>
                <body>

                    <h2>401 - Unauthorized</h2>

                    <p>
                        Incorrect password
                    </p>

                    <p>
                        Failed attempts:
                        {count[username]}
                    </p>

                    <p>
                        Remaining attempts:
                        {remaining}
                    </p>

                    <form action="/login-form" method="get">

                        <button type="submit">
                            Try again
                        </button>

                    </form>

                </body>
            </html>
            """,
            status_code=401
        )

  
    count[username] = 0

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

@app.get("/profile", response_class=HTMLResponse)
def profile(request: Request):

    session = get_session(request)

    if not session:

        return RedirectResponse(
            url="/login-form",
            status_code=303
        )

    username = session["username"]

    return HTMLResponse(f"""
    <html>
        <body>

            <h1>Session Authentication</h1>

            <p>
                Login success:
                {username}
            </p>

            <form action="/logout" method="post">

                <button type="submit">
                    Logout
                </button>

            </form>

        </body>
    </html>
    """)


@app.post("/logout")
def logout(request: Request):

    session_id = request.cookies.get("session_id")

    if session_id:

        sessions.pop(
            session_id,
            None
        )

    response = RedirectResponse(
        url="/login-form",
        status_code=303
    )

    response.delete_cookie("session_id")

    return response



@app.get("/jwt-login-form", response_class=HTMLResponse)
def jwt_login_form():

    return HTMLResponse("""
    <html>

        <body>

            <h1>JWT Login</h1>

            <form action="/jwt-login" method="post">

                <label>
                    Username
                </label>

                <br>

                <input
                    name="username"
                    type="text"
                    required
                >

                <br>

                <label>
                    Password
                </label>

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

        </body>

    </html>
    """)


@app.post("/jwt-login")
def jwt_login(
    username: str = Form(...),
    password: str = Form(...)
):

    user = authenticate_user(
        username,
        password
    )

    if not user:

        return JSONResponse(
            {
                "error": "Invalid username or password"
            },
            status_code=401
        )

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


@app.get("/jwt-profile", response_class=HTMLResponse)
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

    return HTMLResponse(f"""
    <html>

        <body>

            <h1>
                JWT Authentication
            </h1>

            <p>
                Login success:
                {username}
            </p>

            <form
                action="/jwt-logout"
                method="post"
            >

                <button type="submit">
                    Logout
                </button>

            </form>

        </body>

    </html>
    """)


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



@app.get("/users", response_class=HTMLResponse)
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

    return HTMLResponse(f"""
    <html>

        <body>

            <table border="1">

                <tr>
                    <th>ID</th>
                    <th>Username</th>
                </tr>

                {rows}

            </table>

        </body>

    </html>
    """)


if __name__ == "__main__":

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000
    )