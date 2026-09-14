from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse
import uvicorn 
from fastapi import Form
import sqlite3
db_name = "database"
def create_database():
    connect = sqlite3.connect(f"{db_name}.db")
    cursor = connect.cursor()
    cursor.execute("""create table if not exists customers(id integer primary key, username text not null, password text unique not null)""")
    cursor.executemany("""insert into customers(username, password) values(?, ?)""",
                       [("admin", "admin123"),
                        ("user", "user123"),
                        ("staff", "staff123")])
    connect.commit()
    cursor.close()

app = FastAPI(title="user_demo")
create_database()
@app.get("/ping")
def ping():
    return "pong"

@app.get("/login-form",response_class=HTMLResponse) 
def login_form():
    return HTMLResponse("""
    <html>
        <head>
        <meta charset="utf-8">
        </head>
        <body>
            <form>
                <label for="username">Username</label>
                </br>
                <input name="username" type="text">
                </br>
                <label for="password">Password</label>
                </br>
                <input name="password" type="text">
                </br>
                <form action="/login" method="post">
                <button type="submit">Login</button>
                </form>
            </form>
        </body>
    </html>""")
@app.post("/login", response_class=HTMLResponse)
def login(
    username : str = Form(...),
    password : str = Form(...)
):
    connect2 = sqlite3.connect(f"{db_name}.db")
    cursor = connect2.cursor()
    cursor.execute("""select username from customers where username = ? and password = ?""", (username, password))
    customer = cursor.fetchone()
    connect2.close()
    if customer:
        return HTMLResponse("""
        <html>
            <head>
                <meta charset="utf-8">
            </head>
            <body>
                <p>Success</p>
                <form action="/logout" method="post">
                <button type="Submit">Logout</button>
                </form>
            </body>
        </html>        
""")
    else:
        return HTMLResponse("""
            <html>
                <head>
                    <meta charset="utf-8">
                </head>
            <body>
                <p>Fail</p>
                <form action="/logout" method="post">
                <button type="Submit">Try again</button>
                </form>
            </body>
            </html>
        """)

@app.post("/logout")
def log_out():
    return RedirectResponse(
        url="/login-form"
    )
@app.get("/", response_class=HTMLResponse)
def user_list():
    connect3 = sqlite3.connect(f"{db_name}.db")
    cursor = connect3.cursor()
    cursor.execute("""select id, username from customers""")
    users = cursor.fetchall()
    connect3.close()
    rows = ""
    for user in users:
        rows += f"""
     <tr>
            <td>{user[0]}</td>
            <td>{user[1]}</td>
    </tr>"""
    return HTMLResponse(f"""
        <html>
            <head>
                <meta charset="utf-8">
            </head>
            <body>
                <table>
                {rows}
                </table>
            </body>
        </html>
""")
if __name__ == "__main__":
    uvicorn.run(
        app=app,
        port=8080
        
    )

    