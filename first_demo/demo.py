from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import sqlite3
import uvicorn
db_name = "new_database"
def create_db():
    connect = sqlite3.connect(f"{db_name}.db")
    cursor = connect.cursor()
    cursor.execute("""create table if not exists users (id integer primary key, username text unique, password text not null)""")
    cursor.executemany("""
        INSERT OR IGNORE INTO users(username, password) VALUES(?, ?)
    """, [
        ("admin123", "admin"),
        ("user456", "user")
    ])
    connect.commit()
    cursor.close()

app = FastAPI(title="iaw301_webapp")


@app.get("/", response_class=HTMLResponse)
def get_log_in():
    return HTMLResponse("""
    <html>
        <head>
            <meta charset="utf-8>
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
                <button type="submit">Submit</button>
            </form>
        </body>
    </html>""")
@app.post("/login")
def submit():
    return "Registered"
if __name__ == "__main__":
    uvicorn.run(
        app=app,
        port=80
    )