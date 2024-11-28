from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
# from functions import ...

# configure app
app = Flask(__name__)

# Configuration for SQLite-database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///packetTracer.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialise database extension
db = SQLAlchemy(app)

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.secret_key = 'secret_key_here'

# Initialize session extension
Session(app)

# register account
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # local variables
        username = request.form.get("username")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        mailAddress = request.form.get("mailAddress")
        mailPassword = request.form.get("mailPassword")
        
        # check for username input
        if not username:
            flash("Enter a username")
            return render_template("register.html")
        # check if username already exists in db
        check = db.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", username)
        if len(check) > 0:
            flash("Username already exists")
            return render_template("register.html") 
        # check for password input
        if not request.form.get("password"):
            flash("Enter a password")
            return render_template("register.html")
        # check if check password matches
        if password1 != password2:
            flash("Passwords don't match")
            return render_template("register.html")
        # hash account and mail passwords
        accountHash = generate_password_hash(password1)
        mailHash = generate_password_hash(mailPassword)
        # update db with new user data
        db.execute("INSERT INTO users (username, loginHash, mailAddress, mailHash) VALUES (?, ?, ?, ?)", username, accountHash, mailAddress, mailHash)
        # after succesfull register, redirect to login
        return redirect("/login")

    else:
        render_template("register.html")


# login
@app.route("/login", methods=["GET", "POST"])
def login():
    # clear session from previous visit
    session.clear()

    if request.method == "POST":
        # validate form input
        if not request.form.get("username"):
            flash("must provide username")
            return render_template("login.html")

        if not request.form.get("password"):
            flash("must provide password")
            return render_template("login.html")

        # Query db for username 
        try: 
            rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        except Exception as e:
            flash("failed querying database")
            print(f"Databasefout: {e}")
            rows = []
            return render_template("login.html")

        # validate username
        if len(rows) == 0:
            flash("invalid username")
            return render_template("login.html")

        # validate password
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("password incorrect")
            return render_template("login.html")

        # update session
        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]

        # redirect to homepage
        flash(f"Welcome back {rows[0]['username']}")
        return redirect("/")

    # user reached route with GET
    else:
        return render_template("login.html")


# homepage
@app.route("/")
def index(): 
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)


# logout

# history





