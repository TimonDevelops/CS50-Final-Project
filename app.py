from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from functions import login_required

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
        checkUsername = db.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", username)
        if len(checkUsername) > 0:
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
        # check if mailaddress already exists in db
        checkUserMail = db.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", mailAddress)
        if len(checkUserMail) > 0:
            flash("Mail adress already exists")
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

# logout
app.route("/logout")
def logout():
        # clear session from user info
        session.clear()
        flash("Logged out")
        # redirect user to homepage
        redirect("/")

# user page (contains user panel and extra user information, settings to change mail or color theme etc..)
app.route("/user", methods=["GET", "POST"])
@login_required
def user():
    userID = session["user_id"]
    # db query for user info
    currentMail = db.execute("SELECT mailAddress FROM users wherer id = ?", userID)

    if request.method == "POST":
    # update db(button to change), new email, new email password or new account password

        # check for unique email and update if so
        newMailAddress = request.form.get("newMailSetting", "").strip
        if newMailAddress:
            checkUserMail = db.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", newMailAddress)
            if len(checkUserMail) > 0:
                flash("Mail adress already exists")
                return render_template("user.html") 
            db.execute("UPDATE users SET mailAddress = ? WHERE id = ?", newMailAddress, userID)
        # update mail password
        newMailPassword = request.form.get("newMailPassword").strip
        if newMailPassword:
            hash = generate_password_hash(newMailPassword)
            db.execute("UPDATE users SET mailHash = ? WHERE id = ?", hash, userID )
       # fill in recent password as security measure
        filledAccountPassword = request.form.get("filledAccountPassword")
        trueAccountPassword = db.execute("SELECT loginHash FROM users WHERE id = ?", userID)
        if not check_password_hash(trueAccountPassword[0]["loginHash"], filledAccountPassword):
            flash("Password incorrect")
            return render_template("user.html")
         # check if new passwords match
        newAccountPassword1 = request.form.get("newMailPassword1")
        newAccountPassword2 = request.form.get("newMailPassword2")
        if newAccountPassword1 != newAccountPassword2:
            flash("Passwords don't match")
            return render_template("user.html")
        hash = generate_password_hash(newAccountPassword1)
        db.execute("UPDATE users SET loginhash = ? WHERE id = ?", hash, userID)

    else: 
        return render_template("user.html", currentMail=currentMail[0]["mailAddress"])

# usage, showcases tabels of all live package information
@login_required()


# homepage(contains app information, updates, regular information, main page with login/registration button etc)
@app.route("/")
def index(): 
    # if logged in, then show only logout button in navbar
    # if logged out, then show only login and register button in navbar
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)









