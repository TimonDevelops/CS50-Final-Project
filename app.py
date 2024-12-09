from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functions import login_required, is_logged_in
import sqlite3

# configure app
app = Flask(__name__)

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.secret_key = 'secret_key_here'

# Initialize session extension
Session(app)

# Connect with db and create cursor
dbConnection = sqlite3.connect("packageTracker.db")
db = dbConnection.cursor()

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
            flash("Enter a username", "error")
            return render_template("register.html")
        # check if username already exists in db
        checkUsername = db.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", username,)
        if len(checkUsername) > 0:
            flash("Username already exists", "error")
            return render_template("register.html") 
        # check for password input
        if not request.form.get("password"):
            flash("Enter a password", "error")
            return render_template("register.html")
        # check if check password matches
        if password1 != password2:
            flash("Passwords don't match", "error")
            return render_template("register.html")

        # check if mailaddress already exists in db
        checkUserMail = db.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", mailAddress,)
        if len(checkUserMail) > 0:
            flash("Mail adress already exists", "error")
            return render_template("register.html") 
        # hash account and mail passwords
        accountHash = generate_password_hash(password1)
        mailHash = generate_password_hash(mailPassword)
        # update db with new dashboard data
        db.execute("INSERT INTO users (username, loginHash, mailAddress, mailHash) VALUES (?, ?, ?, ?)", username, accountHash, mailAddress, mailHash)
        # after succesfull register, redirect to login
        return redirect("/login")

    else:
        return render_template("register.html")

# login
@app.route("/login", methods=["GET", "POST"])
def login():
    # clear session from previous visit, but preserve potential flash messages
    flashes = session.get("_flashes", [])
    session.clear()
    session["_flashes"] = flashes

    if request.method == "POST":
        # validate form input
        if not request.form.get("username"):
            flash("Must provide username", "error")
            return redirect("/login")

        if not request.form.get("password"):
            flash("Must provide password", "error")
            return redirect("/login")

        # Validate and query db for username and related data
        try: 
            rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"),)
        except Exception as e:
            flash("Invalid username", "error")
            print(f"Databasefout: {e}")
            rows = []
            return redirect("/login")

        # validate password
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Password incorrect", "error")
            return redirect("/login")

        # update session
        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]

        # redirect to homepage
        flash(f"Welcome back {rows[0]['username']}", "succes")
        return redirect("/")

    # dashboard reached route with GET
    else:
        return render_template("login.html")

# logout
@app.route("/logout")
@login_required
def logout():
        # clear session from dashboard info
        flash("Logged out", "succes")
        session.clear()
        # redirect dashboard to homepage
        return redirect("/")

# dashboard page (contains dashboard panel and extra dashboard information, how to set up mail/proxy settings imap, settings to change (proxy)mail or color theme etc..)
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    userID = session["user_id"]
    # db query for dashboard info
    currentMail = db.execute("SELECT mailAddress FROM users wherer id = ?", userID,)

    if request.method == "POST":
    # update db(button to change), new email, new email password or new account password

        # check for unique email and update if so
        newMailAddress = request.form.get("newMailSetting", "").strip
        if newMailAddress:
            checkUserMail = db.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", newMailAddress,)
            if len(checkUserMail) > 0:
                flash("Mail adress already exists", "error")
                return render_template("dashboard.html") 
            db.execute("UPDATE users SET mailAddress = ? WHERE id = ?", newMailAddress, userID)
        # update mail password
        newMailPassword = request.form.get("newMailPassword").strip
        if newMailPassword:
            hash = generate_password_hash(newMailPassword)
            db.execute("UPDATE users SET mailHash = ? WHERE id = ?", hash, userID )
       # fill in recent password as security measure
        filledAccountPassword = request.form.get("filledAccountPassword")
        trueAccountPassword = db.execute("SELECT loginHash FROM users WHERE id = ?", userID,)
        if not check_password_hash(trueAccountPassword[0]["loginHash"], filledAccountPassword):
            flash("Password incorrect", "error")
            return render_template("dashboard.html")
         # check if new passwords match
        newAccountPassword1 = request.form.get("newMailPassword1")
        newAccountPassword2 = request.form.get("newMailPassword2")
        if newAccountPassword1 != newAccountPassword2:
            flash("Passwords don't match", "error")
            return render_template("dashboard.html")
        hash = generate_password_hash(newAccountPassword1)
        db.execute("UPDATE users SET loginhash = ? WHERE id = ?", hash, userID)

    else: 
        return render_template("dashboard.html", currentMail=currentMail[0]["mailAddress"])

# usage, showcases tables of all live package information
@app.route("/ttInfo", methods=["GET", "POST"])
@login_required
def usage():
    userID = session["user_id"]
    row = db.execute("SELECT * FROM ttInfo WHERE userID = ? ", userID,)
    if request.method == "POST":
        # track and trace code is inserted manualy
        userID = session["user_id"]
        ttCode = request.form.get("ttCode")
        db.execute("INSERT INTO ttCode (userID, ttCode) VALUES (?, ?)", userID, ttCode)
        return redirect("/ttInfo")
    # db info to make row with
    else:
        return render_template("ttInfo.html", ttInfo=row)

# homepage(contains app information, updates, regular information, main page with login/registration button etc)
@app.route("/")
def index(): 
    # if logged in, then show only logout button in navbar, else show only login and register button in navbar
    return render_template("index.html", is_logged_in=is_logged_in())

if __name__ == "__main__":
    app.run(debug=True)









