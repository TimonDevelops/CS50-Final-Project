from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functions import login_required, is_logged_in, dbChange, dbRead, ttUpdateDB #, ttMainFunction
import re

# configure app
app = Flask(__name__)

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
        # local variables, mail adress and mail password are not required at register
        username = request.form.get("username")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        mailAddress = request.form.get("mailAddress")
        mailPassword = request.form.get("mailPassword")
        
        # check for username input
        if not username:
            flash("Enter a username", "error")
            return redirect("/register")
        # check if username already exists in db
        checkUsername = dbRead("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (username,))
        if checkUsername:
            flash("Username already exists", "error")
            return redirect("/register") 
        # check for password input
        if not password1 or not password2:
            flash("Enter a account password", "error")
            return redirect("/register")
        
        # check if account password matches
        if password1 != password2:
            flash("Account passwords don't match", "error")
            return redirect("/register")

        # check if mailaddress already exists in db
        checkUserMail = dbRead("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (mailAddress,))
        if checkUserMail:
            flash("Mail adress already exists", "error")
            return redirect("/register") 
        
        # hash account and mail passwords
        accountHash = generate_password_hash(password1)
        mailHash = generate_password_hash(mailPassword)
        # update db with new dashboard data
        dbChange("INSERT INTO users (username, loginHash, mailAddress, mailHash) VALUES (?, ?, ?, ?)", (username, accountHash, mailAddress, mailHash))
        # store mailPassword in db to login mail(encrypt this in updated version)
        dbChange("UPDATE users SET mailPassword = ? WHERE username = ?", (mailPassword, username))
        # after succesfull register, redirect to login
        return redirect("/login")

    else:
        return render_template("register.html", is_logged_in=is_logged_in())

# login
@app.route("/login", methods=["GET", "POST"])
def login():
    # clear session from previous visit, but preserve potential flash messages
    flashes = session.get("_flashes", [])
    session.clear()
    session["_flashes"] = flashes
    username = request.form.get("username")
    password = request.form.get("password")

    if request.method == "POST":
        # validate form input
        if not username:
            flash("Must provide username", "error")
            return redirect("/login")

        if not password:
            flash("Must provide password", "error")
            return redirect("/login")

        # Validate and query db for username and related data
        rows = dbRead("SELECT * FROM users WHERE username = ?", (username,))
        if len(rows) != 1:
            flash("Invalid username", "error")
            return redirect("/login")

        # validate password
        if not check_password_hash(rows[0]["loginHash"], password):
            flash("Password incorrect", "error")
            return redirect("/login")

        # update session
        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]
        userID = session["user_id"]

        ##### update in new version #####
        # # update db with latest tt code information
        # userID = session["user_id"]
        # ttMainFunction(userID)

        # redirect to homepage
        flash(f"Welcome back {rows[0]['username']}", "succes")
        return redirect("/")

    # dashboard reached route with GET
    else:
        return render_template("login.html", is_logged_in=is_logged_in())

# logout
@app.route("/logout")
@login_required
def logout():
        # clear session and route to homepage
        session.clear()
        flash("Logged out", "succes")
        return redirect("/")

# dashboard page for account information and changes
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    userID = session["user_id"]
    # db query for dashboard info
    currentMail = dbRead("SELECT mailAddress FROM users where id = ?", (userID,))

    if request.method == "POST":
    # update db(button to change), new email, new email password or new account password

        # check for unique email and update if so
        newMailAddress = request.form.get("newMailAddress")
        if newMailAddress:
            newMailAddress = request.form.get("newMailAddress").strip()
            checkUserMail = dbRead("SELECT id FROM users WHERE LOWER(mailAddress) = LOWER(?)", (newMailAddress,))
            if len(checkUserMail) > 0:
                flash("Mail adress already exists", "error")
                return redirect("/dashboard") 
            dbChange("UPDATE users SET mailAddress = ? WHERE id = ?", (newMailAddress, userID))
        # update mail password
        newMailPassword = request.form.get("newMailPassword")
        if newMailPassword:
            newMailPassword = request.form.get("newMailPassword").strip()
            hash = generate_password_hash(newMailPassword)
            dbChange("UPDATE users SET mailHash = ?, mailPassword = ? WHERE id = ?", (hash, newMailPassword, userID))
       # fill in recent password as security measure
        filledAccountPassword = request.form.get("filledAccountPassword")
        trueAccountPassword = dbRead("SELECT loginHash FROM users WHERE id = ?", (userID,))
        if filledAccountPassword:
            if not check_password_hash(trueAccountPassword[0]["loginHash"], filledAccountPassword):
                flash("Password incorrect", "error")
                return redirect("/dashboard")
         # check if new passwords match
        newAccountPassword1 = request.form.get("newMailPassword1")
        newAccountPassword2 = request.form.get("newMailPassword2")
        if newAccountPassword1:
            if newAccountPassword1 != newAccountPassword2:
                flash("Passwords don't match", "error")
                return redirect("/dashboard")
            hash = generate_password_hash(newAccountPassword1)
            dbChange("UPDATE users SET loginHash = ? WHERE id = ?", (hash, userID))

        # redirect after all changes are checked
        flash("Credentials succesfully changed")
        return redirect("/dashboard")

    else: 
        return render_template("dashboard.html", currentMail=currentMail[0]["mailAddress"], is_logged_in=is_logged_in())

# usage, showcases tables of all live package information
@app.route("/ttInfo", methods=["GET", "POST"])
@login_required
def usage():
    userID = session["user_id"]
    # tt info rows
    rows = dbRead("SELECT ttStatus, ttTimestamp, itemDescription, ttCode FROM ttInfo WHERE userID = ?", (userID,))
    if request.method == "POST":
        # track and trace code is inserted manualy
        ttCode = request.form.get("ttManual")
        pattern = r"[A-Za-z]{3,4}\d{20,21}" # DHL Express
        # check if tt code is legit
        if re.match(pattern, ttCode):
            # check if already in db
            check = dbRead("SELECT 1 FROM ttInfo WHERE ttCode = ?", (ttCode,))
            if not check:
                itemDescription = request.form.get("itemDescription", "DHL package")
                # update db with new tt code data
                ttUpdateDB(ttCode, userID)
                # set default description into manually added description
                dbChange("UPDATE ttInfo SET itemDescription = ? WHERE ttCode = ?", (itemDescription, ttCode))
                return redirect("/ttInfo")
            else:
                flash("Track and Trace code already in use")
                return redirect("/ttInfo") 
        else:
            flash("No valid DHL Express Track and Trace code")
            return redirect("/ttInfo")
    else:
        # create tables with API
        return render_template("ttInfo.html", rows=rows, is_logged_in=is_logged_in())

# homepage(contains app information, updates, regular information, main page with login/registration button etc)
@app.route("/")
def index(): 
    # if logged in, show only logout button in navbar, else show only login and register button in navbar
    return render_template("index.html", is_logged_in=is_logged_in())

if __name__ == "__main__":
    app.run(debug=True)









