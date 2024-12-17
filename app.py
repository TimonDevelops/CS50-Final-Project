from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functions import login_required, is_logged_in, dbChange, dbRead, ttInfo

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
        # local variables, mail adress and mailpassword are not required at register
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
        if len(checkUsername) > 0:
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
        if len(checkUserMail) > 0:
            flash("Mail adress already exists", "error")
            return redirect("/register") 
        
        # hash account and mail passwords
        accountHash = generate_password_hash(password1)
        mailHash = generate_password_hash(mailPassword)
        # update db with new dashboard data
        dbChange("INSERT INTO users (username, loginHash, mailAddress, mailHash) VALUES (?, ?, ?, ?)", (username, accountHash, mailAddress, mailHash))
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
        # clear session from dashboard info and clear g
        session.clear()
        flash("Logged out", "succes")
        # redirect dashboard to homepage
        return redirect("/")

# dashboard page (contains dashboard panel and extra dashboard information, how to set up mail/proxy settings imap, settings to change (proxy)mail or color theme etc..)
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
            dbChange("UPDATE users SET mailHash = ? WHERE id = ?", (hash, userID))
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
            dbChange("UPDATE users SET loginhash = ? WHERE id = ?", (hash, userID))

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
    rows = dbRead("SELECT ttStatus, ttTimestamp, itemDescription, ttCode FROM ttInfo WHERE userID = ?",  (userID,))
    if request.method == "POST":
        # track and trace code is inserted manualy
        userID = session["user_id"]
        ttCode = request.form.get("ttManual")
        # if tt code is legit, then update db with correct tt code and other data
        ttRequest = ttInfo(ttCode)
        if ttRequest:
            ttData = ttRequest["shipments"][0]
            ttStatusData = ttData["status"]
            ttTimeStamp = ttStatusData["timestamp"]
            ttStatus = ttStatusData["description"]
            itemDescription = request.form.get("itemDescription")
            try:
                dbChange("INSERT INTO ttInfo (userID, ttCode, ttTimestamp, ttStatus, itemDescription) VALUES (?, ?, ?, ?, ?)", (userID, ttCode, ttTimeStamp, ttStatus, itemDescription))
            except Exception as e:
                print(f"Error: {e}")

        ############
        return redirect("/ttInfo")
    # db info to make row with
    else:
        # create tables with API
        return render_template("ttInfo.html", rows=rows, is_logged_in=is_logged_in())

# homepage(contains app information, updates, regular information, main page with login/registration button etc)
@app.route("/")
def index(): 
    # if logged in, then show only logout button in navbar, else show only login and register button in navbar
    return render_template("index.html", is_logged_in=is_logged_in())

if __name__ == "__main__":
    app.run(debug=True)









