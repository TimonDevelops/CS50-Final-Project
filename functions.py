from flask import session
from functools import wraps
from flask import redirect
import sqlite3, requests

# function to check if someone is logged in
def is_logged_in():
    return "user_id" in session

# login required is a decorator that sets decorated_function with f, a function like "user()" is passed true as f to login_required to set decoreated_function with. 
# When app starts, all login_required routes will set their decorated function. 
# When app is running, login_required doesn't run anymore, then the set decorated functions are ready to be activated
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

#db functions
# read - return dictionary type list
def dbRead(query, params=()):
    with sqlite3.connect("packageTracker.db") as db:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
# change - auto commit
def dbChange(query, params=()):
    try:
        with sqlite3.connect("packageTracker.db") as db:
            cursor = db.cursor()
            cursor.execute(query, params)
            db.commit()
        return True
    except sqlite3.Error as e:
        print(F"Database error: {e}")
        return False

# function for DHL API call
# test codes:
# - JVGL06349971001106931267
# - JVGL06290308000728790420

# set url and header
# test
testBase_url = "https://api-test.dhl.com/track/shipments"
headers = {
    "DHL-API-Key" : ""
}
# real
RealBase_url = "https://api-eu.dhl.com/track/shipments"
headers = {
    "DHL-API-Key" : ""
}
# create function
def ttInfo(code):
    url = f"{RealBase_url}?trackingNumber={code}"
    try: 
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            try:
                ttData = response.json()
                return ttData
            except ValueError:
                return {"error": "No valid JSON-response from API."}
        else:    
             return {"error": f"API-error: {response.status_code} - {response.text}"}
    except:
        return {"error": f"Network problem"}

# function for reading emails and retrieving it's tt code(when everythings done)

