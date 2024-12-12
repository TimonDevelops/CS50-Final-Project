from flask import session
from functools import wraps
from flask import g, request, redirect, url_for
import sqlite3

# function to check if someone is logged in
def is_logged_in():
    return "user_id" in session

# login required is a decorator that sets decorated_function with f, a function like "user()" is passed true as f to login_required to set decoreated_function with. 
# When app starts, all login_required routes will set their decorated function. 
# When app is running, login_required doesn't run anymore, then the set decorated functions are ready to be activated
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login', next=request.url))
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

# function for reading emails and retrieving it's tt code

# function for API calls