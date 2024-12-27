from flask import redirect, session, flash
from functools import wraps
from datetime import datetime
import sqlite3, requests, imaplib, email, re, pytz

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
    try:
        with sqlite3.connect("packageTracker.db") as db:
            db.row_factory = sqlite3.Row
            cursor = db.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except sqlite3.Error as e:
        print(query)
        print(params)
        print(f"Database error in dbread(): {e}")
        return []
    except Exception as e:
        print(f"Error in dbRead(): {e}")
        return []
    
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
def ttInfo(code):
    # set url and header
    # test
    testBase_url = "https://api-test.dhl.com/track/shipments"
    headers = {
        "DHL-API-Key" : "demo-key"
    }
    # real
    realBase_url = "https://api-eu.dhl.com/track/shipments"
    headers = {
        "DHL-API-Key" : "key_in_developer_portal"
    }
    url = f"{realBase_url}?trackingNumber={code}"
    try: 
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            try:
                ttData = response.json()
                print(f"ttData: {ttData}")
                return ttData
            except ValueError:
                return {"error": "No valid JSON-response from API."}
        else:
             print(f"error : API-error: {response.status_code} - {response.text}")
             return False
    except:
        print(f"error: Network problem")
        return False
    
# create mail parser
# connect with email outlook
#1
def emailConnect(address, password):
    try:
        imapServer = "outlook.office365.com"
        mail = imaplib.IMAP4_SSL(imapServer)
        mail.login(address, password)
        return mail
    except Exception as e:
        print("Error connecting to email:", e)
        return None

# find tt codes
#3
def ttCodeFinder(emailBody):
    pattern = r"[A-Za-z]{3,4}\d{20,21}" # regular expression for DHL Express code
    match = re.search(pattern, emailBody)
    if match:
        # return complete code as 1 string
        return match.group(0)
    return False

# search emails
#2
def searchMails(mail):
    mail.select("inbox")
    # return string with all messages
    status, messages = mail.search(None, "ALL")
    if status != "OK":
        print(f"Failed retrieving emails")
        return 
    # split all messages from each other for further parsing 
    emailIds = messages[0].split()

    # select each email by id 
    for emailId in emailIds:
        # extract email content and turn into bytes
        status, msgData = mail.fetch(emailId, "(RFC822)")
        if status != "OK":
            print(f"Failed retrieving email with id: {emailId}")
            continue
        #  loop through binairy data parts
        for responsePart in msgData:
            # check if each part is tuple
            if isinstance(responsePart, tuple):
                # set 2nd part, its the message itself, back into text
                msg = email.message_from_bytes(responsePart[1])
                sender = msg.get("From")
                # select body of the email
                body = None
                if msg.is_multipart():
                    # walk trough each part
                    for part in msg.walk():
                        # select content type
                        contentType = part.get_content_type()
                        if contentType == "text/plain":
                            # extract payload, if coded, decode into binairy and then decode into string
                            body = part.get_payload(decode=True).decode()
                            # when body created, break out of loop
                            break
                else:
                    body = msg.get_payload(decode=True).decode()

                if body:
                    # seek tt code in body 
                    code = ttCodeFinder(body)
                    if code:
                        print(f"Track and Trace code found in email: {code}")
                        return code
                    else:
                        print(f"No Track and Trace code found in body from email send by: {sender}") 
                else:
                    print(f"No body found in email from sender: {sender}")

            else:
                print(f"No Track and Trace code found in email from sender {sender}")
        print("No Track and Trace code found in any email")
                    
def ttUpdateDB(ttCode, userID):
    # differ between new and excisting code
    ttRequest = ttInfo(ttCode)
    if ttRequest:
        ttData = ttRequest["shipments"][0]
        ttStatusData = ttData["status"]
        ttTimeStamp = ttStatusData["timestamp"]
        ttStatus = str(ttStatusData["description"]).lower()
        # convert timestamp
        parsedTime = datetime.fromisoformat(ttTimeStamp)
        nlTimeZone= pytz.timezone("Europe/Amsterdam")
        nlTime = parsedTime.astimezone(nlTimeZone)
        formattedTime = nlTime.strftime("%Y-%m-%d at %H:%M:%S")

       
        # check if tt code is new
        check = dbRead("SELECT userID FROM ttInfo WHERE ttCode = ?", (ttCode,))
        if not check:
                # new code
                try:
                    dbChange("INSERT INTO ttInfo (userID, ttCode, ttTimeStamp, ttStatus) VALUES (?, ?, ?, ?)", (userID, ttCode, formattedTime, ttStatus))
                except Exception as e:
                        print(f"Error inserting new track and trace data into database: {e}")
        # excisting code
        else:
            try:
                dbChange("UPDATE ttInfo SET userID = ?, ttTimeStamp = ?, ttStatus = ? WHERE ttCode = ?", (userID, formattedTime, ttStatus, ttCode))
            except Exception as e:
                    print(f"Error updating track and trace data in database: {e}")
    else:
        flash(f"Error fetching data for Track and Trace code {ttCode}.")
        return redirect("/ttInfo")
        
# mainfunction with mailparser, ttcode finder, API calls 
def ttMainFunction(userID):
        try:
            mailAddressQuery = dbRead("SELECT mailAddress FROM users WHERE id = ?", (userID,))
            mailPasswordQuery = dbRead("SELECT mailPassword FROM users WHERE id = ?", (userID,))
            if not mailAddressQuery and not mailPasswordQuery:
                print(f"Error: User {userID} does not have mail credentials stored")
                return
            mailAddress = mailAddressQuery[0]["mailAddress"]
            mailPassword = mailPasswordQuery[0]["mailPassword"]
            if not mailAddress or not mailPassword:
                print(f"Error: Missing email address or password for user {userID}.")
                return
            # connect with mail
            mail = emailConnect(mailAddress, mailPassword)
            if not mail:
                print(f"Error: Could not connect to email for user {userID}.")
                return
            # call ttCodeFinder with ttcode in each email and return tt code
            ttCodeRow = searchMails(mail)
            if not ttCodeRow:
                print("No Track-and-Trace codes found in emails.")
            for code in ttCodeRow:
                ttUpdateDB(code, userID)
        except Exception as e:
            print(f"Error in ttMainFunction for user {userID}: {e}")
        
        finally:
            try:
                if mail:
                    mail.logout()
            except Exception as e:
                print(f"Error during mail logout: {e}")


