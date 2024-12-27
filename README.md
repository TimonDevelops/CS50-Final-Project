# CS50-Final-Project: Package Tracker
#### Video Demo: https://youtu.be/hQfoiQoNYT0
#### Description: Overview all track and trace information on pending and delivered packages

This project is build to learn more about web application devlopment and in the meanwhile solve a real life problem for me.
Every now and then I have several packages ordered and have a hard time overviewing all pending and delivered statuses.
This application will do the track and trace work for me and deliveres a clear overview on all my packages.

For building this application I used:
 * Flask/Python: For building the backend        
 * SQLite: To store user and shipment data in databsae.
 * HTML/CSS/JavaScript: For creating the user interface

This project had a great learning curve due to not relying on the CS50 codespace. But instead setting up a code space myself and learning what is needed to run such an application on my local pc.

# app.py:
This is the main Python script for the application. It depends on several libraries and imports functions from a secondary Python module that I’ve created. The script contains all the routing logic necessary for navigating through the application.

Key Features:
User Authentication: The app handles user login, registration, and session management securely using Flask sessions. Passwords are hashed using werkzeug.security before being stored in the database.

Track and Trace Validation: Currently, the app supports DHL Express Track and Trace codes. Users can input these codes manually, and the app will validate and fetch related tracking information.

Email Parsing (Upcoming feature): The code between lines 103 and 106 provides a preview for the upcoming functionality that will allow the app to automatically parse emails and extract Track and Trace codes.

Security:
Passwords are securely hashed using generate_password_hash and check_password_hash, ensuring user credentials are protected before storage.

Session Management:
Flask’s session management is used to handle user authentication and maintain session states between requests.

Track and Trace Validation:
The app verifies the validity of Track and Trace codes based on a regex pattern designed for DHL Express shipments.

# functions.py
This file contains helper functions designed to streamline database interactions and improve code readability within app.py. It follows an object-oriented approach to organize logic for database operations and future automation.

Key Features:
Database Interaction:

dbRead: A function for reading data from the database. It is used throughout the app to query the database and retrieve necessary information.
dbChange: A function for modifying data within the database, allowing for easier database updates and changes without repeating code in app.py.
Full Auto Mode with Email Parsing:

This file also contains the core logic for the app's upcoming full automation functionality. Specifically, it includes email parsing capabilities that will automatically extract Track and Trace codes from incoming emails.
IMAP Functionality: The email parsing system is designed to work with IMAP email providers, but it is currently awaiting optimization for full functionality. Once optimized, it will fully automate the process of extracting Track and Trace codes from emails and updating the app’s database.
Object-Oriented Workflow:
The functions in this file are designed to keep the workflow modular and maintainable, facilitating future updates and easier code management.


# Future Goals:
Implement Email Parsing for Track-and-Trace Code Automation:

Objective: Fully automate the process of extracting Track-and-Trace codes from incoming emails and inputting them into the app's database.
Current Status: The email parsing system is designed to connect with email providers (e.g., Outlook via IMAP), extract Track-and-Trace codes using regular expressions, and update the database. This system is in development and will be optimized to work seamlessly with all supported email providers.
Next Steps: Enhance and finalize the parsing functionality, improve error handling, and test with a variety of real-world email formats to ensure robust parsing.
Expand Integration with Additional Logistics Providers:

Objective: Extend the application's tracking capabilities by integrating with other major logistics and courier services, such as FedEx, UPS, or USPS, alongside the current DHL integration.
Current Status: Currently, the app supports DHL Express Track-and-Trace codes through the DHL API.
Next Steps: Research and integrate additional APIs or web scraping techniques for other logistics providers. Update the app to handle different tracking formats and statuses for each provider. Ensure the UI remains intuitive while supporting multiple providers.
Develop the App into a Progressive Web App (PWA):

Objective: Transform the current web application into a Progressive Web App (PWA) to allow users to access the app on mobile devices, desktops, and offline, without relying on a local server.
Current Status: The app is built using Flask and requires a local server to run.
Next Steps:
Convert the app into a PWA by implementing a service worker and a manifest file.
Ensure that the app can function offline and has an optimized user experience on mobile and desktop browsers.
Set up caching strategies to allow users to interact with the app even without a network connection, making it more accessible and versatile.
Explore deployment options like cloud hosting to ensure the app is accessible without needing a local server setup.
By achieving these goals, the app will become a more robust and user-friendly platform for tracking packages from multiple logistics providers, streamlining user experience with email-based automation, and expanding its accessibility through PWA capabilities.












