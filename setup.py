# perform required imports
import redis
from flask import Flask
from flask.ext.bcrypt import Bcrypt
from contextlib import closing
from getpass import getpass

# set up database connection and create database if not existent
r0 = redis.StrictRedis(host='localhost', port=6379, db=0)

# Create default admin user
username = raw_input("Please create a default admin user: ")
password = getpass("Please set password for default admin user: ")
email = raw_input("Email address for password reset and notifications: ")

# Setup bcrypt instance and hash password before storing
app = Flask(__name__)
bcrypt = Bcrypt(app)
pw_hash = bcrypt.generate_password_hash(password)

# Commit changes and close database
r0.hmset('user0',{'id':'0','username': username, 'password': pw_hash, 'email' : email})

