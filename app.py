# Perform required imports
import os, redis
from flask import (Flask, request, session, g, redirect, url_for,
     abort, render_template, flash, send_from_directory)
from flask.ext.bcrypt import Bcrypt
from getpass import getpass
from wtforms import Form, BooleanField, TextField, PasswordField, validators


# create our little wishlist application
app = Flask(__name__)

# Database functions
# r0 = auth database
# r1 = posts database
# r2 = images database

r0 = redis.StrictRedis(host='localhost', port=6379, db=0)
r1 = redis.StrictRedis(host='localhost', port=6379, db=1)

# Classes
class LoginForm(Form):
    username = TextField('Username', [validators.Length(min=8, max=32)])
    password = PasswordField('Password', [validators.Required(), validators.EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Re-enter Password')

# Route common static files
@app.route('/robots.txt')
@app.route('/sitemap.xml')
@app.route('/favicon.ico')
def static_from_root():
    return send_from_directory('static', request.path[1:])

# Routes
@app.route('/')
def todo():
    posts = r1.zrangebyscore('posts', '-inf', '+inf')
    for post in posts:
        title = r1.hget(post, 'title')
        data  = r1.hget(post, 'post')
    return render_template('todo.html', posts=[title,data])

@app.route('/add', methods=['POST'])
def add_entry():
    if not session.get('logged_in'):
        abort(401)
    r1.hmset('post:%d',{'id':'%d', 'title':title, 'post':text}) % id
    flash('New entry was successfully posted')
    return redirect(url_for('todo'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User(form.username.data, form.password.data)
        flash('Thank you for logging in.')
        return redirect(url_for('todo.html'))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out.')
    return redirect(url_for('show_wishlist'))

if __name__ == '__main__':
    app.run(debug=True)
