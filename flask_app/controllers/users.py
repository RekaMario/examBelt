from flask_app import app
from flask_app.models import user, magazine
from flask import render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt
import re
bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/dashboardPage')
    return render_template('loginregisterPage.html')

@app.route('/create_user', methods = ['POST'])
def create_user():
    if not user.User.validate_user(request.form):
        return redirect('/')
    data = {
        'first_name': request.form['first_name'],
        'last_name': request.form['last_name'],
        'email': request.form['email'],
        'password': bcrypt.generate_password_hash(request.form['password'])
    }
    user_in_db = user.User.get_user_by_email(data)
    if user_in_db:
        flash("*This email alredy exist, please try another one.", "emailExist")
        return redirect('/')
    user.User.create_user(data)
    return redirect('/')
@app.route('/profilePage')
def account_info():
    if 'user_id' not in session:
        return redirect('/logout')
    data = {
        'user_id': session['user_id']
    }
    magazines = magazine.Magazine.get_all_magazines()
    all_magazines = []
    for row in magazines:
        if row['user_id'] == data['user_id']:
            all_magazines.append(row)
    loggedUser = user.User.get_user_by_id(data)
    return render_template('profilePage.html', loggedUser = loggedUser, all_magazines = all_magazines)

@app.route('/login', methods = ['POST'])
def login():
    data = {
        'email': request.form['login_email']
    }
    if not EMAIL_REGEX.match(data['email']):
        flash("*Invalid email adress.", "emailLogin")
        return redirect('/')
    user_in_db = user.User.get_user_by_email(data)
    if not user_in_db:
        flash("*Invalid Email/Password", "emailLogin")
        return redirect('/')
    if not bcrypt.check_password_hash(user_in_db['password'], request.form['password']):
        flash("*Invalid Email/Password", "emailLogin")
        return redirect('/')
    session['user_id'] = user_in_db['id']
    return redirect('/dashboardPage')

@app.route('/dashboardPage')
def dashboard():
    if 'user_id' not in session:
        return redirect('/logout')
    data = {
        'user_id': session['user_id']
    }
    loggedUser = user.User.get_user_by_id(data)
    all_users = user.User.get_all_users()
    magazines = magazine.Magazine.get_all_magazines()
    user_subscribed_magazines = magazine.Magazine.get_user_subscribed_magazines(data)

    if not loggedUser:
        return('/logout')
    return render_template("dashboardPage.html", loggedUser = loggedUser, all_users = all_users, magazines = magazines, user_subscribed_magazines = user_subscribed_magazines)



@app.route('/update_user', methods = ['POST'])
def update_user():
    if 'user_id' not in session:
        return redirect('/logout')
    if not user.User.validate_update(request.form):
        return redirect('/profilePage')
    data = {
        'user_id': session['user_id'],
        'first_name': request.form['first_name'],
        'last_name': request.form['last_name'],
        'email': request.form['email']
    }
    user_in_db = user.User.get_user_by_email(data)
    if user_in_db:
        flash("*This email alredy exist, please try another one.", "UpdateEmailExist")
        return redirect('/profilePage')
    user.User.update_user(data)
    return redirect('/profilePage')

@app.route('/delete_magazine/<int:magazine_id>')
def remove_post(magazine_id):
    if 'user_id' not in session:
        return redirect('/logout')
    data = {
        'magazine_id': magazine_id,
        'user_id': session['user_id']
    }
    the_magazine = magazine.Magazine.get_magazine_by_id(data)
    if not session['user_id'] == the_magazine['user_id']:
        return redirect('/profilePage')
    magazine.Magazine.delete_all_sub(data)
    magazine.Magazine.remove_magazine(data)
    return redirect('/profilePage')



@app.route('/logout/')
def logout():
    session.clear()
    return redirect('/')