from flask_app import app
from flask_app.models import user
from flask_app.models import magazine
from flask import render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt
import re
bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/subscribe/<int:post_id>')
def add_subscriber(post_id):
    data = {
        'magazine_id': post_id,
        'user_id': session['user_id']
    }
    user_subscribed_magazine = magazine.Magazine.get_subscribed_magazine_by_id(data)
    if not user_subscribed_magazine:
        magazine.Magazine.add_subscriber(data)
        return redirect('/dashboardPage')
    return redirect('/dashboardPage')

@app.route('/unsubscribe/<int:magazine_id>')
def remove_subscriber(magazine_id):
    if 'user_id' not in session:
        return redirect('/log_out')
    data = {
        'magazine_id': magazine_id,
        'user_id': session['user_id']
    }
    user_subscribed_magazine = magazine.Magazine.get_subscribed_magazine_by_id(data)
    if user_subscribed_magazine:
        magazine.Magazine.remove_subscriber(data)
        return redirect('/dashboardPage')
    return redirect('/dashboardPage')

@app.route('/show_magazine/<int:magazine_id>')
def show_magazine(magazine_id):
    if 'user_id' not in session:
        return redirect('/log_out')
    data = {
        'magazine_id': magazine_id
    }
    magazines = magazine.Magazine.get_all_magazines()
    users = user.User.get_all_users()
    for row in magazines:
        if row['id']== magazine_id:
            the_magazine = row
    subscribers = magazine.Magazine.get_all_subcribers(data)
    return render_template("showPage.html", the_magazine = the_magazine, subscribers = subscribers )

@app.route('/add_magazine')
def add_magazine():
    return render_template('newPage.html')

@app.route('/create_magazine', methods = ['POST'])
def create_magazine():
    if 'user_id' not in session:
        return redirect('/logout')
    if not magazine.Magazine.validate_magazine(request.form):
        return redirect('/add_magazine')
    data = {
        'user_id': session['user_id'],
        'title': request.form['title'],
        'description': request.form['description']
    }
    title_in_db = magazine.Magazine.get_magazine_by_title(data)
    if title_in_db:
        flash("*This magazine title alredy exist, please try another one.", "magazineTitle")
        return redirect('/add_magazine')
    magazine.Magazine.create_magazine(data)
    return redirect('/dashboardPage')