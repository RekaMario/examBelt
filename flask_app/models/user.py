from flask_app import app
from flask_app.config.mysqlconnection import connectToMySQL
from flask import flash
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

class User:
    db_name = "examDB"
    def __init__(self, data):
        self.id = data['user_id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
    
    @classmethod
    def create_user(cls, data):
        query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s);"
        return connectToMySQL(cls.db_name).query_db(query, data)

    @classmethod
    def get_all_users(cls):
        query = "SELECT * FROM users;"
        results = connectToMySQL(cls.db_name).query_db(query)
        users = []
        for row in results:
            users.append(row)
        return users

    @classmethod
    def get_user_by_email(cls, data):
        query = "SELECT * FROM users WHERE email = %(email)s"
        result = connectToMySQL(cls.db_name).query_db(query, data)
        if len(result) < 1:
            return False
        return result[0]
    @classmethod
    def update_user(cls, data):
        query = "UPDATE users SET first_name = %(first_name)s, last_name = %(last_name)s, email = %(email)s WHERE users.id = %(user_id)s;"
        return connectToMySQL(cls.db_name).query_db(query, data)

    @classmethod
    def get_user_by_id(cls, data):
        query = "SELECT * FROM users WHERE id = %(user_id)s;"
        result = connectToMySQL(cls.db_name).query_db(query, data)
        if len(result) < 1:
            return False
        return result[0]


    @staticmethod
    def validate_user(data):
        is_valid = True
        if len(data['first_name']) < 3 or data['first_name'].isalpha() == False:
                flash("*First name must be at least 3 characters letters only.", "first_name")
                is_valid = False
        if len(data['last_name']) < 3 or data['last_name'].isalpha() == False:
                flash("*Last name must be at least 3 characters letters only.", "last_name")
                is_valid = False
        if not EMAIL_REGEX.match(data['email']):
            flash("*Invalid email adress.", "email")
            is_valid = False
        if len(data['password']) < 8:
            flash("*Your password is less than 8 characters", "password")
            is_valid = False
        elif data['password'] != data['confirm_pass']:
                flash("*Your confirmation password is wrong", "confirm_pass")
                is_valid = False
        return is_valid
    
    @staticmethod
    def validate_update(data):
        is_valid = True
        if len(data['first_name']) < 3 or data['first_name'].isalpha() == False:
                flash("*First name must be at least 3 characters letters only.", 'firstUpdate')
                is_valid = False
        if len(data['last_name']) < 3 or data['last_name'].isalpha() == False:
                flash("*Last name must be at least 3 characters letters only.", "lastUpdate")
                is_valid = False
        if not EMAIL_REGEX.match(data['email']):
            flash("*Invalid email adress.", 'emailUpdate')
            is_valid = False
        return is_valid