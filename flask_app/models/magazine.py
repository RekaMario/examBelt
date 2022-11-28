from flask_app import app
from flask_app.config.mysqlconnection import connectToMySQL
from flask import flash

class Magazine:
    db_name = "examDB"
    def __init__(self, data):
        self.title = data['title']
        self.description = data['description']
        self.user_id = data['user_id']
        self.magazine_id = data['magazine_id']

    @classmethod
    def create_magazine(cls, data):
        query = "INSERT INTO magazines (title, description, user_id) VALUES (%(title)s,%(description)s, %(user_id)s);"
        return  connectToMySQL(cls.db_name).query_db(query, data)

    @classmethod
    def get_all_magazines(cls):
        query = "SELECT magazines.id, magazines.user_id, magazines.title, magazines.description, COUNT(subscribers.id) as subscribers_num, users.id as creator_id, users.first_name, users.last_name FROM magazines LEFT JOIN users on magazines.user_id = users.id LEFT JOIN subscribers on subscribers.magazine_id = magazines.id GROUP BY magazines.id;"
        results = connectToMySQL(cls.db_name).query_db(query)
        return results

    @classmethod
    def get_magazine_by_title(cls, data):
        query = "SELECT * FROM magazines WHERE title = %(title)s"
        result = connectToMySQL(cls.db_name).query_db(query, data)
        if len(result) < 1:
            return False
        return result[0]

    @classmethod
    def get_magazine_by_id(cls, data):
        query = "SELECT * FROM magazines WHERE id = %(magazine_id)s"
        result = connectToMySQL(cls.db_name).query_db(query, data)
        return result[0]

    @classmethod
    def get_subscribed_magazine_by_id(cls, data):
        query = "SELECT * FROM subscribers WHERE subscribers.magazine_id = %(magazine_id)s and subscribers.user_id = %(user_id)s;"
        result = connectToMySQL(cls.db_name).query_db(query, data)
        return result

    @classmethod
    def add_subscriber(cls, data):
        query = "INSERT INTO subscribers (magazine_id, user_id) VALUES (%(magazine_id)s, %(user_id)s);"
        return connectToMySQL(cls.db_name).query_db(query, data)

    @classmethod
    def remove_subscriber(cls, data):
        query = "DELETE FROM subscribers WHERE magazine_id = %(magazine_id)s and user_id = %(user_id)s;"
        return connectToMySQL(cls.db_name).query_db(query, data)

    @classmethod
    def get_all_subcribers(cls, data):
        query = "SELECT users.id, users.first_name, users.last_name FROM users LEFT JOIN subscribers ON subscribers.user_id = users.id LEFT JOIN magazines ON subscribers.magazine_id = magazines.id WHERE magazines.id = %(magazine_id)s;"
        results = connectToMySQL(cls.db_name).query_db(query, data)
        subscribers = []
        for row in results:
            subscribers.append(row)
        return subscribers
    @classmethod
    def delete_all_sub(cls, data):
        query = "DELETE FROM subscribers WHERE magazine_id = %(magazine_id)s;"
        return connectToMySQL(cls.db_name).query_db(query, data)

    @classmethod
    def get_user_subscribed_magazines(cls, data):
        query = "SELECT magazine_id FROM subscribers LEFT JOIN users on subscribers.user_id = users.id WHERE subscribers.user_id = %(user_id)s;"
        results = connectToMySQL(cls.db_name).query_db(query, data)
        magazines_subscribed = []
        for row in results:
            magazines_subscribed.append(row['magazine_id'])
        return magazines_subscribed

    @classmethod
    def remove_magazine(cls, data):
        query = "DELETE FROM magazines WHERE magazines.id = %(magazine_id)s and magazines.user_id = %(user_id)s;"
        return connectToMySQL(cls.db_name).query_db(query, data)

    @staticmethod
    def validate_magazine(data):
        is_valid = True
        if len(data['title']) < 2:
                flash("*Title must be at least 2 characters", "magazineTitle")
                is_valid = False
        if len(data['description']) < 10:
                flash("*Description must be at least 10 characters", "description")
                is_valid = False
        return is_valid
