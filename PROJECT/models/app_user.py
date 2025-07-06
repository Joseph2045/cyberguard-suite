# models/app_user.py
from flask_login import UserMixin

class AppUser(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email
