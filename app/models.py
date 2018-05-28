from werkzeug.security import generate_password_hash, check_password_hash
from . import login_manager
from flask_login import UserMixin, AnonymousUserMixin, current_user, logout_user
from pymongo import MongoClient
from bson.objectid import ObjectId
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from datetime import datetime
from markdown import markdown
import bleach


# 重置/找回密码token
def generate_reset_password_confirmation_token(email, expiration=3600):
    s = Serializer(current_app.config['SECRET_KEY'], expiration)
    return s.dumps({'password_reset': email}).decode('utf-8')


# 更改邮箱token
def generate_change_email_confirmation_token(email, expiration=3600):
    s = Serializer(current_app.config['SECRET_KEY'], expiration)
    return s.dumps({'change_email': email}).decode('utf-8')


# 密码散列值
def encrypt_passowrd(password):
    return generate_password_hash(password)


# 密码散列值验证
def verify_password(password_hash, password):
    return check_password_hash(password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    user = MongoClient().blog.User.find_one({'_id': ObjectId(user_id)})
    return Temp(id=user.get('_id'), username=user.get('username'), email=user.get('email'),
                password=user.get('password'), activate=user.get('activate'), role=user.get('role'),
                name=user.get('name'),
                location=user.get('location'), about_me=user.get('about_me'), last_since=user.get('last_since'),
                member_since=user.get('member_since'), avatar=user.get('avatar'))


class Permission:
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x80


class Role:
    db = MongoClient().blog.Role

    def __init__(self, name, permission, default):
        self.name = name
        self.permission = permission
        self.default = default

    def new_role(self):
        collection = {
            'name': self.name,
            'permission': self.permission,
            'default': self.default
        }
        self.db.insert(collection)


class User:
    def __init__(self, username, email, password, name, location, about_me, avatar):
        self.username = username
        self.email = email
        self.password_hash = encrypt_passowrd(password)
        self.db = MongoClient().blog.User
        self.name = name
        self.location = location
        self.about_me = about_me
        self.avatar = avatar
        conn = MongoClient().blog.Role
        if self.email == current_app.config['FLASKY_ADMIN']:
            self.role = conn.find_one({'permissions': 0xff}).get('name')
        else:
            self.role = conn.find_one({'default': True}).get('name')

    # 新增用户collection
    def new_user(self):
        collection = {
            'username': self.username,
            'email': self.email,
            'password': self.password_hash,
            'activate': False,
            'role': self.role,
            'name': self.name,
            'location': self.location,
            'about_me': self.about_me,
            'avatar': self.avatar,
            'member_since': datetime.utcnow(),
            'last_since': datetime.utcnow(),
            'followers': [],
            'following': []
        }
        self.db.insert(collection)

    def __repr__(self):
        return self.username


class Temp(UserMixin):
    is_active = True
    is_anonymous = False
    is_authenticated = True
    email = ''
    username = ''

    def __init__(self, id, username, email, password, activate, role, name, location, about_me, last_since,
                 member_since, avatar):
        self.id = str(id)
        self.username = username
        self.email = email
        self.password_hash = password
        self.activate = activate
        self.name = name
        self.location = location
        self.about_me = about_me
        self.last_since = last_since
        self.member_since = member_since
        self.avatar = avatar
        conn = MongoClient().blog.Role.find_one({'name': role})
        self.role = Role(name=role, permission=conn.get('permissions'), default=conn.get('default'))

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return self.id

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id}).decode('utf-8')

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        id = data.get('confirm')
        if data.get('confirm') == MongoClient().blog.User.find_one({'_id': ObjectId(id)}):
            MongoClient().blog.User.update({'_id': ObjectId(id)}, {'$set': {'activate': True}})
            return True
        return False

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            date = s.loads(token.encode('utf-8'))
        except:
            return False
        if date.get('change_email') is None:
            return False
        email = date.get('change_email')
        new_email = MongoClient().blog.User.find_one({'email': email}).get('new_email')
        MongoClient().blog.User.update({'email': email}, {
            '$set': {'email': new_email}})
        MongoClient().blog.User.update({'email': new_email}, {'$unset': {'new_email': new_email}})
        logout_user()
        return True

    @staticmethod
    def password_reset(token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        email = data.get('password_reset')
        user = MongoClient().blog.User.find_one({'email': email})
        password = encrypt_passowrd(new_password)
        if user is None:
            return False
        MongoClient().blog.User.update({'email': email}, {'$set': {'password': password}})
        return True

    def can(self, permission):
        return self.role is not None and \
               (self.role.permission & permission) == permission

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

    def __repr__(self):
        return self.username

    # 最后登陆时间
    def ping(self):
        MongoClient().blog.User.update({'email': self.email}, {'$set': {'last_since': datetime.utcnow()}})

    # 关注人
    def is_following(self, user):
        temp = MongoClient().blog.User.find_one({'username': self.username}).get('following')
        for i in range(temp.__len__()):
            if temp[i][0] == user.username:
                return True
        return False


class AnonymousUser(AnonymousUserMixin):
    def can(self, permission):
        return False

    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser


# 发送博客
class Post:
    def __init__(self, body):
        self.body = body
        self.body_html = ''

    # 新博文
    def new_article(self):
        self.body_html = body_html(self.body)
        collection = {
            'username': current_user.username,
            'user_id': current_user.id,
            'body': self.body,
            'issuing_time': datetime.utcnow(),
            'body_html': self.body_html,
            'comments': []
        }
        MongoClient().blog.Aritical.insert(collection)


def body_html(body):
    allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                    'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                    'h1', 'h2', 'h3', 'p']
    return bleach.linkify(bleach.clean(markdown(body, output_format='html'),
                                       tags=allowed_tags, strip=True))
