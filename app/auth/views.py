from flask import render_template, redirect, request, url_for, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user
from itsdangerous import Serializer, BadSignature
from . import auth
from ..models import verify_password, User, Temp, generate_reset_password_confirmation_token, encrypt_passowrd, \
    generate_change_email_confirmation_token
from .forms import LoginForm, RegistrationForm, PasswordResetRequestForm, PasswordResetForm, ChangePasswordForm, \
    ChangeEmailForm
from pymongo import MongoClient
from ..email import send_email
from bson.objectid import ObjectId
from datetime import datetime, time


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.activate \
                and request.endpoint[:5] != 'auth.' \
                and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.activate:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = MongoClient().blog.User.find_one({'email': form.email.data})
        if user is not None and verify_password(user.get('password'), form.password.data):
            temp_user = Temp(id=user.get('_id'), username=user.get('username'), email=user.get('email'),
                             password=user.get('password'), activate=user.get('activate'), role=user.get('role'),
                             name=user.get('name'),
                             location=user.get('location'), about_me=user.get('about_me'),
                             last_since=user.get('last_since'),
                             member_since=user.get('member_since'), avatar=user.get('avatar'))
            login_user(temp_user, form.remember_me.data)
            MongoClient().blog.User.update({'email': form.email.data}, {'$set': {'last_since': datetime.utcnow()}})
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('无效用户或密码。')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已登出。')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        User(email=form.email.data,
             username=form.username.data,
             password=form.password.data,
             name=form.name.data,
             location=form.location.data,
             about_me=form.about_me.data,
             avatar="/static/avatar/default.jpg").new_user()
        user = MongoClient().blog.User.find_one({'email': form.email.data})
        temp_user = Temp(id=user.get('_id'), username=user.get('username'), email=user.get('email'),
                         password=user.get('password'), activate=False, role=user.get('role'), name=user.get('name'),
                         location=user.get('location'), about_me=user.get('about_me'),
                         last_since=user.get('last_since'),
                         member_since=user.get('member_since'), avatar=user.get('avatar'))
        token = temp_user.generate_confirmation_token()
        send_email(temp_user.email, '激活您的账户',
                   'auth/email/confirm', user=temp_user, token=token)
        flash('验证邮件已发送。')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        s.loads(token)
    except BadSignature:
        return render_template('Link_expired.html')
    data = s.loads(token)
    id = data.get('confirm')
    user = MongoClient().blog.User.find_one({'_id': ObjectId(id)})
    if user is None:
        flash('认证连接无效或已超时。')
    if user.get('activate'):
        flash('此账户已激活。')
        return redirect(url_for('main.index'))
    MongoClient().blog.User.update({'_id': ObjectId(id)}, {'$set': {'activate': True}})
    time.sleep(1)
    flash('您已激活您的账户，谢谢！')
    return redirect(url_for('main.index'))


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, '激活您的账户',
               'auth/email_Chinese/confirm', user=current_user, token=token)
    flash('新的验证邮件已发送。')
    return redirect(url_for('main.index'))


# 重置密码请求
@auth.route('/password_reset_request', methods=['GET', 'POST'])
def password_reset_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        email = form.email.data
        user = MongoClient().blog.User.find_one({'email': email})
        if user:
            token = generate_reset_password_confirmation_token(email=email)
            send_email(email, '重置您的密码', 'auth/email_Chinese/reset_password',
                       user=current_user, token=token,
                       next=request.args.get('next'))
        flash('密码重置邮件已发送。')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)


# 重置密码
@auth.route('/password_reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        if Temp.password_reset(token, form.password.data):
            flash('密码重置，您现在可以登陆了。')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.verify_password(form.old_password.data):
            flash('旧密码错误。')
            form.data.clear()
        else:
            password = encrypt_passowrd(form.password.data)
            MongoClient().blog.User.update({'email': current_user.email}, {'$set': {'password': password}})
            flash('密码修改成功，您现在可以登陆了。')
            return redirect(url_for('auth.login'))
    return render_template('auth/change_password.html', form=form)


# 变更邮箱请求
@auth.route('/change_email_request', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data
            MongoClient().blog.User.update({'email': current_user.email}, {'$set': {'new_email': new_email}})
            token = generate_change_email_confirmation_token(email=current_user.email)
            send_email(new_email, '更改您的邮箱地址',
                       'auth/email_Chinese/change_email', user=current_user, token=token)
            flash('验证邮件已发送。')
            return redirect(url_for('main.index'))
        else:
            flash('无效的邮箱或密码')
    return render_template('auth/change_email_request.html', form=form)


# 变更邮箱
@auth.route('/change_email/<token>', methods=['GET', 'POST'])
def change_email(token):
    if current_user.change_email(token):
        flash('您的邮箱已成功修改，请重新登陆。')
    else:
        flash('无效请求。')
        return render_template('Link_expired.html')
    return redirect(url_for('auth.login'))