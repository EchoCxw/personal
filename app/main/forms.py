from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, SelectField, BooleanField, FileField
from ..auth.forms import Province_choice
from pymongo import MongoClient
from wtforms import ValidationError
from wtforms.validators import DataRequired, Length, Email, Regexp
from flask_pagedown.fields import PageDownField


# 普通用户编辑资料
class EditProfileForm(FlaskForm):
    name = StringField('姓名', validators=[Length(0, 64)])
    location = SelectField('地址', choices=Province_choice)
    about_me = TextAreaField('自我介绍', validators=[Length(0, 64)])
    avatar = FileField('头像')
    submit = SubmitField('提交')


# admin用户编辑资料
class EditProfileAdminForm(FlaskForm):
    choices = [('Administrator', '管理员'), ('Moderator', '协管员'), ('User', '用户')]
    email = StringField('邮箱', validators=[DataRequired(), Length(1, 64),
                                          Email()])
    username = StringField('用户名', validators=[
        DataRequired(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                              '支持英文和字母下划线.')])
    activate = BooleanField('账户激活状态')
    role = SelectField('权限', choices=choices)
    name = StringField('姓名', validators=[Length(0, 64)])
    location = StringField('地址', validators=[Length(0, 64)])
    about_me = TextAreaField('自我介绍')
    submit = SubmitField('提交')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.user = user

    def validate_email(self, field):
        if field.data == self.user.username and \
                MongoClient().blog.User.find_one({'email': field.data}):
            raise ValidationError('邮箱已被注册。')

    def validate_username(self, field):
        if field.data == self.user.username and \
                MongoClient().blog.User.find_one({'username': field.data}):
            raise ValidationError('用户名已被注册。')


class PostForm(FlaskForm):
    body = PageDownField('有什么想说的吗？', validators=[DataRequired()])
    submit = SubmitField('发表')


class EditPostForm(FlaskForm):
    body = PageDownField('', validators=[DataRequired()])
    submit = SubmitField('修改')


class CommentForm(FlaskForm):
    body = StringField('', validators=[DataRequired()])
    submit = SubmitField('评论')
