from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.exc import IntegrityError
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import LoginForm, RegisterForm, CreatePostForm, CommentForm
from flask_gravatar import Gravatar
import smtplib
import os

EMAIL = "YOUR EMAIL"
PASSWORD = "YOUR PASSWORD"

app = Flask(__name__)
# app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(
    app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

# CONNECT TO DB
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create the User Table
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    # *******Add parent relationship*******#
    # "comment_author" refers to the comment_author property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")


# Create the BlogPost Table
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # ***************Parent Relationship*************#
    comments = relationship("Comment", back_populates="parent_post")


# Create the Comment Table
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # ***************Child Relationship*************#
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    # *******Add child relationship*******#
    # "users.id" The users refers to the tablename of the Users class.
    # "comments" refers to the comments property in the User class.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    comment_author = relationship("User", back_populates="comments")
    text = db.Column(db.Text, nullable=False)
# db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            # if current_user.is_anonymous or current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def home():
    posts = BlogPost.query.all()
    return render_template("index.html", posts=posts, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            secure_password = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )  # Hashing and Salting password.
            new_user = User(
                email=form.email.data,
                name=form.name.data,
                password=secure_password
                # secure_password[14:] To avoid method 'pbkdf2:sha256' getting added to password
            )
            db.session.add(new_user)
            db.session.commit()
            # Log in and authenticate user after adding details to database.
            # login_user(new_user)
            # return redirect(url_for("login"))
            login_user(new_user)
            return redirect(url_for("home"))
        except IntegrityError:
            flash('User already exists, Please try again with another email!')
            return redirect(url_for('register'))
    return render_template("register.html", form=form, current_user=current_user)

# Instructor Way:
# def register():
#     form = RegisterForm()
#     if form.validate_on_submit():
#
#         if User.query.filter_by(email=form.email.data).first():
#             print(User.query.filter_by(email=form.email.data).first())
#             #User already exists
#             flash("You've already signed up with that email, log in instead!")
#             return redirect(url_for('login'))
#
#         hash_and_salted_password = generate_password_hash(
#             form.password.data,
#             method='pbkdf2:sha256',
#             salt_length=8
#         )
#         new_user = User(
#             email=form.email.data,
#             name=form.name.data,
#             password=hash_and_salted_password,
#         )
#         db.session.add(new_user)
#         db.session.commit()
#         login_user(new_user)
#         return redirect(url_for("home"))
#
#     return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Find user by email entered.
        user = User.query.filter_by(email=form.email.data).first()
        # Email doesn't exist
        if not user:
            flash("The email you entered does not exist. Please try again")
        # Password incorrect
        elif not check_password_hash(user.password, form.password.data):
            flash("The password you entered is incorrect. Please try again.")
        # Email exists and password correct
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def get_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            # return redirect(url_for("login"))
            return redirect(url_for(f"get_post", post_id=post_id))

        new_comment = Comment(
            text=form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        form.comment_text.data = ""
        return redirect(url_for('get_post', post_id=post_id))

    return render_template("post.html", post=requested_post, form=form, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


# @app.route("/contact")
# def contact():
#     return render_template("contact.html", current_user=current_user)

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        data = request.form
        email_message = f'Subject:New Form\n\nName : {data["name"]}\neMail : {data["email"]}\n' \
                        f'Telephone Number : {data["phone"]}\nMessage : \n{data["message"]}\n'

        with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(user=EMAIL, password=PASSWORD)
            connection.sendmail(from_addr=EMAIL, to_addrs="TARGET EMAIL", msg=email_message)

        return render_template("contact.html", msg_sent=True, current_user=current_user)
    return render_template("contact.html", msg_sent=False, current_user=current_user)


@app.route("/new-post", methods=["GET", "POST"])
# To authenticate
@login_required
# Mark with decorator
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        all_items = {item: value.data for (item, value) in form._fields.items() if item not in ['submit', 'csrf_token']}
        date = datetime.now().strftime('%B %d %Y')
        new_post = BlogPost(date=date, **all_items)
        # new_post = BlogPost(
        #     title=form.title.data,
        #     subtitle=form.subtitle.data,
        #     body=form.body.data,
        #     img_url=form.img_url.data,
        #     author=current_user,
        #     date=date.today().strftime("%B %d, %Y")
        # )

        # use strip_invalid_html-function before saving body (LOOK FUNCTION)
        # body = strip_invalid_html(article.body.data)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    form = CreatePostForm(obj=post)
    # if request.method == 'POST' and form.validate():
    if form.validate_on_submit():
        form.populate_obj(post)
        db.session.commit()
        return redirect(url_for("get_post", post_id=post.id))
    return render_template("make-post.html", form=form, action="Edit", current_user=current_user)
    # edit_form = CreatePostForm(
    #     title=post.title,
    #     subtitle=post.subtitle,
    #     img_url=post.img_url,
    #     author=current_user,
    #     body=post.body
    # )
    # if edit_form.validate_on_submit():
    #     post.title = edit_form.title.data
    #     post.subtitle = edit_form.subtitle.data
    #     post.img_url = edit_form.img_url.data
    #     post.body = edit_form.body.data
    #     db.session.commit()
    #     return redirect(url_for("get_post", post_id=post.id))

    # return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True, port=7007)
