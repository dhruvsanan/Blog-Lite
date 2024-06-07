from flask_sqlalchemy import SQLAlchemy
import csv, json
from os import path
from flask import Flask, Blueprint, render_template, request, flash, redirect, url_for,make_response
from flask_login import login_user, logout_user, login_required, current_user, LoginManager, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.sql import func
from sqlalchemy import update
from werkzeug.utils import secure_filename
from io import StringIO
from fpdf import FPDF
from flask_restful import Api, Resource, marshal_with,fields,reqparse
from werkzeug.exceptions import HTTPException

db = SQLAlchemy()
DB_NAME = "database.db"
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif']) 


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = "asdfghjkuytrds!@#$z5677654"
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    app.config['UPLOAD_FOLDER'] = 'static'
    api= Api(app)
    api.add_resource(UserResources,'/api/user', '/api/user/<string:username>')
    api.add_resource(PostResource,'/api/post', '/api/post/<int:post_id>')
    api.add_resource(FeedResource, '/api/posts/<string:username>')
    global paath
    paath = path.join(app.root_path, 'static')
    db.init_app(app)

    app.register_blueprint(views, url_prefix="/")
    app.register_blueprint(auth, url_prefix="/")

    create_database(app)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app
def create_database(app):
    if not path.exists("website/" + DB_NAME):
        with app.app_context():
            db.create_all()
        print("Created database!")


# MODELS

class View(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
  author = db.Column(db.Integer, db.ForeignKey(
        'user.id', ondelete="CASCADE"), nullable=False)
  date_created = db.Column(db.DateTime(timezone=True), default=func.now())


class Follow(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
  followed_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
  date_created = db.Column(db.DateTime(timezone=True), default=func.now())

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    url = db.Column(db.String)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    date_created = db.Column(db.DateTime(timezone=True), default=func.now())
    posts = db.relationship('Post', backref='user', passive_deletes=True)
    comments = db.relationship('Comment', backref='user', passive_deletes=True)
    follows = db.relationship('Follow', foreign_keys=[Follow.user_id], backref='user')
    followed = db.relationship('Follow', foreign_keys=[Follow.followed_user_id], backref='followed_user')

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, nullable=False)
    text = db.Column(db.Text, nullable=False)
    url = db.Column(db.String)
    date_created = db.Column(db.DateTime(timezone=True), default=func.now())
    author = db.Column(db.Integer, db.ForeignKey(
        'user.id', ondelete="CASCADE"), nullable=False)
    comments = db.relationship('Comment', backref='post', passive_deletes=True)
    likes = db.relationship('Like', backref='post', passive_deletes=True)
    views = db.relationship('View', backref='post', lazy='dynamic')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.DateTime(timezone=True), default=func.now())
    author = db.Column(db.Integer, db.ForeignKey(
        'user.id', ondelete="CASCADE"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey(
        'post.id', ondelete="CASCADE"), nullable=False)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_created = db.Column(db.DateTime(timezone=True), default=func.now())
    author = db.Column(db.Integer, db.ForeignKey(
        'user.id', ondelete="CASCADE"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey(
        'post.id', ondelete="CASCADE"), nullable=False)


# VIEW

views = Blueprint("views", __name__)

@views.route("/")
@views.route("/home")
@login_required
def home():
    follows = Follow.query.filter_by(user_id=current_user.id).all()
    posts = []
    sorted_posts = []
    for follow in follows:
      user = User.query.filter_by(id=follow.followed_user_id).first()
      postss = user.posts
      for post in postss:
        sorted_posts.append((post.id, post))
        sorted_posts = sorted(sorted_posts, reverse=True)
        posts = [post[1] for post in sorted_posts]
    user = User.query.filter_by(id=current_user.id).first()
    postss = user.posts
    for post in postss:
        sorted_posts.append((post.id, post))
        sorted_posts = sorted(sorted_posts, reverse=True)
        posts = [post[1] for post in sorted_posts]
    return render_template("home_posts.html", user=current_user,posts=posts)

@views.route('/export', methods=['POST'])
def export():
    export_format = request.form['format']
    if export_format == 'csv':
        return redirect('/export_as_csv')
    elif export_format == 'pdf':
        return redirect('/export_as_pdf')
    else:
        return 'Invalid export format.'

@views.route('/export_as_pdf')
def export_blog_engagement():
    posts= Post.query.filter_by(author=current_user.id).all()
    pdf = FPDF()
    pdf.set_font('Arial', 'B', 16)
    for post in posts:
        pdf.add_page()
        pdf.cell(0, 10, f'Id: {post.id}')
        pdf.ln()
        pdf.cell(0, 10, f'Title: {post.title}')
        pdf.ln()
        pdf.cell(0, 10, f'Text: {post.text}')
        pdf.ln()
        if post.url:
            pdf.image(f'website/{post.url}', w=100)
            pdf.ln()
        pdf.cell(0, 10, f'Likes: {len(post.likes)}')
        pdf.ln()
        if post.comments:
            for comment in post.comments:
                pdf.cell(0, 10, f'Comment: {comment.text}')
                pdf.ln()
        else:
            pdf.cell(0, 10, 'No comments found', 0, 1)
        pdf.cell(0, 10, f'views: {post.views.count()}')
        pdf.ln()
    
    pdf_file = pdf.output(dest='S').encode('latin1')
    response = make_response(pdf_file)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=blog_engagement.pdf'
    return response

@views.route('/export_as_csv')
def export_data():
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['id', 'title', 'description', 'comments', 'likes', 'views','url'])
    posts= Post.query.filter_by(author=current_user.id).all()
    for post in posts:
        cw.writerow([post.id, post.title, post.text, post.comments, post.likes, post.views.count(), post.url])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=posts.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@views.route('/follow/<username>', methods=['GET', 'POST'])
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('No user with that username exists.', category='error')
        return redirect(url_for('views.home'))
    elif user.id==current_user.id:
        flash('you cannot follow yourself.', category='error')
        return redirect(url_for('views.home'))
    elif Follow.query.filter_by(user_id=current_user.id, followed_user_id=user.id).first() is None:
        follow = Follow(user_id=current_user.id, followed_user_id=user.id)
        db.session.add(follow)
        db.session.commit()
        flash(f'{current_user.username} is following {user.username}', category='success')
    else:
        follow = Follow.query.filter_by(user_id=current_user.id, followed_user_id=user.id).first()
        db.session.delete(follow)
        db.session.commit()
        flash(f'{current_user.username} is no longer following {user.username}', category='error')
    return redirect(url_for('views.posts',user=current_user, username=username))

@views.route('/search-user', methods=['GET', 'POST'])
@login_required
def search():
    username = request.args.get('username')
    if username:
        userss = User.query.filter_by(id=current_user.id).first()
        users = User.query.filter(User.username.like(f"%{username}%")).all()
        if userss in users:
            users.remove(userss)
        return render_template('search_user.html', users=users,user=current_user,userss=userss,Follow=Follow)
    return redirect(url_for('views.home'))

@views.route('/search-post', methods=['GET'])
@login_required
def search_post():
    post = request.args.get('post')
    if post:
        posts = Post.query.filter(Post.title.like(f"%{post}%")).order_by(Post.id.desc()).all()
        return render_template('home_posts.html', posts=posts,user=current_user)
    return redirect(url_for('views.home'))    

@views.route('/followers/<username>', methods=['GET'])
@login_required
def user_followers(username):
    users = User.query.filter_by(username=username).first()
    follows = Follow.query.filter_by(followed_user_id=users.id).all()
    usernames=[]
    for follow in follows:
        user_id=follow.user_id
        user = User.query.filter_by(id=user_id).first()
        usern=user.username
        usernames.append(usern)
    return render_template('followers.html',user=current_user,usernames=usernames,username=username)

@views.route('/following/<username>', methods=['GET'])
@login_required
def user_following(username):
    users = User.query.filter_by(username=username).first()
    follows = Follow.query.filter_by(user_id=users.id).all()
    usernames=[]
    for follow in follows:
        user = User.query.filter_by(id=follow.followed_user_id).first()
        usern=user.username
        usernames.append(usern)
    return render_template('following.html',user=current_user,usernames=usernames,username=username)

@views.route("/create-post", methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == "POST":
        text = request.form.get('text')
        title = request.form.get('title')
        image = request.files['image']
        filename = secure_filename(image.filename)
        url = url_for('static', filename=filename)
        if not title:
                flash('title cannot be empty', category='error')
        elif not text:
            flash('Post cannot be empty', category='error')
        if image:
            if '.' in filename and filename.rsplit('.', 1)[1].lower() not in ALLOWED_EXTENSIONS:
                flash('File type not supported', category='error')
            else:
                post = Post(text=text,title=title, author=current_user.id,url=url)
                image.save(path.join(paath, filename))
                db.session.add(post)
                db.session.commit()
                flash('Post created!', category='success')
            return redirect(url_for('views.home'))
        else:
            post = Post(text=text,title=title, author=current_user.id)
            db.session.add(post)
            db.session.commit()
            flash('Post created!', category='success')
            return redirect(url_for('views.home'))
    return render_template('create_post.html', user=current_user)

@views.route("/delete-post/<post_id>")
@login_required
def delete_post(post_id):
    post = Post.query.filter_by(id=post_id).first()
    delete_c = Comment.__table__.delete().where(Comment.post_id == post.id)
    delete_l= Like.__table__.delete().where(Like.post_id == post.id)
    delete_v= View.__table__.delete().where(View.post_id == post.id)
    if not post:
        flash("Post does not exist.", category='error')
    elif current_user.id != post.author:
        flash('You do not have permission to delete this post.', category='error')
    else:
        db.session.delete(post)
        db.session.execute(delete_l)
        db.session.execute(delete_c)
        db.session.execute(delete_v)
        db.session.commit()
        flash('Post deleted.', category='success')
    return redirect(url_for('views.home'))

@views.route("/delete-user")
@login_required
def delete_user():
    user = User.query.filter_by(id=current_user.id).first()
    delete_p = Post.__table__.delete().where(Post.author == user.id)
    delete_c = Comment.__table__.delete().where(Comment.author == user.id)
    delete_l= Like.__table__.delete().where(Like.author == user.id)
    delete_fs= Follow.__table__.delete().where(Follow.user_id == user.id)
    delete_fd= Follow.__table__.delete().where(Follow.followed_user_id == user.id)
    delete_v= View.__table__.delete().where(View.author == user.id)
    if not user:
        flash("User does not exist.", category='error')
    else:
        if user.posts:
            for post in user.posts:
                delete_pv= View.__table__.delete().where(View.post_id == post.id)
                db.session.execute(delete_pv)
                db.session.commit()
        db.session.delete(user)
        db.session.execute(delete_p)
        db.session.execute(delete_l)
        db.session.execute(delete_c)
        db.session.execute(delete_fs)
        db.session.execute(delete_fd)
        db.session.execute(delete_v)
        db.session.commit()
        flash('User deleted.', category='success')
    logout_user()
    return redirect(url_for('auth.login'))

@views.route("/update-post/<post_id>", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.filter_by(id=post_id).first()
    users = User.query.filter_by(id=current_user.id).first()
    username=users.username
    title = post.title
    text=post.text
    url=post.url
    if not post:
        flash("Post does not exist.", category='error')
    elif current_user.id != post.author:
        flash('You do not have permission to Update this post.', category='error')
    else:
        if request.method == "POST":
            title = request.form.get('title')
            text = request.form.get('text')
            image = request.files.get('image')
            if not title:
                flash('title cannot be empty', category='error')
            elif not text:
                flash('Post cannot be empty', category='error')
            else:
                if image:
                    if '.' in filename and filename.rsplit('.', 1)[1].lower() not in ALLOWED_EXTENSIONS:
                        flash('File type not supported', category='error')
                    else:
                        filename = secure_filename(image.filename)
                        url = url_for('static', filename=filename)
                        image.save(path.join(paath, filename))
                        ex = update(Post.__table__).where(Post.id==post.id).values(text=text,title=title,url=url)
                        db.session.execute(ex)
                        db.session.commit()
                else:
                    ex = update(Post.__table__).where(Post.id==post.id).values(text=text,title=title)
                    db.session.execute(ex)
                    db.session.commit()
                flash('Post updated!', category='success')
                return redirect(url_for('views.posts', username=username))
    return render_template('update_post.html', user=current_user,post=post,url=url,text=text,title=title)

@views.route("/post/<post_id>")
@login_required
def post(post_id):
    post = Post.query.filter_by(id=post_id).first()
    following= Follow.query.filter_by(user_id=current_user.id).first()
    followings= Follow.query.filter_by(followed_user_id=current_user.id).first()
    if not post:
        flash('No such post exists.', category='error')
        return redirect(url_for('views.home'))
    elif post.author!=current_user.id:
        view = View(post_id=post.id,author=current_user.id)
        db.session.add(view)
        db.session.commit()
    return render_template("post.html", user=current_user, post=post,followings=followings,following=following)

@views.route("/posts")
@login_required
def your_posts():
    users = User.query.filter_by(id=current_user.id).first()
    following= Follow.query.filter_by(user_id=current_user.id).first()
    followings= Follow.query.filter_by(followed_user_id=current_user.id).first()
    if not users:
        flash('No user with that username exists.', category='error')
        return redirect(url_for('views.home'))
    username=users.username
    posts = users.posts
    posts = sorted(posts, key=lambda x: x.id, reverse=True)
    return render_template("posts.html", user=current_user,users=users, posts=posts, username=username,followings=followings,following=following)

@views.route("/posts/<username>")
@login_required
def posts(username):
    users = User.query.filter_by(username=username).first()
    following= Follow.query.filter_by(user_id=current_user.id).first()
    followings= Follow.query.filter_by(followed_user_id=users.id).first()
    if not users:
        flash('No user with that username exists.', category='error')
        return redirect(url_for('views.home'))
    posts = users.posts
    posts = sorted(posts, key=lambda x: x.id, reverse=True)
    return render_template("posts.html", user=current_user,users=users, posts=posts, username=username,followings=followings,following=following)

@views.route("/dashboard/<username>")
@login_required
def user_dashboard(username):
    user = User.query.filter_by(username=username).first()
    following= Follow.query.filter_by(user_id=current_user.id).first()
    followings= Follow.query.filter_by(followed_user_id=user.id).first()
    if not user:
        flash('No user with that username exists.', category='error')
        return redirect(url_for('views.home'))
    if user.id==current_user.id:
        return redirect(url_for('views.dashboard'))
    posts = user.posts
    comments=user.comments
    url=user.url
    views=0
    for post in posts:
        view=post.views.count()
        views+=view
    nposts=len(posts)
    ncomments=len(comments)
    follows = Follow.query.filter_by(user_id=user.id).all()
    nfollowed=0
    for follow in follows:
        nfollowed+=1
    followers = Follow.query.filter_by(followed_user_id=user.id).all()
    nfollows=0
    for follow in followers:
        nfollows+=1
    return render_template("user_dashboard.html", user=current_user,views=views,url=url,followings=followings,following=following, Follow=Follow, username=username,nposts=nposts,ncomments=ncomments,nfollows=nfollows,nfollowed=nfollowed)

@views.route("/dashboard")
@login_required
def dashboard():
    user = User.query.filter_by(id=current_user.id).first()
    username=user.username
    email=user.email
    posts = user.posts
    url=user.url
    comments=user.comments
    nposts=len(posts)
    ncomments=len(comments)
    follows = Follow.query.filter_by(user_id=current_user.id).all()
    nfollowed=0
    for follow in follows:
        nfollowed+=1
    followers = Follow.query.filter_by(followed_user_id=current_user.id).all()
    nfollows=0
    for follow in followers:
        nfollows+=1
    views=0
    for post in posts:
        view=post.views.count()
        views+=view
    return render_template("dashboard.html", user=current_user,url=url,views=views, username=username,email=email,nposts=nposts,ncomments=ncomments,nfollows=nfollows,nfollowed=nfollowed)

@views.route("/create-comment/<post_id>", methods=['POST'])
@login_required
def create_comment(post_id):
    text = request.form.get('text')
    if not text:
        flash('Comment cannot be empty.', category='error')
    else:
        post = Post.query.filter_by(id=post_id)
        if post:
            comment = Comment(
                text=text, author=current_user.id, post_id=post_id)
            db.session.add(comment)
            db.session.commit()
        else:
            flash('Post does not exist.', category='error')
    return redirect(url_for('views.post',post_id=post_id))

@views.route("/delete-comment/<comment_id>")
@login_required
def delete_comment(comment_id):
    comment = Comment.query.filter_by(id=comment_id).first()
    if not comment:
        flash('Comment does not exist.', category='error')
    elif current_user.id != comment.author and current_user.id != comment.post.author:
        flash('You do not have permission to delete this comment.', category='error')
    else:
        db.session.delete(comment)
        db.session.commit()
    return redirect(url_for('views.home'))

@views.route("/update-comment/<comment_id>", methods=['GET', 'POST'])
@login_required
def update_comment(comment_id):
    comment = Comment.query.filter_by(id=comment_id).first()
    post_id=comment.post_id
    text=comment.text
    if not comment:
        flash('Comment does not exist.', category='error')
    elif current_user.id != comment.author and current_user.id != comment.post.author:
        flash('You do not have permission to update this comment.', category='error')
    else:
        if request.method == "POST":
            text = request.form.get('text')
            if not text:
                flash('Comment cannot be empty.', category='error')
            else:
                post = Post.query.filter_by(id=post_id)
                if post:
                    ex = update(Comment.__table__).where(Comment.id==comment.id).values(text=text)
                    db.session.execute(ex)
                    db.session.commit()
                    flash('Comment updated!', category='success')
                    return redirect(url_for('views.home'))
                else:
                    flash('Post does not exist.', category='error')
    return render_template('update_comment.html', user=current_user,text=text)
    
@views.route("/like-post/<post_id>", methods=['GET'])
@login_required
def like(post_id):
    post = Post.query.filter_by(id=post_id).first()
    like = Like.query.filter_by(author=current_user.id, post_id=post_id).first()
    if not post:
        flash("Post does not exist.", category="error")
    elif like:
        db.session.delete(like)
        db.session.commit()
    else:
        like = Like(author=current_user.id, post_id=post_id)
        db.session.add(like)
        db.session.commit()
    return redirect(url_for('views.post',post_id=post_id))

@views.route("/update-user", methods=['GET', 'POST'])
@login_required
def update_user():
    user = User.query.filter_by(id=current_user.id).first()
    username=user.username
    email=user.email
    useree = User.query.filter_by(email=user.email).first()
    usernn = User.query.filter_by(username=user.username).first()
    if request.method == 'POST':
        email = request.form.get("email")
        username = request.form.get("username")
        usern = User.query.filter_by(username=request.form.get("username")).all()
        usere = User.query.filter_by(email=request.form.get("email")).all()
        if useree in usere:
                usere.remove(useree)
        if usernn in usern:
                usern.remove(usernn)
        if len(username) < 2:
            flash('Username is too short.', category='error')
        elif len(email) < 4:
            flash("Email is invalid.", category='error')
        elif usere:
            flash("Duplicate email.", category='error')
        elif usern:
            flash("Duplicate username.", category='error')
        else:
            ex = update(User.__table__).where(User.id==current_user.id).values(email=email, username=username)
            db.session.execute(ex)
            db.session.commit()
            flash('User updated!', category='success')
            return redirect(url_for('views.dashboard'))
    return render_template("update_user.html", user=current_user, username=username,email=email)

@views.route("/update-picture", methods=['GET', 'POST'])
@login_required
def update_picture():
    user = User.query.filter_by(id=current_user.id).first()
    if not user:
        flash('User does not exist.', category='error')
    url=user.url
    if request.method == 'POST':
        image = request.files.get('image')
        filename = secure_filename(image.filename)
        if image:
            if '.' in filename and filename.rsplit('.', 1)[1].lower() not in ALLOWED_EXTENSIONS:
                flash('File type not supported', category='error')
            else:
                url = url_for('static', filename=filename)
                image.save(path.join(paath, filename))
                ex = update(User.__table__).where(User.id==user.id).values(url=url)
                db.session.execute(ex)
                db.session.commit()
                flash('Profile Picture updated!', category='success')
                return redirect(url_for('views.dashboard'))
    return render_template("update_picture.html", user=current_user,url=url)

@views.route("/reset_password", methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form.get("username")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        user = User.query.filter_by(username=username,email=email).first()
        if user:
            if password1 != password2:
                flash('Password don\'t match!', category='error')
            elif len(password1) < 6:
                flash('Password is too short.', category='error')
            elif check_password_hash(user.password, password1):
                flash('You cannot use previous password.', category='error')
            else:
                ex = update(User.__table__).where(User.username==username).values(password=generate_password_hash(
                    password1, method='sha256'))
                db.session.execute(ex)
                db.session.commit()
                flash('Password Reseted!', category='success')
                flash('Logged In!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
        else:
            flash('Wrong username and email entered', category='error')
    return render_template("reset_password.html", user=current_user)

@views.route("/update-password", methods=['GET', 'POST'])
@login_required
def update_password():
    user = User.query.filter_by(id=current_user.id).first()
    username=user.username
    if not user:
        flash('User does not exist.', category='error')
    if request.method == 'POST':
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        if password1 != password2:
            flash('Password don\'t match!', category='error')
        elif len(password1) < 6:
            flash('Password is too short.', category='error')
        elif check_password_hash(user.password, password1):
            flash('You cannot use previous password.', category='error')
        else:
            ex = update(User.__table__).where(User.id==current_user.id).values(password=generate_password_hash(password1, method='sha256'))
            db.session.execute(ex)
            db.session.commit()
            flash('Password updated!', category='success')
            return redirect(url_for('views.dashboard'))
    return render_template("update_password.html", user=current_user, username=username)


# AUTH

auth = Blueprint("auth", __name__)

@auth.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in!", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Password is incorrect.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("login.html", user=current_user)


@auth.route("/sign-up", methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get("email")
        username = request.form.get("username")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        image = request.files['image']

        email_exists = User.query.filter_by(email=email).first()
        username_exists = User.query.filter_by(username=username).first()

        if email_exists:
            flash('Email is already in use.', category='error')
        elif username_exists:
            flash('Username is already in use.', category='error')
        elif password1 != password2:
            flash('Password don\'t match!', category='error')
        elif len(username) < 2:
            flash('Username is too short.', category='error')
        elif len(password1) < 6:
            flash('Password is too short.', category='error')
        else:
            if image:
                filename = secure_filename(image.filename)
                if '.' in filename and filename.rsplit('.', 1)[1].lower() not in ALLOWED_EXTENSIONS:
                    flash('File type not supported', category='error')
                else:
                    url = url_for('static', filename=filename)
                    image.save(path.join(paath, filename))
                    new_user = User(email=email, username=username,url=url, password=generate_password_hash(
                        password1, method='sha256'))
                    db.session.add(new_user)
                    db.session.commit()
                    login_user(new_user, remember=True)
                    flash('User created!')
                    return redirect(url_for('views.home'))
            else:
                new_user = User(email=email, username=username, password=generate_password_hash(
                    password1, method='sha256'))
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                flash('User created!')
                return redirect(url_for('views.home'))

    return render_template("signup.html", user=current_user)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("views.home"))


# API


class BusinessValidationError(HTTPException):
    def __init__ (self, status_code,error_codes,error_messages):
        message = {"error_code": error_codes, "error_message": error_messages}
        self.response=make_response(json.dumps(message),status_code)

create_user_parser = reqparse.RequestParser ()
create_user_parser.add_argument ('username')
create_user_parser.add_argument ('email')
create_user_parser.add_argument ('password')

update_user_parser = reqparse.RequestParser ()
update_user_parser.add_argument ('new_username')
update_user_parser.add_argument ('new_email')
update_user_parser.add_argument ('password')

create_post_parser = reqparse.RequestParser ()
create_post_parser.add_argument ('title')
create_post_parser.add_argument ('text')
create_post_parser.add_argument ('author')

update_post_parser = reqparse.RequestParser ()
update_post_parser.add_argument ('title')
update_post_parser.add_argument ('text')
update_post_parser.add_argument ('author')

post_fields = {
    "id": fields.Integer,
    "title": fields.String,
    "text": fields.String,
    "url":fields.String,
    "date_created": fields.DateTime,
    "author": fields.Integer
}

user_fields = {
    "id": fields.Integer,
    "email": fields.String,
    "username": fields.String,
    "url":fields.String,
    "password": fields.String,
    "date_created":fields.DateTime
}

class PostResource(Resource):
    @marshal_with(post_fields)
    def get(self, post_id):
            post = Post.query.filter_by(id=post_id).first()
            num_views = post.views.count()
            if post:
                return post,num_views
            else:
                raise BusinessValidationError(status_code=400, error_codes="BE2005",error_messages="Post does not exist")
    @marshal_with(post_fields)
    def post(self):
        args = create_post_parser.parse_args()
        title = args.get("title", None)
        text = args.get("text", None)
        author = args.get("author", None)
        author_exists = User.query.filter_by(id=author).first()
        if not title:
            raise BusinessValidationError(status_code=400, error_codes="BE2001",error_messages="title is required")
        elif not text:
            raise BusinessValidationError(status_code=400, error_codes="BE2002",error_messages="Description is required")
        elif not author:
            raise BusinessValidationError(status_code=400, error_codes="BE2003",error_messages="User Id is required")
        elif not author_exists:
            raise BusinessValidationError(status_code=400, error_codes="BE2004",error_messages="Author does not exists")
        else:
            post=Post(title=title,text=text,author=author)
            db.session.add(post)
            db.session.commit()
            return post, 201
    @marshal_with(post_fields)
    def put(self, post_id):
        post = Post.query.filter_by(id=post_id).first()
        if not post:
            raise BusinessValidationError(status_code=400, error_codes="BE2005",error_messages="Post does not exist")
        else:
            args = update_post_parser.parse_args()
            title = args.get("title", None)
            text = args.get("text", None)
            author = args.get("author", None)
            author_exists = User.query.filter_by(id=author).first()
            if not title:
                raise BusinessValidationError(status_code=400, error_codes="BE2001",error_messages="title is required")
            if not text:
                raise BusinessValidationError(status_code=400, error_codes="BE2002",error_messages="Description is required")
            if not author:
                raise BusinessValidationError(status_code=400, error_codes="BE2003",error_messages="User Id is required")
            if not author_exists:
                raise BusinessValidationError(status_code=400, error_codes="BE2004",error_messages="Author does not exists")
            else:
                ex=update(Post).where(Post.id==post_id).values(title=title,text=text,author=author)
                db.session.execute(ex)
                db.session.commit()
                return post
    def delete(self, post_id):
        post = Post.query.filter_by(id=post_id).first()
        if post:
            delete_c = Comment.__table__.delete().where(Comment.post_id == post.id)
            delete_l= Like.__table__.delete().where(Like.post_id == post.id)
            delete_v= View.__table__.delete().where(View.post_id == post.id)
            db.session.execute(delete_c)
            db.session.execute(delete_l)
            db.session.execute(delete_v)
            db.session.delete(post)
            db.session.commit()
            return {'success':'Post Deleted'}, 201
        else:
            raise BusinessValidationError(status_code=400, error_codes="BE2005",error_messages="Post does not exist")

class FeedResource(Resource):
    @marshal_with(post_fields)
    def get(self, username):
        users= User.query.filter_by(username=username).first()
        if users:
            follows = Follow.query.filter_by(user_id=users.id).all()
            posts = []
            sorted_posts = []
            if follows:
                for follow in follows:
                    user = User.query.filter_by(id=follow.followed_user_id).first()
                    postss = user.posts
                    for post in postss:
                        sorted_posts.append((post.id, post))
                        sorted_posts = sorted(sorted_posts, reverse=True)
                        posts = [post[1] for post in sorted_posts]
                    if posts:
                        return posts
                    else:
                        raise BusinessValidationError(status_code=400, error_codes="BE2002",error_messages="people you follow have not posted yet. Follow more people")
            else:
                raise BusinessValidationError(status_code=400, error_codes="BE2001",error_messages="You need to follow more users")
        else:
            raise BusinessValidationError(status_code=400, error_codes="BE1007",error_messages="User does not exist")
        
class UserResources(Resource):
    @marshal_with(user_fields)
    def get(self, username):
        user = User.query.filter_by(username=username).first()
        if user:
            return user
        else:
            raise BusinessValidationError(status_code=400, error_codes="BE1007",error_messages="User does not exist")

    @marshal_with(user_fields)
    def post(self):
        args = create_user_parser.parse_args()
        username = args.get("username", None)
        email = args.get("email", None)
        password = args.get("password", None)
        if not username:
            raise BusinessValidationError(status_code=400, error_codes="BE1001",error_messages="Username is required")
        if not password:
            raise BusinessValidationError(status_code=400, error_codes="BE1002",error_messages="Password is required")
        if not email:
            raise BusinessValidationError(status_code=400, error_codes="BE1003",error_messages="Email is required")
        if "@" not in email:
            raise BusinessValidationError(status_code=400, error_codes="BE1004",error_messages="invalid email")   
        usern = User.query.filter_by(username=request.json['username']).first()
        usere = User.query.filter_by(email=request.json['email']).first()
        if usere or usern:
            if usern:
                    raise BusinessValidationError(status_code=400, error_codes="BE1005",error_messages="Duplicate username") 
            else:
                raise BusinessValidationError(status_code=400, error_codes="BE1006",error_messages="Duplicate email") 
        user=User(username=username,email=email,password=generate_password_hash(password, method='sha256'))
        db.session.add(user)
        db.session.commit()
        return user, 201
    
    @marshal_with(user_fields)
    def put(self, username):
        user = User.query.filter_by(username=username).first()
        if not user:
            raise BusinessValidationError(status_code=400, error_codes="BE1007",error_messages="User does not exist")
        else:
            args = update_user_parser.parse_args()
            new_username = args.get("new_username", None)
            new_email = args.get("new_email", None)
            password = args.get("password", None)
            if not new_username:
                raise BusinessValidationError(status_code=400, error_codes="BE1001",error_messages="Username is required")
            if not password:
                raise BusinessValidationError(status_code=400, error_codes="BE1002",error_messages="Password is required")
            if not new_email:
                raise BusinessValidationError(status_code=400, error_codes="BE1003",error_messages="Email is required")
            if "@" not in new_email:
                raise BusinessValidationError(status_code=400, error_codes="BE1004",error_messages="invalid email")   
            useree = User.query.filter_by(email=user.email).first()
            usernn = User.query.filter_by(username=user.username).first()
            usern = User.query.filter_by(username=request.form.get("username")).all()
            usere = User.query.filter_by(email=request.form.get("email")).all()
            if useree in usere:
                    usere.remove(useree)
            if usernn in usern:
                    usern.remove(usernn)
            if usere:
                raise BusinessValidationError(status_code=400, error_codes="BE1005",error_messages="Duplicate username") 
            elif usern:
                raise BusinessValidationError(status_code=400, error_codes="BE1006",error_messages="Duplicate email")
            else:
                ex=update(User).where(User.id==user.id).values(username=new_username,email=new_email,password=generate_password_hash(password, method='sha256'))
                db.session.execute(ex)
                db.session.commit()
                return user

    def delete(self, username):
        user = User.query.filter_by(username=username).first()
        if not user:
            raise BusinessValidationError(status_code=400, error_codes="BE1007",error_messages="User does not exist")
        else:
            if user.posts:
                for post in user.posts:
                    delete_pv= View.__table__.delete().where(View.post_id == post.id)
                    db.session.execute(delete_pv)
                    db.session.commit()
            delete_p = Post.__table__.delete().where(Post.author == user.id)
            delete_p = Post.__table__.delete().where(Post.author == user.id)
            delete_c = Comment.__table__.delete().where(Comment.author == user.id)
            delete_l= Like.__table__.delete().where(Like.author == user.id)
            delete_fs= Follow.__table__.delete().where(Follow.user_id == user.id)
            delete_fd= Follow.__table__.delete().where(Follow.followed_user_id == user.id)
            delete_v= View.__table__.delete().where(View.author == user.id)
            db.session.execute(delete_p)
            db.session.execute(delete_c)
            db.session.execute(delete_l)
            db.session.execute(delete_v)
            db.session.execute(delete_fs)
            db.session.execute(delete_fd)
            db.session.delete(user)
            db.session.commit()
            return {'success':'User Deleted'}, 201