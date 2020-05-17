from flask import Flask, render_template, redirect, url_for, request, session, flash
from datetime import timedelta, datetime
from dateutil.tz import tzlocal
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "FizMat"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usersAVATAR.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(hours=4)

db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column("id", db.Integer, primary_key=True)
    avatar = db.Column(db.String(100))
    fullname = db.Column(db.String(100))
    fullname_lower = db.Column(db.String(100))
    email = db.Column(db.String(100))
    username = db.Column(db.String(100))
    about = db.Column(db.String(200))
    hash_pass = db.Column(db.String(100))

    def __init__(self, fullname, email, username, password, about="",
                 avatar=""):
        self.avatar = avatar
        self.fullname = fullname
        self.fullname_lower = fullname.lower()
        self.email = email
        self.username = username
        self.about = about
        self.hash_pass = password


class Courses(db.Model):
    id = db.Column("id", db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    course_id = db.Column(db.Integer)

    def __init__(self, user_id, course_id=1):
        self.user_id = user_id
        self.course_id = course_id


@app.route("/")
def welcome():
    session["link"] = "http://127.0.0.1:8080/kz"
    return redirect(url_for("main"))


@app.route("/kz", methods=["GET", "POST"])
def main():
    session["link"] = "http://127.0.0.1:8080/kz"
    if request.method == "GET":
        return render_template("main.html", link=session["link"])
    if request.method == "POST":
        return redirect(url_for("login"))


@app.route("/kz/login/", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("user", username=session["username"]))
    else:
        session["link"] = "http://127.0.0.1:8080/kz"
        if request.method == "GET":
            return render_template("login.html", link=session["link"])
        else:
            if request.form.get('remember_me'):
                session.permanent = False
            else:
                session.permanent = True
            username = request.form["username"]
            User = Users.query.filter_by(username=username).first()
            if User:
                password = request.form["password"]
                if check_password_hash(User.hash_pass, password):
                    session["fullname"] = User.fullname
                    session["email"] = User.email
                    session["hash_pass"] = User.hash_pass
                    session["username"] = User.username
                    return redirect(url_for("user", username=username))
                else:
                    flash("Сіз терген құпиясөз қате")
                    return render_template("login.html", link=session["link"])
            else:
                flash("Сіз терген пайдаланушы аты қате")
                return render_template("login.html", link=session["link"])


@app.route("/kz/signup", methods=["GET", "POST"])
def signup():
    if "username" in session:
        return redirect(url_for("user", username=session["username"]))
    else:
        session["link"] = "http://127.0.0.1:8080/kz"
        if request.method == "GET":
            return render_template("signup.html", link=session["link"])
        else:
            if request.form.get('remember_me'):
                session.permanent = False
            else:
                session.permanent = True
            fullname = request.form["fullname"]
            username = request.form["username"]
            email = request.form["email"]
            password = request.form["password"]
            confirm = request.form["confirm_password"]
            if Users.query.filter_by(username=username).all():
                flash("Бұл пайдаланушы аты бос емес")
                return render_template("signup.html", link=session["link"])
            if password.isalpha() or password.isdigit():
                flash("Құпиясөз сандар мен әріптерден тұруы қажет")
                return render_template("signup.html", link=session["link"])
            if len(password) < 8:
                flash("Құпиясөз ұзындығы 8 символдан артық болуы қажет")
                return render_template("signup.html", link=session["link"])
            if password != confirm:
                flash("Құпиясөзді дұрыс растамадыңыз")
                return render_template("signup.html", link=session["link"])
            session["username"] = username
            session["fullname"] = fullname
            session["email"] = email
            password = generate_password_hash(request.form["password"])
            session["hash_pass"] = password

            User = Users(fullname=fullname, email=email, username=username, password=password)
            db.session.add(User)
            db.session.commit()
            return redirect(url_for("user", username=username, link=session["link"],))


@app.route("/kz/user/<username>", methods=["GET", "POST"])
def user(username):
    session["link"] = "http://127.0.0.1:8080/kz"
    if "username" in session:
        if request.method == "GET":
            User = Users.query.filter_by(username=session["username"]).first()
            return render_template("user.html", link=session["link"], User=User)
    else:
        return redirect(url_for("welcome"))


@app.route("/kz/user/<username>/settings", methods=["GET", "POST"])
def settings(username):
    session["link"] = "http://127.0.0.1:8080/kz"
    if "username" not in session:
        return redirect(url_for("welcome"))
    else:
        if request.method == "GET":
            return render_template("settings.html", link=session["link"],
                                   User=Users.query.filter_by(username=session["username"]).first())
        else:
            User = Users.query.filter_by(username=session["username"]).first()

            # username
            username = request.form["username"]
            fullname = request.form["fullname"]
            if username == session["username"] and fullname == session["fullname"]:
                pass
            else:
                if (Users.query.filter_by(username=username).all() and username != session["username"]) \
                        or (len(username.split()) == 0):
                    flash("Бұл қолданушы ат бос емес немесе қате")
                    return render_template("settings.html", link=session["link"],
                                           User=Users.query.filter_by(username=session["username"]).first())
                else:
                    if len(fullname.split()) == 0:
                        flash("Аты-жөніңіз қате енгізілді")
                        return render_template("settings.html", link=session["link"],
                                               User=Users.query.filter_by(username=session["username"]).first())
                    else:
                        pass_to_confirm_username = request.form["pass_to_confirm_username"]
                        if check_password_hash(User.hash_pass, pass_to_confirm_username):
                            User.username = username
                            User.fullname = fullname
                            session["username"] = username
                            session["fullname"] = fullname
                            db.session.commit()
                        else:
                            flash(f"Қате құпиясөз енгіздіңіз {fullname}")
                            return render_template("settings.html", link=session["link"],
                                                   User=Users.query.filter_by(username=session["username"]).first())

            # email
            old_email = request.form["old_email"]
            new_email = request.form["new_email"]
            if len(old_email) == 0 and len(new_email) == 0:
                pass
            else:
                if old_email != User.email:
                    flash("Электронды почта қате")
                    return render_template("settings.html",
                                           User=Users.query.filter_by(username=session["username"]).first())
                else:
                    pass_to_confirm_email = request.form["pass_to_confirm_email"]
                    if check_password_hash(User.hash_pass, pass_to_confirm_email):
                        User.email = new_email
                        session["email"] = new_email
                    else:
                        flash("Қате құпиясөз енгіздіңіз email")
                        return render_template("settings.html",
                                               User=Users.query.filter_by(username=session["username"]).first())

            # password
            old_pass = request.form["old_pass"]
            new_pass = request.form["new_pass"]
            new_pass_confirm = request.form["new_pass_confirm"]
            if len(old_pass) == 0 and new_pass == "" and new_pass_confirm == "":
                pass
            else:
                if check_password_hash(User.hash_pass, old_pass):
                    if new_pass.isalpha() or new_pass.isdigit():
                        flash("Құпиясөз сандар мен әріптерден тұруы қажет")
                        return render_template("settings.html", User=Users.query.filter_by(
                            username=session["username"]).first())
                    if len(new_pass) < 8:
                        flash("Құпиясөз ұзындығы 8 символдан артық болуы қажет")
                        return render_template("settings.html", User=Users.query.filter_by(
                            username=session["username"]).first())
                    if new_pass != new_pass_confirm:
                        flash("Құпиясөзді дұрыс растамадыңыз")
                        return render_template("settings.html", User=Users.query.filter_by(
                            username=session["username"]).first())
                else:
                    flash("Қате құпиясөз енгіздіңіз")
                    return render_template("settings.html",
                                           User=Users.query.filter_by(username=session["username"]).first())
        return redirect(url_for("user", username=session["username"]))


@app.route("/kz/course/c_plus_plus", methods=["GET", "POST"])
def c_plus_plus():
    session["link"] = "http://127.0.0.1:8080/kz"
    User = Users.query.filter_by(fullname=session["fullname"]).first()
    if request.method == "GET":
        return render_template("c_plus_plus.html", User=User, link=session["link"])
    else:
        lesson = Courses(user_id=User.id)
        db.session.add(lesson)
        db.session.commit()
        return redirect(url_for("lesson_1"))


@app.route("/kz/course/c_plus_plus/lesson_1", methods=["GET", "POST"])
def lesson_1():
    session["link"] = "http://127.0.0.1:8080/kz"
    User = Users.query.filter_by(fullname=session["fullname"]).first()
    if request.method == "GET":
        return render_template("study_c_pp_lesson_1.html", User=User, link=session["link"])
    else:
        return redirect(url_for("test_1"))


@app.route("/kz/course/c_plus_plus/lesson_1/test_1", methods=["GET", "POST"])
def test_1():
    session["link"] = "http://127.0.0.1:8080/kz"
    User = Users.query.filter_by(fullname=session["fullname"]).first()
    if request.method == "GET":
        return render_template("study_c_pp_test_1.html", User=User, link=session["link"])
    else:
        return redirect(url_for("test_2"))





@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("fullname", None)
    session.pop("email", None)
    session.pop("hash_pass", None)
    return redirect(url_for("welcome"))


if __name__ == "__main__":
    db.create_all()
    app.run(host="127.0.0.1", port=8080, debug=True)
