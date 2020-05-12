from flask import Flask, render_template, redirect, url_for, request
from datetime import timedelta, datetime

app = Flask(__name__)
app.secret_key = "FizMat"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///READY.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(days=5)


@app.route("/")
def welcome():
    return redirect(url_for("main"))


@app.route("/kz", methods=["GET", "POST"])
def main():
    if request.method == "GET":
        return render_template("main.html", link="http://127.0.0.1")
    else:
        return None


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)