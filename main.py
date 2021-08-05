from flask import Flask, render_template, request, url_for, redirect, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
login_manager = LoginManager()

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["DOWNLOADS"] = "/static/files/"
db = SQLAlchemy(app)
login_manager.init_app(app)



##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method == "POST":

        hashed_pass = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256', salt_length=8)

        new_user = User(
        email=request.form.get('email'),
        password=hashed_pass,
        name = request.form['name'],
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return render_template("secrets.html", name=request.form['name'])

    return render_template("register.html")




@app.route('/login', methods=['POST','GET'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        name = user.name
        if check_password_hash(pwhash=user.password, password=password):
            login_user(user)
            return render_template("secrets.html", name=name)
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', filename="files/cheat_sheet.pdf")

if __name__ == "__main__":
    app.run(debug=True)
