from flask import Flask, flash, render_template, redirect, request, url_for, session
from flask_mysqldb import MySQL, MySQLdb
import bcrypt
from configparser import ConfigParser


app = Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Flask@123'
app.config['MYSQL_DB'] = 'comunication_ltd'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)


def load_passwords_config():
    config = ConfigParser()
    config.read("configs/passwords_config.ini")
    return config['PASSWORDS']


# Load passwords config
config = load_passwords_config()


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    else:
        # collect data from the post request
        username = request.form['uname']
        password = request.form['psw'].encode('utf-8')
        email = request.form['email']

        # Email validation
        cur = mysql.connection.cursor()
        count = cur.execute("SELECT * FROM users WHERE Email=%s", (email,))
        if (count != 0):
            flash('Error: This email address is already in use.')
            return render_template("register.html", username = username)

        # check if username is already taken
        cur = mysql.connection.cursor()
        count = cur.execute("SELECT * FROM users WHERE Username=%s", (username,))
        if (count != 0):
            flash('Error: This Username is already taken.')
            return render_template("register.html", username = username, email = email)

        # check if password is long enough
        if len(password) < int(config['minimal_password_length']):
            flash('Error: password must contain at least {0} characters.'.format(config['minimal_password_length']))
            return render_template("register.html", username = username, email = email)

        # check if password contains capital letters
        if config['must_include_capital_letters'] == 'True':
            if not any(x.isupper() for x in password.decode('utf-8')): # if there's no at least one capital letter
                flash('Error: password must contain uppercase letters.')
                return render_template("register.html", username = username, email = email)


        # If email is valid...
        hash_password = bcrypt.hashpw(password, bcrypt.gensalt())
        
        # connect to database and insert new user data
        cur = mysql.connection.cursor()
        cur.execute('INSERT INTO users (Username,Password,Email) VALUES (%s,%s,%s)', (username,hash_password,email))
        mysql.connection.commit()
        session['name'] = username
        session['email'] = email

    # redirect to home page
    return redirect(url_for('home'))
        

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        # retrieve the data from the POST request
        email = request.form['email']
        password = request.form['psw'].encode('utf-8')

        # check if email exist in database
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()

        if user != None: # if email exist in Database
            if bcrypt.hashpw(password, user['Password'].encode('utf-8')) == user['Password'].encode('utf-8'): # if passwords match
                session['name'] = user['Username']
                session['email'] = user['Email']
                flash('You were successfully logged in')
                
                return redirect(url_for('home'))
            else:
                flash('Error: Email or password do not match.') # passwords do not match
                return render_template("login.html")
        else:
            flash('Error: Email or password do not match.') # not user is registered with this email
            return render_template("login.html")


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.secret_key = 'aB,.9AS98ahs*$#^n%'
    app.run()