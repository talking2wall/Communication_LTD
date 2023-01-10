from flask import Flask, flash, render_template, redirect, request, url_for, session
from flask_mysqldb import MySQL, MySQLdb
import bcrypt
from configparser import ConfigParser
import re
from flask_mail import Mail, Message
import uuid
import ssl

app = Flask(__name__)

# MySQL credentials
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Flask@123'
app.config['MYSQL_DB'] = 'comunication_ltd'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)


# Email credentials
app.config['MAIL_SERVER'] = 'CENSORED'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'CENSORED'
app.config['MAIL_PASSWORD'] = 'CENSORED'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)


def generate_sha1(email):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, email))


def load_passwords_config():
    config = ConfigParser()
    config.read("configs/passwords_config.ini")
    return config['PASSWORDS']


# Load passwords config
config = load_passwords_config()


# check if string (password) contains at least one special character
def is_contain_special_character(str): 
    regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]') 
    if(regex.search(str) == None): 
        is_contains_special_char = False
    else: 
        is_contains_special_char = True
    return(is_contains_special_char)


# home page
@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')


# forgot password page
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot_password.html')
    else:
        # Check if email exists in the database
        email = request.form['email']
        cur = mysql.connection.cursor()
        count = cur.execute("SELECT * FROM users WHERE Email=%s", [email])
        user = cur.fetchone()
        cur.close()
        
        # if email found (or not found) -> send a reset password request
        if (count != 0):
            token = generate_sha1(email)
            reset_password_link = request.url_root + 'reset_password/' + token

            # add token to the assigned email address
            cur = mysql.connection.cursor()
            cur.execute("UPDATE users SET token = %s WHERE Email = %s", (token, email))
            cur.close()
            mysql.connection.commit()

            # send a reset password request to the assigned email adress
            msg = Message(subject='Communication LTD - Reset Password request', sender=app.config.get('MAIL_USERNAME'), recipients = [email])
            msg.html = render_template('reset_password_form.html', username = user['Username'], reset_password_link = reset_password_link)
            mail.send(msg)
        
        # show this message (even if email found or not)
        flash('A password reset request has been sent to your Email address.')

        return render_template("forgot_password.html")


# reset password page
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):

    # if user is logged in, redirect him back to home page
    if 'login' in session:
        return redirect('/')

    # check if the token exists in the database
    cur = mysql.connect.cursor()
    count = cur.execute('SELECT * FROM users WHERE token=%s', [token])
    cur.close()

    if (count == 0):
        return "Invalid token."

    if request.method == 'GET':
        return render_template("reset_password.html", token = token)
    else:
        new_password = request.form['psw']
        confirm_new_password = request.form['confirm_psw']

        if (new_password != confirm_new_password):
            flash('Error: Password do not match, please enter again.', 'alert')
            return render_template("reset_password.html", token = token)
        else: # update password and redirect to home page
            password = new_password.encode('utf-8')

            # password validation
            if (config['allow_simple_password'] == 'False'): # for debug purposes only

                # check if password is long enough
                if len(password) < int(config['minimal_password_length']):
                    flash('Error: password must contain at least {0} characters.'.format(config['minimal_password_length']), 'alert')
                    return render_template("reset_password.html", token = token)

                # check if password contains at least one lowercase character
                if config['must_contain_lowercase_characters'] == 'True':
                    if not any(x.islower() for x in password.decode('utf-8')): # if there's no at least one lowercase letter
                        flash('Error: password must contain at least one lowercase letter.', 'alert')
                        return render_template("reset_password.html", token = token)

                # check if password contains at least one uppercase character
                if config['must_contain_uppercase_characters'] == 'True':
                    if not any(x.isupper() for x in password.decode('utf-8')): # if there's no at least one uppercase letter
                        flash('Error: password must contain at least one uppercase letter.', 'alert')
                        return render_template("reset_password.html", token = token)

                # check if password contains at least one numeric character
                if config['must_contain_numeric_characters'] == 'True':
                    if not any(x.isnumeric() for x in password.decode('utf-8')): # if there's no at least one numeric character
                        flash('Error: password must contain at least one numeric character.', 'alert')
                        return render_template("reset_password.html", token = token)

                # check if password contains special characters
                if config['must_contain_special_characters'] == 'True':
                    if not is_contain_special_character(password.decode('utf-8')): # if there's no at least one special character
                        flash('Error: password must contain one special character.', 'alert')
                        return render_template("reset_password.html", token = token)
        

            # encrypt password + add salt
            hash_password = bcrypt.hashpw(password, bcrypt.gensalt())

            # update the password in database and remove token
            cur = mysql.connection.cursor()
            count = cur.execute('UPDATE users SET Password = %s WHERE token = %s', (hash_password, token))
            cur.execute('UPDATE users SET token = NULL WHERE token = %s', [token])
            mysql.connection.commit()
            cur.close()
            
            # show information message
            flash('Password has updated successfuly.', 'info')
            return render_template("reset_password.html", token = token)


# register page
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
        count = cur.execute("SELECT * FROM users WHERE Email=%s", [email])
        if (count != 0):
            flash('Error: This email address is already in use.')
            return render_template("register.html", username = username)

        # check if username is already taken
        cur = mysql.connection.cursor()
        count = cur.execute("SELECT * FROM users WHERE Username=%s", [username])
        if (count != 0):
            flash('Error: This Username is already taken.')
            return render_template("register.html", username = username, email = email)

        # password validation
        if (config['allow_simple_password'] == 'False'): # for debug purposes only

            # check if password is long enough
            if len(password) < int(config['minimal_password_length']):
                flash('Error: password must contain at least {0} characters.'.format(config['minimal_password_length']))
                return render_template("register.html", username = username, email = email)

            # check if password contains at least one lowercase character
            if config['must_contain_lowercase_characters'] == 'True':
                if not any(x.islower() for x in password.decode('utf-8')): # if there's no at least one lowercase letter
                    flash('Error: password must contain at least one lowercase letter.')
                    return render_template("register.html", username = username, email = email)

            # check if password contains at least one uppercase character
            if config['must_contain_uppercase_characters'] == 'True':
                if not any(x.isupper() for x in password.decode('utf-8')): # if there's no at least one uppercase letter
                    flash('Error: password must contain at least one uppercase letter.')
                    return render_template("register.html", username = username, email = email)

            # check if password contains at least one numeric character
            if config['must_contain_numeric_characters'] == 'True':
                if not any(x.isnumeric() for x in password.decode('utf-8')): # if there's no at least one numeric character
                    flash('Error: password must contain at least one numeric character.')
                    return render_template("register.html", username = username, email = email)

            # check if password contains special characters
            if config['must_contain_special_characters'] == 'True':
                if not is_contain_special_character(password.decode('utf-8')): # if there's no at least one special character
                    flash('Error: password must contain one special character.')
                    return render_template("register.html", username = username, email = email)
        

        # encrypt password + add salt
        hash_password = bcrypt.hashpw(password, bcrypt.gensalt())
        
        # connect to database and insert new user data
        cur = mysql.connection.cursor()
        cur.execute('INSERT INTO users (Username,Password,Email) VALUES (%s,%s,%s)', (username,hash_password,email))
        mysql.connection.commit()
        cur.close()
        session['name'] = username
        session['email'] = email

    # redirect to home page
    return redirect(url_for('home'))
        

# login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    # create a login-attempt-cookie for the user
    if 'WrongLoginAttemptCount' not in session:
        session['WrongLoginAttemptCount'] = 0

    # handle the GET / POST request:
    if request.method == 'GET':
        return render_template('login.html')
    else:
        # if too many wrong login attempts were made, show error message and stop the login proccess
        if (session['WrongLoginAttemptCount'] >= int(config['max_login_attempts']) - 1):
            flash('Error: Too many incorrect login attempts. Please review the mail sent to this Email address.')
            return render_template("login.html")

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
                session['login'] = True
                session['name'] = user['Username']
                session['email'] = user['Email']
                flash('You were successfully logged in')
                return redirect(url_for('home'))
            else: # passwords do not match
                session['WrongLoginAttemptCount'] = session['WrongLoginAttemptCount'] + 1
                flash('Error: Email or password do not match.')
                return render_template("login.html", email = email)
        else: # email doesn't exist in Database
            flash('Error: Email or password do not match.') # not user is registered with this email
            return render_template("login.html", email = email)


# logout page/button
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


# Vulnerable page
@app.route('/vulnerable_page', methods=['GET'])
def vulnerable_page():
    return render_template('vulnerable_page.html')


if __name__ == '__main__':
    app.secret_key = 'aB,.9AS98ahs*$#^n%'
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) # can also choose: ssl.PROTOCOL_TLSv1_2
    context.load_cert_chain(certfile='certificate/cert.pem', keyfile='certificate/key.pem')
    app.run(debug=True, ssl_context=context)