from flask import Flask, flash, render_template, redirect, request, url_for, session
from flask_mysqldb import MySQL, MySQLdb
import bcrypt
from configparser import ConfigParser
import re
from flask_mail import Mail, Message
import ssl
import hmac
import hashlib
import secrets

app = Flask(__name__)


# MySQL server configuration
def mysql_database_config():
    global mysql
    mysql_config = ConfigParser()
    mysql_config.read('configs/mysql_config.ini')
    app.config['MYSQL_HOST'] = mysql_config.get('MYSQL', 'MYSQL_HOST')
    app.config['MYSQL_USER'] = mysql_config.get('MYSQL', 'MYSQL_USER')
    app.config['MYSQL_PASSWORD'] = mysql_config.get('MYSQL', 'MYSQL_PASSWORD')
    app.config['MYSQL_DB'] = mysql_config.get('MYSQL', 'MYSQL_DB')
    app.config['MYSQL_CURSORCLASS'] = mysql_config.get('MYSQL', 'MYSQL_CURSORCLASS')
    mysql = MySQL(app)


# email server configuration
def load_smtp_config():
    config = ConfigParser()
    config.read('configs/smtp_config.ini')
    app.config['MAIL_SERVER'] = config.get('SMTP', 'MAIL_SERVER')
    app.config['MAIL_PORT'] = config.getint('SMTP', 'MAIL_PORT')
    app.config['MAIL_USERNAME'] = config.get('SMTP', 'MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = config.get('SMTP', 'MAIL_PASSWORD')
    app.config['MAIL_USE_TLS'] = config.getboolean('SMTP', 'MAIL_USE_TLS')
    app.config['MAIL_USE_SSL'] = config.getboolean('SMTP', 'MAIL_USE_SSL')
    global mail
    mail = Mail(app)


# generates a random token, and encrypting it by sha1
def generate_sha1():
    random_token = secrets.token_hex(32)
    sha1 = hashlib.sha1()
    sha1.update(random_token.encode())
    return sha1.hexdigest()


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
        count = cur.execute('SELECT * FROM users WHERE Email=%s', [email])
        user = cur.fetchone()
        cur.close()
        
        # if email found (or not found) -> send a reset password request
        if (count != 0):
            token = generate_sha1()
            reset_password_link = request.url_root + 'reset_password/' + token

            # add token to the assigned email address
            cur = mysql.connection.cursor()
            cur.execute('UPDATE users SET Token = %s, TokenDate = NOW() WHERE Email = %s', (token, email))
            cur.close()
            mysql.connection.commit()

            # send a reset password request to the assigned email adress
            msg = Message(subject='Communication LTD - Reset Password request', sender = app.config.get('MAIL_USERNAME'), recipients = [email])
            msg.html = render_template('reset_password_form.html', username = user['Username'], reset_password_link = reset_password_link)
            mail.send(msg)
        
        # show this message (even if email found or not)
        flash('A password reset request has been sent to your Email address.')

        return render_template('forgot_password.html')


# reset password page
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):

    # if user is logged in, redirect him back to home page
    if 'login' in session:
        return redirect('/')

    # check if the token exists in the database
    cur = mysql.connect.cursor()

    # check if token exists in database
    count = cur.execute('SELECT * FROM users WHERE Token=%s', [token])    

    if (count == 0):
        cur.close()
        return 'Invalid token.'

    # check if he token is expired (24 hours already left since the token was created)
    count = cur.execute('SELECT * FROM users WHERE Token = %s AND TokenDate > DATE_SUB(NOW(), INTERVAL 1 HOUR)', [token])

    if (count == 0):
        cur.close()
        return 'Expired token.'

    if request.method == 'GET':
        return render_template('reset_password.html', token = token)
    else:
        new_password = request.form['psw']
        confirm_new_password = request.form['confirm_psw']

        if (new_password != confirm_new_password):
            flash('Error: Passwords do not match, please enter again.', 'alert')
            return render_template('reset_password.html', token = token)
        else: # update password and redirect to home page
            password = new_password.encode('utf-8')

            # password validation
            if (PasswordsConfig.getboolean('PASSWORDS', 'allow_simple_password')) == False: # for debug purposes only

                ### check if the password is exists in passwords_history table
                # get userid by token
                cur = mysql.connection.cursor()
                cur.execute('SELECT * FROM users WHERE Token=%s', [token])
                user = cur.fetchone()
                userid = user['userid']
                # encrypt password + add salt
                hash_password = bcrypt.hashpw(password, bcrypt.gensalt())

                # get all encrypted passwords from the passwords_history table
                cur.execute('SELECT Password FROM passwords_history WHERE userid = %s', [userid])
                passwords_list = cur.fetchall()

                # check if one of the passwords was used before
                for password_with_salt in passwords_list:
                    if (bcrypt.hashpw(password, password_with_salt['Password'].encode('utf-8')) == password_with_salt['Password'].encode('utf-8')):
                        flash('Error: This password was already in use.', 'alert')
                        return render_template('reset_password.html', token = token)

                # check if password is long enough
                if len(password) < PasswordsConfig.getint('PASSWORDS', 'minimal_password_length'):
                    flash('Error: password must contain at least {0} characters.'.format(PasswordsConfig.get('PASSWORDS', 'minimal_password_length')), 'alert')
                    return render_template('reset_password.html', token = token)

                # check if password is too long
                if len(password) > PasswordsConfig.getint('PASSWORDS', 'maximal_password_length'):
                    flash('Error: Password must not contain over {0} characters.'.format(PasswordsConfig.get('PASSWORDS', 'maximal_password_length')))
                    return render_template('register.html', token = token)

                # check if password contains at least one lowercase character
                if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_lowercase_characters'):
                    if not any(x.islower() for x in password.decode('utf-8')): # if there's no at least one lowercase letter
                        flash('Error: password must contain at least one lowercase letter.', 'alert')
                        return render_template('reset_password.html', token = token)

                # check if password contains at least one uppercase character
                if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_uppercase_characters'):
                    if not any(x.isupper() for x in password.decode('utf-8')): # if there's no at least one uppercase letter
                        flash('Error: password must contain at least one uppercase letter.', 'alert')
                        return render_template('reset_password.html', token = token)

                # check if password contains at least one numeric character
                if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_numeric_characters'):
                    if not any(x.isnumeric() for x in password.decode('utf-8')): # if there's no at least one numeric character
                        flash('Error: password must contain at least one numeric character.', 'alert')
                        return render_template('reset_password.html', token = token)

                # check if password contains special characters
                if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_special_characters'):
                    if not is_contain_special_character(password.decode('utf-8')): # if there's no at least one special character
                        flash('Error: password must contain one special character.', 'alert')
                        return render_template('reset_password.html', token = token)
        
                # check for unsafe passwords / block dictionary attacks (we could also use a suffix tree to improve the complexity time)
                for line in unsafe_passwords_list:
                    if password == line.strip().encode():
                        flash('Error: Password is too weak, please try another one.', 'alert')
                        return render_template('register.html', token = token)


            # update the password in database (in users and passwords_history), and delete token
            count = cur.execute('SELECT * FROM passwords_history WHERE userid = %s', [userid])

            if count >= PasswordsConfig.getint('PASSWORDS', 'password_history'):
                # delete last entery
                cur.execute('DELETE FROM passwords_history WHERE userid = %s ORDER BY DateChanged ASC LIMIT 1', [userid])
                mysql.connection.commit()

            cur.execute('UPDATE users SET Password = %s WHERE token = %s', (hash_password, token))
            cur.execute('UPDATE users SET token = NULL WHERE token = %s', [token])
            cur.execute('INSERT INTO passwords_history (userid,Password,DateChanged) VALUES (%s,%s,NOW())', (userid,hash_password))
            mysql.connection.commit()
            cur.close()

            # show information message
            flash('Password has updated successfuly.', 'info')
            return render_template('reset_password.html', token = token)


# register page (sqli)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    else:
        # collect data from the post request
        username = request.form['uname']
        password = request.form['psw'].encode('utf-8')
        confirm_password = request.form['confirm_psw'].encode('utf-8')
        email = request.form['email']

        if (password != confirm_password):
            flash('Error: Passwords do not match, please enter again.')
            return render_template('register.html', username = username, email = email)

        # Email validation
        cur = mysql.connection.cursor()
        count = cur.execute('SELECT * FROM users WHERE Email=%s', [email])
        if (count != 0):
            flash('Error: This email address is already in use.')
            return render_template('register.html', username = username)

        # check if username is already taken
        cur = mysql.connection.cursor()
        count = cur.execute('SELECT * FROM users WHERE Username=%s', [username])
        if (count != 0):
            flash('Error: This Username is already taken.')
            return render_template('register.html', username = username, email = email)
        
        # password validation
        if PasswordsConfig.getboolean('PASSWORDS', 'allow_simple_password') == False: # for debug purposes only

            # check if password is long enough
            if len(password) < PasswordsConfig.getint('PASSWORDS', 'minimal_password_length'):
                flash('Error: password must contain at least {0} characters.'.format(PasswordsConfig.get('PASSWORDS', 'minimal_password_length')))
                return render_template('register.html', username = username, email = email)

            # check if password is too long
            if len(password) > PasswordsConfig.getint('PASSWORDS', 'maximal_password_length'):
                flash('Error: Password must not contain over {0} characters.'.format(PasswordsConfig.get('PASSWORDS', 'maximal_password_length')))
                return render_template('register.html', username = username, email = email)

            # check if password contains at least one lowercase character
            if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_lowercase_characters'):
                if not any(x.islower() for x in password.decode('utf-8')): # if there's no at least one lowercase letter
                    flash('Error: password must contain at least one lowercase character.')
                    return render_template('register.html', username = username, email = email)

            # check if password contains at least one uppercase character
            if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_uppercase_characters'):
                if not any(x.isupper() for x in password.decode('utf-8')): # if there's no at least one uppercase letter
                    flash('Error: password must contain at least one uppercase character.')
                    return render_template('register.html', username = username, email = email)

            # check if password contains at least one numeric character
            if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_numeric_characters'):
                if not any(x.isnumeric() for x in password.decode('utf-8')): # if there's no at least one numeric character
                    flash('Error: password must contain at least one numeric character.')
                    return render_template('register.html', username = username, email = email)

            # check if password contains special characters
            if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_special_characters'):
                if not is_contain_special_character(password.decode('utf-8')): # if there's no at least one special character
                    flash('Error: password must contain one special character.')
                    return render_template('register.html', username = username, email = email)
        
            # check for unsafe passwords / block dictionary attacks (we could also use a suffix tree to improve the complexity time)
            for line in unsafe_passwords_list:
                if password == line.strip().encode():
                    flash('Error: Password is too weak, please try another one.', 'alert')
                    return render_template('register.html', username = username, email = email)

        # encrypt password + add salt
        hash_password = bcrypt.hashpw(password, bcrypt.gensalt())
        
        # connect to database and insert new user data
        cur = mysql.connection.cursor()
        ##############################################################################################
        ################################## SQL INJECTION ALERT #######################################
        ########### This part of code made intentionally vulnerable to sql injection attack! #########
        ##############################################################################################
        # UNSAFE to update the database (vulnerable to SQL INJECTION attack)
        cur.execute('INSERT INTO users (Username,Password,Email,Admin) VALUES (\'{0}\',\'{1}\',\'{2}\',{3})'.format(username, hash_password.decode() , email, 0))

        # SAFE way to update the database
        #cur.execute('INSERT INTO users (Username,Password,Email,Admin) VALUES (%s,%s,%s,%s)', (username,hash_password,email,0))
        # and even safer
        #cur.execute('INSERT INTO users (Username,Password,Email) VALUES (%s,%s,%s)', (username,hash_password,email))
        mysql.connection.commit()
        ##############################################################################################
        
        # get user by email
        cur.execute('SELECT * FROM users WHERE email=%s', [email])
        user = cur.fetchone()
        userid = user['userid']

        # update the passwords_history table
        cur.execute('INSERT INTO passwords_history (userid,Password,DateChanged) VALUES (%s,%s,NOW())', (userid,hash_password))
        mysql.connection.commit()
        session['login'] = True
        session['name'] = username
        session['email'] = email
        session['admin'] = user['Admin']
        cur.close()

    # redirect to home page
    return redirect(url_for('home'))
        

# login page (sqli)
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
        if (session['WrongLoginAttemptCount'] >= PasswordsConfig.getint('PASSWORDS', 'max_login_attempts') - 1):
            flash('Error: Too many incorrect login attempts. Please review the mail sent to this Email address.')
            return render_template('login.html')

        # retrieve the data from the POST request
        email = request.form['email']
        password = request.form['psw'].encode('utf-8')

        # check if email exist in database
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        ##############################################################################################
        ################################## SQL INJECTION ALERT #######################################
        ########### This part of code made intentionally vulnerable to sql injection attack! #########
        ##############################################################################################
        # UNSAFE to update the database (vulnerable to SQL INJECTION attack)
        # assuming the database passwords was not encrypted & this could be a valid way to make a (vulnerable) login page
        ALLOW_UNSADE_LOGIN = True
        ASSUME_PASSWORDS_NOT_ENCRYPTED_WITH_SALT = False
        UNSAFE_LOGIN = False
        if ALLOW_UNSADE_LOGIN and ASSUME_PASSWORDS_NOT_ENCRYPTED_WITH_SALT:
            count = cur.execute('SELECT * FROM users WHERE email = \'{0}\' AND Password = \'{1}\''.format(email, password))
            if count != 0:
                UNSAFE_LOGIN = True
            else:
                UNSAFE_LOGIN = False
        else:         
            # SAFE way
            cur.execute('SELECT * FROM users WHERE email = %s', [email])
        ##############################################################################################
        user = cur.fetchone()
        cur.close()

        if user != None or UNSAFE_LOGIN: # if email exist in Database
            if bcrypt.hashpw(password, user['Password'].encode('utf-8')) == user['Password'].encode('utf-8') or UNSAFE_LOGIN: # if passwords match
                session['login'] = True
                session['name'] = user['Username']
                session['email'] = user['Email']
                session['admin'] = user['Admin']
                #flash('You were successfully logged in')
                return redirect(url_for('home'))
            else: # passwords do not match
                session['WrongLoginAttemptCount'] = session['WrongLoginAttemptCount'] + 1
                flash('Error: Incorrect login, Email or password do not match.')
                return render_template('login.html', email = email)
        else: # email doesn't exist in Database
            flash('Error: Incorrect login, Email or password do not match.')
            return render_template('login.html', email = email)


# logout page/button
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


# Settings page
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'GET':
        return render_template('settings.html')
    else:
        # collect data from the post request
        current_password = request.form['current-password']
        new_password = request.form['new-password']
        confirm_password = request.form['confirm-password']

        # grab the user password from the database
        cur = mysql.connection.cursor()
        cur.execute('SELECT * FROM users WHERE Email = %s', [session['email']])
        user = cur.fetchone()

        # encode the new password to avoid using unicode characters (and for bcrypt)
        password = new_password.encode('utf-8')

        # check if the current password is correct
        if bcrypt.hashpw(current_password.encode('utf-8'), user['Password'].encode('utf-8')) != user['Password'].encode('utf-8'):
            flash('Error: The password was incorrect.', 'alert')
            return render_template('settings.html')

        # check if the new_password equals to the confirm_password
        if (new_password != confirm_password):
            flash('Error: The new password and \'confirm password\' do not much.', 'alert')
            return render_template('settings.html') 

        # password validation
        if PasswordsConfig.getboolean('PASSWORDS', 'allow_simple_password') == False: # for debug purposes only

            ### check if the password is exists in passwords_history table
            # get userid by token
            cur = mysql.connection.cursor()
            cur.execute('SELECT * FROM users WHERE Email = %s', [session['email']])
            user = cur.fetchone()
            userid = user['userid']
            # encrypt password + add salt
            hash_password = bcrypt.hashpw(password, bcrypt.gensalt())

            # get all encrypted passwords from the passwords_history table
            cur.execute('SELECT Password FROM passwords_history WHERE userid = %s', [userid])
            passwords_list = cur.fetchall()

            # check if one of the passwords was used before
            for password_with_salt in passwords_list:
                if (bcrypt.hashpw(password, password_with_salt['Password'].encode('utf-8')) == password_with_salt['Password'].encode('utf-8')):
                    flash('Error: This password was already in use.', 'alert')
                    return render_template('settings.html')

            # check if password is long enough
            if len(password) < PasswordsConfig.getint('PASSWORDS', 'minimal_password_length'):
                flash('Error: password must contain at least {0} characters.'.format(PasswordsConfig.get('PASSWORDS', 'minimal_password_length')), 'alert')
                return render_template('settings.html')

            # check if password is too long
            if len(password) > PasswordsConfig.getint('PASSWORDS', 'maximal_password_length'):
                flash('Error: Password must not contain over {0} characters.'.format(PasswordsConfig.get('PASSWORDS', 'maximal_password_length')), 'alert')
                return render_template('settings.html')

            # check if password contains at least one lowercase character
            if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_lowercase_characters'):
                if not any(x.islower() for x in password.decode('utf-8')): # if there's no at least one lowercase letter
                    flash('Error: password must contain at least one lowercase character.', 'alert')
                    return render_template('settings.html')

            # check if password contains at least one uppercase character
            if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_uppercase_characters'):
                if not any(x.isupper() for x in password.decode('utf-8')): # if there's no at least one uppercase letter
                    flash('Error: password must contain at least one uppercase character.', 'alert')
                    return render_template('settings.html')

            # check if password contains at least one numeric character
            if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_numeric_characters'):
                if not any(x.isnumeric() for x in password.decode('utf-8')): # if there's no at least one numeric character
                    flash('Error: password must contain at least one numeric character.', 'alert')
                    return render_template('settings.html')

            # check if password contains special characters
            if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_special_characters'):
                if not is_contain_special_character(password.decode('utf-8')): # if there's no at least one special character
                    flash('Error: password must contain one special character.', 'alert')
                    return render_template('settings.html')
        
            # check for unsafe passwords / block dictionary attacks (we could also use a suffix tree to improve the complexity time)
            for line in unsafe_passwords_list:
                if password == line.strip().encode():
                    flash('Error: Password is too weak, please try another one.', 'alert')
                    return render_template('settings.html')

        
        # update the password in database (in users and passwords_history), and delete token
        count = cur.execute('SELECT * FROM passwords_history WHERE userid = %s', [user['userid']])

        if count >= PasswordsConfig.getint('PASSWORDS', 'password_history'):
            # delete last entery
            cur.execute('DELETE FROM passwords_history WHERE userid = %s ORDER BY DateChanged ASC LIMIT 1', [user['userid']])
            mysql.connection.commit()

        cur.execute('UPDATE users SET Password = %s WHERE userid = %s', (hash_password, (user['userid'])))
        cur.execute('INSERT INTO passwords_history (userid,Password,DateChanged) VALUES (%s,%s,NOW())', (user['userid'],hash_password))
        mysql.connection.commit()
        cur.close()

        # show information message
        flash('Password has updated successfuly.', 'info')
        return render_template('settings.html')


# System page (sqli)
@app.route('/system', methods=['GET', 'POST'])
def system():
    # get the user data from the database
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM users WHERE Email = %s', [session['email']])
    user = cur.fetchone()

    # if user is not admin, don't show the page
    if user['Admin'] != 1:
        return "Unauthorized."

    if request.method == 'GET':
        return render_template('system.html')
    else:
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        confirm_password = request.form['confirm-password'].encode('utf-8')
        email = request.form['email']

        if (password != confirm_password):
            flash('Error: Passwords do not match, please enter again.', 'alert')
            return render_template('system.html', username = username, email = email)

        # Email validation
        cur = mysql.connection.cursor()
        count = cur.execute('SELECT * FROM users WHERE Email=%s', [email])
        if (count != 0):
            flash('Error: This email address is already in use.', 'alert')
            return render_template('system.html', username = username)

        # check if username is already taken
        cur = mysql.connection.cursor()
        count = cur.execute('SELECT * FROM users WHERE Username=%s', [username])
        if (count != 0):
            flash('Error: This Username is already taken.', 'alert')
            return render_template('system.html', username = username, email = email)
        
        # password validation
        if PasswordsConfig.getboolean('PASSWORDS', 'allow_simple_password') == False: # for debug purposes only

            # check if password is long enough
            if len(password) < PasswordsConfig.getint('PASSWORDS', 'minimal_password_length'):
                flash('Error: password must contain at least {0} characters.'.format(PasswordsConfig.get('PASSWORDS', 'minimal_password_length')), 'alert')
                return render_template('system.html', username = username, email = email)

            # check if password is too long
            if len(password) > PasswordsConfig.getint('PASSWORDS', 'maximal_password_length'):
                flash('Error: Password must not contain over {0} characters.'.format(PasswordsConfig.get('PASSWORDS', 'maximal_password_length')), 'alert')
                return render_template('system.html', username = username, email = email)

            # check if password contains at least one lowercase character
            if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_lowercase_characters'):
                if not any(x.islower() for x in password.decode('utf-8')): # if there's no at least one lowercase letter
                    flash('Error: password must contain at least one lowercase character.', 'alert')
                    return render_template('system.html', username = username, email = email)

            # check if password contains at least one uppercase character
            if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_uppercase_characters'):
                if not any(x.isupper() for x in password.decode('utf-8')): # if there's no at least one uppercase letter
                    flash('Error: password must contain at least one uppercase character.', 'alert')
                    return render_template('system.html', username = username, email = email)

            # check if password contains at least one numeric character
            if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_numeric_characters'):
                if not any(x.isnumeric() for x in password.decode('utf-8')): # if there's no at least one numeric character
                    flash('Error: password must contain at least one numeric character.', 'alert')
                    return render_template('system.html', username = username, email = email)

            # check if password contains special characters
            if PasswordsConfig.getboolean('PASSWORDS', 'must_contain_special_characters'):
                if not is_contain_special_character(password.decode('utf-8')): # if there's no at least one special character
                    flash('Error: password must contain one special character.', 'alert')
                    return render_template('system.html', username = username, email = email)
        
            # check for unsafe passwords / block dictionary attacks (we could also use a suffix tree to improve the complexity time)
            for line in unsafe_passwords_list:
                if password == line.strip().encode():
                    flash('Error: Password is too weak, please try another one.', 'alert', 'alert')
                    return render_template('system.html', username = username, email = email)

        # encrypt password + add salt
        hash_password = bcrypt.hashpw(password, bcrypt.gensalt())
        
        # connect to database and insert new user data
        cur = mysql.connection.cursor()

        ##############################################################################################
        ################################## SQL INJECTION ALERT #######################################
        ########### This part of code made intentionally vulnerable to sql injection attack! #########
        ##############################################################################################
        # UNSAFE to update the database (vulnerable to SQL INJECTION attack)
        cur.execute('INSERT INTO users (Username,Password,Email,Admin) VALUES (\'{0}\',\'{1}\',\'{2}\',{3})'.format(username, hash_password.decode() , email, 0))

        # SAFE way to update the database
        #cur.execute('INSERT INTO users (Username,Password,Email,Admin) VALUES (%s,%s,%s,%s)', (username,hash_password,email,0))
        # and even safer
        #cur.execute('INSERT INTO users (Username,Password,Email) VALUES (%s,%s,%s)', (username,hash_password,email))
        mysql.connection.commit()
        ##############################################################################################
        
        # get user by email
        cur.execute('SELECT * FROM users WHERE email=%s', [email])
        user = cur.fetchone()
        userid = user['userid']

        # update the passwords_history table
        cur.execute('INSERT INTO passwords_history (userid,Password,DateChanged) VALUES (%s,%s,NOW())', (userid,hash_password))
        mysql.connection.commit()
        cur.close()

        #flash('The User {0} has been added successfuly.'.format(username), 'info')
        return render_template('system.html', created_username = username)



if __name__ == '__main__':
    app.secret_key = 'aB,.9AS98ahs*$#^n%'
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) # can also choose: ssl.PROTOCOL_TLSv1_2
    context.load_cert_chain(certfile='certificate/cert.pem', keyfile='certificate/key.pem')

    # load smtp config
    load_smtp_config()

    # load mysql config
    mysql_database_config()

    # Load passwords config
    global PasswordsConfig
    PasswordsConfig = ConfigParser()
    PasswordsConfig.read('configs/passwords_config.ini')

    # Load unsafe passwords file
    global unsafe_passwords_list
    unsafe_passwords_file = open('configs/UnsafePasswords.txt', 'r')
    unsafe_passwords_list = unsafe_passwords_file.readlines()
    unsafe_passwords_file.close()

    app.run(debug=True, ssl_context=context)