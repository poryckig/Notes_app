import sqlite3
import bleach
import markdown
from flask import Flask, render_template, request, redirect, flash, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from passlib.hash import bcrypt
from datetime import datetime, timedelta
from cipher_utils import encrypt_note_content, decrypt_note_content
from werkzeug.middleware.proxy_fix import ProxyFix
from input_checks import MAX_LENGTH_OF_NOTE, MIN_ENTROPY_OF_PASSWORD, is_valid_username, is_valid_password, measure_password_complexity, is_valid_note_title, analyze_note_content

PATH_TO_DATABASE = "./sqlite3.db"
MAX_LENGTH_OF_NOTE = 10_000
bleach.ALLOWED_TAGS = []
BCRYPT_ROUNDS = 12
MAX_LOGIN_ATTEMPTS = 4
BLOCK_DURATION_IN_SECONDS = 600


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

auth_manager = LoginManager()
auth_manager.init_app(app)

app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"


class User(UserMixin):
    pass


def block_address_id(address_ip):          # zablokowanie danego adresu ip
    data_base_connection = sqlite3.connect(PATH_TO_DATABASE)
    data_base = data_base_connection.cursor()

    block_until = datetime.now() + timedelta(0, BLOCK_DURATION_IN_SECONDS)    # ustawienie do kiedy ma byc blokada danego adresu ip

    data_base.execute("UPDATE blocked_addresses_ip SET blocked_until = ? WHERE address_ip = ?", (block_until, address_ip))       # uaktualniamy tabelę zbanowanych adresow ip (dla danego adresu ip ustawiamy do kiedy ma byc zablokowany)
    
    data_base.commit()
    data_base.close()


def is_address_ip_blocked(address_ip):
    data_base_connection = sqlite3.connect(PATH_TO_DATABASE, detect_types = sqlite3.PARSE_DECLTYPES)
    data_base = data_base_connection.cursor()

    data_base.execute("SELECT blocked_until FROM blocked_addresses_ip WHERE address_ip = ?", (address_ip,))

    try:
        banned_until, = data_base.fetchone()
        if datetime.now() > banned_until:
            unblock_address_up(address_ip)
            return False
        return True
    except:
        return False


def unblock_address_up(address_ip):
    data_base_connection = sqlite3.connect(PATH_TO_DATABASE)
    data_base = data_base_connection.cursor()

    data_base.execute("DELETE FROM blocked_addresses_ip WHERE address_ip = ?", (address_ip,))
    
    data_base_connection.commit()
    data_base_connection.close()


def increase_ip_address_series_of_failed_logins(address_ip):
    data_base_connection = sqlite3.connect(PATH_TO_DATABASE)
    data_base = data_base_connection.cursor()

    data_base.execute("SELECT series_of_failed_logins FROM blocked_addresses_ip WHERE address_ip = ?", (address_ip,))
    
    try:
        attempts, = data_base.fetchone()

        if attempts > MAX_LOGIN_ATTEMPTS:
            block_address_id(address_ip)

        data_base.execute("UPDATE blocked_addresses_ip SET series_of_failed_logins = ? WHERE address_ip = ?", (attempts + 1, address_ip))

    except:
        attempts = 1
        data_base.execute("INSERT INTO blocked_addresses_ip (address_ip, series_of_failed_logins) VALUES (?, ?)", (address_ip, attempts))
    
    data_base_connection.commit()
    data_base_connection.close()

    return attempts + 1 > MAX_LOGIN_ATTEMPTS


@auth_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    data_base_connection = sqlite3.connect(PATH_TO_DATABASE, detect_types = sqlite3.PARSE_DECLTYPES)
    data_base = data_base_connection.cursor()

    data_base.execute(f"SELECT username, password FROM user WHERE username = ?", (username,))
    
    row = data_base.fetchone()
    data_base_connection.close()
    try:
        username, password = row
    except:
        return None

    user = User()
    user.id = username
    user.password = password

    return user


@auth_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = user_loader(username)
    return user


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        username = str(request.form.get("username"))
        password = str(request.form.get("password"))
        user_ip = request.remote_addr
        user = user_loader(username)

        if user is None:
            flash("Incorrect username or password.")
            return render_template("index.html")

        if is_address_ip_blocked(user_ip):
            flash("Your IP address is temporarily blocked. Please try again later.")
            return render_template("index.html")

        if bcrypt.verify(password, user.password):
            login_user(user)
            return redirect('/welcome')
        else:
            flash("Incorrect username or password.")
            if increase_ip_address_series_of_failed_logins(user_ip):
                flash("Your IP address has been temporarily blocked for 10 minutes.")

            return render_template("index.html")


@ app.route("/logout",  methods=["POST"])
@ login_required
def logout():
    logout_user()
    return redirect("/")


@ app.route("/welcome", methods=['GET'])
@ login_required
def welcome():
    if request.method == 'GET':
        return render_template("welcome.html", username = current_user.id, notes = retrieve_user_notes(current_user.id))


def retrieve_user_notes(username):
    data_base_connection = sqlite3.connect(PATH_TO_DATABASE)
    data_base = data_base_connection.cursor()

    data_base.execute("SELECT note_id, username, title FROM notes WHERE username == ? OR is_public = 1", (username,))
    notes = data_base.fetchall()

    data_base_connection.close()
    return notes


@ app.route("/submit_note", methods=['POST'])
@ login_required
def submit_note():
    note_content = str(request.form.get("markdown", ""))
    note_title = request.form.get("title")
    is_public = request.form.get("public")
    is_encrypted = request.form.get("encrypt")
    encryption_password = str(request.form.get("password"))
    flags_invalid = False

    
    if note_title is None or note_title == "" or note_title.isspace():
        flash("Your note requires a title.")
        return render_template("welcome.html", username = current_user.id, raw_note = note_content, notes = retrieve_user_notes(current_user.id), title = note_title)
    
    if not is_valid_note_title(note_title):
        flash("The title is permitted to have 1-25 alphanumeric characters and special signs.")
        return render_template("welcome.html", username = current_user.id, raw_note = note_content, notes=retrieve_user_notes(current_user.id), title = note_title)
    
    [is_note_valid, note_valid_messages] = analyze_note_content(note_content)
    if not is_note_valid:
        for message in note_valid_messages:
            flash(message)
        return render_template("welcome.html", username = current_user.id, raw_note = note_content, notes = retrieve_user_notes(current_user.id), title = note_title)

    if is_public == None:
        is_public = False
    elif is_public == 'on':
        is_public = True
    else:
        flags_invalid = True
    if is_encrypted == None:
        is_encrypted = False
    elif is_encrypted == 'on':
        is_encrypted = True
    else:
        flags_invalid = True

    if flags_invalid:
        flash("Mistake in render request.")
        return render_template("welcome.html", username = current_user.id, raw_note = note_content, notes = retrieve_user_notes(current_user.id), title = note_title)

    if is_encrypted and is_public:
        flash("The note cannot be simultaneously encrypted and public.")
        return render_template("welcome.html", username = current_user.id, raw_note = note_content, notes = retrieve_user_notes(current_user.id), title = note_title)

    if is_encrypted:
        if not is_valid_password(encryption_password):
            flash("Password should have 10-128 characters, special signs and numbers.")
            return render_template("welcome.html", username = current_user.id, raw_note = note_content, notes=retrieve_user_notes(current_user.id), title = note_title)
        
        [password_too_weak, entropy] = measure_password_complexity(
            encryption_password)
        if password_too_weak:
            flash(f"Too low entropy of password, required entropy: {MIN_ENTROPY_OF_PASSWORD}, your entropy: {entropy}.")
            return render_template("welcome.html", username = current_user.id, raw_note = note_content, notes = retrieve_user_notes(current_user.id), title = note_title)

        cleaned = bleach.clean(note_content)
        rendered = markdown.markdown(cleaned)
        username = current_user.id

        [encrypted, salt, init_vector] = encrypt_note_content(
            rendered, encryption_password)
        encryption_password_hash = bcrypt.using(
            rounds = BCRYPT_ROUNDS).hash(encryption_password)
        data_base_connection = sqlite3.connect(PATH_TO_DATABASE)
        data_base = data_base_connection.cursor()
        data_base.execute(f"INSERT INTO notes (username, title, note, is_public, password_hash, AES_salt, init_vector) VALUES (?, ?, ?, ?, ?, ?, ?)", (username, note_title, encrypted, is_public, encryption_password_hash, salt, init_vector))
        data_base_connection.commit()
        data_base_connection.close()

        return render_template("note.html", rendered = rendered)

    else:
        cleaned = bleach.clean(note_content)
        rendered = markdown.markdown(cleaned)
        username = current_user.id
        data_base_connection = sqlite3.connect(PATH_TO_DATABASE)
        data_base = data_base_connection.cursor()
        data_base.execute(f"INSERT INTO notes (username, title, note, is_public) VALUES (?, ?, ?, ?)", (username, note_title, rendered, is_public))
        data_base_connection.commit()
        data_base_connection.close()
        return render_template("note.html", rendered = rendered)


@ app.route("/note/<rendered_id>", methods=['GET'])
@ login_required
def get_note(rendered_id):
    if request.method == "GET":
        data_base_connection = sqlite3.connect(PATH_TO_DATABASE)
        data_base = data_base_connection.cursor()
        data_base.execute("SELECT note_id, username, is_public, password_hash FROM notes WHERE note_id == ?", (rendered_id,))

        try:
            note_id, username, is_public, password_hash = data_base.fetchone()
            data_base_connection.close()
            if username != current_user.id and not is_public:
                return "Access to note forbidden.", 403

            if password_hash:
                return redirect(f"/note/encrypted/{note_id}")
            return redirect(f"/note/unencrypted/{note_id}")
        except:
            data_base_connection.close()
            return "Note not found.", 404


@app.route("/note/<int:rendered_id>/delete", methods=['POST'])
@login_required
def delete_note(rendered_id):
    note_id = rendered_id
    try:
        data_base_connection = sqlite3.connect(PATH_TO_DATABASE)
        data_base = data_base_connection.cursor()
        # Check if the note belongs to the user before attempting to delete
        data_base.execute("SELECT username FROM notes WHERE note_id == ?", (note_id,))
        note_data = data_base.fetchone()

        if note_data:
            username, = note_data
            if username != current_user.id:
                data_base_connection.close()
                flash("You do not have permission to delete this note.")
                return redirect(url_for('welcome'))

            data_base.execute("DELETE FROM notes WHERE note_id == ?", (note_id,))
            data_base_connection.commit()
            flash("Note has been successfully deleted.")
        else:
            flash("Note is not found.")
        
        data_base_connection.close()
        return redirect(url_for('welcome'))
    except sqlite3.Error as e:
        data_base_connection.close()
        flash(f"A database error occurred: {e}")
        return redirect(url_for('welcome'))


@ app.route("/note/unencrypted/<rendered_id>")
@ login_required
def render_unencrypted(rendered_id):
    data_base_connection = sqlite3.connect(PATH_TO_DATABASE)
    data_base = data_base_connection.cursor()
    data_base.execute(f"SELECT username, note, is_public, password_hash FROM notes WHERE note_id == ?",(rendered_id,))

    try:
        username, note, is_public, password_hash = data_base.fetchone()
        data_base_connection.close()
        if (password_hash):
            return "Access to note forbidden.", 403
        if username != current_user.id and not is_public:
            return "Access to note forbidden.", 403

        return render_template("note.html", rendered = note)
    except:
        data_base_connection.close()
        return "Note is not found.", 404


@app.route("/note/encrypted/<rendered_id>", methods=['GET', 'POST'])
@login_required
def render_encrypted(rendered_id):
    # Ensure note_id is available throughout the function
    note_id = rendered_id  # As rendered_id is the note_id from the URL

    if request.method == 'GET':
        try:
            data_base_connection = sqlite3.connect(PATH_TO_DATABASE)
            data_base = data_base_connection.cursor()
            data_base.execute("SELECT username, password_hash FROM notes WHERE note_id == ?", (note_id,))
            note_data = data_base.fetchone()
            data_base_connection.close()

            if note_data:
                username, password_hash = note_data
                if not password_hash:
                    return "Access to note is forbidden.", 403
                if username != current_user.id:
                    return "Access to note is forbidden.", 403
                return render_template("decipher.html", id=note_id)
            else:
                return "Note is not found.", 404

        except sqlite3.Error as e:
            flash(f"A database error occurred: {e}")
            return redirect(url_for('welcome'))

    if request.method == 'POST':
        password = str(request.form.get("password"))
        try:
            data_base_connection = sqlite3.connect(PATH_TO_DATABASE)
            data_base = data_base_connection.cursor()
            data_base.execute("SELECT username, note, password_hash, AES_salt, init_vector FROM notes WHERE note_id == ?", (note_id,))
            note_data = data_base.fetchone()
            data_base_connection.close()

            if note_data:
                username, encrypted_note, password_hash, salt, init_vector = note_data
                if username != current_user.id:
                    return "Access to note is forbidden.", 403
                if bcrypt.verify(password, password_hash):
                    decrypted_note = decrypt_note_content(encrypted_note, password, salt, init_vector)
                    return render_template("note.html", rendered=decrypted_note)
                else:
                    flash("Password is wrong.")
                    return render_template("decipher.html", id=note_id)
            else:
                return "Note is not found.", 404

        except sqlite3.Error as e:
            flash(f"A database error occurred: {e}")
            return redirect(url_for('welcome'))

    # In case of any other HTTP method
    return "Method Not Allowed", 405


@ app.route("/user/register", methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("sign_up.html")
    if request.method == 'POST':
        username = str(request.form.get('username'))
        password = str(request.form.get('password'))
        is_valid = True

        if not is_valid_password(password):
            flash(
                'Your password should have 10-128 characters, numbers and special signs')
            is_valid = False
        [password_too_weak, entropy] = measure_password_complexity(password)
        if password_too_weak:
            flash(
                f'Too low entropy of password, required entropy: {MIN_ENTROPY_OF_PASSWORD}, your entropy: {entropy}.')
            is_valid = False
        if not is_valid_username(username):
            flash('Your username should have 3-20 alphanumeric characters.')
            is_valid = False
        if user_loader(username):
            flash('Username already taken.')
            is_valid = False
        if not is_valid:
            return render_template("sign_up.html")
        data_base_connection = sqlite3.connect(PATH_TO_DATABASE)
        data_base = data_base_connection.cursor()
        data_base.execute(f"INSERT INTO user (username, password) VALUES (?, ?);",
                    (username, bcrypt.using(rounds = BCRYPT_ROUNDS).hash(password),))

        data_base_connection.commit()
        data_base_connection.close()
        return redirect('/')


@ app.route("/user/passwd", methods=['GET', 'POST'])
@ login_required
def change_password():
    if request.method == "GET":
        return render_template("change_password.html")
    if request.method == "POST":
        password = str(request.form.get("password_old"))
        password_new = str(request.form.get("password_new"))
        password_retyped = str(request.form.get("password_retyped"))

        data_base_connection = sqlite3.connect(
            PATH_TO_DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        data_base = data_base_connection.cursor()
        data_base.execute(
            f"SELECT password FROM user WHERE username = ?", (current_user.id,))
        password_hash, = data_base.fetchone()

        if bcrypt.verify(password, password_hash):
            is_valid = True
            if not is_valid_password(password_new):
                flash('Your password should have 10-128 characters, numbers and special signs.')
                is_valid = False
            [password_too_weak, entropy] = measure_password_complexity(
                password_new)

            if password_too_weak:
                flash(
                    f'Too low entropy of password, required entropy: {MIN_ENTROPY_OF_PASSWORD}, your entropy: {entropy}.')
                is_valid = False
            if password_new != password_retyped:
                flash("Retyped password must be the same as new password.")
                is_valid = False
            if not is_valid:
                return render_template("change_password.html")

            data_base.execute("UPDATE user SET password = ? WHERE username = ?", (bcrypt.using(rounds = BCRYPT_ROUNDS).hash(password_new), current_user.id,))
            data_base_connection.commit()
            data_base_connection.close()
            return redirect("/welcome")
        else:
            data_base_connection.close()
            flash("Password is wrong.")
            return render_template("change_password.html")
