import sqlite3

DATABASE = "./sqlite3.db"
MAX_LENGTH_OF_NOTE = 10_000

print("*** Database initialization ***")

data_base_connection = sqlite3.connect(DATABASE)
data_base = data_base_connection.cursor()

data_base.execute("DROP TABLE IF EXISTS blocked_addresses_ip;")
data_base.execute("CREATE TABLE blocked_addresses_ip (address_ip VARCHAR(40), series_of_failed_logins INTEGER NOT NULL, blocked_until timestamp);")
data_base.execute("DELETE FROM blocked_addresses_ip;")

data_base.execute("DROP TABLE IF EXISTS user;")
data_base.execute("CREATE TABLE user (username VARCHAR(30), password VARCHAR(128));")
data_base.execute("DELETE FROM user;")

data_base.execute("DROP TABLE IF EXISTS notes;")
data_base.execute(f"CREATE TABLE notes (note_id INTEGER PRIMARY KEY, username VARCHAR(30), title VARCHAR(30), note VARCHAR({MAX_LENGTH_OF_NOTE }), is_public INTEGER NOT NULL, password_hash VARCHAR(128), AES_salt VARCHAR(25), init_vector VARCHAR(25));")
data_base.execute("DELETE FROM notes;")

data_base_connection.commit()
