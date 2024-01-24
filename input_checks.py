import bleach
import markdown
import re
from math import log2

MAX_LENGTH_OF_NOTE = 10_000
MIN_ENTROPY_OF_PASSWORD = 3.4

def is_valid_username(username: str):
    username_pattern = r"^[a-zA-Z0-9]{3,20}$"
    compiled_username_pattern = re.compile(username_pattern)
    match_result = re.search(compiled_username_pattern, username)

    if match_result:
        return True
    return False


def is_valid_password(password: str):
    password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,128}$"
    compiled_password_pattern = re.compile(password_pattern)
    match_result = re.search(compiled_password_pattern, password)

    if match_result:
        return True
    return False


def measure_password_complexity(password: str):
    password_entropy = 0.0
    chars_frequency = {}
    for c in password:
        if c in chars_frequency:
            chars_frequency[c] += 1
        else:
            chars_frequency[c] = 1

    length_of_password = len(password)

    for i in chars_frequency:
        probability = password.count(i) / length_of_password
        if probability > 0.0:
            password_entropy += probability * log2(probability)

    return - password_entropy < MIN_ENTROPY_OF_PASSWORD, - password_entropy


def is_valid_note_title(note_title: str):
    if note_title is None or note_title.isspace() or len(note_title) < 1 or len(note_title) > 25:
        return False
    return True


def analyze_note_content(note: str):
    is_valid = True
    feedback_messages = []

    if not note or note.isspace():
        feedback_messages.append("The note cannot be empty.")

    sanitized_content = markdown.markdown(bleach.clean(note))

    if len(sanitized_content) > MAX_LENGTH_OF_NOTE:
        is_valid = False
        feedback_messages.append(f"The note exceeds the maximum allowed length of {MAX_LENGTH_OF_NOTE} characters.")
        return is_valid, feedback_messages

    img_pattern = '<img[^>]*src="([^"]+)"[^>]*>'
    found_images = re.findall(img_pattern, sanitized_content)
    for image_link in found_images:
        print(image_link)
        if is_valid_image_link(image_link):
            is_valid = False
            feedback_messages.append(f"The image link '{image_link}' is not valid.")
            break

    return is_valid, feedback_messages


def is_valid_image_link(image_url: str):
    if not re.search(r"127.0.0.1|localhost", image_url):
        return False
    if not re.search(r"^https:\\", image_url):
        return False
    if not re.search(r".(gif|jpg|jpeg|png)", image_url):
        return False
    return True
