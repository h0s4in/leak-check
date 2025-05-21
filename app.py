from flask import Flask, request, jsonify, redirect, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask import send_from_directory
from pymongo import MongoClient
import bcrypt
import re
import hashlib
import requests

app = Flask(__name__)

@app.route("/")
def home():
    return redirect("/login.html")

@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)

def is_password_strong(password):
    if len(password) < 8:
        return False, "Password Must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|]", password):
        return False, "Password must contain at least one special character."
    return True, ""


def is_password_leaked(password):
    password_hash = hashlib.sha1(password.encode()).hexdigest()
    if password_hash:
        identifier = password_hash[:5]
        pwn_response = requests.get(f"https://api.pwnedpasswords.com/range/{identifier}")
        if pwn_response.status_code == 200:
            hashes = pwn_response.text.splitlines()
            for line in hashes:
                hash_suffix, count = line.split(":")
                if hash_suffix.lower() == password_hash[5:].lower():
                    return False, f"Password has been leaked {count} times!"
    return True, "Safe password"

# Configure Flask-JWT-Extended
app.config["JWT_SECRET_KEY"] = "superfuckingsecretforthejwtsigning"  # Change this to a strong secret key
jwt = JWTManager(app)

# Set up MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["flask_jwt_db"]  # Name of the database
users_collection = db["users"]  # Collection for users


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    is_valid, message = is_password_strong(password)
    if not is_valid:
        return jsonify({"message": message}), 400

    is_leaked, response = is_password_leaked(password)
    if not is_leaked:
        return jsonify({"message": response}), 400

    if users_collection.find_one({"username": username}):
        return jsonify({"message": "User already exists!"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    users_collection.insert_one({
        "username": username,
        "password": hashed_password
    })

    return jsonify({"message": "User registered successfully!"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    # Find the user in the database
    user = users_collection.find_one({"username": data["username"]})
    if not user:
        return jsonify({"message": "User not found!"}), 404

    # Check if the password is correct
    if not bcrypt.checkpw(data["password"].encode('utf-8'), user["password"]):
        return jsonify({"message": "Invalid password!"}), 401

    # Create a JWT token for the user
    access_token = create_access_token(identity=data["username"])

    return jsonify(access_token=access_token), 200

@app.route("/panel", methods=["GET"])
@jwt_required()
def panel():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hello {current_user}!"})

@app.route("/logout", methods=["POST"])
def logout():
    return jsonify({"message": "You have logged out!"}), 200

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)

