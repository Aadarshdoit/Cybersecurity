from flask import Flask, render_template, request
import re
import hashlib
import requests
app = Flask(__name__)
def check_password_strength(password):
    strength = 0
    remarks = []

    if len(password) >= 8:
        strength += 1
    else:
        remarks.append("Password too short")

    if re.search(r"[A-Z]", password):
        strength += 1
    else:
        remarks.append("Add uppercase letter")

    if re.search(r"[a-z]", password):
        strength += 1
    else:
        remarks.append("Add lowercase letter")

    if re.search(r"[0-9]", password):
        strength += 1
    else:
        remarks.append("Add digits")

    if re.search(r"[!@#$%^&*()_+=-]", password):
        strength += 1
    else:
        remarks.append("Add special characters")

    if strength <= 2:
        return "Weak", remarks
    elif strength == 3 or strength == 4:
        return "Medium", remarks
    else:
        return "Strong", remarks
def check_breach(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        return "Error checking breach"

    hashes = response.text.splitlines()
    for h in hashes:
        hash_suffix, count = h.split(":")
        if hash_suffix == suffix:
            return f"Breached {count} times"

    return "Not found in breaches"
@app.route("/", methods=["GET", "POST"])
def index():
    strength = ""
    remarks = []
    breach_status = ""

    if request.method == "POST":
        password = request.form["password"]

        strength, remarks = check_password_strength(password)
        breach_status = check_breach(password)

    return render_template(
        "index.html",
        strength=strength,
        remarks=remarks,
        breach_status=breach_status
    )
if __name__ == "__main__":
    app.run(debug=True)
