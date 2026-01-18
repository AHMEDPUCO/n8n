# app.py
import os
import subprocess
import pickle
import yaml
from flask import Flask, request

app = Flask(__name__)

# 1️⃣ Command Injection (os.system)
@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    os.system(cmd)  # ❌ Semgrep: command-injection
    return "ok"

# 2️⃣ Command Injection (subprocess + shell=True)
@app.route("/exec")
def exec_cmd():
    cmd = request.args.get("cmd")
    subprocess.run(cmd, shell=True)  # ❌ Semgrep: shell injection
    return "done"

# 3️⃣ Insecure deserialization (pickle)
@app.route("/load")
def load():
    data = request.args.get("data").encode()
    pickle.loads(data)  # ❌ Semgrep: insecure deserialization
    return "loaded"

# 4️⃣ Unsafe YAML load
@app.route("/yaml")
def load_yaml():
    content = request.args.get("y")
    yaml.load(content, Loader=yaml.Loader)  # ❌ Semgrep: unsafe yaml load
    return "yaml loaded"

# 5️⃣ Hardcoded secret
API_KEY = "sk_test_1234567890abcdef"  # ❌ Semgrep: hardcoded secret

if __name__ == "__main__":
    app.run(debug=True)
