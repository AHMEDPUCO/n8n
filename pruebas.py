from flask import Flask, request, render_template_string
import subprocess
import sqlite3
import os

app = Flask(__name__)

# Crear base de datos insegura
def init_db():
    conn = sqlite3.connect('vuln.db')
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT)")
    c.execute("INSERT INTO users VALUES (1, 'admin'), (2, 'user')")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return '''
    <h1>Vulnerable App</h1>
    <ul>
        <li><a href="/search">SQL Injection</a></li>
        <li><a href="/ping">Command Injection</a></li>
        <li><a href="/file?filename=report.txt">Path Traversjjal</a></li>
    </ul>
    '''

# 1. SQL Injection
@app.route('/search')
def search():
    user_id = request.args.get('id', '')
    conn = sqlite3.connect('vuln.db')
    cursor = conn.cursor()
    # ¡VULNERABLE! Concatenación directa de input del usuario
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return str(result)

# 2. Command Injection
@app.route('/ping')
def ping():
    ip = request.args.get('ip', '')
    # ¡VULNERABLE! Ejecución directa de comandos con input del usuario
    output = subprocess.check_output(f"ping -c 1 {ip}", shell=True)
    return output.decode()
    

# 3. Path Traversal
@app.route('/file')
def read_file():
    filename = request.args.get('filename', '')
    # ¡VULNERABLE! No hay sanitización de rutas
    with open(os.path.join('files', filename), 'r') as f:
        return f.read()

if __name__ == '__main__':
    init_db()
    os.makedirs('files', exist_ok=True)
    with open('files/report.txt', 'w') as f:
        f.write('Contenido sensijjjjjjjjjjjjjjjjjjjjbfdfdsafsdfasdle')
    app.run(debug=True, host='0.0.0.0', port=5000)