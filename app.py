# app.py
import os
import subprocess
import requests

# --- Credenciales expustas (falsas, pero triggerea Gitleaks) ---
AWS_ACCESS_KEY_ID = "AKIAFAKEKEY1234567890"
AWS_SECRET_ACCESS_KEY = "f4k3s3cr3tKeyTest987654321"
DB_PASSWORD = "my_db_password_123"
API_TOKEN = "ghp_FAKEPERSONALTOKEN123456789abcd"

# Dependencia vulnerable intencional
# (requests<2.20 tiene vulnerabilidades CVE)
import requests

def vulnerable_exec(command):
    # ¡Vulnerabilidad! Semgrep debería detectar esto.
    os.system(command)


def another_vulnerable_call(request):
    # ¡Vulnerabilidad! Inyección por shell=Tr
    cmd = request.args.get("cmd")
    subprocess.run(cmd, shell=True)


# Otra vulnerabilidad: descarga insegura (HTTP sin TLS)
def insecure_download():
    r = requests.get("http://insecure-domain.test/data.txt")
    print(r.text)


print("Archivo vulnerable de prueba")
print("Hola mundodddd")
print("Funcionamiento")
