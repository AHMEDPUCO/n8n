# app.py
import os
import subprocess

def vulnerable_exec(command):
    # ¡Vulnerabilidad! Semgrep debería detectar esto.
    os.system(command)

def another_vulnerable_call(request):
    # ¡Vulnerabilidad! Inyección de comandos.
    cmd = request.args.get('cmd')
    subprocess.run(cmd, shell=True)

print("Archivo vulnerable de prueba")
print("Hola mundo")
print("Funcionamiento")