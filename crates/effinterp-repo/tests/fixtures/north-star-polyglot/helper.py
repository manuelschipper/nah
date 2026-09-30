import subprocess

subprocess.run([
    "docker", "run", "--name", "worker",
    "-v", "./scripts:/workspace",
    "-w", "/workspace",
    "-e", "TENANT=acme",
    "postgres:16", "sh", "/workspace/run.sh",
])
