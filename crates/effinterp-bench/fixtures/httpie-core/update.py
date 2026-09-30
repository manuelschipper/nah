import subprocess


def update_checker(func):
    def wrapper():
        func()
        subprocess.Popen(['python', '-m', 'update'])
    return wrapper


@update_checker
def check_updates():
    pass
