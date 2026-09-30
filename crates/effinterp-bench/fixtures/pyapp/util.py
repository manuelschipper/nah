import shutil, os
def wipe(root, t):
    shutil.rmtree(os.path.join(root, t))
