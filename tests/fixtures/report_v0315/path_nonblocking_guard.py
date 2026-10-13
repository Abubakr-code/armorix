import sys
PROJECTS = {"alpha": {}}
def main():
    project = sys.argv[1]
    if project not in PROJECTS:
        print("invalid")
    with open("/tmp/" + project + "-deploy.lock", "w") as lock:
        pass
