import sys
PROJECTS = {"alpha": {}, "beta": {}}
def main():
    if len(sys.argv) != 3 or sys.argv[1] not in PROJECTS:
        raise SystemExit("invalid project")
    project, target = sys.argv[1:]
    with open("/tmp/" + project + "-deploy.lock", "w") as lock:
        pass
