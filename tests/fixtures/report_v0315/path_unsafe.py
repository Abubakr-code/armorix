import sys
def main():
    project = sys.argv[1]
    with open("/tmp/" + project + "-deploy.lock", "w") as lock:
        pass
