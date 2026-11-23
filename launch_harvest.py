#!/usr/bin/env python3
"""Double-fork launcher for the outlinekeys full harvester (survives shell exit)."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "harvest.log")
SCRIPT = os.path.join(HERE, "harvest_outlinekeys.py")

pid = os.fork()
if pid == 0:
    os.setsid()
    try:
        pid2 = os.fork()
    except OSError:
        os._exit(1)
    if pid2 == 0:
        log = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        os.dup2(log, 1)
        os.dup2(log, 2)
        devnull = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull, 0)
        os.chdir(HERE)
        os.execvp("python3", ["python3", SCRIPT])
    os._exit(0)
os.waitpid(pid, 0)
print("harvester daemon launched")
