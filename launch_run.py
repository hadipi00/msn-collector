#!/usr/bin/env python3
"""Double-fork launcher for a single manual run.sh cycle (survives the shell).
Usage: python3 launch_run.py   (runs bash run.sh in this dir, log -> manual_run.log)"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "manual_run.log")

pid = os.fork()
if pid == 0:
    os.setsid()
    try:
        pid2 = os.fork()
    except OSError:
        os._exit(1)
    if pid2 == 0:
        os.chdir(HERE)
        devnull = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull, 0)
        log = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        os.dup2(log, 1)
        os.dup2(log, 2)
        os.execvp("bash", ["bash", os.path.join(HERE, "run.sh")])
    os._exit(0)
os.waitpid(pid, 0)
print("run.sh launched from", HERE)
