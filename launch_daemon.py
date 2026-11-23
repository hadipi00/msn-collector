#!/usr/bin/env python3
"""Double-fork launcher so scheduler.sh survives the parent shell.
Usage: python3 launch_daemon.py   (starts bash scheduler.sh in this dir)"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

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
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        os.execvp("bash", ["bash", os.path.join(HERE, "scheduler.sh")])
    os._exit(0)
os.waitpid(pid, 0)
print("daemon launched from", HERE)
