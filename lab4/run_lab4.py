"""Run only on a fresh, disposable Ubuntu runner, as root. Never a personal host."""
from pathlib import Path
import datetime
import json
import os
import platform
import pwd
import grp
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results"
sections = []

def section(title):
    sections.append({"title": title, "commands": []})

def run(command, user="root", expected=0, display=None):
    process = subprocess.run(["bash", "-e", "-c", command] if user == "root" else
                             ["runuser", "-u", user, "--", "bash", "-e", "-c", command],
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             env={**os.environ, "LC_ALL": "C", "TERM": "xterm-256color"})
    record = {"user": user, "command": display or command, "output": process.stdout,
              "exit_code": process.returncode, "expected_exit_code": expected}
    sections[-1]["commands"].append(record)
    print(f"{user}@ubuntu-actions:{'/home/' + user if user != 'root' else '~'}{'#' if user == 'root' else '$'} {record['command']}")
    print(process.stdout, end="" if process.stdout.endswith("\n") else "\n")
    print(f"[exit={process.returncode}; expected={expected}]", flush=True)
    if process.returncode != expected:
        save(False)
        raise RuntimeError(f"Unexpected return code for {command}")
    return process.stdout

def save(success):
    OUT.mkdir(exist_ok=True)
    data = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "platform": platform.platform(), "run_url": os.environ.get("LAB_RUN_URL", ""),
            "success": success, "sections": sections}
    (OUT / "execution.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    text = "\n\n".join(s["title"] + "\n" + "\n".join(
        f"{c['user']} $ {c['command']}\n{c['output']}[exit={c['exit_code']}]" for c in s["commands"]) for s in sections)
    (OUT / "terminal.log").write_text(text + "\n", encoding="utf-8")

def main():
    if sys.platform != "linux" or os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Only root on a disposable GitHub Actions Linux runner is supported.")
    for name in ("jenny", "kobzei"):
        try: pwd.getpwnam(name)
        except KeyError: pass
        else: raise SystemExit(f"Refusing to modify existing account {name}")
    try: grp.getgrnam("HR")
    except KeyError: pass
    else: raise SystemExit("Refusing to modify existing HR group")
    section("01 Environment and root privileges")
    run("cat /etc/os-release; uname -sr; id; whoami")
    run("sudo -n su -c 'id; whoami'", user="runner")
    section("02 Create HR group")
    run("groupadd HR; getent group HR")
    run("cat /etc/group > '" + str(OUT) + "/etc-group.txt'; tail -n 6 /etc/group")
    section("03 Create jenny and kobzei")
    run("adduser --disabled-password --gecos 'Jenny' jenny")
    run("adduser --disabled-password --gecos 'Oleksandr Kobzei' kobzei")
    run("printf 'jenny:lasocial\\nkobzei:tooth\\n' | chpasswd")
    run("usermod -aG HR jenny; usermod -aG HR kobzei; id jenny; id kobzei; getent group HR")
    section("04 Verify passwd and shadow")
    run("cat /etc/passwd > '" + str(OUT) + "/etc-passwd.txt'; getent passwd jenny kobzei")
    run("cat /etc/shadow > '" + str(OUT) + "/etc-shadow.txt'; getent shadow jenny kobzei")
    run("passwd -S jenny; passwd -S kobzei; stat -c '%a %U:%G %n' /etc/passwd /etc/shadow")
    section("05 Real password authentication through su")
    # pexpect drives a real pseudo-terminal. su runs as unprivileged runner, so PAM verifies passwords.
    import pexpect
    for name, password in (("jenny", "lasocial"), ("kobzei", "tooth")):
        command = f"runuser -u runner -- su - {name} -c 'whoami; id; pwd'"
        child = pexpect.spawn("bash", ["-c", command], encoding="utf-8", timeout=20, echo=False)
        child.expect("Password:")
        child.sendline(password)
        child.expect(pexpect.EOF)
        output = "Password: [hidden]\n" + child.before.replace("\r", "")
        child.close()
        sections[-1]["commands"].append({"user": "root", "command": command, "output": output,
            "exit_code": child.exitstatus, "expected_exit_code": 0})
        print(command + "\n" + output, flush=True)
        if child.exitstatus != 0 or f"/home/{name}" not in output:
            save(False); raise RuntimeError("Password authentication failed")
    section("06 Adapt modern home permissions for baseline")
    run("ls -ld /home/jenny /home/kobzei; stat -c '%a %U:%G %n' /home/jenny /home/kobzei")
    run("getfacl -cp /home/jenny /home/kobzei")
    # Hosted runner adds default ACLs. Remove them only from the two new lab homes.
    run("setfacl -b -k /home/jenny /home/kobzei; getfacl -cp /home/kobzei")
    # Ubuntu 24.04 defaults to 750, unlike the old manual's 755. Set an explicit baseline.
    run("chmod 755 /home/jenny /home/kobzei; ls -ld /home/jenny /home/kobzei")
    section("07 Jenny can traverse kobzei home at 755")
    run("cd /home/jenny; pwd; cd ..; ls -ld jenny kobzei; cd kobzei; pwd; cd ..; pwd", user="jenny")
    section("08 Remove others execute symbolically")
    run("cd /home; chmod o-x kobzei; ls -ld kobzei; stat -c '%a %U:%G %n' kobzei")
    run("cd /home; cd kobzei", user="jenny", expected=1)
    section("09 Owner sets absolute mode 705 and creates test file")
    run("cd /home/kobzei; pwd; cd ..; ls -ld kobzei; chmod 705 kobzei; ls -ld kobzei; cd kobzei; umask 022; touch test.txt; ls -l test.txt", user="kobzei")
    section("10 Jenny can read but cannot create a file")
    run("cd /home; ls -ld kobzei; cd kobzei; pwd; ls -l test.txt; cat test.txt", user="jenny")
    run("cd /home/kobzei; touch jenny.txt", user="jenny", expected=1)
    section("11 Group class priority at 705")
    # Both are HR members, but directory group is kobzei, so Jenny falls into others.
    run("id jenny; stat -c '%a %U:%G %n' /home/kobzei; chgrp HR /home/kobzei; ls -ld /home/kobzei")
    run("cd /home/kobzei", user="jenny", expected=1)
    run("chgrp kobzei /home/kobzei; stat -c '%a %U:%G %n' /home/kobzei")
    run("cd /home/kobzei; pwd", user="jenny")
    section("12 Final verification")
    run("id jenny; id kobzei; getent group HR; stat -c '%a %U:%G %n' /home/kobzei /home/kobzei/test.txt; test ! -e /home/kobzei/jenny.txt; echo 'jenny.txt absent: PASS'")
    save(True)
    print("ALL LAB 4 CHECKS PASSED")

if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    main()
