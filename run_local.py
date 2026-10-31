"""Start both loopback services; Ctrl+C stops both. No real credentials required."""
import subprocess,sys,os
from pathlib import Path
env=os.environ.copy();env['AUTHLIB_INSECURE_TRANSPORT']='1'
root=Path(__file__).parent
children=[subprocess.Popen([sys.executable,str(root/f)],cwd=root,env=env) for f in ('idp.py','app.py')]
try:
    print('Open http://127.0.0.1:5000. Local demo services only. Ctrl+C to stop.',flush=True)
    for child in children: child.wait()
except KeyboardInterrupt: pass
finally:
    for child in children:
        if child.poll() is None: child.terminate()
