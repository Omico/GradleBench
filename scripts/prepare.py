#!/usr/bin/env python3
"""Fetch official Wrapper, pin all distribution checksums. No SDK installation."""
import hashlib, json, subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def fetch(url, path):
    from locking import project_path
    project_path(ROOT,path)
    subprocess.run(['curl','-fL','--retry','2','--connect-timeout','20','--max-time','300',url,'-o',str(path)],check=True)

def main():
    wrapper=ROOT/'gradle/wrapper'
    fetch('https://raw.githubusercontent.com/gradle/gradle/v7.6.6/gradlew', ROOT/'gradlew')
    fetch('https://raw.githubusercontent.com/gradle/gradle/v7.6.6/gradlew.bat', ROOT/'gradlew.bat')
    fetch('https://raw.githubusercontent.com/gradle/gradle/v7.6.6/gradle/wrapper/gradle-wrapper.jar', wrapper/'gradle-wrapper.jar')
    fetch('https://services.gradle.org/distributions/gradle-7.6.6-wrapper.jar.sha256',wrapper/'wrapper.sha256')
    if hashlib.sha256((wrapper/'gradle-wrapper.jar').read_bytes()).hexdigest()!=(wrapper/'wrapper.sha256').read_text().strip():raise RuntimeError('Wrapper JAR checksum mismatch')
    checks={}
    for v in ['7.5.1','7.6.6']:
        p=wrapper/f'{v}.sha256'
        fetch(f'https://services.gradle.org/distributions/gradle-{v}-bin.zip.sha256',p)
        checks[v]=p.read_text().strip()
        if len(checks[v])!=64:raise RuntimeError('Invalid distribution checksum')
    from locking import project_path
    project_path(ROOT,wrapper/'checksums.json')
    (wrapper/'checksums.json').write_text(json.dumps(checks,indent=2)+'\n')
    (ROOT/'gradlew').chmod(0o755)
    select('7.5.1')

def ensure():
    wrapper=ROOT/'gradle/wrapper'
    if not all((wrapper/name).is_file() for name in ['gradle-wrapper.jar','wrapper.sha256','checksums.json','7.5.1.sha256','7.6.6.sha256']):main()
    if hashlib.sha256((wrapper/'gradle-wrapper.jar').read_bytes()).hexdigest()!=(wrapper/'wrapper.sha256').read_text().strip():raise RuntimeError('Wrapper JAR checksum mismatch')
    checks=json.loads((wrapper/'checksums.json').read_text())
    for version in ['7.5.1','7.6.6']:
        if checks[version]!=(wrapper/(version+'.sha256')).read_text().strip():raise RuntimeError('Distribution checksum mismatch: '+version)


def select(v):
    from locking import project_path
    project_path(ROOT,ROOT/'gradle/wrapper/gradle-wrapper.properties')
    checks=json.loads((ROOT/'gradle/wrapper/checksums.json').read_text())
    (ROOT/'gradle/wrapper/gradle-wrapper.properties').write_text(f'''distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https\\://services.gradle.org/distributions/gradle-{v}-bin.zip
distributionSha256Sum={checks[v]}
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
networkTimeout=300000
''')
if __name__=='__main__':
    from locking import benchmark_lock
    with benchmark_lock(ROOT):main()
