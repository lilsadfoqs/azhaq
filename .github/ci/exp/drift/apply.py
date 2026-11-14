#!/usr/bin/env python3
"""apply.py DIR EPOCH --vulhub DIR --labdns BIN: applies an epoch to the live
estate that plan.py planned and up.py started.

EPOCH 0 starts what up.py does not: the deploy app at v1 (from a copy of
bench/truth/deploy, bound to its own address, as another user), the counting
chain, and the fence for every user that must not reach the proxy's backends.
EPOCH 1 and 3 apply their changes: compose up and down per environment, the
zone (the resolver is restarted), the proxy's routes (nginx reloads), the deploy
v2. EPOCH 2 is churn only: containers restarted, DNS answers in another order.
Then it waits for what changed to answer; a change that did not come up is
dropped from drift-key.json (counted, never named in the log).

DIR is plan.py's output, up.py having run. State is DIR/live.json. Output is
counts only: the job log is public.
"""
import argparse
import concurrent.futures
import copy
import getpass
import http.client
import json
import os
import subprocess
import sys
import time

import driftlib as dl
import rangelib
import up

APPDIR = "/opt/srv/app"  # neutral names: the reviewing user can list /opt
STATE = APPDIR + "/state"
MARK = {"v1": "/api/legacy/report", "v2": "/api/v2/export"}


def sudo(cmd, **kw):
    return rangelib.sh(["sudo", "-n"] + cmd, **kw)


# --- the deploy app ---------------------------------------------------------------

def deploy_install(dep, run=sudo):
    """A copy of the fixture, bound to its own address: only the bind differs from
    bench/truth/deploy/app.py (its routes and both versions are copied as they are)."""
    src = os.path.join(dl.REPO, "bench", "truth", "deploy")
    text = open(os.path.join(src, "app.py"), encoding="utf-8").read()
    old = 'ThreadingHTTPServer(("127.0.0.1", PORT)'
    if text.count(old) != 1:
        raise SystemExit("deploy app.py has no single bind to patch")
    tmp = os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "drift-app.py")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text.replace(old, 'ThreadingHTTPServer(("%s", PORT)' % dep["address"]))
    run(["mkdir", "-p", APPDIR])
    run(["cp", "-r", os.path.join(src, "v1"), os.path.join(src, "v2"), APPDIR + "/"])
    run(["install", "-m", "640", "-g", "nogroup", tmp, APPDIR + "/app.py"])
    # The app's own user reads it; no one else can list or read either version.
    run(["chgrp", "-R", "nogroup", APPDIR])
    run(["chmod", "-R", "u=rwX,g=rX,o=", APPDIR])
    os.unlink(tmp)


def deploy_version(version, run=sudo):
    tmp = os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "drift-state")
    with open(tmp, "w") as f:
        f.write(version + "\n")
    rc, out = run(["install", "-m", "640", "-g", "nogroup", tmp, STATE])
    os.unlink(tmp)
    return rc == 0


def deploy_start(dep, run_as="nobody", popen=subprocess.Popen):
    popen(["sudo", "-n", "-u", run_as, "setsid", "nohup", "python3", "-I", APPDIR + "/app.py", str(dep["port"]), STATE],
          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def deploy_stop(run=sudo):
    run(["pkill", "-f", "[d]eploy-app/app.py"])  # the bracket keeps the pattern from matching this command
    time.sleep(1)


def deploy_ready(dep, version, deadline=60):
    end = time.time() + deadline
    while time.time() < end:
        try:
            c = http.client.HTTPConnection(dep["address"], dep["port"], timeout=3)
            c.request("GET", "/main.js")
            body = c.getresponse().read().decode("utf-8", "replace")
            c.close()
            if MARK[version] in body:
                return True
        except OSError:
            pass
        time.sleep(1)
    return False


# --- compose, the zone, the proxy ----------------------------------------------------

def env_dir(ctx, env):
    return os.path.join(ctx.vulhub, env["path"])


def compose(ctx, env, *args, timeout=600):
    d = env_dir(ctx, env)
    cmd = rangelib.compose_cmd(env["project"], d, os.path.join(ctx.out, env["override"]), *args)
    return ctx.run(cmd, cwd=d, env={"TARGET_IP": env["address"]}, timeout=timeout)


def probe_via(proxy, host, probe, timeout=4):
    try:
        c = http.client.HTTPConnection(proxy, 80, timeout=timeout)
        c.request("GET", probe.get("path", "/") if probe.get("kind") == "http" else "/", headers={"Host": host, "User-Agent": "range-probe"})
        st = c.getresponse().status
        c.close()
        return st < (probe.get("status_below", 500) if probe.get("kind") == "http" else 500)
    except (OSError, http.client.HTTPException):
        return False


def wait_env(ctx, env, model):
    """Direct environments answer their probe; a backend answers through the proxy by its name."""
    if not env.get("backend"):
        return up.wait_env(ctx, env)[0]
    host = next((r[0] for r in model["routes"] if r[2] == env["address"]), None)
    end = time.time() + max(180, 2 * env["ready_s"] + 90)
    while host:
        if probe_via(model["proxy"]["address"], host, env["probe"]):
            return True
        if time.time() > end:
            break
        time.sleep(3)
    return False


def write_zone(ctx, model):
    dl.save_json(os.path.join(ctx.out, "zone-1.json"), model["zone"])


def write_conf(ctx, model):
    # In place: the container mounts the file, a new inode would not be seen.
    with open(os.path.join(ctx.out, model["proxy"]["conf"]), "w") as f:
        f.write(dl.render_conf(model))


def reload_proxy(ctx, model):
    name = model["proxy"]["name"]
    rc, out = ctx.run(["docker", "exec", name, "nginx", "-t"])
    if rc != 0:
        raise SystemExit("the proxy's config does not test")
    ctx.run(["docker", "exec", name, "nginx", "-s", "reload"])


def restart_dns(ctx, plan, model, labdns, run_as):
    d = plan["dns"][0]
    b = os.path.basename(labdns)
    sudo(["pkill", "-f", "[%s]%s -addr %s" % (b[0], b[1:], d["listen"])])
    time.sleep(1.5)
    write_zone(ctx, model)
    up.start_dns(ctx, d, labdns, run_as)
    return up.dns_ready(ctx, d, model["apex"] + ".")


def refence(ctx, model, ents, base_key, plan, live, users):
    key, p = dl.live_key(model, ents, base_key)
    live["fence_n"] = live.get("fence_n", 0) + 1
    chain = "AZQ%d" % live["fence_n"]
    rules = dl.fence_for(key, p, chain, users)
    rules.insert(1, ["-A", chain, "-j", "AZCNT"])
    for r in rules:
        rc, out = sudo(["iptables"] + r, timeout=30)
        if rc != 0:
            ctx.note("iptables %s: %s" % (" ".join(r), out[-200:]))
            return False
    old = live.get("chain")
    if old:
        sudo(["iptables", "-D", "OUTPUT", "-j", old])
        sudo(["iptables", "-F", old])
        sudo(["iptables", "-X", old])
    live["chain"] = chain
    return True


def pmap(fn, items, workers=8):
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(fn, items))


# --- epochs ----------------------------------------------------------------------------

def host_up(kjson, name):
    h = next((h for h in kjson["estates"][0]["hosts"] if h.get("host") == name), None)
    return bool(h) and h.get("up", True)


def epoch0(ctx, est, args, ents, plan, base_key, dplan):
    model = dl.model_from_files(est)
    live = {"chain": "AZQ", "model": model, "epoch": 0}
    dep = model["deploy"]
    if not args.no_deploy:
        deploy_install(dep)
        deploy_version("v1")
        deploy_start(dep, args.run_as)
        ok = deploy_ready(dep, "v1")
        kj = dl.load_json(os.path.join(est, "key.json"))
        for h in kj["estates"][0]["hosts"]:
            if h.get("app") == "deploy":
                h["up"] = ok
        dl.save_json(os.path.join(est, "key.json"), kj)
        print("epoch 0: deploy app %s" % ("answers" if ok else "DOES NOT ANSWER"))
    if not args.no_fence:
        dl.counters_setup(model["net"], int(plan["dns"][0]["listen"].rsplit(":", 1)[1]))
        print("epoch 0: fence %s" % ("rebuilt" if refence(ctx, model, ents, base_key, plan, live, args.users) else "FAILED"))
    dl.save_json(os.path.join(est, "live.json"), live)
    return 0


def epoch_changes(ctx, est, args, ents, plan, base_key, dplan, live, e):
    model = live["model"]
    kjson = dl.load_json(os.path.join(est, "key.json"))
    dkey = dl.load_json(os.path.join(est, "drift-key.json"))
    changes = dplan["epochs"][e]["changes"]
    dropped = []
    keep = []
    for ch in changes:
        k = ch["key"]
        needs_host = ch["class"] in ("swap", "gone", "new-port")
        if needs_host and not host_up(kjson, k["name"]):
            dropped.append(ch["id"])
        else:
            keep.append(ch)
    before = copy.deepcopy(model)
    # Down first (a swap reuses the address and ports), then up.
    downs = [before["envs"][i] for ch in keep for i in ch.get("envs_down", []) if i in before["envs"]]
    pmap(lambda env: compose(ctx, env, "down", "-v", "--timeout", "10"), downs)
    ups = [(ch, pe) for ch in keep for pe in ch.get("envs_up", [])]
    started = pmap(lambda cp: up.start_env(ctx, cp[1]), ups)
    m = copy.deepcopy(before)
    for ch in keep:
        dl.apply_change(m, ch)
    write_conf(ctx, m)
    reload_proxy(ctx, m)
    dns_ok = restart_dns(ctx, plan, m, args.labdns, args.run_as)
    # The fence first: a new port or host answers nothing through the old one, probes included.
    if not args.no_fence:
        refence(ctx, m, ents, base_key, plan, live, args.users)
    waited = pmap(lambda cp: wait_env(ctx, cp[1], m), ups)
    failed = {cp[0]["id"] for cp, s, w in zip(ups, started, waited) if not (s[0] and w)}
    for ch in keep:
        if ch.get("deploy"):
            ok = deploy_version(ch["deploy"]) and deploy_ready(m["deploy"], ch["deploy"])
            if not ok:
                failed.add(ch["id"])
    if failed:
        for ch, pe in ups:
            if ch["id"] in failed:
                compose(ctx, pe, "down", "-v", "--timeout", "10")
        m = copy.deepcopy(before)
        for ch in keep:
            dl.apply_change(m, {"envs_down": ch.get("envs_down", [])} if ch["id"] in failed else ch)
        write_conf(ctx, m)
        reload_proxy(ctx, m)
        dns_ok = restart_dns(ctx, plan, m, args.labdns, args.run_as)
        dropped += sorted(failed)
    if failed and not args.no_fence:
        refence(ctx, m, ents, base_key, plan, live, args.users)
    live["model"], live["epoch"] = m, e
    drop = set(dropped)
    row = dkey["epochs"][e]
    row["changes"] = [k for k in row["changes"] if k["id"] not in drop]
    row["dropped"] = sorted(drop)
    dkey["dropped"] += len(drop)
    dl.save_json(os.path.join(est, "drift-key.json"), dkey)
    dl.save_json(os.path.join(est, "live.json"), live)
    print("epoch %d: %d changes planned, %d came up, %d dropped; resolver %s" % (e, len(changes), len(changes) - len(drop), len(drop), "answers" if dns_ok else "DOES NOT ANSWER"))
    return 1 if not dns_ok else 0


def epoch_churn(ctx, est, args, ents, plan, base_key, dplan, live, e):
    model = live["model"]
    churn = dplan["epochs"][e]["churn"]
    envs = [model["envs"][i] for i in churn["restart"] if i in model["envs"]]
    pmap(lambda env: compose(ctx, env, "restart", "--timeout", "10"), envs)
    if churn.get("proxy"):
        ctx.run(["docker", "restart", model["proxy"]["name"]])
    if churn.get("deploy") and not args.no_deploy:
        deploy_stop()
        deploy_start(model["deploy"], args.run_as)
        deploy_ready(model["deploy"], model["deploy"]["version"])
    dns_ok = True
    if churn.get("dns"):
        dl.dns_churn(model)
        dns_ok = restart_dns(ctx, plan, model, args.labdns, args.run_as)
    waited = pmap(lambda env: wait_env(ctx, env, model), envs)
    dl.save_json(os.path.join(est, "live.json"), live)
    print("epoch %d: %d containers restarted, %d answer again; resolver %s" % (e, len(envs), sum(waited), "answers" if dns_ok else "DOES NOT ANSWER"))
    return 0 if dns_ok and all(waited) else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir")
    ap.add_argument("epoch", type=int, choices=(0, 1, 2, 3))
    ap.add_argument("--vulhub", required=True)
    ap.add_argument("--labdns", default="/usr/local/sbin/dnsd")
    ap.add_argument("--run-as", default="nobody")
    ap.add_argument("--users", default=getpass.getuser() + ",analyst", help="users kept from the proxy's backends (the fence): this one and the agent's")
    ap.add_argument("--no-fence", action="store_true", help="tests")
    ap.add_argument("--no-deploy", action="store_true", help="tests")
    a = ap.parse_args(argv)
    a.users = [u for u in a.users.split(",") if u]
    est = os.path.abspath(a.dir)
    vulhub = os.path.abspath(a.vulhub)
    os.chdir("/")  # a user the resolver or the app runs as may not enter the runner's folder: they inherit this one
    ctx = up.Ctx(est, vulhub)
    ents = dl.by_id(rangelib.load_catalog())
    plan = dl.load_json(os.path.join(est, "plan.json"))
    base_key = dl.load_json(os.path.join(est, "key.json"))
    dplan = dl.load_json(os.path.join(est, "drift-plan.json"))
    if a.epoch == 0:
        return epoch0(ctx, est, a, ents, plan, base_key, dplan)
    live = dl.load_json(os.path.join(est, "live.json"))
    if live["epoch"] != a.epoch - 1:
        raise SystemExit("epoch %d comes after epoch %d" % (a.epoch, live["epoch"]))
    fn = epoch_churn if "churn" in dplan["epochs"][a.epoch] else epoch_changes
    return fn(ctx, est, a, ents, plan, base_key, dplan, live, a.epoch)


if __name__ == "__main__":
    sys.exit(main())
