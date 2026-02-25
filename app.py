from flask import Flask, render_template, request, jsonify, Response
import subprocess, json, xml.etree.ElementTree as ET, threading, queue, shutil

app = Flask(__name__)

def parse_xml(xml_text):
    result = {"hosts": [], "elapsed": "", "total_hosts": "0"}
    try:
        root = ET.fromstring(xml_text)
        fin = root.find("runstats/finished")
        if fin is not None:
            result["elapsed"] = fin.get("elapsed", "")
        he = root.find("runstats/hosts")
        if he is not None:
            result["total_hosts"] = he.get("total", "0")
        for host in root.findall("host"):
            st = host.find("status")
            status = st.get("state", "unknown") if st is not None else "unknown"
            h = {"ip":"","mac":"","vendor":"","hostnames":[],"ports":[],"os":[],"scripts":[],"status":status}
            for a in host.findall("address"):
                t = a.get("addrtype","")
                if t in ("ipv4","ipv6"): h["ip"] = a.get("addr","")
                elif t == "mac": h["mac"] = a.get("addr",""); h["vendor"] = a.get("vendor","")
            for hn in host.findall("hostnames/hostname"):
                nm = hn.get("name","")
                if nm: h["hostnames"].append(nm)
            for port in host.findall("ports/port"):
                ps = port.find("state"); svc = port.find("service")
                p = {
                    "port": port.get("portid",""), "proto": port.get("protocol",""),
                    "state": ps.get("state","") if ps is not None else "",
                    "reason": ps.get("reason","") if ps is not None else "",
                    "service": svc.get("name","") if svc is not None else "",
                    "product": svc.get("product","") if svc is not None else "",
                    "version": svc.get("version","") if svc is not None else "",
                    "extrainfo": svc.get("extrainfo","") if svc is not None else "",
                    "scripts": []
                }
                for sc in port.findall("script"):
                    p["scripts"].append({"id":sc.get("id",""),"output":sc.get("output","")})
                h["ports"].append(p)
            for om in host.findall("os/osmatch"):
                h["os"].append({"name":om.get("name",""),"accuracy":om.get("accuracy","")})
            for sc in host.findall("hostscript/script"):
                h["scripts"].append({"id":sc.get("id",""),"output":sc.get("output","")})
            result["hosts"].append(h)
    except ET.ParseError as e:
        result["parse_error"] = str(e)
    return result

def build_cmd(p):
    nmap_path = shutil.which("nmap") or "nmap"
    cmd = [nmap_path]
    target = p.get("target","").strip()
    if not target: return None, "Chưa nhập mục tiêu"

    scan_type = p.get("scan_type","common")
    type_map = {
        "common":   [],
        "vuln":     ["-sV","--script","vuln"],
        "allports": ["-p-"],   "syn":     ["-sS"],
        "connect":  ["-sT"],   "ack":     ["-sA"],
        "window":   ["-sW"],   "fin":     ["-sF"],
        "null":     ["-sN"],   "xmas":    ["-sX"],
        "maimon":   ["-sM"],   "udp":     ["-sU"],
        "ping":     ["-sn"],
    }
    use_aggressive = scan_type == "full" or bool(p.get("aggressive"))
    if scan_type != "full":
        cmd += type_map.get(scan_type, [])

    ports = p.get("ports","").strip()
    if ports: cmd += ["-p", ports]
    elif p.get("fast_scan"): cmd += ["-F"]

    if p.get("os_detect"):       cmd += ["-O"]
    if p.get("version_detect"):  cmd += ["-sV"]
    if p.get("default_script"):  cmd += ["-sC"]
    if use_aggressive:           cmd += ["-A"]
    if p.get("udp_scan"):        cmd += ["-sU"]
    if p.get("no_ping"):         cmd += ["-Pn"]
    if p.get("traceroute"):      cmd += ["--traceroute"]
    if p.get("verbose"):         cmd += ["-v"]
    if p.get("no_dns"):          cmd += ["-n"]

    hd = p.get("host_discovery","")
    if hd == "syn_ping":   cmd += ["-PS"]
    elif hd == "ack_ping": cmd += ["-PA"]
    elif hd == "udp_ping": cmd += ["-PU"]
    elif hd == "icmp":     cmd += ["-PE"]
    elif hd == "arp":      cmd += ["-PR"]

    script = p.get("nse_script","").strip()
    if script and "--script" not in " ".join(cmd):
        cmd += ["--script", script]

    timing = p.get("timing","T3")
    cmd += [f"-{timing}"]

    custom = p.get("custom_flags","").strip()
    if custom: cmd += custom.split()

    cmd += ["-oX", "-", target]
    return cmd, None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/preview", methods=["POST"])
def preview():
    cmd, err = build_cmd(request.json or {})
    if err: return jsonify({"error": err})
    return jsonify({"command": " ".join(cmd)})

# ── DEBUG endpoint: truy cập /debug để kiểm tra môi trường ──────────────────
@app.route("/debug")
def debug():
    nmap_path = shutil.which("nmap")
    info = {"nmap_path": nmap_path or "NOT FOUND"}
    if nmap_path:
        try:
            r = subprocess.run([nmap_path, "--version"], capture_output=True, text=True, timeout=5)
            info["version"] = r.stdout.strip().split("\n")[0]
        except Exception as e:
            info["version_error"] = str(e)
        try:
            r = subprocess.run([nmap_path, "-sn", "-oX", "-", "scanme.org"],
                               capture_output=True, text=True, timeout=30)
            info["test_returncode"] = r.returncode
            info["test_stderr"] = r.stderr[:300]
            info["test_xml_bytes"] = len(r.stdout)
            info["test_xml_preview"] = r.stdout[:400]
        except Exception as e:
            info["test_error"] = str(e)
    return jsonify(info)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json or {}
    cmd, err = build_cmd(data)
    if err: return jsonify({"error": err}), 400

    def stream():
        cmd_str = " ".join(cmd)
        try:
            yield f"data:{json.dumps({'type':'log','line':'▶ Lệnh: ' + cmd_str})}\n\n"
            yield f"data:{json.dumps({'type':'log','line':'─'*50})}\n\n"

            # stdout = XML only | stderr = human log
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            log_lines = []
            q = queue.Queue()

            def read_stderr():
                for line in proc.stderr:
                    q.put(line.rstrip())
                q.put(None)  # sentinel

            xml_holder = []
            def read_stdout():
                xml_holder.append(proc.stdout.read())

            t_err = threading.Thread(target=read_stderr, daemon=True)
            t_out = threading.Thread(target=read_stdout, daemon=True)
            t_err.start()
            t_out.start()

            # Stream stderr lines while waiting
            done = False
            while not done:
                try:
                    item = q.get(timeout=0.3)
                    if item is None:
                        done = True
                    else:
                        log_lines.append(item)
                        yield f"data:{json.dumps({'type':'log','line':item})}\n\n"
                except queue.Empty:
                    pass

            t_err.join()
            t_out.join()
            proc.wait()

            xml_data = xml_holder[0] if xml_holder else ""

            yield f"data:{json.dumps({'type':'log','line':f'[DEBUG] XML: {len(xml_data)} bytes | exit code: {proc.returncode}'})}\n\n"

            if not xml_data.strip():
                msg = "[LỖI] nmap không trả về XML. Thử: sudo python app.py hoặc kiểm tra nmap đã cài chưa tại /debug"
                yield f"data:{json.dumps({'type':'log','line':msg})}\n\n"
                yield f"data:{json.dumps({'type':'result','data':{'hosts':[],'elapsed':'','total_hosts':'0'},'raw':'\n'.join(log_lines),'cmd':cmd_str,'code':proc.returncode})}\n\n"
                yield f"data:{json.dumps({'type':'done'})}\n\n"
                return

            parsed = parse_xml(xml_data)
            if parsed.get("parse_error"):
                yield f"data:{json.dumps({'type':'log','line':'[XML Parse Error] ' + parsed['parse_error']})}\n\n"
                yield f"data:{json.dumps({'type':'log','line':'Preview: ' + xml_data[:300]})}\n\n"

            yield f"data:{json.dumps({'type':'result','data':parsed,'raw':chr(10).join(log_lines),'cmd':cmd_str,'code':proc.returncode})}\n\n"
            yield f"data:{json.dumps({'type':'done'})}\n\n"

        except Exception as ex:
            yield f"data:{json.dumps({'type':'error','msg':str(ex)})}\n\n"

    return Response(stream(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
