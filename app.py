from __future__ import annotations
import io, json, re
from collections import defaultdict
from typing import Any
import pandas as pd
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="AEE-CBP | Automotive Bus Protocol Analyzer", version="1.0.0")
MAX_BYTES = 12 * 1024 * 1024
MAX_ROWS = 150000

def can_id(value: Any) -> int:
    s = str(value).strip()
    if s.lower().startswith("0x") or re.search(r"[a-f]", s, re.I): return int(s, 16)
    return int(s, 10)

def payload(value: Any) -> list[int]:
    s = str(value or "").strip()
    if s.startswith("[") and s.endswith("]"):
        try:
            a = json.loads(s)
            return [int(str(x), 16) if isinstance(x, str) and re.search(r"[a-f]", x, re.I) else int(x, 0) if isinstance(x, str) and x.lower().startswith("0x") else int(x) for x in a]
        except Exception: pass
    s = s.replace("0x", "").replace("0X", "")
    parts = [x for x in re.split(r"[,;:\s]+", s) if x] if re.search(r"[,;:\s]", s) else ([s[i:i+2] for i in range(0,len(s),2)] if len(s)%2==0 else [])
    if not parts and s: raise ValueError("Payload must contain complete hexadecimal bytes")
    out = [int(x,16) for x in parts]
    if any(x < 0 or x > 255 for x in out): raise ValueError("Payload bytes must be 0–255")
    return out

def parse_csv(text: str) -> list[dict]:
    df = pd.read_csv(io.StringIO(text), comment="#", nrows=MAX_ROWS+1)
    if len(df)>MAX_ROWS: raise ValueError("Trace exceeds row limit")
    aliases = {"timestamp":["timestamp","time","time_s","seconds","ts"],"can_id":["can_id","canid","id","arbitration_id","identifier","message_id"],"dlc":["dlc","len","length"],"data":["data","payload","bytes","data_bytes","message_data"]}
    lookup = {str(c).strip().lower().replace(" ","_"):c for c in df.columns}
    ren={}
    for target, names in aliases.items():
        for n in names:
            if n in lookup: ren[lookup[n]]=target; break
    df=df.rename(columns=ren)
    if not {"timestamp","can_id","data"}.issubset(df.columns): raise ValueError("CSV must contain timestamp, can_id (or id), and data/payload columns")
    out=[]
    for i,r in df.iterrows():
        try:
            ts=float(r["timestamp"]); cid=can_id(r["can_id"]); data=payload(r["data"])
            dlc=int(r["dlc"]) if "dlc" in df.columns and pd.notna(r.get("dlc")) else len(data)
            if ts<0 or dlc<0 or dlc>64: raise ValueError("Invalid timestamp or DLC")
            out.append({"timestamp":ts,"can_id":cid,"dlc":dlc,"data":data,"line":int(i)+2})
        except Exception as e: out.append({"parse_error":str(e),"line":int(i)+2,"timestamp":None,"can_id":None,"dlc":None,"data":[]})
    return out

def parse_asc(text: str) -> list[dict]:
    # Common Vector ASC CAN data line: timestamp channel id Rx d dlc data-bytes
    pat=re.compile(r"^\s*(\d+(?:\.\d+)?)\s+\d+\s+([0-9a-fx]+)\s+(?:Rx|Tx)\s+(?:d\s+)?(\d+)\s+((?:[0-9a-f]{2}\s*)*)",re.I)
    out=[]
    for n,line in enumerate(text.splitlines(),1):
        m=pat.match(line)
        if not m: continue
        try: out.append({"timestamp":float(m.group(1)),"can_id":can_id(m.group(2)),"dlc":int(m.group(3)),"data":[int(x,16) for x in m.group(4).split()],"line":n})
        except Exception as e: out.append({"parse_error":str(e),"line":n,"timestamp":None,"can_id":None,"dlc":None,"data":[]})
        if len(out)>MAX_ROWS: raise ValueError("Trace exceeds frame limit")
    if not out: raise ValueError("No supported CAN data lines found in ASC file")
    return out

def analyze(frames: list[dict], cfg: dict) -> dict:
    valid=sorted([f for f in frames if not f.get("parse_error") and f.get("timestamp") is not None],key=lambda f:f["timestamp"])
    bad=[f for f in frames if f.get("parse_error")]
    byid=defaultdict(list); events=[]
    for f in valid:
        byid[f["can_id"]].append(f)
        if f["dlc"] != len(f["data"]): events.append({"severity":"warning","type":"DLC mismatch","timestamp":f["timestamp"],"can_id":f["can_id"],"details":"DLC does not match parsed payload length","line":f["line"]})
    for f in bad: events.append({"severity":"error","type":"Parse error","timestamp":None,"can_id":None,"details":f["parse_error"],"line":f["line"]})
    for rule in cfg.get("timeouts",[]):
        try: cid=can_id(rule["can_id"]); limit=float(rule["period_ms"])/1000*float(rule.get("multiplier",2))
        except Exception: continue
        if limit<=0: continue
        for a,b in zip(byid[cid],byid[cid][1:]):
            gap=b["timestamp"]-a["timestamp"]
            if gap>limit: events.append({"severity":"error","type":"Message timeout","timestamp":b["timestamp"],"can_id":cid,"details":"Gap %.3f ms exceeds configured %.3f ms"%(gap*1000,limit*1000),"line":b["line"]})
    sigout=[]
    for ix,s in enumerate(cfg.get("signals",[])):
        try:
            cid=can_id(s["can_id"]); start=int(s.get("start_byte",0)); length=int(s.get("length",1))
            scale=float(s.get("scale",1)); offset=float(s.get("offset",0)); endian="little" if s.get("byte_order","little")=="little" else "big"
            name=str(s.get("name") or "Signal "+str(ix+1)); unit=str(s.get("unit") or "")
            low=float(s["minimum"]) if s.get("minimum") not in (None,"") else None
            high=float(s["maximum"]) if s.get("maximum") not in (None,"") else None
            if start<0 or length<1 or length>8 or start+length>64: raise ValueError("byte position/length out of range")
        except Exception as e:
            events.append({"severity":"warning","type":"Invalid signal rule","timestamp":None,"can_id":None,"details":str(e),"line":None}); continue
        points=[]
        for f in byid[cid]:
            if start+length>len(f["data"]): continue
            raw=int.from_bytes(bytes(f["data"][start:start+length]),byteorder=endian,signed=bool(s.get("signed",False)))
            value=raw*scale+offset; points.append({"timestamp":f["timestamp"],"value":value})
            if low is not None and value<low: events.append({"severity":"warning","type":"Below threshold","timestamp":f["timestamp"],"can_id":cid,"details":name+" = "+str(value)+" "+unit+" below minimum "+str(low),"line":f["line"]})
            if high is not None and value>high: events.append({"severity":"warning","type":"Above threshold","timestamp":f["timestamp"],"can_id":cid,"details":name+" = "+str(value)+" "+unit+" above maximum "+str(high),"line":f["line"]})
        sigout.append({"name":name,"can_id":cid,"unit":unit,"points":points})
    ids=sorted(byid)
    output=[{"timestamp":f["timestamp"],"can_id":"0x%X"%f["can_id"],"dlc":f["dlc"],"data":" ".join("%02X"%b for b in f["data"]),"line":f["line"]} for f in valid]
    duration=valid[-1]["timestamp"]-valid[0]["timestamp"] if len(valid)>1 else 0
    return {"summary":{"frames":len(valid),"parse_errors":len(bad),"unique_ids":len(ids),"duration_seconds":round(duration,6),"events":len(events),"error_events":sum(e["severity"]=="error" for e in events),"warning_events":sum(e["severity"]=="warning" for e in events)},"ids":[{"can_id":"0x%X"%c,"frames":len(byid[c]),"first_timestamp":byid[c][0]["timestamp"],"last_timestamp":byid[c][-1]["timestamp"]} for c in ids],"frames":output[:5000],"signals":sigout,"events":sorted(events,key=lambda e:(e["timestamp"] is None,e["timestamp"] or 0))[:5000],"notes":["Timeouts require configured expected message periods.","Decoding is byte-aligned; verify definitions against the correct vehicle network specification."]}

@app.get("/",response_class=HTMLResponse)
def home(): return HTML

@app.get("/health")
def health(): return {"status":"ok","service":"AEE-CBP","version":"1.0.0"}

@app.post("/api/analyze")
async def api_analyze(file: UploadFile=File(...),config: str=Form("{}")):
    name=(file.filename or "").strip()
    ext=name.rsplit(".",1)[-1].lower() if "." in name else ""
    if ext not in {"csv","asc"}: raise HTTPException(415,"Upload a .csv or .asc file")
    raw=await file.read(MAX_BYTES+1)
    if len(raw)>MAX_BYTES: raise HTTPException(413,"Maximum upload size is 12 MB")
    try: text=raw.decode("utf-8-sig")
    except UnicodeDecodeError: text=raw.decode("latin-1")
    try:
        cfg=json.loads(config or "{}")
        if not isinstance(cfg,dict): raise ValueError("Config must be a JSON object")
        frames=parse_csv(text) if ext=="csv" else parse_asc(text)
        result=analyze(frames,cfg); result["filename"]=name[:180]
        return JSONResponse(result)
    except ValueError as e: raise HTTPException(400,str(e))

HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#0b1018"><title>AEE-CBP | Automotive Bus Protocol Analyzer</title><script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js" defer></script><style>
:root{color-scheme:dark;--bg:#090e15;--p:#111b27;--line:#29394a;--txt:#eaf0f7;--muted:#9aabbe;--cyan:#65e2dc;--red:#ff7d88;--amber:#ffd18b}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 80% 0,#183344,transparent 40%),var(--bg);color:var(--txt);font:14px/1.5 system-ui,sans-serif}.wrap{max-width:1380px;margin:auto;padding:26px 22px 55px}.top{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);padding-bottom:20px}.brand{display:flex;align-items:center;gap:12px}.logo{background:linear-gradient(135deg,#65e2dc,#7ca9ff);color:#06141b;border-radius:12px;padding:13px;font-weight:900}.eyebrow{font-size:10px;letter-spacing:.17em;color:var(--cyan);font-weight:800}.title{font-size:22px;font-weight:800}.muted{color:var(--muted)}.hero{display:grid;grid-template-columns:1.5fr .5fr;gap:20px;padding:32px 0 20px}.hero h1{font-size:clamp(30px,4vw,46px);letter-spacing:-.05em;line-height:1.08;margin:8px 0 14px}.hero h1 span{color:var(--cyan)}.hero p{color:var(--muted);max-width:720px}.callout,.panel,.metric{border:1px solid var(--line);background:linear-gradient(145deg,#14202c,#0f1721);border-radius:14px}.callout{padding:18px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:8px 0 20px}.metric{padding:16px}.metric small{color:var(--muted)}.metric strong{display:block;font-size:28px;margin:6px 0}.layout{display:grid;grid-template-columns:minmax(280px,.8fr) minmax(0,1.4fr);gap:15px}.panel{padding:17px;margin-bottom:15px;min-width:0}.head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}.head h2{font-size:15px;margin:0}.pill{font-size:10px;color:var(--cyan);border:1px solid #2c5960;border-radius:20px;padding:4px 8px}.drop{border:1px dashed #3d5c6d;border-radius:12px;text-align:center;padding:22px 10px;background:#0b141e}.btn{border:1px solid #355061;background:#192936;color:var(--txt);border-radius:8px;padding:9px 12px;cursor:pointer;font-weight:650}.primary{background:var(--cyan);color:#06141b;border-color:var(--cyan)}.btn:disabled{opacity:.45}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.field{display:flex;flex-direction:column;gap:5px;margin-top:10px}.field label{font-size:11px;color:var(--muted)}input,select{width:100%;background:#0a121b;color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:9px}.formgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.notice,.error,.success{font-size:12px;padding:10px;border-radius:9px;margin-top:10px}.notice{background:#12232c;border:1px solid #294653;color:#b9dce5}.error{background:#351a20;border:1px solid #67313c;color:#ffb6bd}.success{background:#12291f;border:1px solid #285440;color:#a9f0c8}.tabs{display:flex;gap:5px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:10px;margin-bottom:14px}.tab{background:none;border:1px solid transparent;border-radius:7px;color:var(--muted);padding:7px 10px;cursor:pointer}.tab.active{color:var(--cyan);background:#192c38;border-color:#355260}.tabcontent{display:none}.tabcontent.active{display:block}.tablewrap{overflow:auto;max-height:380px;border:1px solid var(--line);border-radius:9px}table{border-collapse:collapse;width:100%;font-size:12px;white-space:nowrap}td,th{padding:9px 11px;text-align:left;border-bottom:1px solid #253342}th{position:sticky;top:0;background:#162330;color:var(--muted)}.chartbox{height:280px}.empty{padding:30px 10px;text-align:center;color:var(--muted)}.event{border:1px solid var(--line);border-radius:9px;padding:11px;margin:8px 0}.tag{font-size:10px;padding:3px 6px;border-radius:5px;font-weight:800}.tag.error{background:#421f28;color:#ff9da6}.tag.warning{background:#392c19;color:#ffd18b}.small{font-size:11px}.rule{border:1px solid var(--line);border-radius:8px;padding:9px;margin-top:8px}.remove{border:0;background:none;color:var(--red);cursor:pointer}.foot{font-size:11px;color:var(--muted);line-height:1.7}.footer{border-top:1px solid var(--line);padding-top:18px;margin-top:16px;color:var(--muted);font-size:11px}@media(max-width:850px){.hero,.layout{grid-template-columns:1fr}.grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:520px){.wrap{padding:15px 10px}.formgrid{grid-template-columns:1fr}.status{display:none}.panel{padding:12px}}
</style></head><body><main class="wrap">
<header class="top"><div class="brand"><div class="logo">CBP</div><div><div class="eyebrow">AEE / AUTOMOTIVE ENGINEERING</div><div class="title">Bus Protocol Analyzer</div><div class="muted small">Trace inspection · Signal decoding · Anomaly flagging</div></div></div><div class="pill status">● WORKSPACE READY</div></header>
<section class="hero"><div><div class="eyebrow">CAN TRACE INTELLIGENCE</div><h1>Make every frame<br><span>tell a story.</span></h1><p>Inspect automotive bus logs, decode configured payload signals, and surface timing gaps or threshold breaches in one engineering workspace.</p></div><aside class="callout"><div class="eyebrow">ENGINEERING NOTE / 001</div><p class="muted">Reliable findings start with correct signal definitions and expected message periods. Configure these from your network specification before interpreting results.</p><div class="small muted">CSV + Vector ASC · In-memory analysis</div></aside></section>
<section class="grid"><div class="metric"><small>Frames analyzed</small><strong id="mFrames">—</strong><small>Valid parsed frames</small></div><div class="metric"><small>Unique CAN IDs</small><strong id="mIds">—</strong><small>Distinct identifiers</small></div><div class="metric"><small>Flagged events</small><strong id="mEvents">—</strong><small>Configured rules + parse issues</small></div><div class="metric"><small>Trace duration</small><strong id="mDuration">—</strong><small>First to last timestamp</small></div></section>
<section class="layout"><div>
<div class="panel"><div class="head"><h2>01 / Load trace</h2><span class="pill">MAX 12 MB</span></div><div class="drop" id="drop"><div style="font-size:28px;color:var(--cyan)">⇧</div><b>Drop a trace file here</b><p class="muted small">ASC or CSV · processed in memory</p><input id="file" type="file" accept=".asc,.csv" hidden><button class="btn" id="browse">Choose file</button><div id="filename" class="muted small" style="margin-top:9px">No file selected</div></div><div class="actions"><button class="btn primary" id="run" disabled>Analyze trace →</button><button class="btn" id="sample">Load sample data</button></div><div id="message"></div><div class="notice">Synthetic sample only; not a real vehicle trace.</div></div>
<div class="panel"><div class="head"><h2>02 / Message timeout rules</h2><span class="pill">OPTIONAL</span></div><p class="muted small">Flag gaps above expected period × multiplier.</p><div class="formgrid"><div class="field"><label>CAN ID</label><input id="tId" placeholder="0x100"></div><div class="field"><label>Expected period (ms)</label><input id="tPeriod" type="number" value="10" min=".01"></div><div class="field"><label>Multiplier</label><input id="tMult" type="number" value="2" min=".1"></div></div><div class="actions"><button class="btn" id="addT">+ Add timeout rule</button></div><div id="timeouts" class="small muted">No timeout rules configured.</div></div>
<div class="panel"><div class="head"><h2>03 / Signal definitions</h2><span class="pill">BYTE-ALIGNED</span></div><p class="muted small">Define from your CAN database or network specification.</p><div class="formgrid"><div class="field"><label>Signal name</label><input id="sName" placeholder="Engine RPM"></div><div class="field"><label>CAN ID</label><input id="sId" placeholder="0x100"></div><div class="field"><label>Start byte (zero-based)</label><input id="sStart" type="number" min="0" value="0"></div><div class="field"><label>Length (1–8 bytes)</label><input id="sLen" type="number" min="1" max="8" value="2"></div><div class="field"><label>Byte order</label><select id="sEndian"><option value="little">Little-endian</option><option value="big">Big-endian</option></select></div><div class="field"><label>Signed integer</label><select id="sSigned"><option value="false">Unsigned</option><option value="true">Signed</option></select></div><div class="field"><label>Scale</label><input id="sScale" type="number" value="1" step="any"></div><div class="field"><label>Offset</label><input id="sOffset" type="number" value="0" step="any"></div><div class="field"><label>Unit</label><input id="sUnit" placeholder="rpm"></div><div class="field"><label>Minimum (optional)</label><input id="sMin" type="number" step="any"></div><div class="field"><label>Maximum (optional)</label><input id="sMax" type="number" step="any"></div></div><div class="actions"><button class="btn" id="addS">+ Add signal</button></div><div id="signalsRules" class="small muted">No signal definitions configured.</div><p class="foot">Supports byte-aligned decoding, not full DBC/ARXML bit-level layouts or multiplexing. Verify definitions before use.</p></div></div>
<div><div class="panel"><div class="head"><h2>Trace analysis</h2><span class="pill" id="activeFile">AWAITING INPUT</span></div><div id="empty" class="empty"><b>Awaiting a trace</b><p>Upload a CSV or ASC file, or load sample data.</p></div><div id="results" hidden><div class="tabs"><button class="tab active" data-tab="signals">Signals</button><button class="tab" data-tab="events">Events</button><button class="tab" data-tab="frames">Frames</button><button class="tab" data-tab="ids">CAN IDs</button></div>
<div id="tab-signals" class="tabcontent active"><div class="head"><h2>Decoded signal timeline</h2><button class="btn" id="expS">Export CSV</button></div><div id="chartEmpty" class="empty">Add signal definitions and analyze again to view decoded signals.</div><div class="chartbox" id="chartBox" hidden><canvas id="chart"></canvas></div><div id="signalTable"></div></div>
<div id="tab-events" class="tabcontent"><div class="head"><h2>Flagged events</h2><button class="btn" id="expE">Export CSV</button></div><div id="eventList"></div></div>
<div id="tab-frames" class="tabcontent"><div class="head"><h2>Parsed frame preview</h2><button class="btn" id="expF">Export CSV</button></div><div class="field"><label>Filter by ID or payload</label><input id="filter" placeholder="0x100 or 2A"></div><div id="frameTable"></div></div>
<div id="tab-ids" class="tabcontent"><h2>Message inventory</h2><div id="idTable"></div></div></div></div>
<div class="panel"><div class="head"><h2>Analysis method</h2><span class="pill">TRANSPARENT RULES</span></div><div class="foot"><p><b>Frame integrity:</b> malformed records and DLC/payload mismatches are reported.</p><p><b>Timeouts:</b> checked only against explicitly configured expected periods.</p><p><b>Signal limits:</b> optional minimum and maximum are evaluated after scaling and offset.</p><p><b>Scope:</b> findings indicate trace anomalies, not confirmed physical faults. Not a safety-critical diagnostic system.</p></div></div></div></section>
<div class="footer">AEE-CBP · Automotive Engineering / CAN trace analysis · Local in-memory processing · Validate engineering assumptions</div></main>
<script>
const $=id=>document.getElementById(id);let file=null,data=null,chart=null,timeouts=[],signals=[];
function esc(x){return String(x==null?"":x).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function idNum(v){v=String(v).trim();if(!v)throw Error("CAN ID is required");return /^0x/i.test(v)||/[a-f]/i.test(v)?parseInt(v.replace(/^0x/i,""),16):parseInt(v,10);}
function idHex(v){return "0x"+Number(v).toString(16).toUpperCase();}
function msg(s,cls){$("message").innerHTML=s?'<div class="'+(cls||"notice")+'">'+s+"</div>":"";}
$("browse").onclick=()=>$("file").click();$("file").onchange=()=>{file=$("file").files[0]||null;labelFile();};
function labelFile(){$("filename").textContent=file?file.name+" · "+(file.size/1024).toFixed(1)+" KB":"No file selected";$("run").disabled=!file;}
$("drop").ondragover=e=>{e.preventDefault();$("drop").style.borderColor="var(--cyan)"};$("drop").ondragleave=()=> $("drop").style.borderColor="";$("drop").ondrop=e=>{e.preventDefault();$("drop").style.borderColor="";if(e.dataTransfer.files[0]){file=e.dataTransfer.files[0];labelFile();}};
$("sample").onclick=()=>{const csv="timestamp,can_id,dlc,data\n0.000,0x100,8,10 27 00 00 00 00 00 00\n0.010,0x100,8,20 27 00 00 00 00 00 00\n0.020,0x100,8,30 27 00 00 00 00 00 00\n0.030,0x100,8,40 27 00 00 00 00 00 00\n0.000,0x201,4,2A 00 00 00\n0.025,0x201,4,32 00 00 00\n0.050,0x201,4,3C 00 00 00\n0.100,0x100,8,50 27 00 00 00 00 00 00\n";file=new File([csv],"sample_data.csv",{type:"text/csv"});labelFile();$("tId").value="0x100";$("sName").value="Example raw value";$("sId").value="0x100";$("sLen").value="2";$("sUnit").value="raw";msg("Synthetic sample loaded. Add a timeout rule or signal, then analyze.","success");};
$("addT").onclick=()=>{try{let can_id=idNum($("tId").value),period_ms=Number($("tPeriod").value),multiplier=Number($("tMult").value);if(!(period_ms>0&&multiplier>0))throw Error("Period and multiplier must be positive");timeouts.push({can_id,period_ms,multiplier});renderRules();}catch(e){msg(esc(e.message),"error");}};
$("addS").onclick=()=>{try{let s={name:$("sName").value.trim()||"Signal "+(signals.length+1),can_id:idNum($("sId").value),start_byte:Number($("sStart").value),length:Number($("sLen").value),byte_order:$("sEndian").value,signed:$("sSigned").value==="true",scale:Number($("sScale").value),offset:Number($("sOffset").value),unit:$("sUnit").value,minimum:$("sMin").value===""?null:Number($("sMin").value),maximum:$("sMax").value===""?null:Number($("sMax").value)};if(!Number.isInteger(s.start_byte)||s.start_byte<0||!Number.isInteger(s.length)||s.length<1||s.length>8||s.start_byte+s.length>64)throw Error("Byte position/length is invalid");if(!Number.isFinite(s.scale)||!Number.isFinite(s.offset))throw Error("Scale and offset must be numeric");if(s.minimum!==null&&s.maximum!==null&&s.minimum>s.maximum)throw Error("Minimum exceeds maximum");signals.push(s);renderRules();}catch(e){msg(esc(e.message),"error");}};
function renderRules(){$("timeouts").innerHTML=timeouts.length?timeouts.map((t,i)=>'<div class="rule">'+idHex(t.can_id)+" · "+t.period_ms+" ms × "+t.multiplier+' <button class="remove" data-t="'+i+'">Remove</button></div>').join(""):"No timeout rules configured.";$("signalsRules").innerHTML=signals.length?signals.map((s,i)=>'<div class="rule"><b>'+esc(s.name)+"</b> · "+idHex(s.can_id)+"<div class=muted>Byte "+s.start_byte+", "+s.length+" bytes, "+s.byte_order+" · scale "+s.scale+", offset "+s.offset+" "+esc(s.unit)+'</div><button class="remove" data-s="'+i+'">Remove</button></div>').join(""):"No signal definitions configured.";}
document.addEventListener("click",e=>{if(e.target.dataset.t!==undefined){timeouts.splice(+e.target.dataset.t,1);renderRules()}if(e.target.dataset.s!==undefined){signals.splice(+e.target.dataset.s,1);renderRules()}});
$("run").onclick=async()=>{if(!file)return;let b=$("run");b.disabled=true;b.textContent="Analyzing…";try{let fd=new FormData();fd.append("file",file);fd.append("config",JSON.stringify({timeouts:timeouts,signals:signals}));let r=await fetch("/api/analyze",{method:"POST",body:fd}),j=await r.json();if(!r.ok)throw Error(j.detail||"Analysis failed");data=j;render();msg("Analysis complete: "+j.summary.frames+" valid frames, "+j.summary.events+" flagged events.","success");}catch(e){msg(esc(e.message),"error")}finally{b.disabled=!file;b.textContent="Analyze trace →"}};
function fmt(n,d){return n==null||!Number.isFinite(Number(n))?"—":Number(n).toFixed(d==null?3:d)}
function table(head,rows){return rows.length?'<div class="tablewrap"><table><thead><tr>'+head.map(x=>"<th>"+esc(x)+"</th>").join("")+"</tr></thead><tbody>"+rows.map(row=>"<tr>"+row.map(x=>"<td>"+x+"</td>").join("")+"</tr>").join("")+"</tbody></table></div>":'<div class="empty">No records to display.</div>'}
function render(){let s=data.summary;$("mFrames").textContent=s.frames.toLocaleString();$("mIds").textContent=s.unique_ids;$("mEvents").textContent=s.events;$("mDuration").textContent=fmt(s.duration_seconds,3)+" s";$("activeFile").textContent=data.filename;$("empty").hidden=true;$("results").hidden=false;
let pts=data.signals.flatMap(a=>a.points.map(p=>({name:a.name,unit:a.unit,can_id:a.can_id,...p})));$("signalTable").innerHTML=table(["Signal","Time (s)","Value","Unit"],pts.slice(0,500).map(p=>[esc(p.name),fmt(p.timestamp,4),fmt(p.value,4),esc(p.unit)]));
if(chart){chart.destroy();chart=null}if(data.signals.some(x=>x.points.length)&&window.Chart){$("chartEmpty").hidden=true;$("chartBox").hidden=false;chart=new Chart($("chart"),{type:"line",data:{datasets:data.signals.filter(x=>x.points.length).map(x=>({label:x.name+(x.unit?" ("+x.unit+")":""),data:x.points.map(p=>({x:p.timestamp,y:p.value})),borderWidth:2,pointRadius:0,tension:.1}))},options:{responsive:true,maintainAspectRatio:false,parsing:false,interaction:{mode:"nearest",intersect:false},plugins:{legend:{labels:{color:"#bdcbd9"}}},scales:{x:{type:"linear",title:{display:true,text:"Time (s)",color:"#9aabbe"},ticks:{color:"#9aabbe"},grid:{color:"#293747"}},y:{ticks:{color:"#9aabbe"},grid:{color:"#293747"}}}}})}else{$("chartEmpty").hidden=false;$("chartBox").hidden=true}
$("eventList").innerHTML=data.events.length?data.events.map(e=>'<div class="event"><span class="tag '+e.severity+'">'+esc(e.severity.toUpperCase())+"</span> <b>"+esc(e.type)+"</b><div class=muted>"+(e.can_id==null?"":idHex(e.can_id)+" · ")+(e.timestamp==null?"":fmt(e.timestamp,4)+" s")+"</div><p>"+esc(e.details)+"</p><div class=muted>Line: "+(e.line==null?"—":e.line)+"</div></div>").join(""):'<div class="empty">No events flagged by configured rules.</div>';
$("frameTable").innerHTML=frameTable(data.frames);$("idTable").innerHTML=table(["CAN ID","Frames","First (s)","Last (s)"],data.ids.map(x=>[esc(x.can_id),x.frames,fmt(x.first_timestamp,4),fmt(x.last_timestamp,4)]));}
function frameTable(frames){return table(["Time (s)","CAN ID","DLC","Payload","Line"],frames.map(f=>[fmt(f.timestamp,4),esc(f.can_id),f.dlc,"<code>"+esc(f.data)+"</code>",f.line]))}
document.querySelectorAll(".tab").forEach(b=>b.onclick=()=>{document.querySelectorAll(".tab").forEach(t=>t.classList.toggle("active",t===b));document.querySelectorAll(".tabcontent").forEach(t=>t.classList.toggle("active",t.id==="tab-"+b.dataset.tab))});
$("filter").oninput=()=>{if(!data)return;let q=$("filter").value.toLowerCase();$("frameTable").innerHTML=frameTable(data.frames.filter(f=>f.can_id.toLowerCase().includes(q)||f.data.toLowerCase().includes(q)).slice(0,500))};
function csv(name,rows){if(!rows.length)return;let text=rows.map(row=>row.map(v=>{v=String(v==null?"":v);return /[",\r\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v}).join(",")).join("\r\n");let a=document.createElement("a"),u=URL.createObjectURL(new Blob([text],{type:"text/csv"}));a.href=u;a.download=name;a.click();URL.revokeObjectURL(u)}
$("expF").onclick=()=>data&&csv("aee-cbp-frames.csv",[["timestamp","can_id","dlc","data","line"],...data.frames.map(f=>[f.timestamp,f.can_id,f.dlc,f.data,f.line])]);
$("expE").onclick=()=>data&&csv("aee-cbp-events.csv",[["severity","type","timestamp","can_id","details","line"],...data.events.map(e=>[e.severity,e.type,e.timestamp,e.can_id==null?"":idHex(e.can_id),e.details,e.line])]);
$("expS").onclick=()=>data&&csv("aee-cbp-signals.csv",[["signal","timestamp","value","unit","can_id"],...data.signals.flatMap(s=>s.points.map(p=>[s.name,p.timestamp,p.value,s.unit,idHex(s.can_id)]))]);
</script></body></html>'''
