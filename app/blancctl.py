#!/usr/bin/env python3
"""xray-ctl VLESS subscription manager for Xray TUN."""
import argparse, base64, concurrent.futures, contextlib, fcntl, hashlib, io, json, math, os, pathlib, pwd, socket
import ipaddress, re, shutil, subprocess, sys, tempfile, time, urllib.parse

STATE = pathlib.Path(os.getenv("BLANCCTL_STATE", "/var/lib/blancctl"))
SUB, NODES, PINGS, PICK, CONF, STATS, FAILOVER = [STATE / n for n in
    ("subscription.url", "nodes.json", "latencies.json", "selected.json", "xray.json", "stats.json", "failover.json")]
LOCK = STATE / "operation.lock"
DOWNLOAD = STATE / "subscription-download.json"
HISTORY = STATE / "latency-history.json"
SITES = STATE / "site-results.json"
RAW = STATE / "subscription.raw"
RAW_DIR = STATE / "subscription-raw"
SUBSCRIPTIONS = STATE / "subscriptions.json"
ROUTES = STATE / "routing.json"
RETAINED = STATE / "retained-nodes.json"
REFRESH_STATUS = STATE / "subscription-refresh.json"
CONTROL = "/usr/lib/blancctl/service-control"
LOCAL_PROXY = "socks5h://127.0.0.1:10808"
TEST_URLS = (
    "https://cp.cloudflare.com/generate_204",
    "https://web.telegram.com/",
    "https://chatgpt.com/",
    "https://youtube.com/",
)
DEFAULT_WORKERS = min(32, max(16, (os.cpu_count() or 8)*2))
DEFAULT_PROBE_TIMEOUT = 8
COLOR = sys.stdout.isatty() and 'NO_COLOR' not in os.environ
VERSION = "0.6.1"

def paint(code,text): return f"\033[{code}m{text}\033[0m" if COLOR else text

def die(s): print("xray-ctl:", s, file=sys.stderr); raise SystemExit(1)
def current_user(): return pwd.getpwuid(os.geteuid()).pw_name
def sudo_executable(wrapper=pathlib.Path('/run/wrappers/bin/sudo')):
    """Prefer NixOS' privileged wrapper over the unprivileged store binary."""
    if wrapper.is_file() and os.access(wrapper,os.X_OK): return str(wrapper)
    return shutil.which('sudo')
def configured_owner():
    owner_file=pathlib.Path('/etc/blancctl/owner')
    try: return owner_file.read_text().strip()
    except FileNotFoundError: die(f"not configured; run: sudo xray-ctl-setup {current_user()}")
    except OSError as e: die(f"cannot read {owner_file}: {e}")

def require_user():
    if os.geteuid()==0:
        user=os.environ.get('SUDO_USER') or '<user>'
        die(f"do not run blancctl with sudo; run it as your normal user ({user})")

def load(p, default):
    if not p.exists(): return default
    try: return json.loads(p.read_text())
    except PermissionError: die(f"cannot read {p}; run: sudo xray-ctl-setup $USER")
    except (OSError,json.JSONDecodeError) as e: die(f"cannot load {p.name}: {e}")
def save_text(p,text):
    p.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix=p.name+'.',dir=p.parent)
    try:
        with os.fdopen(fd,'w') as out: out.write(text)
        os.replace(name,p)
    finally:
        if os.path.exists(name): os.unlink(name)
def save(p,data):
    save_text(p,json.dumps(data,ensure_ascii=False,indent=2)+'\n')
def subscription_sources():
    sources=load(SUBSCRIPTIONS,None)
    if sources is None:
        return {'default':SUB.read_text().strip()} if SUB.exists() else {}
    if not isinstance(sources,dict) or any(not isinstance(k,str) or not isinstance(v,str)
                                            for k,v in sources.items()):
        die("invalid subscriptions.json")
    return sources
def valid_source_name(name):
    return bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}',name))
def subscription_url(value):
    p=pathlib.Path(value).expanduser()
    url=p.read_text().strip() if p.is_file() else value
    if not url.startswith(('http://','https://')): die("expected URL or file containing URL")
    return url
@contextlib.contextmanager
def operation_lock():
    STATE.mkdir(parents=True,exist_ok=True)
    with LOCK.open('a+') as lock:
        os.chmod(LOCK,0o600)
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: die("another configuration operation is already running")
        yield
@contextlib.contextmanager
def try_operation_lock():
    STATE.mkdir(parents=True,exist_ok=True)
    with LOCK.open('a+') as lock:
        os.chmod(LOCK,0o600)
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        yield True
def flag(s):
    x=[ord(c)-0x1f1e6 for c in s[:2]]
    return ''.join(chr(65+n) for n in x) if len(x)==2 and all(0<=n<26 for n in x) else "XX"
def country(s):
    while s and ord(s[0])>=0x1f000: s=s[1:]
    p=[x.strip() for x in s.split(',') if not x.strip().lower().startswith('extra')]
    return p[1] if len(p)>1 else p[0] if p else "Unknown"
def parse(line, i):
    u=urllib.parse.urlsplit(line); q={k:v[-1] for k,v in urllib.parse.parse_qs(u.query).items()}
    if u.scheme!="vless" or not all((u.username,u.hostname,u.port)): raise ValueError
    network=q.get('type','tcp')
    if network not in ('tcp','ws','xhttp','splithttp','grpc','httpupgrade'): raise ValueError
    security=q.get('security','none')
    if security not in ('none','tls','reality'): raise ValueError
    extra=q.get('extra','')
    if extra:
        parsed_extra=json.loads(extra)
        if not isinstance(parsed_extra,dict): raise ValueError
        extra=json.dumps(parsed_extra,ensure_ascii=False,sort_keys=True,separators=(',',':'))
    label=urllib.parse.unquote(u.fragment) or f"server-{i+1}"
    return dict(id=f"node-{i+1:03d}",label=label,country_code=flag(label),country=country(label),
      address=u.hostname,port=u.port,uuid=urllib.parse.unquote(u.username),network=network,
      security=security,flow=q.get('flow',''),encryption=q.get('encryption','none'),
      sni=q.get('sni',''),fingerprint=q.get('fp','chrome'),public_key=q.get('pbk',''),
      short_id=q.get('sid',''),path=q.get('path','/'),host=q.get('host',''),header=q.get('headerType','none'),
      mode=q.get('mode',''),extra=extra,service_name=q.get('serviceName',''),
      authority=q.get('authority',''),alpn=q.get('alpn',''),
      allow_insecure=q.get('allowInsecure','').lower() in ('1','true'),spider_x=q.get('spx',''))
NODE_FIELDS=('address','port','uuid','network','security','flow','encryption','sni',
  'fingerprint','public_key','short_id','path','host','header','mode','extra',
  'service_name','authority','alpn','allow_insecure','spider_x')
def node_key(n):
    return tuple(n.get(field,False if field=='allow_insecure' else '') for field in NODE_FIELDS)
def endpoint_key(n):
    # SNI, short ID, and transport paths can be independent ways through a
    # whitelist. Keep every profile, but count their common server only once.
    return tuple(n.get(field,'') for field in
      ('address','port','uuid','network','security','flow','public_key'))
def endpoint_groups(ns):
    groups={}
    for n in ns: groups.setdefault(endpoint_key(n),[]).append(n)
    return list(groups.values())
def disabled_node(n):
    if str(n.get('country_code','')).upper()=='RU': return True
    name=str(n.get('country','')).strip().casefold()
    return name.startswith(('russia','росси'))
def selectable_nodes(ns):
    return [n for n in ns if not disabled_node(n)]
def diverse_candidates(ns,limit):
    groups=endpoint_groups(ns)
    ordered=[]
    while groups and len(ordered)<limit:
        next_groups=[]
        for group in groups:
            ordered.append(group.pop(0))
            if group: next_groups.append(group)
            if len(ordered)>=limit: break
        groups=next_groups
    return ordered
def compact_nodes(cached,selected_id=None):
    unique={}
    for n in cached:
        key=node_key(n)
        if key not in unique:
            unique[key]=n
            continue
        previous=unique[key]
        preferred=n if previous.get('stale') and not n.get('stale') else previous
        if selected_id in (previous.get('id'),n.get('id')):
            preferred={**preferred,'id':selected_id}
        preferred={**preferred,'sources':sorted(set(previous.get('sources',['default']))|
                                                set(n.get('sources',['default'])))}
        unique[key]=preferred
    return list(unique.values())
def merge_nodes(fetched,cached,selected_id=None):
    cached=compact_nodes(cached,selected_id)
    old={node_key(n):n for n in cached}
    used_ids={n['id'] for n in cached}
    seen={}; current=[]
    for n in fetched:
        key=node_key(n)
        if key in seen:
            existing=seen[key]
            existing['sources']=sorted(set(existing.get('sources',[]))|set(n.get('sources',[])))
            continue
        seen[key]=n
        previous=old.get(key)
        if previous:
            n['id']=previous['id']
        else:
            digest=hashlib.sha256(json.dumps(key,ensure_ascii=False).encode()).hexdigest()
            base='node-'+digest[:16]
            n['id']=base
            suffix=2
            while n['id'] in used_ids:
                n['id']=f'{base}-{suffix}'
                suffix+=1
            used_ids.add(n['id'])
        n['stale']=False
        current.append(n)
    retained=[{**n,'stale':True} for n in cached if node_key(n) not in seen]
    return current+retained,len(current),len(retained)
def download_limits():
    previous=load(DOWNLOAD,{}).get('seconds')
    if not isinstance(previous,(int,float)) or not math.isfinite(previous) or previous<=0: return 2.5,8
    return round(min(4,max(2,previous*.75+1)),1),round(min(12,max(5,previous*1.75+2)),1)
def download_source(name,url,connect_timeout,total_timeout):
    proxy=[]
    try:
        with socket.create_connection(('127.0.0.1',10808),.2): proxy=['--proxy',LOCAL_PROXY]
    except OSError: pass
    try:
        r=subprocess.run(['curl','--fail','--location','--silent','--show-error',
          '--connect-timeout',str(connect_timeout),'--max-time',str(total_timeout),
          '--max-filesize',str(8*1024*1024),'-A','v2rayN/7.0',*proxy,url],
          capture_output=True,timeout=total_timeout+2)
    except subprocess.TimeoutExpired:
        raise RuntimeError("download timed out") from None
    if r.returncode:
        reason={22:'HTTP error',28:'timeout'}.get(r.returncode,'network error')
        raise RuntimeError(f"{reason} (curl exit {r.returncode})")
    raw=r.stdout
    if len(raw)>8*1024*1024: raise RuntimeError("subscription is larger than 8 MiB")
    raw_text=raw.decode(errors='replace')
    text=raw_text.strip()
    if 'vless://' not in text:
        try: text=base64.b64decode(text+'='*(-len(text)%4)).decode()
        except Exception: raise RuntimeError("invalid subscription encoding") from None
    out=[]; unparsed=0
    for index,line in enumerate(text.splitlines()):
        if not line.strip(): continue
        try:
            node=parse(line.strip(),index)
            node['sources']=[name]
            out.append(node)
        except ValueError: unparsed+=1
    return out,text,unparsed
def update(url=None,replace=False):
    sources={'default':url} if url is not None else subscription_sources()
    if not sources: die("no subscriptions configured; use: xray-ctl subscription add NAME URL")
    connect_timeout,total_timeout=download_limits()
    started=time.monotonic()
    fetched=[]; failed={}; unparsed=0; succeeded=0
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8,len(sources))) as pool:
        futures={pool.submit(download_source,name,source,connect_timeout,total_timeout):name
                 for name,source in sources.items()}
        for future in concurrent.futures.as_completed(futures):
            name=futures[future]
            try: nodes_for_source,text,missing=future.result()
            except RuntimeError as e:
                failed[name]=str(e)
                continue
            raw_path=RAW if name=='default' else RAW_DIR/(hashlib.sha256(name.encode()).hexdigest()[:16]+'.raw')
            save_text(raw_path,text+'\n')
            if not nodes_for_source:
                failed[name]="no supported VLESS servers"
                unparsed+=missing
                continue
            fetched.extend(nodes_for_source)
            unparsed+=missing
            succeeded+=1
    if not fetched:
        details=', '.join(f'{name}: {reason}' for name,reason in failed.items())
        die(f"all subscription downloads failed ({details})")
    cached=[] if replace else load(NODES,[])+load(RETAINED,[])
    if failed:
        for node in cached:
            source_names=node.get('sources',['default'])
            if not node.get('stale') and any(name in failed for name in source_names):
                fetched.append({**node,'sources':source_names})
    selected_id=load(PICK,{}).get('id') if not replace else None
    merged,current,retained=merge_nodes(fetched,cached,selected_id)
    if replace:
        save_text(SUB,url+'\n')
    # Stage the full merged set first. Either order of the final two writes
    # could otherwise lose a profile if refresh is interrupted midway.
    save(RETAINED,merged)
    save(NODES,merged[:current])
    save(RETAINED,merged[current:])
    save(DOWNLOAD,{'seconds':round(time.monotonic()-started,2)})
    duplicates=len(fetched)-current
    endpoints=len(endpoint_groups(merged[:current]))
    print(f"Updated {succeeded}/{len(sources)} subscriptions: {endpoints} current endpoints "
          f"({current} VLESS profiles); {duplicates} identical links collapsed; "
          f"{retained} older profiles retained; {unparsed} unsupported entries.")
    for name,reason in failed.items(): print(f"Subscription {name} kept from cache: {reason}",file=sys.stderr)
    return merged
def cached_nodes():
    selected=load(PICK,{}).get('id')
    stored=load(NODES,[])
    current=compact_nodes([n for n in stored if not n.get('stale')],selected)
    retained=compact_nodes([{**n,'stale':True} for n in load(RETAINED,[])]+\
                           [n for n in stored if n.get('stale')],selected)
    current_keys={node_key(n) for n in current}
    retained=[n for n in retained if node_key(n) not in current_keys]
    return current,retained
def nodes():
    current,retained=cached_nodes()
    if not current and not retained:
        updated=update()
        return [n for n in updated if not n.get('stale')]
    return current or retained
def physical_interface():
    r=subprocess.run(['ip','-4','route','show','default'],capture_output=True,text=True)
    for line in r.stdout.splitlines():
        fields=line.split()
        if 'dev' in fields: return fields[fields.index('dev')+1]
    die("no physical default network interface found")
def outbound(n,interface=None):
    user={'id':n['uuid'],'encryption':n['encryption']}
    if n['flow']: user['flow']=n['flow']
    network='xhttp' if n['network']=='splithttp' else n['network']
    stream={'network':network,'security':n['security']}
    if n['security']=='reality': stream['realitySettings']={'serverName':n['sni'],'fingerprint':n['fingerprint'],'publicKey':n['public_key'],'shortId':n['short_id'],'spiderX':n.get('spider_x','')}
    elif n['security']=='tls':
        tls={'serverName':n['sni'],'fingerprint':n['fingerprint']}
        if n.get('alpn'): tls['alpn']=n['alpn'].split(',')
        if n.get('allow_insecure'): tls['allowInsecure']=True
        stream['tlsSettings']=tls
    if n['network']=='ws':
        stream['wsSettings']={'path':n['path']}
        if n['host']: stream['wsSettings']['headers']={'Host':n['host']}
    elif network=='xhttp':
        xhttp={'path':n['path']}
        if n['host']: xhttp['host']=n['host']
        if n.get('mode'): xhttp['mode']=n['mode']
        if n.get('extra'):
            extra=json.loads(n['extra'])
            if interface and isinstance(extra.get('downloadSettings'),dict):
                download=extra['downloadSettings']
                sockopt=download.get('sockopt')
                download['sockopt']={**sockopt,'interface':interface} if isinstance(sockopt,dict) else {'interface':interface}
            xhttp['extra']=extra
        stream['xhttpSettings']=xhttp
    elif network=='grpc':
        grpc={'serviceName':n.get('service_name','')}
        if n.get('authority'): grpc['authority']=n['authority']
        stream['grpcSettings']=grpc
    elif network=='httpupgrade':
        stream['httpupgradeSettings']={'path':n['path'],'host':n['host']}
    if interface: stream['sockopt']={'interface':interface}
    return {'tag':'proxy','protocol':'vless','settings':{'vnext':[{'address':n['address'],'port':n['port'],'users':[user]}]},
      'streamSettings':stream}
def normalize_route_value(kind,value):
    if kind=='domains':
        prefix='domain:'
        for candidate in ('full:','domain:','geosite:'):
            if value.startswith(candidate): prefix,value=candidate,value[len(candidate):]; break
        if prefix=='geosite:':
            if not re.fullmatch(r'[A-Za-z0-9@._-]+',value): die("invalid geosite name")
            return prefix+value.lower()
        try: host=value.rstrip('.').encode('idna').decode('ascii').lower()
        except UnicodeError: die("invalid domain")
        if not host or len(host)>253 or any(not re.fullmatch(r'[a-z0-9-]{1,63}',part)
                                         for part in host.split('.')):
            die("invalid domain")
        return prefix+host
    if kind=='ips':
        if value.startswith('geoip:'):
            if not re.fullmatch(r'geoip:[A-Za-z0-9@._-]+',value): die("invalid geoip name")
            return value.lower()
        try: return str(ipaddress.ip_network(value,strict=False))
        except ValueError: die("expected an IP address, CIDR, or geoip:NAME")
    die("route kind must be domain or ip")
def routing_config():
    raw=load(ROUTES,{})
    if not isinstance(raw,dict): die("routing.json must be an object")
    if set(raw)-{'default','direct','proxy','block'}: die("unknown routing.json key")
    default=raw.get('default','proxy')
    if default not in ('proxy','direct'): die("routing default must be proxy or direct")
    result={'default':default}
    for action in ('direct','proxy','block'):
        group=raw.get(action,{})
        if not isinstance(group,dict) or set(group)-{'domains','ips'}:
            die(f"invalid routing {action} rules")
        result[action]={}
        for kind in ('domains','ips'):
            values=group.get(kind,[])
            if not isinstance(values,list) or len(values)>500 or any(not isinstance(v,str) for v in values):
                die(f"invalid routing {action} {kind}")
            result[action][kind]=list(dict.fromkeys(normalize_route_value(kind,v) for v in values))
    return result
def routing_rules():
    config=routing_config()
    rules=[{'type':'field','ip':['geoip:private'],'outboundTag':'direct'}]
    for action in ('block','proxy','direct'):
        for kind in ('domains','ips'):
            values=config[action][kind]
            if values: rules.append({'type':'field','domain' if kind=='domains' else 'ip':values,
                                     'outboundTag':action})
    rules.append({'type':'field','network':'tcp,udp','outboundTag':config['default']})
    return rules
def tun(n):
    interface=physical_interface(); direct={'tag':'direct','protocol':'freedom','streamSettings':{'sockopt':{'interface':interface}}}
    return {'log':{'loglevel':'warning'},'dns':{'servers':['1.1.1.1','8.8.8.8','localhost']},
      'inbounds':[{'tag':'tun-in','protocol':'tun','settings':{'name':'blanc0','mtu':1400,
       'gateway':['172.30.0.1/30','fd30::1/126']},
       'sniffing':{'enabled':True,'destOverride':['http','tls','quic'],'routeOnly':True}},
       {'tag':'socks-in','listen':'127.0.0.1','port':10808,'protocol':'socks','settings':{'udp':True}}],
      'outbounds':[outbound(n,interface),direct,{'tag':'block','protocol':'blackhole'}],
      'routing':{'domainStrategy':'AsIs','rules':routing_rules()}}
def socks(n,port,interface=None):
    return {'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'udp':True}}],
      'outbounds':[outbound(n,interface or physical_interface())],'routing':{'rules':[{'type':'field','network':'tcp,udp','outboundTag':'proxy'}]}}
def port():
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
def probe_urls(proxy,urls,timeout):
    connect_timeout=min(timeout,2.5)
    command=['curl','-sS','-L','--range','0-0','--max-redirs','3',
      '-A','Mozilla/5.0','--proxy',proxy,
      '--connect-timeout',str(connect_timeout),'--max-time',str(timeout),'--parallel',
      '--parallel-immediate','--parallel-max',str(len(urls)),
      '-w','%{urlnum} %{http_code} %{time_starttransfer}\n']
    for url in urls: command.extend(('-o','/dev/null',url))
    try:
        r=subprocess.run(command,capture_output=True,text=True,timeout=timeout+2)
    except subprocess.TimeoutExpired: return [None]*len(urls)
    values=[None]*len(urls)
    for line in r.stdout.splitlines():
        try:
            urlnum,status,elapsed=line.split(); urlnum=int(urlnum); status=int(status); elapsed=float(elapsed)
            if 0<=urlnum<len(values) and 200<=status<400 and elapsed>0: values[urlnum]=elapsed*1000
        except ValueError: pass
    return values
def adaptive_timeout(previous,limit):
    if not isinstance(previous,(int,float)) or not math.isfinite(previous) or previous<=0: return min(limit,5.5)
    return min(limit,max(3.0,round(previous/1000*1.5+2.0,1)))
def probe_score(values):
    ordered=sorted(value for value in values if value is not None)
    if not ordered: return None
    return round((ordered[(len(ordered)-1)//2]+ordered[len(ordered)//2])/2,1)
def test(n,timeout,interface=None,urls=TEST_URLS):
    p=port()
    with tempfile.TemporaryDirectory(prefix='blancctl-') as d:
        c=pathlib.Path(d)/'c.json'; c.write_text(json.dumps(socks(n,p,interface)))
        x=subprocess.Popen(['xray','run','-c',str(c)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            end=time.monotonic()+2.5
            while time.monotonic()<end:
                if x.poll() is not None: return n['id'],None,[None]*len(urls)
                try:
                    with socket.create_connection(('127.0.0.1',p),.15): break
                except OSError: time.sleep(.05)
            else: return n['id'],None,[None]*len(urls)
            proxy=f'socks5h://127.0.0.1:{p}'
            values=probe_urls(proxy,urls,timeout)
            return n['id'],probe_score(values),values
        finally:
            if x.poll() is None:
                x.terminate()
                try: x.wait(1)
                except subprocess.TimeoutExpired:
                    x.kill(); x.wait()
def benchmark(ns,workers,timeout):
    if not ns: return {}
    if not math.isfinite(timeout) or timeout<=0: die("probe timeout must be a positive finite number")
    sites=', '.join(urllib.parse.urlsplit(url).hostname for url in TEST_URLS)
    workers=max(1,min(workers,len(ns)))
    interface=physical_interface()
    groups=endpoint_groups(ns)
    print(f"Testing {len(groups)} endpoints ({len(ns)} profiles) with {workers} workers via {sites}…")
    result=load(PINGS,{})
    history=load(HISTORY,{})
    sites=load(SITES,{})
    for n in ns:
        value=result.get(n['id'])
        if value is not None and n['id'] not in history: history[n['id']]=value
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        fs={pool.submit(test,n,adaptive_timeout(history.get(n['id']),timeout),interface):n for n in ns}
        remaining={endpoint_key(group[0]):len(group) for group in groups}
        completed=0
        for f in concurrent.futures.as_completed(fs):
            k,v,values=f.result(); result[k]=v
            if v is not None: history[k]=v
            sites[k]=[value is not None for value in values]
            group_key=endpoint_key(fs[f])
            remaining[group_key]-=1
            if remaining[group_key]==0:
                completed+=1
                group=next(group for group in groups if endpoint_key(group[0])==group_key)
                working=[n for n in group if result.get(n['id']) is not None]
                winner=min(working,key=lambda n:(-sum(sites[n['id']]),result[n['id']])) if working else group[0]
                latency=result.get(winner['id'])
                value=f'{latency} ms' if latency is not None else paint('31','failed')
                markers=' '.join(f"{name}{'✓' if passed else '×'}" for name,passed in
                  zip(('CF','TG','GPT','YT'),sites[winner['id']]))
                print(f"{paint('2',f'[{completed}/{len(groups)}]')} {winner['label']} "
                      f"({len(group)} profiles): {value} · {markers}")
    save(PINGS,result)
    save(HISTORY,history)
    save(SITES,sites)
    return result,sites
def speedtest(timeout=20):
    size=1024*1024; end=time.monotonic()+5
    while time.monotonic()<end:
        try:
            with socket.create_connection(('127.0.0.1',10808),.2): break
        except OSError: time.sleep(.1)
    else: return None
    try:
        r=subprocess.run(['curl','-sS','-L','--retry','2','--retry-all-errors','-o','/dev/null',
          '--proxy',LOCAL_PROXY,'--connect-timeout','8','--max-time',str(timeout),
          '-w','%{size_download} %{time_total}',f'https://speed.cloudflare.com/__down?bytes={size}'],
          capture_output=True,text=True,timeout=timeout+2)
    except subprocess.TimeoutExpired: return None
    if r.returncode: return None
    try:
        downloaded,elapsed=map(float,r.stdout.split())
        return round(downloaded*8/elapsed/1_000_000,1) if downloaded and elapsed else None
    except (ValueError,ZeroDivisionError): return None
def pingtest(timeout=10):
    successful=[value for value in probe_urls(LOCAL_PROXY,TEST_URLS,timeout) if value is not None]
    return round(min(successful),1) if successful else None
def routes_healthy():
    if not pathlib.Path('/sys/class/net/blanc0').exists(): return False
    families=['-4']
    if pathlib.Path('/proc/net/if_inet6').exists(): families.append('-6')
    for family in families:
        rules=subprocess.run(['ip',family,'rule','show'],capture_output=True,text=True)
        routes=subprocess.run(['ip',family,'route','show','table','4269'],capture_output=True,text=True)
        if rules.returncode or routes.returncode: return False
        if 'lookup 4269' not in (rules.stdout or ''): return False
        if not any(line.split()[:3]==['default','dev','blanc0'] for line in (routes.stdout or '').splitlines()):
            return False
    return True
def failover(_):
    threshold=max(1,int(os.getenv('BLANCCTL_FAILOVER_FAILURES','3')))
    timeout=max(1,float(os.getenv('BLANCCTL_FAILOVER_TIMEOUT','5')))
    max_candidates=max(1,int(os.getenv('BLANCCTL_FAILOVER_CANDIDATES','6')))
    active=subprocess.run(['systemctl','is-active','--quiet','blancctl.service']).returncode==0
    if not active:
        failed=subprocess.run(['systemctl','is-failed','--quiet','blancctl.service']).returncode==0
        if not failed:
            print("BlancVPN is stopped; skipping this failover check.")
            return
        with try_operation_lock() as available:
            if not available:
                print("Configuration operation in progress; skipping this failover check.")
                return
            if subprocess.run(['systemctl','is-failed','--quiet','blancctl.service']).returncode==0:
                print("BlancVPN service failed; attempting to restart it.")
                try: service('restart')
                except SystemExit: print("Service restart failed; checking cached alternatives.")
        active=subprocess.run(['systemctl','is-active','--quiet','blancctl.service']).returncode==0
        failed=True
    else:
        failed=False
    with try_operation_lock() as available:
        if not available:
            print("Configuration operation in progress; skipping this failover check.")
            return
    state=load(FAILOVER,{})
    selected=load(PICK,{})
    disabled_current=disabled_node(selected)
    latency=None if disabled_current or not active else pingtest(timeout)
    if latency is not None:
        if not routes_healthy():
            now=int(time.time())
            if now-state.get('route_repair_at',0)<120:
                print("TUN route is still unavailable; waiting before another repair attempt.")
                return
            with try_operation_lock() as available:
                if not available:
                    print("Configuration operation in progress; deferring TUN route repair.")
                    return
                still_active=subprocess.run(['systemctl','is-active','--quiet','blancctl.service']).returncode==0
                if not still_active or load(PICK,{}).get('id')!=selected.get('id'):
                    print("Connection changed during the check; deferring TUN route repair.")
                    return
                save(FAILOVER,{**state,'route_repair_at':now,'checked_at':now})
                state['route_repair_at']=now
                print("TUN route is unavailable; restarting Xray to restore it.")
                try: service('restart')
                except SystemExit:
                    print("TUN route repair failed; will retry later.")
                    return
            if not routes_healthy() or pingtest(timeout) is None:
                print("TUN route remains unavailable after restart; will retry later.")
                return
        if state.get('failures',0): print(f"Connection recovered: {latency:.0f} ms")
        save(FAILOVER,{**state,'failures':0,'checked_at':int(time.time())})
        return
    failures=threshold if disabled_current or failed else state.get('failures',0)+1
    save(FAILOVER,{'failures':failures,'checked_at':int(time.time())})
    if failures < threshold:
        print(f"Health check failed ({failures}/{threshold}); keeping the current server.")
        return
    current,retained=cached_nodes()
    ns=selectable_nodes(current+retained)
    if not ns: die("failover has no enabled cached servers; Russia endpoints are disabled")
    pings=load(PINGS,{})
    history=load(HISTORY,{})
    candidates=[n for n in ns if n['id']!=selected.get('id')]
    candidates.sort(key=lambda n:(bool(n.get('stale')),history.get(n['id'],pings.get(n['id'])) is None,
      history.get(n['id'],pings.get(n['id'])) or float('inf')))
    candidates=diverse_candidates(candidates,max_candidates)
    reason="Selected Russia endpoint is disabled" if disabled_current else f"Current server failed {failures} checks"
    print(f"{reason}; testing {len(candidates)} alternatives…")
    if not candidates:
        print("No alternative cached server is available; will retry later.")
        return
    working=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8,len(candidates))) as pool:
        probes={pool.submit(test,n,timeout,urls=TEST_URLS):n for n in candidates}
        for future in concurrent.futures.as_completed(probes):
            try: _,candidate_latency,sites=future.result()
            except Exception: continue
            if candidate_latency is not None:
                working.append((probes[future],candidate_latency,sum(value is not None for value in sites)))
    working.sort(key=lambda item:(-item[2],item[1]))
    for n,candidate_latency,_ in working:
        with try_operation_lock() as available:
            if not available:
                print("Configuration operation started during the check; deferring failover.")
                return
            if load(PICK,{}).get('id')!=selected.get('id'):
                print("Selected server changed during the check; deferring failover.")
                return
            now_active=subprocess.run(['systemctl','is-active','--quiet','blancctl.service']).returncode==0
            if not now_active and subprocess.run(['systemctl','is-failed','--quiet','blancctl.service']).returncode!=0:
                print("BlancVPN was stopped during the check; not reconnecting.")
                return
            recovered_latency=None if disabled_current or not now_active else pingtest(timeout)
            if recovered_latency is not None:
                print(f"Connection recovered during failover testing: {recovered_latency:.0f} ms")
                save(FAILOVER,{'failures':0,'checked_at':int(time.time())})
                return
            print(f"Failing over to {n['label']} ({candidate_latency:.0f} ms).")
            try: select(n,ping=candidate_latency)
            except SystemExit:
                print("Alternative failed its live check; trying the next cached server.")
                continue
            save(FAILOVER,{'failures':0,'checked_at':int(time.time()),'switched_at':int(time.time())})
            return
    print("Failover could not find a working cached server; will retry later.")
def record_speed():
    stats=load(STATS,{}); stats['speed_mbps']=speedtest(); stats['tested_at']=int(time.time()); save(STATS,stats)
def best(ns,r,sites,selected_id=None):
    ok=[n for n in ns if r.get(n['id']) is not None]
    if not ok: die("no working server found")
    count=lambda n: sum(sites.get(n['id'],[]))
    winner=min(ok,key=lambda n:(-count(n),r[n['id']]))
    current=next((n for n in ok if n['id']==selected_id),None)
    if current and count(current)==count(winner) and r[current['id']]<=r[winner['id']]*1.25+100:
        return current
    return winner
def benchmark_choice(ns,workers,timeout,fallback=()):
    r,sites=benchmark(ns,workers,timeout)
    if not any(r.get(n['id']) is not None for n in ns) and fallback:
        print(f"No current profile worked; checking {len(fallback)} retained backups…")
        ns=list(fallback)
        r,sites=benchmark(ns,workers,timeout)
    return best(ns,r,sites,load(PICK,{}).get('id')),r
def service(action):
    if os.getenv('BLANCCTL_NO_SERVICE')=='1': return
    owner=configured_owner(); user=current_user()
    if user != owner:
        die(f"configured for {owner}, but running as {user}; repair with: sudo xray-ctl-setup {user}")
    sudo=sudo_executable()
    if sudo is None: die("required command is missing: sudo")
    r=subprocess.run([sudo,'-n',CONTROL,action],capture_output=True,text=True)
    if r.returncode:
        detail=(r.stderr or r.stdout).strip().splitlines()
        reason=f": {detail[-1]}" if detail else ""
        die(f"service control failed{reason}; repair with: sudo xray-ctl-setup {owner}")

def dead_local_proxy_environment():
    names=('HTTP_PROXY','HTTPS_PROXY','FTP_PROXY','ALL_PROXY',
      'http_proxy','https_proxy','ftp_proxy','all_proxy')
    endpoints={}
    for name in names:
        value=os.getenv(name)
        if not value: continue
        try:
            parsed=urllib.parse.urlsplit(value if '://' in value else 'http://'+value)
            host=parsed.hostname
            port=parsed.port
        except ValueError:
            continue
        if host not in ('127.0.0.1','localhost','::1') or port is None: continue
        endpoints.setdefault((host,port),[]).append(name)
    problems=[]
    for (host,port),variables in endpoints.items():
        try:
            with socket.create_connection((host,port),.2): pass
        except OSError:
            problems.append(
              f"dead local proxy {host}:{port} in {','.join(variables)}; "
              "unset HTTP_PROXY HTTPS_PROXY FTP_PROXY ALL_PROXY "
              "http_proxy https_proxy ftp_proxy all_proxy")
    return problems

def doctor(_):
    problems=[]
    owner_file=pathlib.Path('/etc/blancctl/owner')
    owner=owner_file.read_text().strip() if owner_file.exists() else ''
    user=current_user()
    if not owner: problems.append("not configured (owner file is missing)")
    elif owner != user: problems.append(f"configured owner is {owner}, current user is {user}")
    if not STATE.exists(): problems.append(f"state directory is missing: {STATE}")
    elif not os.access(STATE,os.R_OK|os.W_OK|os.X_OK): problems.append(f"state directory is not accessible: {STATE}")
    for command in ('curl','ip','systemctl','xray'):
        if shutil.which(command) is None: problems.append(f"required command is missing: {command}")
    sudo=sudo_executable()
    if sudo is None: problems.append("required command is missing: sudo")
    problems.extend(dead_local_proxy_environment())
    if owner == user:
        r=subprocess.run([sudo,'-n',CONTROL,'check'],capture_output=True,text=True)
        if r.returncode: problems.append("passwordless service control is not configured")
    if problems:
        for problem in problems: print(f"{paint('31','FAIL')}  {problem}")
        print(f"Repair with: sudo xray-ctl-setup {user}",file=sys.stderr)
        raise SystemExit(1)
    print(f"{paint('32','OK')}  xray-ctl {VERSION} is configured for {user}")
def select(n,restart=True,ping=None,speed=None,force=False):
    if disabled_node(n): die("Russia endpoints are disabled; no connection was changed")
    config=tun(n)
    if restart and not force and CONF.exists() and PICK.exists():
        previous_pick=load(PICK,{})
        if previous_pick.get('id')==n['id'] and load(CONF,{})==config:
            active=subprocess.run(['systemctl','is-active','--quiet','blancctl.service']).returncode==0
            if active:
                print("Already using:",paint('36',n['label']))
                return
    with tempfile.TemporaryDirectory(prefix='blancctl-check-') as d:
        validation=dict(config)
        validation['inbounds']=[{'listen':'127.0.0.1','port':port(),'protocol':'socks',
          'settings':{'udp':True},'sniffing':config['inbounds'][0]['sniffing']}]
        c=pathlib.Path(d)/'c.json'; c.write_text(json.dumps(validation))
        r=subprocess.run(['xray','run','-test','-c',str(c)],capture_output=True,text=True)
        if r.returncode:
            detail=(r.stderr or r.stdout).strip().splitlines()
            die("generated Xray TUN configuration is invalid"+(f": {detail[-1]}" if detail else ""))
    previous={p:p.read_text() if p.exists() else None for p in (CONF,PICK,STATS)}
    save(CONF,config)
    save(PICK,{'id':n['id'],'label':n['label'],'country_code':n['country_code'],'country':n['country']})
    save(STATS,{'ping_ms':ping,'speed_mbps':speed,'tested_at':int(time.time())})
    if restart:
        try:
            service('restart')
            if os.getenv('BLANCCTL_NO_SERVICE')!='1' and pingtest(5.5) is None:
                raise ConnectionError("new server did not pass a live connectivity check")
        except (SystemExit,ConnectionError) as failure:
            for path,old_text in previous.items():
                if old_text is None: path.unlink(missing_ok=True)
                else: save_text(path,old_text)
            if previous[CONF] is not None:
                try: service('restart')
                except SystemExit: die("new connection failed; previous configuration was restored but its service restart failed")
            reason=str(failure) if isinstance(failure,ConnectionError) else 'service restart failed'
            die(f"{reason}; previous configuration restored")
    print(paint('1;32','Selected:'),paint('36',n['label']))
def start(_):
    old=load(PICK,{})
    current,retained=cached_nodes()
    ns=selectable_nodes(current+retained)
    n=next((x for x in ns if x['id']==old.get('id')),None)
    if n:
        select(n,force=True)
    elif old and CONF.exists() and not disabled_node(old):
        service('restart')
        print("Started the previously saved connection; its node is not in the current cache.")
    else:
        if not ns: ns=selectable_nodes(update())
        if not ns: die("no enabled servers available; Russia endpoints are disabled")
        select(ns[0])
def countries(_):
    groups={}
    for n in selectable_nodes(nodes()): groups.setdefault(n['country_code'],[]).append(n)
    for code,es in sorted(groups.items()):
        names=[x['country'] for x in es]; name=max(set(names),key=lambda x:(names.count(x),len(x)))
        print(f"{code:2}  {name} ({len(endpoint_groups(es))} endpoints, {len(es)} profiles)")
def bycountry(a):
    q=a.country.casefold(); current,retained=cached_nodes()
    if not current and not retained: current=nodes()
    matches=lambda n:n['country_code'].casefold()==q or q in n['country'].casefold() or q in n['label'].casefold()
    ns=[n for n in selectable_nodes(current) if matches(n)]
    fallback=[n for n in selectable_nodes(retained) if matches(n)]
    if not ns: ns,fallback=fallback,[]
    if not ns:
        if any(matches(n) and disabled_node(n) for n in current+retained):
            die("Russia endpoints are disabled; no connection was changed")
        die("country not found")
    n,r=benchmark_choice(ns,a.workers,a.timeout,fallback)
    select(n,ping=r[n['id']])
def refresh(_):
    ns=update()
    selected=load(PICK,{}).get('id')
    if selected and any(n['id']==selected for n in ns):
        print("Updated; the selected server and running connection were not changed.")
    else: print("Updated; the running connection was not changed. Run: xray-ctl best to select a cached server.")
def refresh_cache(_):
    deadline=time.monotonic()+60
    while True:
        with try_operation_lock() as available:
            if available:
                save(REFRESH_STATUS,{'state':'running','started_at':int(time.time())})
                errors=io.StringIO()
                try:
                    with contextlib.redirect_stderr(errors): refreshed=update()
                except SystemExit:
                    lines=errors.getvalue().strip().splitlines()
                    save(REFRESH_STATUS,{'state':'failed','finished_at':int(time.time()),
                      'message':lines[-1] if lines else 'subscription update failed'})
                except Exception:
                    save(REFRESH_STATUS,{'state':'failed','finished_at':int(time.time()),
                      'message':'unexpected subscription update error'})
                else:
                    save(REFRESH_STATUS,{'state':'completed','finished_at':int(time.time()),
                      'current':sum(not n.get('stale') for n in refreshed),
                      'retained':sum(bool(n.get('stale')) for n in refreshed)})
                return
        if time.monotonic()>=deadline:
            save(REFRESH_STATUS,{'state':'failed','finished_at':int(time.time()),
              'message':'another configuration operation held the lock for 60 seconds'})
            return
        time.sleep(.25)
def background_refresh():
    state=load(REFRESH_STATUS,{})
    if state.get('state') in ('queued','running') and time.time()-state.get('started_at',0)<60:
        print("Subscription refresh is already running; check: xray-ctl update-status")
        return
    save(REFRESH_STATUS,{'state':'queued','started_at':int(time.time())})
    try:
        subprocess.Popen([sys.executable,os.path.abspath(__file__),'refresh-cache'],
          stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
          start_new_session=True,close_fds=True)
    except OSError as e:
        save(REFRESH_STATUS,{'state':'failed','finished_at':int(time.time()),
          'message':'background process could not start'})
        print(f"Background subscription refresh could not start: {e}",file=sys.stderr)
        return
    print("Subscription refresh started in the background; check: xray-ctl update-status")
def update_status(_):
    state=load(REFRESH_STATUS,{})
    if not state: print("No background subscription refresh has run yet."); return
    suffix=f" at {time.ctime(state['finished_at'])}" if state.get('finished_at') else ''
    print(f"Background subscription refresh: {state['state']}{suffix}")
    if state.get('message'): print(state['message'])
    if state.get('state')=='completed':
        print(f"Current: {state['current']}; retained: {state['retained']}")
def allbest(a):
    current,retained=cached_nodes()
    attempted_refresh=a.refresh or not selectable_nodes(current+retained)
    if attempted_refresh:
        try:
            update()
            current,retained=cached_nodes()
        except SystemExit:
            if not (current or retained): raise
            print(f"Using {len(current)} cached profiles because the subscription update failed.",file=sys.stderr)
    a.refresh_after=not attempted_refresh
    current,retained=selectable_nodes(current),selectable_nodes(retained)
    if not (current or retained): die("no enabled servers available; Russia endpoints are disabled")
    selected_id=load(PICK,{}).get('id')
    selected_backup=next((n for n in retained if n['id']==selected_id),None)
    ns=current or retained
    if current and selected_backup: ns=current+[selected_backup]
    fallback=[n for n in retained if n is not selected_backup] if current else []
    n,r=benchmark_choice(ns,a.workers,a.timeout,fallback)
    select(n,ping=r[n['id']])
def subscription(a):
    parts=a.args
    if parts==['list']:
        sources=subscription_sources()
        for name in sorted(sources): print(name)
        if not sources: print("No subscriptions configured.")
        return
    if len(parts)==1 and parts[0] not in ('add','set','remove'):
        parts=['set','default',parts[0]]
    if len(parts)==3 and parts[0] in ('add','set'):
        action,name,value=parts
        if not valid_source_name(name): die("source name must be 1-64 ASCII letters, digits, dots, dashes or underscores")
        sources=subscription_sources()
        if action=='add' and name in sources: die(f"subscription {name} already exists; use: subscription set")
        sources[name]=subscription_url(value)
        save(SUBSCRIPTIONS,sources)
        if name=='default': save_text(SUB,sources[name]+'\n')
        print(f"Subscription {name} saved; run: xray-ctl update")
        return
    if len(parts)==2 and parts[0]=='remove':
        name=parts[1]; sources=subscription_sources()
        if name not in sources: die(f"subscription {name} not found")
        del sources[name]
        save(SUBSCRIPTIONS,sources)
        current,retained=cached_nodes()
        keep=[]; older=list(retained)
        for node in current:
            remaining=[s for s in node.get('sources',['default']) if s!=name]
            if remaining: keep.append({**node,'sources':remaining})
            else: older.append({**node,'stale':True})
        save(RETAINED,compact_nodes(older))
        save(NODES,keep)
        print(f"Subscription {name} removed; its unique profiles kept as inactive backups. Running connection unchanged.")
        return
    die("use: xray-ctl subscription list|add NAME URL|set NAME URL|remove NAME")
def route(a):
    parts=a.args
    if parts==['show']:
        print(json.dumps(routing_config(),ensure_ascii=False,indent=2))
        return
    if len(parts)==2 and parts[0]=='default':
        if parts[1] not in ('proxy','direct'): die("route default must be proxy or direct")
        config=routing_config(); config['default']=parts[1]
        save(ROUTES,config)
        print("Routing default saved; run: xray-ctl route apply")
        return
    if len(parts)==4 and parts[0] in ('add','remove'):
        action,kind=parts[1:3]
        if action not in ('direct','proxy','block') or kind not in ('domain','ip'):
            die("use action direct|proxy|block and kind domain|ip")
        config=routing_config()
        values=config[action]['domains' if kind=='domain' else 'ips']
        value=normalize_route_value('domains' if kind=='domain' else 'ips',parts[3])
        if parts[0]=='add' and value not in values: values.append(value)
        if parts[0]=='remove' and value in values: values.remove(value)
        save(ROUTES,config)
        print("Routing rule saved; run: xray-ctl route apply")
        return
    if parts==['apply']:
        selected=load(PICK,{}).get('id')
        current,retained=cached_nodes()
        node=next((n for n in current+retained if n['id']==selected),None)
        if node is None: die("selected profile is not cached; run: xray-ctl best")
        select(node,force=True)
        return
    die("use: xray-ctl route show|default proxy|direct|add ACTION domain|ip VALUE|remove ACTION domain|ip VALUE|apply")
def status(_):
    active=subprocess.run(['systemctl','is-active','--quiet','blancctl.service']).returncode==0
    pick=load(PICK,{}); stats=load(STATS,{})
    if not active: print(f"{paint('2','○ BlancVPN')}  {paint('31','off')}"); return
    if not routes_healthy():
        print(f"{paint('1;31','! BlancVPN')}  {paint('33','route unavailable')} · run: xray-ctl log"); return
    place=' '.join(x for x in (pick.get('country_code'),pick.get('country')) if x) or 'unknown'
    ping_value=pingtest(); speed_value=speedtest() if ping_value is not None else None
    stats={'ping_ms':ping_value,'speed_mbps':speed_value,'tested_at':int(time.time())}; save(STATS,stats)
    ping=f"{ping_value:.0f} ms" if ping_value is not None else f"ping {paint('31','n/a')}"
    speed=f"{speed_value:.1f} Mbps" if speed_value is not None else f"speed {paint('31','n/a')}"
    print(f"{paint('32','● BlancVPN')}  {paint('36',place)} · {ping} · {speed}")
def logs(_): service('log')
def proxy(_): print(f"SOCKS5  {LOCAL_PROXY}")
def main():
    require_user()
    p=argparse.ArgumentParser(prog='xray-ctl'); p.add_argument('--version',action='version',version=f'%(prog)s {VERSION}'); s=p.add_subparsers(dest='cmd')
    s.add_parser('start').set_defaults(fn=start); s.add_parser('countries').set_defaults(fn=countries)
    c=s.add_parser('country'); c.add_argument('country'); c.add_argument('--workers',type=int,default=DEFAULT_WORKERS); c.add_argument('--timeout',type=float,default=DEFAULT_PROBE_TIMEOUT); c.set_defaults(fn=bycountry)
    s.add_parser('update').set_defaults(fn=refresh)
    b=s.add_parser('best'); b.add_argument('--workers',type=int,default=DEFAULT_WORKERS); b.add_argument('--timeout',type=float,default=DEFAULT_PROBE_TIMEOUT); b.add_argument('--refresh',action='store_true',help='refresh subscription before testing'); b.set_defaults(fn=allbest)
    u=s.add_parser('subscription'); u.add_argument('args',nargs='+'); u.set_defaults(fn=subscription)
    rt=s.add_parser('route'); rt.add_argument('args',nargs='+'); rt.set_defaults(fn=route)
    s.add_parser('update-status').set_defaults(fn=update_status)
    s.add_parser('refresh-cache',help=argparse.SUPPRESS).set_defaults(fn=refresh_cache)
    s.add_parser('status').set_defaults(fn=status); s.add_parser('log').set_defaults(fn=logs)
    s.add_parser('doctor').set_defaults(fn=doctor)
    s.add_parser('proxy').set_defaults(fn=proxy)
    s.add_parser('stop').set_defaults(fn=lambda _:service('stop'))
    s.add_parser('failover-check',help=argparse.SUPPRESS).set_defaults(fn=failover)
    a=p.parse_args(); fn=start if a.cmd is None else a.fn
    if a.cmd in (None,'start','stop','country','update','best','subscription','route'):
        try:
            with operation_lock(): fn(a)
        finally:
            if a.cmd=='best' and getattr(a,'refresh_after',False): background_refresh()
    else: fn(a)
if __name__=='__main__': main()
