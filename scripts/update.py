"""Roz chalti hai (GitHub Actions). Jobs fetch karti hai, scam filter lagati hai,
aur scholarship pages mein change detect karti hai."""
import json, os, re, hashlib, datetime, urllib.request, urllib.parse

UA = {"User-Agent": "OpportunityFinder/1.0"}
NOW = datetime.date.today().isoformat()

def get(url, as_json=True, timeout=30):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode("utf-8", "ignore")
    return json.loads(raw) if as_json else raw

# ---------- Scam filter ----------
BAD = re.compile(r"(registration fee|processing fee|pay (a )?fee|send money|western union|"
                 r"visa fee.{0,20}(candidate|applicant)|whatsapp only|telegram|guaranteed (job|visa)|"
                 r"no experience.{0,20}\$\d{3,}\s*(/|per)\s*(day|hour))", re.I)
FREE_MAIL = re.compile(r"@(gmail|yahoo|hotmail|outlook)\.", re.I)
def looks_scam(text): return bool(BAD.search(text) or FREE_MAIL.search(text))

def strip(s): return re.sub(r"<[^>]+>", " ", s or "")

# ---------- Job sources ----------
CITY = {"Germany":["berlin","munich","münchen","hamburg","frankfurt","cologne","köln","stuttgart","düsseldorf","dusseldorf","leipzig","dresden","hannover","nuremberg","bremen","germany","deutschland"],
 "UK":["london","manchester","birmingham","edinburgh","glasgow","bristol","leeds","cambridge","oxford","united kingdom"," uk"],
 "Netherlands":["amsterdam","rotterdam","utrecht","eindhoven","the hague","netherlands"],
 "France":["paris","lyon","marseille","toulouse","france"],
 "Austria":["vienna","wien","graz","salzburg","austria"],
 "Switzerland":["zurich","zürich","geneva","basel","switzerland"],
 "Ireland":["dublin","cork","ireland"],"Spain":["madrid","barcelona","spain"],
 "Sweden":["stockholm","gothenburg","sweden"],"Poland":["warsaw","krakow","poland"],
 "Portugal":["lisbon","porto","portugal"],"Italy":["milan","rome","italy"],
 "Denmark":["copenhagen","denmark"],"Belgium":["brussels","belgium"],
 "USA":["new york","san francisco","usa","united states"],"Canada":["toronto","vancouver","canada"]}
def guess_country(loc):
    l = " " + (loc or "").lower()
    for c, keys in CITY.items():
        if any(k in l for k in keys): return c
    return "Europe/Other"

def arbeitnow():
    out = []
    d = get("https://www.arbeitnow.com/api/job-board-api")
    for j in d.get("data", []):
        txt = strip(j.get("description", ""))
        tags = " ".join(j.get("tags", []) + j.get("job_types", []))
        loc = j.get("location", "")
        is_remote = bool(j.get("remote")) or "remote" in loc.lower() or "remote" in j["title"].lower()
        out.append(dict(title=j["title"], company=j["company_name"], location=loc,
            country=guess_country(loc), remote=is_remote,
            visa=("visa" in (tags + txt).lower() and "sponsor" in (tags + txt).lower()),
            url=j["url"], source="Arbeitnow", date=NOW, _t=txt))
    return out

def remotive():
    out = []
    d = get("https://remotive.com/api/remote-jobs?limit=100")
    for j in d.get("jobs", []):
        txt = strip(j.get("description", ""))
        out.append(dict(title=j["title"], company=j["company_name"],
            location=j.get("candidate_required_location", "Worldwide"), country="Remote",
            remote=True, visa=False, salary=j.get("salary", ""), url=j["url"],
            source="Remotive", date=NOW, _t=txt))
    return out

def reliefweb():
    app = os.environ.get("RELIEFWEB_APPNAME")  # reliefweb.int se free approve karwayein
    if not app: return []
    q = urllib.parse.urlencode({"appname": app, "limit": 50, "profile": "list",
        "preset": "latest", "fields[include][]": "title"})
    d = get("https://api.reliefweb.int/v2/jobs?" + q)
    return [dict(title=i["fields"]["title"], company="via ReliefWeb", location="", country="Global",
        remote=False, visa=False, url=i["fields"].get("url", ""), source="ReliefWeb", date=NOW, _t="")
        for i in d.get("data", [])]

def build_jobs():
    jobs, rejected = [], 0
    for fn in (arbeitnow, remotive, reliefweb):
        try:
            for j in fn():
                t = j.pop("_t", "")
                if looks_scam(j["title"] + " " + t): rejected += 1; continue
                jobs.append(j)
        except Exception as e:
            print("source failed:", fn.__name__, e)
    jobs.sort(key=lambda j: (not j["visa"], j["title"]))
    json.dump(dict(updated=NOW, rejected_as_suspicious=rejected, jobs=jobs[:300]),
              open("data/jobs.json", "w"), ensure_ascii=False, indent=1)
    print(len(jobs), "jobs saved,", rejected, "rejected")

# ---------- Scholarship change watcher ----------
def watch_scholarships():
    sch = json.load(open("data/scholarships.json"))
    for s in sch["scholarships"]:
        try:
            html = get(s["url"], as_json=False)
            text = re.sub(r"\s+", " ", strip(re.sub(r"(?s)<(script|style).*?</\1>", "", html)))
            h = hashlib.sha256(text.encode()).hexdigest()
            if s.get("hash") and s["hash"] != h:
                s["needs_review"] = True; s["changed_on"] = NOW
            s["hash"] = h; s["checked"] = NOW
        except Exception as e:
            print("watch failed:", s["name"], e)
    json.dump(sch, open("data/scholarships.json", "w"), ensure_ascii=False, indent=1)

if __name__ == "__main__":
    build_jobs()
    if datetime.date.today().weekday() == 0 or os.environ.get("FORCE"):  # haftay mein ek baar
        watch_scholarships()
