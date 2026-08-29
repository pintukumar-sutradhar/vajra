#!/usr/bin/env python3
"""VAJRA wordlist forge - deterministically expands compact seed corpora into
massive ranked wordlists (users/passwords/dirs/subdomains).

Run:  python3 tools/gen_wordlists.py
Outputs land in ../wordlists/ (idempotent, stable ordering)."""
import itertools
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "wordlists")

YEARS = [str(y) for y in range(1970, 2027)]
SPECIALS = ["!", "@", "#", "$", "%", "*", "_", "?", ".", "!!", "123", "@123",
            "!@#", "2024", "2025"]
DIGITS = [str(i) for i in range(100)]
DIGITS3 = ["%03d" % i for i in range(0, 1000, 3)]

PASSWORD_SEEDS = """
123456 password 123456789 12345678 12345 qwerty abc123 football monkey letmein
dragon 111111 baseball iloveyou trustno1 sunshine master welcome shadow ashley
michael ninja mustang password1 admin login guest root toor pass passwd changeme
superman batman spiderman hello freedom whatever starwars computer summer
winter spring autumn princess magician lovely flower hottie loveme qazwsx
1q2w3e4r zaq12wsx 1234qwer qwe123 asdfgh zxcvbn poiuyt lkjhgf mnbvcx
letmein1 welcome1 monkey1 dragon1 sunshin3 passw0rd p@ssw0rd adm1n r00t t00r
security secure test testing tester user users default operator service
internet samsung apple google android nokia huawei xiaomi oppo vivo lenovo
dell hp acer asus toshiba canon nikon fujifilm playstation xbox nintendo
minecraft fortnite pokemon naruto onepiece anime gaming gamer twitch youtube
facebook instagram twitter tiktok linkedin snapchat whatsapp netflix prime
spotify paypal visa mastercard bitcoin ethereum blockchain wallet mining
chocolate cookie coffee pizza burger chicken biryani masala curry mango
banana orange apple grape lemon pepper salt sugar honey butter bread rice
london paris tokyo delhi mumbai kolkata chennai bangalore hyderabad pune
india pakistan bangladesh nepal srilanka america brazil canada france
germany italy spain mexico japan china korea russia england scotland
monday tuesday wednesday thursday friday saturday sunday january february
march april may june july august september october november december
lovely1 angel1 prince1 princess1 queen king royal crown emperor empire
warrior hunter fighter soldier sniper gunner archer wizard mage knight
phoenix dragonfly eagle falcon tiger lion panther jaguar cheetah wolf
bear shark dolphin whale octopus penguin flamingo peacock parrot sparrow
redblue greenblue blackwhite silvergold darklight nightday sunrise sunset
moonstar skyearth waterfire windrain snowstorm thunder lightning cyclone
helloworld thankyou goodbye goodmorning goodnight takecare seeyou
iloveu missyou mylove sweetheart darling babydoll cutiepie smiley happy
giggle laugh joke funny comedy drama action romance thriller mystery
college school university student teacher professor class exam result
office boss employee manager director company business money income
salary bonus profit market stock trading invest bank account credit
server client network router switch firewall database query table index
linux ubuntu debian centos fedora redhat suse kali parrot backtrack
python java script html css sql php ruby perl golang rust swift kotlin
matrix neo trinity morpheus cypher tank dozer apoc switchblade
terminator robocop predator alien predator galaxy universe planet mars
ferrari lamborghini porsche mercedes bmw audi toyota honda suzuki yamaha
cricket football basketball tennis hockey volleyball badminton boxing
champion winner loser player coach team captain striker defender keeper
summer2 hotdog coldcoffee redbull vodka whiskey rum beer wine drinks
party birthday anniversary wedding honeymoon vacation holiday festival
diwali holi eid christmas newyear goodfriday ramadan navratri pongal
password123 admin123 root123 test123 guest123 user123 dev123 ops123
pakistan1 india123 kerala1 punjab1 gujarat1 mumbai1 delhi1 bihar1
asdf 1234 12345678910 10203040 50607080 aaaa bbbb cccc dddd zzzz
secret secrets private confidential internal project projectx omega sigma
alpha beta gamma delta epsilon lambda theta titan atlas orion vega nova
zeus hermes apollo ares hades poseidon athena hera artemis hades3
nirvana paradise heaven hell purgatory karma dharma zen yoga mantra
iphone ipad macbook imac watch airpods charger battery screen camera
google1 facebook1 twitter1 insta1 github gitlab stackoverflow reddit
qwertyuiop asdfghjkl zxcvbnm 1234567890 0987654321 987654321 147258369
159357 753951 13579 24680 112233 121212 123123 654321 696969 420420
007bond 000000 11111 22222 33333 44444 55555 66666 77777 88888 99999
abcd abcd1234 a1b2c3d4 q1w2e3r4t5 z9y8x7w6 vfr4 bhu8 njm9 ikol
temp temporary throwaway backup archive old new final final2 final3
"""

USERNAME_SEEDS = """
admin administrator adm admin1 admin2 admin123 administrator1 sysadmin
root superuser superadmin operator user user1 test test1 testuser guest demo
manager manager1 moderator editor author publisher developer dev dev1 devops
qa qa1 tester support helpdesk help info contact sales marketing hr finance
accounting legal audit compliance security secops soc noc dba database backup
ftp mail webmail smtp pop imap postmaster hostmaster webmaster abuse noc1
service services system daemon bin daemon1 cron syslog uucp games gnats
www www-data nginx apache tomcat jenkins gitlab github runner build deploy
oracle postgres mysql mariadb mongo redis memcached elastic logstash kibana
ubuntu debian centos fedora suse alpine raspbian pi vagrant docker kubernetes
cisco juniper aruba fortinet paloalto sonicwall mikrotik ubnt pfsense opnsense
zabbix nagios icinga grafana prometheus datadog sentry newrelic splunk
jira confluence wiki wikiuser forum community chat mattermost slack discord
sales1 salesforce crm erp sap oracle1 netsuite quickbooks tally zoho
john mike david sarah emma alex chris james robert michael william joseph
thomas charles mary patricia jennifer linda elizabeth barbara susan jessica
karen nancy lisa betty helen sandra donna carol ruth sharon michelle laura
kimberly deborah dorothy amy angela ashley brenda emma olivia sophia isabella
charlotte mia amelia harper evelyn abigail liam noah lucas mason ethan logan
jacob jack henry owen daniel matthew ryan nathan carter julian levi ezra
arjun rahul vikram ankit rohit amit sumit deepak manoj sanjay vijay ajay
priya sneha pooja neha anjali kavya divya meera ritu shreya aditi riya
rahul1 amit1 vikas naveen kiran ravi suresh mahesh ramesh dinesh rajesh
mohit rohit1 nitin sachin kapil rakesh mukesh anil sunny rocky happy lucky
ahmed ali hassan husain omar yousuf bilal zain imran kamran salman tariq
chen wei li zhang wang liu yang huang zhao wu zhou xu sun zhu ma lin
garcia rodriguez martinez hernandez lopez gonzalez perez sanchez ramirez
smith johnson williams brown jones miller davis wilson anderson taylor
thomas moore martin lee clark walker hall allen young king wright hill
"""

DIR_SEEDS = """
admin administrator adminpanel admin_area controlpanel cpanel panel dashboard
home main index portal landing landing-page start intro welcome
login logout signin signup register registration auth authentication oauth sso
account accounts profile profiles settings preferences options config
user users member members customer customers client clients partner partners
api api/v1 api/v2 api/v3 apis rest restv1 graphql grpc rpc soap wsdl endpoint
internal intranet private restricted secret hidden protected secure secured
test testing tests beta alpha staging stage dev development prod production
demo sandbox lab experiment pilot preview rc release nightly canary edge
backup backups bak dump export imports import migrate migration sync
data dataset databases db sql dump.sql backup.sql database.sql
files file upload uploads download downloads media images img assets static
documents docs doc documentation manual guide guides howto faq knowledge
blog news press articles post posts category categories tag tags archive
forum boards community groups group team teams org department
shop store cart checkout order orders payment payments billing invoice
search find query results filter sort page pages view views display show
report reports analytics metrics stats statistics monitor monitoring health
status uptime ping probe debug trace logs log audit trails events history
mail email emails newsletter subscribe unsubscribe campaign campaigns
calendar events schedule scheduler tasks todo jobs queue worker workers
cron batch scripts script shell terminal console cli command cmd exec
install installer setup wizard upgrade update patch hotfix rollback deploy
phpinfo info php phpmyadmin adminer pma mysql postgres pgsql mongo redis
jenkins ci cd pipeline builds artifacts nexus artifactory registry harbor
git svn hg repo repositories source scm codebase trunk branch branches
wp-admin wp-content wp-includes wp-json wp-login xmlrpc xmlrpc.php
sites default modules themes plugins extensions components libraries vendor
misc files_private tmp temp cache sessions locks locksfile run var log
old legacy deprecated archived trash deleted drafts pending review approved
mobile app apps application applications android ios apk ipa plist
vpn proxy gateway tunnel tunnel2 remote rdp vnc ssh telnet ftp sftp
status2 metrics2 grafana prometheus-alert kibana-app es-cluster search
solr sphinx elastic index indices snapshot snapshots repository repos
sso-idp sso-sp metadata saml openid connect well-known acme challenge
actuator swagger openapi api-docs swagger-ui graphql-playground graphiql
healthcheck health ready live readiness liveness version build-info env
backup-old backup-new bak-old site site-backup www html public public_html
webapp webapps app1 app2 appv1 appv2 v1 v2 v3 v4 v5 old1 new1
"""

SUB_SEEDS = """
www www2 www3 mail mail2 mx mx1 mx2 mx3 ns ns1 ns2 ns3 dns dns1 dns2 dns3
webmail smtp smtp2 pop pop3 imap imap2 exchange owa autodiscover autoconfig
vpn vpn1 vpn2 remote remote2 rdp gateway gw gw1 router fw firewall proxy
cdn cdn1 cdn2 static assets media img images video videos stream live tv radio
ftp ftp2 sftp samba share files storage nas cloud cloud2 drive bucket s3
dev dev1 dev2 develop developer development test test1 test2 testing qa qa1
uat stage staging stg preprod pre production prod prod1 beta alpha demo sandbox
lab labs research experiments pilot poc trial preview next legacy old old1
new new1 archive backup backups restore snapshot
api api2 apis apidev apitestapistaging apiportal gateway apigateway rest graphql
auth auth2 sso saml idp id oauth oauth2 token session accounts account identity
admin admin1 adminpanel console control cpanel whm plesk manage manager portal
db db1 database mysql pg postgres mongo redis cache memcache queue mq kafka rabbit
es elastic elasticsearch solr search indexer crawler spider bot scrape
ci cd jenkins build builds drone travis circle gitlab-ci runner artifact
git gitlab github bitbucket svn hg code source repo repos mirror npm pypi gem
monitor monitor1 zabbix nagios grafana prometheus kibana sentry status statuspage
logs log logging syslog fluentd graylog splunk datadog elk loki tempo
wiki docs doc documentation confluence handbook kb help helpdesk support ticket
forum community chat irc matrix element mattermost rocket rocketchat zulip
meet zoom teams conference vc webinar training learn academy lms moodle
crm erp hrm payroll attendance leave sales leads pipeline deals hubspot
shop store cart checkout pay payment payments billing invoice stripe razorpay
app app1 app2 appv2 mobile m mobileapi wap amp lite go micro microservice svc
edge edge1 lb lb1 haproxy nginx traefik istio linkerd consul etcd vault nomad
k8s kube kubernetes rancher portainer helm tiller argo flux tekton harbor
iot sensors mqtt broker mosquitto nifi flink spark hadoop hive presto trino
time time2 ntp chrony syslog-relay relay relay1 mxbackup backupmx dr dr1
us us1 us2 eu eu1 eu2 ap ap1 apac emea latam in1 uk1 de1 fr1 jp1 sg1 au1
"""


def _seeds(block):
    return [w for w in block.split() if w]


def _write(path, items):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(items) + "\n")
    return len(items)


def gen_passwords(target):
    seeds = _seeds(PASSWORD_SEEDS)
    out = []
    seen = set()

    def add(w):
        w = str(w)
        if w not in seen and 3 <= len(w) <= 40:
            seen.add(w)
            out.append(w)

    for s in seeds:
        add(s)
        add(s.capitalize())
    rules = [
        lambda s: s + y,
        lambda s: s.capitalize() + y,
        lambda s: s + d,
        lambda s: s.capitalize() + d,
        lambda s: s + sp,
        lambda s: s.capitalize() + sp,
        lambda s: s + sp + y,
        lambda s: s + "_" + y,
        lambda s: s + "-" + d,
        lambda s: s + "." + d,
        lambda s: s.upper() + d,
        lambda s: s.replace("a", "@").replace("s", "$"),
        lambda s: s.replace("o", "0").replace("i", "1"),
        lambda s: s.replace("e", "3") + d,
        lambda s: s[::-1],
        lambda s: s[::-1] + d,
        lambda s: s + s,
        lambda s: s.capitalize() + "!" + y[-2:],
    ]
    combos = []
    for rule_idx, rule in enumerate(rules):
        for si, s in enumerate(seeds):
            for yi, y in enumerate(YEARS[:20] if rule.__code__.co_consts and
                                   any("19" in repr(c) or "20" in repr(c)
                                       for c in []) else YEARS):
                try:
                    combos.append((rule_idx * 1000 + yi, rule(s)))
                except Exception:
                    pass
            for di, d in enumerate(DIGITS):
                try:
                    combos.append((500000 + rule_idx * 1000 + di, rule(s)))
                except Exception:
                    pass
            for spi, sp in enumerate(SPECIALS):
                try:
                    combos.append((900000 + rule_idx * 1000 + spi, rule(s)))
                except Exception:
                    pass
            for d3 in DIGITS3[::7]:
                try:
                    combos.append((1200000 + rule_idx * 1000, rule(s)))
                except Exception:
                    pass
    combos.sort(key=lambda t: t[0])
    for _, w in combos:
        if len(out) >= target:
            break
        add(w)
    return out[:target]


def gen_users(target):
    seeds = _seeds(USERNAME_SEEDS)
    firsts = seeds
    lasts = [s for s in seeds if len(s) > 2]
    out = []
    seen = set()

    def add(w):
        w = str(w).lower()
        if w not in seen and 2 <= len(w) <= 30:
            seen.add(w)
            out.append(w)

    for s in seeds:
        add(s)
        add(s + "1")
    pairs = list(itertools.islice(itertools.product(firsts[:220], lasts[:220]),
                                  400000))
    idx = 0
    for a, b in pairs:
        if len(out) >= target:
            break
        add(a + "." + b)
        add(a + "_" + b)
        add(a[0] + b)
        add(a + b)
        add(b + "." + a)
        add(a + str(idx % 99))
        idx += 1
    return out[:target]


def gen_dirs(target):
    seeds = _seeds(DIR_SEEDS)
    out = []
    seen = set()

    def add(w):
        w = w.strip("/").lower()
        if w and w not in seen and len(w) <= 60:
            seen.add(w)
            out.append(w)

    for s in seeds:
        add(s)
    subs = ["panel", "login", "new", "old", "backup", "test", "dev", "v1",
            "v2", "v3", "admin", "app", "public", "private", "api", "internal",
            "legacy", "archive", "beta", "prod"]
    exts = ["", ".bak", ".old", ".zip", ".tar.gz", ".sql", ".json", ".xml",
            ".txt", ".php.bak", ".save", "~", ".swp", ".orig", ".copy"]
    for s in seeds[:600]:
        for sb in subs:
            add("%s/%s" % (s, sb))
    for s in seeds[:900]:
        for e in exts:
            add(s + e)
    for s in seeds[:500]:
        for sb in subs[:10]:
            for e in exts[::2]:
                add("%s/%s%s" % (s, sb, e))
    cms = ["wp-content/plugins/", "wp-content/themes/", "wp-includes/js/",
           "sites/all/modules/", "modules/system/", "components/com_",
           "skin/frontend/", "media/catalog/", "administrator/components/"]
    tails = ["index.php", "config.php", "settings.py", "conf.json", "env",
             ".htaccess", "web.config", "readme.txt", "changelog", "version",
             "upgrade", "install", "setup", "debug", "error_log", "access.log"]
    for c in cms:
        for t in tails:
            add(c + t)
    for v in range(1, 12):
        for ep in ["users", "auth", "login", "orders", "products", "items",
                   "accounts", "profile", "admin", "search", "upload", "export"]:
            add("api/v%d/%s" % (v, ep))
    return out[:target]


def gen_subs(target):
    seeds = _seeds(SUB_SEEDS)
    regions = ["us", "eu", "ap", "uk", "in", "au", "ca", "sa", "jp", "de",
               "fr", "sg", "br", "za"]
    envs = ["dev", "test", "qa", "stage", "prod", "uat", "demo", "beta"]
    out = []
    seen = set()

    def add(w):
        w = w.lower()
        if w and w not in seen and len(w) <= 48:
            seen.add(w)
            out.append(w)

    for s in seeds:
        add(s)
    for r in regions:
        for s in seeds[:140]:
            add("%s-%s" % (r, s))
    for e in envs:
        for s in seeds[:160]:
            add("%s-%s" % (e, s))
            add("%s.%s" % (s, e))
    for s in seeds[:200]:
        for n in range(2, 16):
            add("%s%d" % (s, n))
    for s in seeds[:420]:
        for n in range(1, 31):
            add("%s%d" % (s, n))
    for r in regions:
        for e2 in envs[:4]:
            for s in seeds[:60]:
                add("%s-%s-%s" % (r, e2, s))
    return out[:target]


AD_FIRST = ["john","mike","david","sarah","emma","alex","chris","james",
            "robert","mary","patricia","linda","arjun","priya","rahul",
            "vikram","neha","amit","raj","kiran","ahmed","ali","omar",
            "chen","wei","garcia","smith","johnson","brown","davis"]
AD_LAST = ["smith","johnson","williams","brown","jones","garcia","miller",
           "davis","wilson","anderson","taylor","thomas","moore","martin",
           "lee","walker","hall","young","king","wright","scott","green",
           "adams","baker","carter","turner","phillips","campbell","parker",
           "evans","edwards","collins","stewart","morris","murphy","cook"]
AD_SERVICE = ["sql","svc-sql","backup","jira","confluence","jenkins","git",
              "build","deploy","app","web","api","db","mail","scan","print",
              "monitor","grafana","vault","ansible","puppet","chef","nagios",
              "zabbix","elastic","kibana","logstash","splunk","service"]

SEASON = ["Spring", "Summer", "Autumn", "Winter"]
MONTHS = ["January","February","March","April","May","June","July",
          "August","September","October","November","December"]


def gen_ad_users(target):
    out, seen = [], set()
    def add(w):
        w = w.lower()
        if w not in seen and 2 <= len(w) <= 40:
            seen.add(w); out.append(w)
    for f in AD_FIRST:
        add("adm." + f)
    for s in AD_SERVICE:
        for suf in ("", "svc", "01"):
            add("%s%s" % (s, "svc" if suf == "svc" else "") if not suf else
                "%s-%s" % (suf, s) if suf.isdigit() is False and False else
                ("%ssvc" % s if suf == "svc" else "%s" % s))
    pairs = [(a, b) for a in AD_FIRST for b in AD_LAST]
    idx = 0
    for a, b in pairs:
        if len(out) >= target: break
        add("%s.%s" % (a, b)); add("%s.%s" % (a[0], b))
        add("%s_%s" % (a, b)); add(a + b); add(b[0] + a)
        add("%s%d" % (a, idx % 99)); idx += 1
    return out[:target]


def gen_ad_passwords(target):
    out, seen = [], set()
    def add(w):
        if w not in seen and 4 <= len(w) <= 64:
            seen.add(w); out.append(w)
    base = ["Welcome", "Password", "Summer", "Winter", "Spring", "Autumn",
            "Corporate", "Company", "Monday", "Friday", "Secret", "Change",
            "Global", "Master", "Qwerty", "Admin"]
    for b in base:
        for y in range(2020, 2027):
            add("%s%d!" % (b, y)); add("%s%d" % (b, y))
            add("%s@%d" % (b, y)); add("%s%d#" % (b, y))
        add(b + "123!"); add(b.capitalize() + "@123"); add(b + "!2025")
    for m in MONTHS:
        for y in (2024, 2025, 2026):
            add("%s%d!" % (m, y))
    corp = ["corp", "ad", "dc", "hr", "it", "dev", "ops", "fin"]
    for c in corp:
        for y in range(2023, 2027):
            add("%s%d!" % (c.upper(), y)); add("%s-%d!Aa" % (c, y))
    return out[:target]


def main():
    os.makedirs(OUT, exist_ok=True)
    plan = [
        ("users.txt", gen_users(600), "users (fast tier)"),
        ("users_full.txt", gen_users(115000), "users (complete tier)"),
        ("passwords.txt", gen_passwords(2500), "passwords (fast tier)"),
        ("passwords_full.txt", gen_passwords(148000), "passwords (complete tier)"),
        ("dirs_common.txt", gen_dirs(1200), "dirs (fast tier)"),
        ("dirs_full.txt", gen_dirs(16000), "dirs (complete tier)"),
        ("subs_common.txt", gen_subs(1500), "subs (fast tier)"),
        ("subs_full.txt", gen_subs(22000), "subs (complete tier)"),
        ("ad_users.txt", gen_ad_users(8000), "AD usernames (spray pool)"),
        ("ad_passwords.txt", gen_ad_passwords(12000),
         "AD corporate password patterns"),
    ]
    total = 0
    for name, data, label in plan:
        n = _write(os.path.join(OUT, name), data)
        total += n
        print("  %-18s %7d entries  (%s)" % (name, n, label))
    print("[+] forged %d total entries" % total)


if __name__ == "__main__":
    sys.exit(main())
