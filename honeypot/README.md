# Honeypot integration

**[English](#english) | [Español](#español)**

---

## English

Wazuh rules for the events written by the [ssh-honeypot](https://github.com/TinchoLay/ssh-honeypot) project. The honeypot runs in Docker on its own EC2 instance, with a Wazuh agent that reports to the same manager as the rest of this pack.

This is lab work, not production.

### How it fits together

```
attacker -> honeypot container -> logs/*.json (bind mount) -> Wazuh agent -> manager -> rules 100300 to 100370
```

Agent side, in `ossec.conf` of the honeypot instance:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/ubuntu/honeypot-aws/logs/*.json</location>
</localfile>
```

The honeypot writes one JSON object per line with a `honeypot_event` field: `ssh_login_attempt`, `ssh_connection`, `http_request`, `ftp_login_attempt`, `shell_command` or `malware_capture`.

Manager side: copy the rule files to `/var/ossec/etc/rules/`, check them with `wazuh-analysisd -t` and restart the manager. Reloading is not enough, see the notes below.

### Files

| File | Rules |
|---|---|
| `honeypot_rules.xml` | 100300 to 100320: SSH, shell commands and malware captures |
| `honeypot_rules_http.xml` | 100340 to 100348: HTTP and FTP |
| `honeypot_ioc_rules.xml` | 100330: failed logins from a known attacker IP |
| `honeypot-attackers.example` | Format of the CDB list that rule 100330 reads |
| `honeypot_rules_ssh.xml` | 100350 to 100369: how each SSH connection ended, and what the attacker types |
| `honeypot_rules_ssh_correlation.xml` | 100370: brute force followed by an accepted login. Separate file so it can be removed on its own |
| `logtest_ssh_samples.txt` | Sample events to paste into `wazuh-logtest`, with the rule each one should fire |

The name `honeypot_rules_http.xml` is deliberate. Wazuh loads rule files in alphabetical order and a child rule has to load after its parent. My first name, `honeypot_http_rules.xml`, sorted before `honeypot_rules.xml`, so the HTTP rules were loaded before the rule they depend on (100300) and were ignored. `honeypot_rules_ssh.xml` follows the same rule: it sorts after `honeypot_rules.xml`, so its parent (100300) is already loaded. More on that below.

### Rules

| ID | Level | What it detects |
|---|---|---|
| 100300 | 0 | Any honeypot event (parent rule) |
| 100301 | 2 | SSH login attempt. Below the default alert threshold (3), so it is counted but not shown |
| 100302 | 10 | 8 login attempts from the same IP in 60 s (T1110). `ignore="60"` limits repeats |
| 100303 | 8 | Slow brute force: 5 login attempts from the same IP in 10 minutes (T1110) |
| 100310 | 8 | Download attempt from the fake shell (T1105) |
| 100320 | 12 | Captured file flagged as malicious by at least one VirusTotal engine (T1105) |
| 100330 | 12 | Failed authentication on a real system from an IP in the honeypot attacker list (T1110) |
| 100340 | 2 | Any HTTP request (base rule for the HTTP set, counted but not shown) |
| 100341 | 8 | Request to `GponForm/diag_Form`, the GPON router exploit path (T1190) |
| 100342 | 5 | Open proxy probe: a full URL as the path, or `CONNECT host:port` (T1595) |
| 100343 | 5 | WebLogic T3 handshake sent to the HTTP port (T1595.002) |
| 100344 | 3 | Traffic that is not HTTP at all, such as a stray protocol or binary junk (T1595) |
| 100345 | 5 | Probe for a known target: `wp-json`, `wp-login`, `xmlrpc.php`, `/.env`, `/.git`, `phpmyadmin`, `actuator`, `/solr`, `manager/html`, Jenkins, GeoServer (T1595.002) |
| 100346 | 5 | 10 HTTP requests from the same IP in 120 s, `ignore="300"` (T1595) |
| 100347 | 4 | FTP login as `anonymous` (T1078) |
| 100348 | 6 | Probe for an AI model API: `/v1/models`, `/v1beta/models`, `/v1/chat/completions`, `/api/tags`, `/ollama/` (T1595.002) |
| 100350 | 2 | Any SSH connection (base rule for the connection set, counted but not shown) |
| 100351 | 3 | Scanner: the connection ended with no SSH banner or with a protocol error (T1595) |
| 100352 | 6 | The honeypot accepted the login: result `autenticado_sin_shell`, `exec` or `shell` (T1078) |
| 100353 | 7 | Same as 100352, but the client banner is an SSH library used by programs (`Go`, `libssh`, `paramiko`, `makiko`, `AsyncSSH`, `JSCH`), not a person's client (T1078) |
| 100354 | 9 | 5 accepted logins from the same IP in 300 s, `ignore="300"` (T1110). It counts the group `honeypot_login_ok` |
| 100360 | 3 | Any command typed or sent by the attacker (base rule for the command set) |
| 100361 | 12 | Command that mentions `authorized_keys`: leaving an SSH key behind (T1098.004) |
| 100362 | 12 | Cryptominer names or the `stratum` protocol (T1496) |
| 100363 | 10 | Download and run in one command: `wget ...; chmod`, `curl ... \| sh` (T1105, T1059.004) |
| 100364 | 9 | Creating or changing user accounts: `useradd`, `chpasswd`, `passwd` (T1098, T1136.001) |
| 100365 | 7 | Touching cron: `crontab`, `/etc/cron`. It also matches the read-only `crontab -l` (T1053.003) |
| 100366 | 8 | Covering tracks: `history -c`, `unset HISTFILE`, deleting logs (T1070.003, T1070.002) |
| 100367 | 5 | System recon: `uname`, `/proc/cpuinfo`, `nproc`, `lscpu`, `/etc/passwd`, `whoami` (T1082, T1033) |
| 100368 | 10 | Reading password hashes: `/etc/shadow`, `/etc/gshadow` (T1003.008). Evaluated before 100367 |
| 100369 | 6 | Shell check: random arithmetic `$((a*b+c))`, `check_<hash>` markers, `set` with arguments, `ignore="300"` (T1059.004). Evaluated before 100367 |
| 100370 | 12 | An accepted login (100352) after a brute-force alert (100302 or 100303) from the same IP within 600 s, `ignore="300"` (T1110.001, T1078) |

Severity follows how much evidence there is. A login attempt or a plain GET is noise, a request to an exploit path shows intent, and a sample that VirusTotal confirms is proof.

The HTTP honeypot also stores the POST body. That matters for 100341: the GPON exploit puts its command in the body, not in the URL, and the path alone does not say what the attacker wanted to run.

### Attacker IP list (CDB)

`honeypot-attackers.example` shows the format (`ip:label`). Install it as `/var/ossec/etc/lists/honeypot-attackers`, register `<list>etc/lists/honeypot-attackers</list>` in the `<ruleset>` block of `ossec.conf` and restart the manager. Rule 100330 raises a failed login from a listed IP from the stock level 5 (`5760`) to level 12.

Status: simulated only. I checked the lookup and the rule priority with `wazuh-logtest`: a listed IP gave 100330 and an unlisted one gave 5760. The list is filled by hand. Feeding it from alerts 100302 and 100320 would need a script and a manager restart to reload it. I have not built that.

### What I learned while testing

- **Rule files load in alphabetical order.** A child rule (`if_sid`) must come after its parent. With the wrong file name, `wazuh-logtest` printed warnings and the rules did nothing. Renaming the file fixed it.
- **The field name matters.** My first version used `event_type`, which collided with the stock Suricata rule 86600. Renaming it to `honeypot_event` fixed it.
- **Level 0 rules do not count toward frequency rules.** The base login rule is level 2 on purpose, so 100302 can count it. The same goes for 100340 and 100346.
- **`wazuh-logtest` is not production.** It reloads the rules on every run and the running engine only loads them at manager start. The rules passed in logtest and produced nothing live until I restarted the manager. I made the same mistake again with the SSH rule set.
- **JSON strings stop at a null byte.** A request that began with a null character arrived with an empty `method`, because the decoder cuts the string at `\u0000`. That is why 100344 looks at what the method is not, instead of looking for known junk.
- **Wildcard paths find new files late.** The agent noticed a new file about 40 s after it appeared and only read what came after. That is an observation from two tests, not a measured interval.
- **Nested JSON fields use dots**, for example `virustotal.maliciosos`.
- **Frequency rules group by source IP, so the source IP has to be real.** Docker publishes ports through `docker-proxy`. A redirect to that proxy port makes every attacker look like the bridge address, and 100302, 100303 and 100346 would count all of them as one. For the SSH port I forward with DNAT straight to the container, which keeps the real source address.
- **Check the syntax with the real engine, not only the logic.** The first version of 100364 was rejected by `wazuh-analysisd -t` (`Syntax error on tag 'command'`) even though every pattern passed in my own Python test, which uses a different regex engine. I changed the rule more than once (removed a lookbehind, replaced escaped entities, wrapped a top-level `|` in a group) and it loaded after the last change. I cannot say which change fixed it. `-t` stops at the first error, so a clean run is the only proof that the rules after it are fine too.
- **Cleaning your own test traffic takes three places.** My own connections reached the honeypot logs, the Wazuh alert files and the indexer. My first cleanup did nothing, and I only noticed because I counted afterwards. After the second try the count was zero. On 28 October I did it differently, with a script that blanks each matching line in place with spaces, so the file keeps its size and the Wazuh agent has nothing new to read. It only rewrites the rotated `.gz` files, which nothing is reading. I tested it on fake data first: sizes identical, and IPs that only look similar are not touched. Result: 8 lines in the honeypot logs (two tests, in four files) and 4 in one rotated alert file, and a second dry run found 0 in both places. The indexer had none, because those alerts came from before the template fix. The backups stay outside the repositories. Checked afterwards: the agent log has no `File size reduced` message, and no honeypot log contains the IPs any more. I did not measure the alert count before and after in the same minute, so "the agent did not send anything again" rests on that missing message and on the manager's count growing at a normal pace (about 302 to 319 alerts in an hour and a half).

### Network isolation

The honeypot instance has its own security group. Inbound, the honeypot ports are open to the internet: 2222, 8080, 2121 and now 22 (see below). Outbound traffic is limited to what the project needs:

| Port | Destination | Why |
|---|---|---|
| TCP 1514, 1515 | Wazuh manager only (/32) | Agent events and enrollment |
| TCP 443 | Any | VirusTotal lookups and HTTPS sample downloads |
| TCP 80 | Any | HTTP sample downloads |

Checked from the instance: 80 and 443 answer, ports 22 and 25 to the internet time out, 1514 to the manager connects, the agent stays `Active` and the container still reaches VirusTotal.

Limits, stated plainly:
- 80 and 443 must stay open to any destination because the honeypot downloads whatever URL an attacker types. The security group cannot tell that apart from a legitimate request. The protection against internal targets lives in the code (`url_es_segura`), and it does not cover DNS rebinding.
- Downloads from other ports, such as 8080, time out by design. How the code reports that failure has not been tested.
- From the AWS documentation (not tested here): security groups do not filter traffic to the VPC DNS resolver, instance metadata or the time service. DNS therefore stays an exit path this control cannot close. Metadata access from the container is blocked separately (IMDSv2 with hop limit 1, no instance role).

### First night exposed

The honeypot ran with ports 2222 (fake SSH), 8080 (fake HTTP) and 2121 (fake FTP) open to the internet for about 15 hours. This is one small overnight sample, so it is a case study and not statistics.

What arrived:
- 27 HTTP requests from about nine sources, almost all plain GETs with no credentials. Several sources sent bursts of 3 to 6 requests within seconds, which points to scripts probing several paths.
- 3 SSH login attempts, all from one source, using `root` with `123456`, `password` and `12345678`.
- No malware downloads and no shell commands. Nobody got past the login, which is expected on a non-standard port.

What the HTTP probes were looking for:

| Path | What it tells |
|---|---|
| `/` (19 times) | "Is anything listening?" The first step of any scanner |
| `/wp-json`, `/license.txt` | Looking for WordPress and its version |
| `/hudson` | Looking for a Jenkins CI server |
| `/login`, `/favicon.ico` | Generic login panel search and product fingerprinting |
| `http://a7x[.]overflow[.]biz/hachk.php` | A full URL sent as the path: a test for an open proxy. The honeypot does not proxy, so nothing was fetched |

Two non-HTTP payloads also arrived (a lone Arabic character and a short text block with `AS:2048`). I could not identify the second one, so I am not guessing.

Nothing resembled exploitation. Everything was reconnaissance (ATT&CK T1595, active scanning).

The most useful finding was the SSH source. It sent one attempt about every 30 seconds. Rule 100302 needs a burst of attempts inside 60 seconds, so this pattern would never have triggered it. That is a low and slow brute force, and it exposed a gap in my own detection that I only found because I had real traffic.

I closed it with rule 100303 (5 attempts in 10 minutes, level 8). Tested two ways:
- In `wazuh-logtest`, 12 attempts in a row: 100303 fired on the 5th event and 100302 on the 9th. I read the 9th as the 8th counted login, because the 5th was consumed by 100303. That explanation is my interpretation, the position is the measurement. After each firing the next events fell back to 100301, which is consistent with `ignore` working.
- Live, 6 attempts 30 seconds apart: exactly one alert, 100303, and no 100302.

On a fast burst both rules fire, first level 8 and then level 10, so severity escalates by itself.

### The HTTP and FTP rules (100340 to 100348)

The first night showed what HTTP scanners send, but the first version of the pack only had SSH rules. I wrote the HTTP set after reading what had actually arrived: GPON exploit attempts, open proxy probes, a WebLogic handshake on an HTTP port and the usual hunt for WordPress and Jenkins.

How I checked them:
- Each of the eight rules in `wazuh-logtest`, with a sample event.
- Live, with real traffic that reached the honeypot and a burst test I generated myself.
- By design, a plain `GET /` stays at level 2, so it is counted for 100346 but does not reach the dashboard.

Limits:
- 100345 matches path fragments. A real application that has a `/solr` or `/.git` path would trigger it, and it is a list I wrote from what I saw, not a complete one.
- 100344 is level 3, the lowest that reaches the dashboard. I do not know yet whether it is more useful than noisy.
- 100347 treats any anonymous FTP login as suspicious. On a honeypot that is fair, on a real FTP server it would not be.

### SSH connections and commands (100350 to 100370)

The honeypot records two things that no rule covered: how every SSH connection ends (`ssh_connections.json`) and what the attacker types, now including commands sent without a shell. The [honeypot README](https://github.com/TinchoLay/ssh-honeypot) explains how it records them. I wrote this set on 26 October from two numbers in the honeypot data: 802 connections that got in and left without a shell, and only 39 commands captured in total.

How it is built:
- The connection rules look at the `resultado` field. 100351 is scanner noise, 100352 means the honeypot accepted the login, and 100353 refines that when the client banner belongs to an SSH library used by programs. 100354 counts by group instead of by rule ID because I was not sure that `if_matched_sid` would count an event that ended on a child rule.
- The command rules look at the `command` field with regular expressions. They run from most to least severe, because my understanding is that the first sibling rule that matches is the one that fires. It fits what I saw in `wazuh-logtest`, but I did not test a command that matches two rules.
- The patterns come from well-known bot behavior (leaving an SSH key, mining, download and run), not from my own data. I only had 39 captured commands, so treat them as hypotheses to tune once real `exec` commands arrive.
- The honeypot logs a whole `exec` command once, and logs a download inside it again as its own event with a note. One command can therefore raise 100363 and 100310.
- Level 12 rules reach the default email threshold of Wazuh. No email is configured here.

Limits:
- `/etc/shadow` was a known gap (it only reached the base rule 100360) and 100368 closes it. It looks at the whole command text, so `cat /etc/shadow` and `cp /etc/shadow /tmp` both match.
- 100369 also matches harmless arithmetic such as `echo $((2*3))`. On a honeypot nobody legitimate types that, on a real server it would be noise.
- 100364 and 100365 are broad. `crontab -l` only reads and still alerts at level 7.
- The banner list in 100353 is short, and a banner is trivial to fake.
- The thresholds of 100354 (5 in 300 s) are a first guess.

### Rules added on 27 October

I read a day of real traffic (27 October) and added four rules from what it showed:

- **100348, AI API probing.** HTTP requests for `/api/v1/models`, `/v1beta/models` and similar. The scanners look for an open model endpoint to use for free. It does not overlap with 100345, which I checked pattern by pattern.
- **100368, password hashes.** It closes the `/etc/shadow` gap above. It sits before 100367 in the file, because the first sibling that matches wins and 100367 also reads `/etc/passwd`.
- **100369, shell check.** One IP (80.94.92.179) came back twice, 1 h 45 min apart, and ran commands like `sh -c 'printf ... check_<32 hex> "$((956*983+35))"'`, a function, `set -- ...` and `$$`. As far as I can tell, it checks that the shell really computes before doing anything else. Before this rule those 26 commands only raised the base rule 100360, so it was a real detection gap. I tagged it T1059.004 (Unix shell). I first thought of T1497.001 (sandbox checks), but I cannot show that is what the bot wants, so I left it out.
- **100370, brute force then success.** Same idea as the stock rule 40112. It lives in its own file because a child has to load after its parent (100352), and because I wrote it from memory of 40112, so I am less sure of its syntax than of the others. If `wazuh-analysisd -t` rejects it, remove that file and the rest still works. The honeypot accepts the password on the third attempt on purpose, so this rule fires on that design. On a real SSH server it would be a strong signal.

To feed 100368 and 100370, rules 100302 and 100303 now also belong to the group `honeypot_bruteforce`. Nothing else about them changed.

A network in CIDR form (`77.239.124.0/24:campaign`) does not work as a key in this list. I tested it on Wazuh 4.14.8: `77.239.124.50` gave the stock rule 5760, while an exact IP in the same list (`80.94.92.179`) gave 100330. The list needs one line per IP, so for a network I generate the 254 lines with a loop. I had assumed CIDR worked, because I remembered it from the documentation, and the test proved me wrong. The check for any list change is the `wazuh-logtest` line at the end of `logtest_ssh_samples.txt`. With the 254 lines of the /24 loaded, `77.239.124.50` gave 100330, `77.239.125.50` (outside the range) gave 5760 and `80.94.92.179` gave 100330. The real list stays on the server and is not published here, because it has real attacker addresses. The `.example` file shows the CIDR format with a documentation range.

### Alerts that never reached the dashboard

On 27 October the dashboard showed none of the honeypot alerts, while `alerts.json` on the manager had hundreds (293 with an ID starting in `1003` that day, 4 of them the 100354 rule). The services were all running. The Filebeat log had the answer, repeated for every event:

```
mapper_parsing_exception: failed to parse field [data.timestamp] of type [date] ... Preview of field's value: '2026-10-27 18:57:52'
```

The honeypot writes its own `timestamp` as `YYYY-MM-DD HH:MM:SS`. The Wazuh JSON decoder stores it as `data.timestamp`, the index template maps that field as a strict date (ISO 8601, with a `T`) and the indexer answers 400. Filebeat does not retry a 400, so every alert from these rules was dropped on the way to the indexer, from the first day. The only reason I noticed is that I looked for a rule that I knew had fired. Nothing alerted on it.

The fix is on the Wazuh side, so the honeypot keeps its format: in `/etc/filebeat/wazuh-template.json`, the field `data.timestamp` gets `"format": "yyyy-MM-dd HH:mm:ss||strict_date_optional_time||epoch_millis"`. Then `filebeat setup --index-management -E output.logstash.enabled=false` and a Filebeat restart. The alternative was to write ISO dates in the honeypot, but the honeypot's own dashboard and my analysis scripts read the current format.

Status:
- Verified: the template is loaded in the indexer with the new format.
- Verified on 28 October: the last Filebeat indexing error was at 23:53 UTC on 27 October, and the index created at 00:00 UTC holds the same alert counts per rule as `alerts.json` (for example 180 for 100369 in both).
- Alerts from before the fix are not in the indexer. They are still in `alerts.json` and in the rotated `.json.gz` files, and could be re-sent. I have not done that.
- A Wazuh upgrade may overwrite the template file, so this is a local change to remember.

### Port 22

The fake SSH was listening only on 2222, which scanners rarely try first. I opened port 22 to the internet with a DNAT rule to the container. The rule skips the network I administer from, so the real admin `sshd` (key-only) stays reachable only for me. The rule is not persistent: after a reboot the real `sshd` answers on 22 again, which is the safe direction to fail.

Status: open since 19 October. The first week of results is in the honeypot README. The first alert from the new connection rules (100351) fired on a real scanner on 26 October, after the manager restart. I will add the rest, including whether 100301, 100302, 100303 and the new SSH rules fire on real attackers from end to end, after a few more days of traffic.

### Verified and not verified

Verified end to end with synthetic events (documentation IPs `203.0.113.x`): 100310, 100320, 100302 and 100303 reach `alerts.json`, and 100301 does not (level 2, below the alert threshold of 3). Ten login attempts from one IP produced exactly one 100302 alert.

Verified in `wazuh-logtest` and live: the HTTP and FTP set, 100340 to 100347.

Verified after a stop and start of both instances: the honeypot container comes back on its own (`restart: unless-stopped`) and the agent reconnects to the manager.

Verified only in `wazuh-logtest`: 100330 and the CDB lookup with exact IPs. A CIDR key does not match (see above).

SSH connection and command rules (100350 to 100367), as of 26 October:
- Syntax: the whole file loads with `wazuh-analysisd -t` and no errors.
- In `wazuh-logtest`: 100353, 100361, 100364 and 100367 gave the expected rule, level and ATT&CK technique. `cat /etc/passwd` gave 100367 and not 100364.
- Live: 100351 fired on a real scanner after the manager restart.
- Checked only against my own Python simulator (42 events, Python's regex engine, not Wazuh's): 100350, 100352, 100362, 100363, 100365, 100366 and the group logic of 100354.
- Not verified: 100352 and 100354 with real events, the order in which sibling rules are evaluated, and whether real `exec` commands look like what the patterns expect. `logtest_ssh_samples.txt` has a sample for each rule.

Rules added on 27 October (100348, 100368, 100369, 100370):
- `wazuh-analysisd -t` loads the four files with no errors. In `wazuh-logtest` all four gave the expected rule and level: 100348 (`/api/v1/models`), 100368 (`cat /etc/shadow`, ahead of 100367), 100369 (a command rebuilt from the real shell checks) and 100370. I had checked the patterns first in my Python simulator (51 of 52 cases; the 52nd was the old expectation that `cat /etc/shadow` stops at 100360, which 100368 changes).
- The 100370 test was a sequence: 8 login attempts from one IP, then an accepted login. The fifth attempt fired 100303 (slow brute force) and the accepted login fired 100370. The eighth attempt did not fire 100302. My reading is that the event that fires 100303 is not counted again for 100302, so 100302 needs a ninth. It fits what I saw live earlier (ten attempts, one 100302), but I did not isolate it.
- 100370 has `ignore="300"` because the campaign I saw reconnects hundreds of times, and without it every accepted login after a brute-force alert would raise a level 12 alert. That is a guess about the noise, not something I measured.
- Live: 100348 fired 3 times on 27 October. On 28 October (UTC), 100369 fired 180 times, all from one IP (195.178.110.228) in 3 interactive sessions, and 100370 fired once (77.239.124.67). 100368 has not fired yet, because nobody has read `/etc/shadow`. 180 alerts for one visitor is a lot, so I added `ignore="300"` to 100369. It applies to the whole rule, not per IP, so while it lasts a second visitor doing the same check raises no alert (the command still reaches `shell_commands.json`). I have not verified yet that `ignore` works on a rule without `frequency`. The markers (`check_<hash>_small_math` and similar) have the same format as the ones 80.94.92.179 used on 27 October from another network. That suggests the same tool, but I only compared the markers.
- The CIDR key in the CDB list was tested and does not match (see the list section); exact IPs do.

Live on 27 October, after about 20 hours on port 22: 100351, 100352, 100353, 100354, 100360 and 100367 fired on real traffic. 100361 to 100366 did not fire once, so I still do not know if their patterns match what real bots send.

Not isolated: whether `ignore="60"` suppresses repeats. The test sent 10 attempts, which cannot reach a second burst of 8, so it does not tell `ignore` apart from the frequency counter alone.

Not verified: whether Filebeat sends duplicate alerts to the indexer after an alert file is shortened by hand, as I did when cleaning my own traffic. Also not measured yet: the full SSH rule set under a few days of real traffic on port 22.

---

## Español

Reglas de Wazuh para los eventos que escribe el proyecto [ssh-honeypot](https://github.com/TinchoLay/ssh-honeypot). El honeypot corre en Docker en su propia instancia EC2, con un agente de Wazuh que reporta al mismo manager que el resto de este pack.

Es trabajo de laboratorio, no de producción.

### Cómo encaja todo

```
atacante -> contenedor honeypot -> logs/*.json (bind mount) -> agente Wazuh -> manager -> reglas 100300 a 100370
```

Del lado del agente, en el `ossec.conf` de la instancia del honeypot:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/ubuntu/honeypot-aws/logs/*.json</location>
</localfile>
```

El honeypot escribe un objeto JSON por línea con un campo `honeypot_event`: `ssh_login_attempt`, `ssh_connection`, `http_request`, `ftp_login_attempt`, `shell_command` o `malware_capture`.

Del lado del manager: copiar los archivos de reglas a `/var/ossec/etc/rules/`, validarlos con `wazuh-analysisd -t` y reiniciar el manager. Recargar no alcanza, mirá las notas más abajo.

### Archivos

| Archivo | Reglas |
|---|---|
| `honeypot_rules.xml` | 100300 a 100320: SSH, comandos de la shell y capturas de malware |
| `honeypot_rules_http.xml` | 100340 a 100348: HTTP y FTP |
| `honeypot_ioc_rules.xml` | 100330: logins fallidos desde una IP de atacante conocida |
| `honeypot-attackers.example` | Formato de la lista CDB que lee la regla 100330 |
| `honeypot_rules_ssh.xml` | 100350 a 100369: cómo terminó cada conexión SSH y qué escribe el atacante |
| `honeypot_rules_ssh_correlation.xml` | 100370: fuerza bruta seguida de un login aceptado. Archivo aparte para poder sacarlo solo |
| `logtest_ssh_samples.txt` | Eventos de ejemplo para pegar en `wazuh-logtest`, con la regla que debería disparar cada uno |

El nombre `honeypot_rules_http.xml` es a propósito. Wazuh carga los archivos de reglas en orden alfabético y una regla hija tiene que cargarse después de su padre. Mi primer nombre, `honeypot_http_rules.xml`, quedaba antes que `honeypot_rules.xml`, así que las reglas HTTP se cargaban antes de la regla de la que dependen (100300) y se ignoraban. `honeypot_rules_ssh.xml` sigue la misma regla: queda después de `honeypot_rules.xml`, así que su padre (100300) ya está cargado. Más abajo está el detalle.

### Reglas

| ID | Nivel | Qué detecta |
|---|---|---|
| 100300 | 0 | Cualquier evento del honeypot (regla padre) |
| 100301 | 2 | Intento de login SSH. Está bajo el umbral de alerta por defecto (3), así que se cuenta pero no se muestra |
| 100302 | 10 | 8 intentos de login desde la misma IP en 60 s (T1110). `ignore="60"` limita las repeticiones |
| 100303 | 8 | Fuerza bruta lenta: 5 intentos de login desde la misma IP en 10 minutos (T1110) |
| 100310 | 8 | Intento de descarga desde la shell falsa (T1105) |
| 100320 | 12 | Archivo capturado que al menos un motor de VirusTotal marca como malicioso (T1105) |
| 100330 | 12 | Autenticación fallida en un sistema real desde una IP de la lista de atacantes del honeypot (T1110) |
| 100340 | 2 | Cualquier request HTTP (regla base del conjunto HTTP, se cuenta pero no se muestra) |
| 100341 | 8 | Request a `GponForm/diag_Form`, la ruta del exploit de routers GPON (T1190) |
| 100342 | 5 | Prueba de proxy abierto: una URL completa como ruta, o `CONNECT host:puerto` (T1595) |
| 100343 | 5 | Handshake T3 de WebLogic enviado al puerto HTTP (T1595.002) |
| 100344 | 3 | Tráfico que no es HTTP, como un protocolo perdido o basura binaria (T1595) |
| 100345 | 5 | Búsqueda de un objetivo conocido: `wp-json`, `wp-login`, `xmlrpc.php`, `/.env`, `/.git`, `phpmyadmin`, `actuator`, `/solr`, `manager/html`, Jenkins, GeoServer (T1595.002) |
| 100346 | 5 | 10 requests HTTP desde la misma IP en 120 s, `ignore="300"` (T1595) |
| 100347 | 4 | Login FTP como `anonymous` (T1078) |
| 100348 | 6 | Sondeo de una API de modelos de IA: `/v1/models`, `/v1beta/models`, `/v1/chat/completions`, `/api/tags`, `/ollama/` (T1595.002) |
| 100350 | 2 | Cualquier conexión SSH (regla base del conjunto de conexiones, se cuenta pero no se muestra) |
| 100351 | 3 | Scanner: la conexión terminó sin banner SSH o con un error de protocolo (T1595) |
| 100352 | 6 | El honeypot aceptó el login: resultado `autenticado_sin_shell`, `exec` o `shell` (T1078) |
| 100353 | 7 | Igual que 100352, pero el banner del cliente es una librería SSH que usan los programas (`Go`, `libssh`, `paramiko`, `makiko`, `AsyncSSH`, `JSCH`), no el cliente de una persona (T1078) |
| 100354 | 9 | 5 logins aceptados desde la misma IP en 300 s, `ignore="300"` (T1110). Cuenta el grupo `honeypot_login_ok` |
| 100360 | 3 | Cualquier comando que escribe o manda el atacante (regla base del conjunto de comandos) |
| 100361 | 12 | Comando que menciona `authorized_keys`: dejar una clave SSH propia (T1098.004) |
| 100362 | 12 | Nombres de criptomineros o el protocolo `stratum` (T1496) |
| 100363 | 10 | Descargar y ejecutar en un solo comando: `wget ...; chmod`, `curl ... \| sh` (T1105, T1059.004) |
| 100364 | 9 | Crear o modificar cuentas de usuario: `useradd`, `chpasswd`, `passwd` (T1098, T1136.001) |
| 100365 | 7 | Tocar cron: `crontab`, `/etc/cron`. También coincide con `crontab -l`, que es solo lectura (T1053.003) |
| 100366 | 8 | Borrar rastros: `history -c`, `unset HISTFILE`, borrar logs (T1070.003, T1070.002) |
| 100367 | 5 | Reconocimiento del sistema: `uname`, `/proc/cpuinfo`, `nproc`, `lscpu`, `/etc/passwd`, `whoami` (T1082, T1033) |
| 100368 | 10 | Lectura de hashes de contraseñas: `/etc/shadow`, `/etc/gshadow` (T1003.008). Se evalúa antes que 100367 |
| 100369 | 6 | Verificación de la shell: aritmética al azar `$((a*b+c))`, marcadores `check_<hash>`, `set` con argumentos, `ignore="300"` (T1059.004). Se evalúa antes que 100367 |
| 100370 | 12 | Un login aceptado (100352) después de una alerta de fuerza bruta (100302 o 100303) desde la misma IP en 600 s, `ignore="300"` (T1110.001, T1078) |

La severidad sigue cuánta evidencia hay. Un intento de login o un GET simple es ruido, un request a una ruta de exploit muestra intención y una muestra que VirusTotal confirma es una prueba.

El honeypot HTTP también guarda el cuerpo del POST. Eso importa para la regla 100341: el exploit de GPON manda su comando en el cuerpo y no en la URL, y la ruta sola no dice qué quería ejecutar el atacante.

### Lista de IPs de atacantes (CDB)

`honeypot-attackers.example` muestra el formato (`ip:etiqueta`). Se instala como `/var/ossec/etc/lists/honeypot-attackers`, se registra `<list>etc/lists/honeypot-attackers</list>` en el bloque `<ruleset>` de `ossec.conf` y se reinicia el manager. La regla 100330 sube un login fallido desde una IP de la lista del nivel 5 de fábrica (`5760`) al nivel 12.

Estado: solo simulado. Probé la búsqueda y la prioridad de la regla con `wazuh-logtest`: una IP de la lista dio 100330 y una que no estaba dio 5760. La lista se llena a mano. Alimentarla desde las alertas 100302 y 100320 necesitaría un script y un reinicio del manager para recargarla. No lo construí.

### Lo que aprendí probando

- **Los archivos de reglas se cargan en orden alfabético.** Una regla hija (`if_sid`) tiene que ir después de su padre. Con el nombre equivocado, `wazuh-logtest` mostró advertencias y las reglas no hacían nada. Renombrar el archivo lo arregló.
- **El nombre del campo importa.** Mi primera versión usaba `event_type`, que chocaba con la regla de Suricata 86600. Cambiarlo a `honeypot_event` lo resolvió.
- **Las reglas de nivel 0 no cuentan para las reglas de frecuencia.** La regla base de login es de nivel 2 a propósito, para que 100302 pueda contarla. Lo mismo vale para 100340 y 100346.
- **`wazuh-logtest` no es producción.** Recarga las reglas en cada ejecución y el motor en marcha solo las carga al iniciar el manager. Las reglas pasaron en logtest y no produjeron nada en vivo hasta que reinicié el manager. Volví a cometer el mismo error con el conjunto de reglas SSH.
- **Los strings de JSON se cortan en un byte nulo.** Un request que empezaba con un carácter nulo llegó con el `method` vacío, porque el decodificador corta el string en `\u0000`. Por eso 100344 mira lo que el método no es, en vez de buscar basura conocida.
- **Las rutas con comodín encuentran los archivos nuevos tarde.** El agente detectó un archivo nuevo unos 40 s después de que apareció y solo leyó lo que vino después. Es una observación de dos pruebas, no un intervalo medido.
- **Los campos anidados de JSON usan puntos**, por ejemplo `virustotal.maliciosos`.
- **Las reglas de frecuencia agrupan por IP de origen, así que esa IP tiene que ser la real.** Docker publica los puertos a través de `docker-proxy`. Una redirección a ese puerto hace que todos los atacantes parezcan la dirección del bridge, y 100302, 100303 y 100346 los contarían a todos como uno solo. Para el puerto SSH reenvío con DNAT directo al contenedor, que conserva la dirección de origen real.
- **Probá la sintaxis con el motor real, no solo la lógica.** La primera versión de 100364 fue rechazada por `wazuh-analysisd -t` (`Syntax error on tag 'command'`) aunque todos los patrones pasaban en mi prueba en Python, que usa otro motor de expresiones regulares. Cambié la regla más de una vez (saqué un lookbehind, reemplacé entidades escapadas, encerré un `|` de nivel superior en un grupo) y cargó después del último cambio. No puedo decir cuál lo arregló. `-t` frena en el primer error, así que una corrida limpia es la única prueba de que las reglas que vienen después también están bien.
- **Limpiar tu propio tráfico de prueba lleva tres lugares.** Mis conexiones llegaron a los logs del honeypot, a los archivos de alertas de Wazuh y al indexador. Mi primera limpieza no hizo nada y me di cuenta solo porque conté después. Tras el segundo intento el conteo dio cero. El 28 de octubre lo hice distinto, con un script que deja en blanco cada línea que coincide, en el mismo lugar y con espacios, así que el archivo conserva su tamaño y el agente de Wazuh no tiene nada nuevo que leer. Solo reescribe los `.gz` rotados, que nadie está leyendo. Lo probé antes con datos de mentira: tamaños idénticos, y las IPs que solo se parecen no se tocan. Resultado: 8 líneas en los logs del honeypot (dos pruebas, en cuatro archivos) y 4 en un archivo de alertas rotado, y un segundo modo seco dio 0 en los dos lugares. El indexer no tenía ninguna, porque esas alertas eran de antes del arreglo de la plantilla. Los backups quedan fuera de los repositorios. Comprobado después: el log del agente no tiene ningún mensaje `File size reduced`, y ningún log del honeypot contiene ya las IPs. No medí la cantidad de alertas antes y después en el mismo minuto, así que "el agente no reenvió nada" se apoya en ese mensaje que no aparece y en que el conteo del manager crece a un ritmo normal (de unas 302 a 319 alertas en una hora y media).

### Aislamiento de red

La instancia del honeypot tiene su propio security group. De entrada, los puertos del honeypot están abiertos a internet: 2222, 8080, 2121 y ahora 22 (más abajo). El tráfico de salida se limita a lo que el proyecto necesita:

| Puerto | Destino | Para qué |
|---|---|---|
| TCP 1514, 1515 | Solo el manager de Wazuh (/32) | Eventos del agente y enrolamiento |
| TCP 443 | Cualquiera | Consultas a VirusTotal y descargas de muestras por HTTPS |
| TCP 80 | Cualquiera | Descargas de muestras por HTTP |

Comprobado desde la instancia: 80 y 443 responden, los puertos 22 y 25 hacia internet dan timeout, 1514 al manager conecta, el agente sigue `Active` y el contenedor todavía llega a VirusTotal.

Límites, dichos sin vueltas:
- 80 y 443 tienen que quedar abiertos a cualquier destino porque el honeypot descarga la URL que el atacante escriba. El security group no puede distinguir eso de un request legítimo. La protección contra destinos internos está en el código (`url_es_segura`) y no cubre el DNS rebinding.
- Las descargas desde otros puertos, como el 8080, dan timeout a propósito. No probé cómo reporta ese error el código.
- Según la documentación de AWS (no probado acá): los security groups no filtran el tráfico al resolver DNS de la VPC, a los metadatos de la instancia ni al servicio de hora. El DNS queda entonces como una vía de salida que este control no puede cerrar. El acceso a los metadatos desde el contenedor se bloquea aparte (IMDSv2 con hop limit 1, sin rol de instancia).

### Primera noche expuesto

El honeypot estuvo unas 15 horas con los puertos 2222 (SSH falso), 8080 (HTTP falso) y 2121 (FTP falso) abiertos a internet. Es una muestra chica de una sola noche, así que es un caso de estudio y no estadística.

Qué llegó:
- 27 requests HTTP de unas nueve fuentes, casi todos GET simples sin credenciales. Varias fuentes mandaron ráfagas de 3 a 6 requests en pocos segundos, lo que apunta a scripts que prueban varias rutas.
- 3 intentos de login SSH, todos de una sola fuente, con `root` y `123456`, `password` y `12345678`.
- Ninguna descarga de malware ni comandos en la shell. Nadie pasó el login, que es lo esperable en un puerto no estándar.

Qué buscaban los sondeos HTTP:

| Ruta | Qué indica |
|---|---|
| `/` (19 veces) | "¿Hay algo escuchando?" El primer paso de cualquier scanner |
| `/wp-json`, `/license.txt` | Busca WordPress y su versión |
| `/hudson` | Busca un servidor Jenkins |
| `/login`, `/favicon.ico` | Búsqueda genérica de paneles de login y fingerprinting de productos |
| `http://a7x[.]overflow[.]biz/hachk.php` | Una URL completa mandada como ruta: prueba de proxy abierto. El honeypot no hace de proxy, así que no se descargó nada |

También llegaron dos payloads que no eran HTTP (un solo carácter árabe y un bloque de texto corto con `AS:2048`). No pude identificar el segundo, así que no adivino.

Nada se parecía a una explotación. Todo era reconocimiento (ATT&CK T1595, escaneo activo).

El hallazgo más útil fue la fuente SSH. Mandaba un intento cada 30 segundos más o menos. La regla 100302 necesita una ráfaga de intentos dentro de 60 segundos, así que este patrón nunca la hubiera disparado. Es una fuerza bruta lenta, y dejó a la vista un hueco en mi propia detección que solo encontré porque tuve tráfico real.

Lo cerré con la regla 100303 (5 intentos en 10 minutos, nivel 8). Probada de dos formas:
- En `wazuh-logtest`, 12 intentos seguidos: 100303 saltó en el evento 5 y 100302 en el 9. Interpreto el 9 como el octavo login contado, porque el 5 lo consumió 100303. Esa explicación es mi interpretación, la posición es la medición. Después de cada disparo los eventos siguientes volvieron a 100301, lo que es coherente con que `ignore` funcione.
- En vivo, 6 intentos separados por 30 segundos: exactamente una alerta, 100303, y ninguna 100302.

En una ráfaga rápida saltan las dos reglas, primero la de nivel 8 y después la de nivel 10, así que la severidad escala sola.

### Las reglas HTTP y FTP (100340 a 100348)

La primera noche mostró lo que mandan los scanners HTTP, pero la primera versión del pack solo tenía reglas de SSH. Escribí el conjunto HTTP después de leer lo que había llegado de verdad: intentos de exploit de GPON, sondeos de proxy abierto, un handshake de WebLogic en un puerto HTTP y la búsqueda de siempre de WordPress y Jenkins.

Cómo las comprobé:
- Cada una de las ocho reglas en `wazuh-logtest`, con un evento de ejemplo.
- En vivo, con tráfico real que llegó al honeypot y una prueba de ráfaga que generé yo.
- Por diseño, un `GET /` simple se queda en nivel 2: lo cuenta 100346, pero no llega al dashboard.

Límites:
- 100345 busca fragmentos de ruta. Una aplicación real que tenga una ruta `/solr` o `/.git` la dispararía, y es una lista que armé con lo que vi, no una lista completa.
- 100344 es de nivel 3, el más bajo que llega al dashboard. Todavía no sé si es más útil que ruidosa.
- 100347 trata cualquier login FTP anónimo como sospechoso. En un honeypot es razonable, en un servidor FTP real no.

### Conexiones y comandos SSH (100350 a 100370)

El honeypot registra dos cosas que ninguna regla cubría: cómo termina cada conexión SSH (`ssh_connections.json`) y lo que escribe el atacante, ahora incluyendo comandos enviados sin shell. El [README del honeypot](https://github.com/TinchoLay/ssh-honeypot) explica cómo los registra. Escribí este conjunto el 26 de octubre a partir de dos números de los datos del honeypot: 802 conexiones que entraron y se fueron sin una shell, y solo 39 comandos capturados en total.

Cómo está armado:
- Las reglas de conexión miran el campo `resultado`. 100351 es ruido de scanners, 100352 significa que el honeypot aceptó el login y 100353 lo refina cuando el banner del cliente es de una librería SSH que usan los programas. 100354 cuenta por grupo y no por ID de regla porque no estaba seguro de que `if_matched_sid` contara un evento que terminó en una regla hija.
- Las reglas de comandos miran el campo `command` con expresiones regulares. Van de la más grave a la menos grave, porque entiendo que dispara la primera regla hermana que coincide. Coincide con lo que vi en `wazuh-logtest`, pero no probé un comando que coincida con dos reglas.
- Los patrones salen de comportamientos de bots muy conocidos (dejar una clave SSH, minar, descargar y ejecutar), no de mis datos. Solo tenía 39 comandos capturados, así que son hipótesis para ajustar cuando lleguen comandos `exec` reales.
- El honeypot registra una vez el comando `exec` completo, y registra de nuevo una descarga dentro de él como evento propio con una nota. Un solo comando puede entonces disparar 100363 y 100310.
- Las reglas de nivel 12 alcanzan el umbral de correo por defecto de Wazuh. Acá no hay correo configurado.

Límites:
- `/etc/shadow` era un hueco conocido (solo llegaba a la regla base 100360) y 100368 lo cierra. Mira todo el texto del comando, así que `cat /etc/shadow` y `cp /etc/shadow /tmp` coinciden los dos.
- 100369 también coincide con aritmética inofensiva como `echo $((2*3))`. En un honeypot nadie legítimo escribe eso, en un servidor real sería ruido.
- 100364 y 100365 son amplias. `crontab -l` solo lee y igual alerta en nivel 7.
- La lista de banners de 100353 es corta, y un banner es trivial de falsificar.
- Los umbrales de 100354 (5 en 300 s) son una primera estimación.

### Reglas agregadas el 27 de octubre

Leí un día de tráfico real (27 de octubre) y sumé cuatro reglas a partir de lo que mostró:

- **100348, sondeo de APIs de IA.** Requests HTTP a `/api/v1/models`, `/v1beta/models` y parecidos. Los escáneres buscan un endpoint de modelos abierto para usarlo gratis. No se pisa con 100345, lo comprobé patrón por patrón.
- **100368, hashes de contraseñas.** Cierra el hueco de `/etc/shadow` de arriba. Está antes que 100367 en el archivo, porque gana la primera hermana que coincide y 100367 también lee `/etc/passwd`.
- **100369, verificación de la shell.** Una IP (80.94.92.179) volvió dos veces con 1 h 45 min de diferencia y corrió comandos como `sh -c 'printf ... check_<32 hex> "$((956*983+35))"'`, una función, `set -- ...` y `$$`. Hasta donde puedo ver, comprueba que la shell de verdad calcula antes de hacer otra cosa. Antes de esta regla esos 26 comandos solo levantaban la base 100360, o sea que era un hueco real de detección. La etiqueté T1059.004 (shell de Unix). Primero pensé en T1497.001 (chequeos de sandbox), pero no puedo demostrar que eso sea lo que busca el bot, así que la dejé afuera.
- **100370, fuerza bruta y después éxito.** Misma idea que la regla de fábrica 40112. Está en su propio archivo porque una hija tiene que cargarse después de su padre (100352), y porque la escribí de memoria de la 40112, así que estoy menos seguro de su sintaxis que de las otras. Si `wazuh-analysisd -t` la rechaza, se saca ese archivo y el resto sigue andando. El honeypot acepta la contraseña en el tercer intento a propósito, así que esta regla salta por ese diseño. En un servidor SSH real sería una señal fuerte.

Para alimentar 100368 y 100370, las reglas 100302 y 100303 ahora también pertenecen al grupo `honeypot_bruteforce`. No cambió nada más de ellas.

Una red en formato CIDR (`77.239.124.0/24:campaign`) no funciona como clave en esta lista. Lo probé en Wazuh 4.14.8: `77.239.124.50` dio la regla de fábrica 5760, mientras que una IP exacta de la misma lista (`80.94.92.179`) dio 100330. La lista necesita una línea por IP, así que para una red genero las 254 líneas con un bucle. Yo había dado por hecho que CIDR funcionaba, porque lo recordaba de la documentación, y la prueba me desmintió. La comprobación para cualquier cambio de la lista es la línea de `wazuh-logtest` al final de `logtest_ssh_samples.txt`. Con las 254 líneas de la /24 cargadas, `77.239.124.50` dio 100330, `77.239.125.50` (fuera del rango) dio 5760 y `80.94.92.179` dio 100330. La lista real queda en el servidor y no se publica acá, porque tiene direcciones reales de atacantes. El archivo `.example` muestra el formato CIDR con un rango de documentación.

### Alertas que nunca llegaron al dashboard

El 27 de octubre el dashboard no mostraba ninguna alerta del honeypot, mientras que `alerts.json` en el manager tenía cientos (293 con un ID que empieza en `1003` ese día, 4 de ellas de la regla 100354). Todos los servicios estaban corriendo. La respuesta estaba en el log de Filebeat, repetida en cada evento:

```
mapper_parsing_exception: failed to parse field [data.timestamp] of type [date] ... Preview of field's value: '2026-10-27 18:57:52'
```

El honeypot escribe su propio `timestamp` como `AAAA-MM-DD HH:MM:SS`. El decoder JSON de Wazuh lo guarda como `data.timestamp`, la plantilla del índice mapea ese campo como fecha estricta (ISO 8601, con una `T`) y el indexer contesta 400. Filebeat no reintenta un 400, así que todas las alertas de estas reglas se perdían en el camino al indexer, desde el primer día. Me di cuenta solo porque busqué una regla que sabía que había saltado. Nada avisó de esto.

El arreglo es del lado de Wazuh, para que el honeypot conserve su formato: en `/etc/filebeat/wazuh-template.json`, el campo `data.timestamp` recibe `"format": "yyyy-MM-dd HH:mm:ss||strict_date_optional_time||epoch_millis"`. Después `filebeat setup --index-management -E output.logstash.enabled=false` y reiniciar Filebeat. La alternativa era escribir fechas ISO en el honeypot, pero su propio dashboard y mis scripts de análisis leen el formato actual.

Estado:
- Verificado: la plantilla está cargada en el indexer con el formato nuevo.
- Verificado el 28 de octubre: el último error de indexado de Filebeat fue a las 23:53 UTC del 27 de octubre, y el índice creado a las 00:00 UTC tiene los mismos conteos de alertas por regla que `alerts.json` (por ejemplo 180 para 100369 en los dos).
- Las alertas anteriores al arreglo no están en el indexer. Siguen en `alerts.json` y en los `.json.gz` rotados, y se podrían reenviar. No lo hice.
- Una actualización de Wazuh puede pisar el archivo de la plantilla, así que es un cambio local para recordar.

### Puerto 22

El SSH falso solo escuchaba en el 2222, que los scanners casi nunca prueban primero. Abrí el puerto 22 a internet con una regla DNAT hacia el contenedor. La regla saltea la red desde la que administro, así que el `sshd` real de administración (solo con clave) queda accesible solo para mí. La regla no es persistente: después de un reinicio vuelve a responder el `sshd` real en el 22, que es la dirección segura en la que fallar.

Estado: abierto desde el 19 de octubre. Los resultados de la primera semana están en el README del honeypot. La primera alerta de las reglas nuevas de conexión (100351) saltó con un scanner real el 26 de octubre, después de reiniciar el manager. Voy a agregar el resto, incluyendo si 100301, 100302, 100303 y las reglas SSH nuevas saltan de punta a punta con atacantes reales, después de unos días más de tráfico.

### Verificado y no verificado

Verificado de punta a punta con eventos sintéticos (IPs de documentación `203.0.113.x`): 100310, 100320, 100302 y 100303 llegan a `alerts.json`, y 100301 no (nivel 2, bajo el umbral de alerta de 3). Diez intentos de login desde una IP produjeron exactamente una alerta 100302.

Verificado en `wazuh-logtest` y en vivo: el conjunto HTTP y FTP, de 100340 a 100347.

Verificado después de apagar y prender las dos instancias: el contenedor del honeypot vuelve solo (`restart: unless-stopped`) y el agente se reconecta al manager.

Verificado solo en `wazuh-logtest`: 100330 y la búsqueda en la CDB con IPs exactas. Una clave CIDR no coincide (ver arriba).

Reglas de conexión SSH y de comandos (100350 a 100367), al 26 de octubre:
- Sintaxis: el archivo completo carga con `wazuh-analysisd -t` y sin errores.
- En `wazuh-logtest`: 100353, 100361, 100364 y 100367 dieron la regla, el nivel y la técnica de ATT&CK esperados. `cat /etc/passwd` dio 100367 y no 100364.
- En vivo: 100351 saltó con un scanner real después de reiniciar el manager.
- Comprobado solo con mi propio simulador en Python (42 eventos, motor de regex de Python, no el de Wazuh): 100350, 100352, 100362, 100363, 100365, 100366 y la lógica de grupo de 100354.
- No verificado: 100352 y 100354 con eventos reales, el orden en que se evalúan las reglas hermanas, y si los comandos `exec` reales se parecen a lo que esperan los patrones. `logtest_ssh_samples.txt` tiene un ejemplo para cada regla.

Reglas agregadas el 27 de octubre (100348, 100368, 100369, 100370):
- `wazuh-analysisd -t` carga los cuatro archivos sin errores. En `wazuh-logtest` las cuatro dieron la regla y el nivel esperados: 100348 (`/api/v1/models`), 100368 (`cat /etc/shadow`, antes que 100367), 100369 (un comando reconstruido a partir de los chequeos reales de la shell) y 100370. Antes había comprobado los patrones en mi simulador de Python (51 de 52 casos; el 52 era la expectativa vieja de que `cat /etc/shadow` se quedaba en 100360, que 100368 cambia).
- La prueba de 100370 fue una secuencia: 8 intentos de login desde una IP y después un login aceptado. El quinto intento disparó 100303 (fuerza bruta lenta) y el login aceptado disparó 100370. El octavo intento no disparó 100302. Mi lectura es que el evento que dispara 100303 no se cuenta de nuevo para 100302, así que 100302 necesita un noveno. Coincide con lo que vi en vivo antes (diez intentos, una 100302), pero no lo aislé.
- 100370 tiene `ignore="300"` porque la campaña que vi reconecta cientos de veces, y sin eso cada login aceptado después de una alerta de fuerza bruta levantaría una alerta de nivel 12. Es una suposición sobre el ruido, no algo que haya medido.
- En vivo: 100348 saltó 3 veces el 27 de octubre. El 28 de octubre (UTC), 100369 saltó 180 veces, todas desde una IP (195.178.110.228) en 3 sesiones interactivas, y 100370 saltó una vez (77.239.124.67). 100368 todavía no saltó, porque nadie leyó `/etc/shadow`. 180 alertas para un solo visitante es mucho, así que le agregué `ignore="300"` a 100369. Vale para toda la regla, no por IP, así que mientras dura, un segundo visitante que haga el mismo chequeo no genera alerta (el comando igual llega a `shell_commands.json`). Todavía no verifiqué que `ignore` funcione en una regla sin `frequency`. Los marcadores (`check_<hash>_small_math` y parecidos) tienen el mismo formato que los que usó 80.94.92.179 el 27 de octubre desde otra red. Eso sugiere la misma herramienta, pero solo comparé los marcadores.
- La clave CIDR en la lista CDB se probó y no coincide (ver la sección de la lista); las IPs exactas sí.

En vivo el 27 de octubre, después de unas 20 horas en el puerto 22: 100351, 100352, 100353, 100354, 100360 y 100367 saltaron con tráfico real. 100361 a 100366 no saltaron ni una vez, así que todavía no sé si sus patrones coinciden con lo que mandan los bots reales.

No aislado: si `ignore="60"` suprime las repeticiones. La prueba mandó 10 intentos, que no alcanzan para una segunda ráfaga de 8, así que no distingue `ignore` del contador de frecuencia solo.

No verificado: si Filebeat manda alertas duplicadas al indexador después de acortar a mano un archivo de alertas, como hice al limpiar mi propio tráfico. Tampoco medido todavía: el conjunto completo de reglas SSH con unos días de tráfico real en el puerto 22.
