# Honeypot integration

Rules for the events written by the [ssh-honeypot](https://github.com/TinchoLay/ssh-honeypot) project, which runs in Docker on its own EC2 instance with a Wazuh agent reporting to the same manager as the rest of this pack.

## How it fits together

```
attacker -> honeypot container -> logs/*.json (bind mount) -> Wazuh agent -> manager -> rules 100300-100320
```

Agent side, in `ossec.conf` of the honeypot instance:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/ubuntu/honeypot-aws/logs/*.json</location>
</localfile>
```

The honeypot writes one JSON object per line with a `honeypot_event` field (`ssh_login_attempt`, `http_request`, `ftp_login_attempt`, `shell_command`, `malware_capture`). Manager side: copy `honeypot_rules.xml` to `/var/ossec/etc/rules/`, check it with `wazuh-analysisd -t` and **restart the manager**.

## Rules

| ID | Level | What it detects |
|---|---|---|
| 100300 | 0 | Any honeypot event (parent rule) |
| 100301 | 2 | SSH login attempt. Below the default alert threshold (3), so it is counted but not shown |
| 100302 | 10 | 8 login attempts from the same IP in 60 s (T1110). `ignore="60"` limits repeats |
| 100310 | 8 | Download attempt from the fake shell (T1105) |
| 100320 | 12 | Captured file flagged as malicious by at least one VirusTotal engine (T1105) |
| 100330 | 12 | Failed authentication on a real system from an IP that is in the honeypot attacker list (T1110). Defined in `honeypot_ioc_rules.xml` |

Severity follows how much evidence there is: a login attempt is noise, a download attempt shows intent, a VirusTotal-confirmed sample is proof.

## Attacker IP list (CDB)

`honeypot-attackers.example` shows the format (`ip:label`). Install it as `/var/ossec/etc/lists/honeypot-attackers`, register `<list>etc/lists/honeypot-attackers</list>` in the `<ruleset>` block of `ossec.conf`, and restart the manager. Rule `100330` raises a failed login from a listed IP from the stock level 5 (`5760`) to level 12.

Status: **simulated only.** The endpoint's security group allows SSH only from my own network, so no attacker IP can reach it. The lookup and the rule priority were checked with `wazuh-logtest`: a listed IP gave `100330`, an unlisted one gave `5760`. The list is filled by hand for now; feeding it automatically from alerts `100302` and `100320` would need a script and a manager restart to reload it, and is not built.

## What I learned while testing

- **The field name matters.** My first version used `event_type`, which collided with the stock Suricata rule 86600. Renaming it to `honeypot_event` fixed it.
- **Level 0 rules do not count toward frequency rules.** The base login rule is level 2 on purpose, so `100302` can count it.
- **`wazuh-logtest` is not production.** It reloads the rules on every run; the running engine only loads them at manager start. The rules passed in logtest but produced nothing live until I restarted the manager.
- **Wildcard paths find new files late.** The agent noticed a new file about 40 s after it appeared, and only read what was written after that. This is an observation from two tests, not a measured interval.
- **Nested JSON fields use dots**, for example `virustotal.maliciosos`.

## Network isolation

The honeypot instance has its own security group. Outbound traffic is limited to what the project needs:

| Port | Destination | Why |
|---|---|---|
| TCP 1514, 1515 | Wazuh manager only (/32) | Agent events and enrollment |
| TCP 443 | Any | VirusTotal lookups and HTTPS sample downloads |
| TCP 80 | Any | HTTP sample downloads |

Checked from the instance: 80 and 443 answer, ports 22 and 25 to the internet time out, 1514 to the manager connects, the agent stays `Active`, and the container still reaches VirusTotal.

Limits, stated plainly:
- 80 and 443 must stay open to any destination because the honeypot downloads whatever URL an attacker types. The security group cannot tell that apart from a legitimate request. The protection against internal targets lives in the code (`url_es_segura`), and it does not cover DNS rebinding.
- Downloads from other ports, such as 8080, time out by design. How the code reports that failure has not been tested.
- From the AWS documentation (not tested here): security groups do not filter traffic to the VPC DNS resolver, instance metadata or the time service. DNS therefore stays an exit path this control cannot close. Metadata access from the container is blocked separately (IMDSv2 with hop limit 1, no instance role).

## Verified and not verified

Verified end to end with synthetic events (documentation IPs `203.0.113.x`): `100310`, `100320` and `100302` reach `alerts.json`, and `100301` does not (level 2, below the alert threshold of 3). Ten login attempts from one IP produced exactly one `100302` alert.
Verified after a stop and start of both instances: the honeypot container comes back on its own (`restart: unless-stopped`) and the agent reconnects to the manager.
Verified only in `wazuh-logtest`: `100330` and the CDB lookup (simulated, see above).
Not isolated: whether `ignore="60"` suppresses repeats. The test sent 10 attempts, which cannot reach a second burst of 8, so it does not tell `ignore` apart from the frequency counter alone.
Not yet measured: behavior under real internet traffic.
