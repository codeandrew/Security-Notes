# Red Team Threat Intel
> https://tryhackme.com/room/redteamthreatintel

Threat Intelligence (TI) or Cyber Threat Intelligence (CTI) is the information, or TTPs (Tactics, Techniques, and Procedures), attributed to an adversary, commonly used by defenders to aid in detection measures. The red cell can leverage CTI from an offensive perspective to assist in adversary emulation.

TIBER-EU (Threat Intelligence-based Ethical Red Teaming) is a common framework developed by the European Central Bank that centers around the use of threat intelligence.

From the ECB TIBER-EU white paper, "The Framework for Threat Intelligence-based Ethical Red Teaming (TIBER-EU) enables European and national authorities to work with financial infrastructures and institutions (hereafter referred to collectively as 'entities') to put in place a programme to test and improve their resilience against sophisticated cyber attacks."



The main difference between this framework and others is the "Testing" phase that requires threat intelligence to feed the red team's testing.

This framework encompasses a best practice rather than anything actionable from a red team perspective.

There are several public white papers and documents if you are interested in reading about this framework further,

https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf
https://www.crest-approved.org/membership/tiber-eu/
https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/pf/ms/sb-tiber-eu.pdf

**TTP MAPPING** 

TTP Mapping is employed by the red cell to map adversaries' collected TTPs to a standard cyber kill chain. Mapping TTPs to a kill chain aids the red team in planning an engagement to emulate an adversary.

To begin the process of mapping TTPs, an adversary must be selected as the target. An adversary can be chosen based on,

- Target Industry
- Employed Attack Vectors
- Country of Origin
- Other Factors

As an example for this task, we have decided to use APT 39, a cyber-espionage group run by the Iranian ministry, known for targeting a wide variety of industries.

We will use the Lockheed Martin cyber kill chain as our standard cyber kill chain to map TTPs.


Going through the Navigator layer, we can assign various TTPs we want to employ during the engagement. Below is a compiled kill chain with mapped TTPs for APT39.

- Reconnaissance:
    - No identified TTPs, use internal team methodology
- Weaponization:
    - Command and Scripting Interpreter
        - PowerShell
        - Python
        - VBA
    - User executed malicious attachments
- Delivery:
    - Exploit Public-Facing Applications
    - Spearphishing
- Exploitation:
    - Registry modification
    - Scheduled tasks
    - Keylogging
    - Credential dumping
- Installation:
    - Ingress tool transfer
    - Proxy usage
- Command & Control:
    - Web protocols (HTTP/HTTPS)
    - DNS
- Actions on Objectives
    - Exfiltration over C2


Other open-source and enterprise threat intelligence platforms can aid red teamers in adversary emulation and TTP mapping, such as,

Mandiant Advantage
Ontic
CrowdStrike Falcon

**Questions**
Open the provided ATT&CK Navigator layer and identify matched TTPs to the cyber kill chain. Once TTPs are identified, map them to the cyber kill chain in the static site.

To complete the challenge, you must submit one technique name per kill chain section.

Once the chain is complete and you have received the flag, submit it below.

THM{7HR347_1N73L_12_4w35om3}
Answer questions below relating to needed engagement resources.

What web shell is APT 41 known to use? 

ASPXSpy
What LOLBAS (Living Off The Land Binaries and Scripts) tool does APT 41 use to aid in file transfers? 

certutil
What tool does APT 41 use to mine and monitor SMS traffic? 

MESSAGETAPc
Task



## Notes:
- Rundll32
- Valid Accounts

- APT41 - research their techniques https://attack.mitre.org/groups/G0096/


## References:

- https://mitre-attack.github.io/attack-navigator/

- https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0008%2FG0008-enterprise-layer.json


- https://intezer.com/ost-map/ A map tracking the use of libraries with offensive capabilities by threat actors.
  - https://www.virusbulletin.com/conference/vb2020/abstracts/ost-map-mapping-malware-usage-open-source-offensive-security-tools

- https://attack.mitre.org/groups/G0096/