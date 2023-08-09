# Red Team Fundamentals

Cybersecurity is a constant race between white hat hackers and black hat hackers. As threats in the cyber-world evolve, so does the need for more specialized services that allow companies to prepare for real attacks the best they can.

While conventional security engagements like vulnerability assessments and penetration tests could provide an excellent overview of the technical security posture of a company, they might overlook some other aspects that a real attacker can exploit. In that sense, we could say that conventional penetration tests are good at showing vulnerabilities so that you can take proactive measures but might not teach you how to respond to an actual ongoing attack by a motivated adversary.


**Vulnerability Assessments**

Vulnerability Assessments aim to find weaknesses in network systems. They scan many hosts for security flaws but avoid harmful actions. Focus is on identifying issues and enabling effective fixes. Automated tools and non-technical operators are mostly used. It's like spotting problems without causing harm.

**Pentetration Tests**
Penetration Tests go beyond finding vulnerabilities. They try to exploit them and assess their impact on the whole network. It's like testing how attackers could use weaknesses to break in and spread through the network. This approach considers vulnerabilities' interactions. It's about understanding how attackers can exploit weaknesses for wider damage.


**Advanced Persistent Threats and why Regular Pentesting is not Enough**
Regular pentesting has limitations: it's loud, may miss non-tech attacks, and relaxes security. Real attackers (Advanced Persistent Threats or APTs) are more covert and skilled. They persistently infiltrate networks. APTs challenge companies' readiness, often targeting critical sectors. Red teaming is a realistic response to APTs, simulating actual attacks for better defense.


![redteam](./media/22-red-team.png)

Notes: 
- Vulnerability Assessments CANNOT prepare us to detect a real attacker on our network 
- Penetration Testers are not concerned about being detected by the client 

## Red Team Engagements 

Red teaming complements penetration tests, focusing on detection and response to real threats. It simulates adversary tactics and strategies to test blue team's reaction without their prior knowledge. Goals are set, like compromising a key system, and red team tries to achieve them while evading detection. It's not about outsmarting blue team, but improving their ability to handle real threats. 


Red team engagements also improve on regular penetration tests by considering several attack surfaces:

- Technical Infrastructure: Like in a regular penetration test, a red team will try to uncover technical vulnerabilities, with a much higher emphasis on stealth and evasion.
- Social Engineering: Targeting people through phishing campaigns, phone calls or social media to trick them into revealing information that should be private.
- Physical Intrusion: Using techniques like lockpicking, RFID cloning, exploiting weaknesses in electronic access control devices to access restricted areas of facilities.
- Depending on the resources available, the red team exercise can be run in several ways:

- Full Engagement: Simulate an attacker's full workflow, from initial compromise until final goals have been achieved.
- Assumed Breach: Start by assuming the attacker has already gained control over some assets, and try to achieve the goals from there. As an example, the red team could receive access to some user's credentials or even a workstation in the internal network.
- Table-top Exercise:  An over the table simulation where scenarios are discussed between the red and blue teams to evaluate how they would theoretically respond to certain threats. Ideal for situations where doing live simulations might be complicated.

Notes: 
- The goals of a red team engagement will often be referred to as flags or "crow jewels"
- Tactics, Techniques and Procedures - During a red team engagement, common methods used by attackers are emulated against the target




