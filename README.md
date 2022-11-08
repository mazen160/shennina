# Shennina


![](https://mazin.s3.amazonaws.com/public/adaecb27-bc60-4f9c-b917-2e5dc5b28930/shennina-banner-2.png)



---
## Automating Host Exploitation with AI


# Abstract

Shennina is an automated host exploitation framework. The mission of the project is to fully automate the scanning, vulnerability scanning/analysis, and exploitation using Artificial Intelligence. Shennina is integrated with Metasploit and Nmap for performing the attacks, as well as being integrated with an in-house Command-and-Control Server for exfiltrating data from compromised machines automatically.

This was developed by [Mazin Ahmed](https://www.linkedin.com/in/infosecmazinahmed/) and [Khalid Farah](https://www.linkedin.com/in/khaledfarah) within the [HITB CyberWeek 2019 AI challenge](https://cyberweek.ae/2019/session/hitb-ai-challenge/). The project is developed based on the concept of [DeepExploit](https://github.com/13o-bbr-bbq/machine_learning_security/tree/master/DeepExploit) by [Isao Takaesu](https://www.linkedin.com/in/isao-takaesu-47485a77/).


Shennina scans a set of input targets for available network services, uses its AI engine to identify recommended exploits for the attacks, and then attempts to test and attack the targets. If the attack succeeds, Shennina proceeds with the post-exploitation phase.

The AI engine is initially trained against live targets to learn reliable exploits against remote services.

Shennina also supports a "Heuristics" mode for identfying recommended exploits.


The documentation can be found in the Docs directory within the project.

# Features

- Automated self-learning approach for finding exploits.
- High performance using managed concurrency design.
- Intelligent exploits clustering.
- Post exploitation capabilities.
- Deception detection.
- Ransomware simulation capabilities.
- Automated data exfiltration.
- Vulnerability scanning mode.
- Heuristic mode support for recommending exploits.
- Windows, Linux, and macOS support for agents.
- Scriptable attack method within the post-exploitation phase.
- Exploits suggestions for Kernel exploits.
- Out-of-Band technique testing for exploitation checks.
- Automated exfiltration of important data on compromised servers.
- Reporting capabilities.
- Coverage for 40+ TTPs within the MITRE ATT&CK Framework.
- Supports multi-input targets.


---


## Why are we solving this problem with AI?

The problem should be solved by a hash tree without using "AI", however, the HITB Cyber Week AI Challenge required the project to find ways to solve it through AI.

## Note

**This project is a security experiment.**

# Legal Disclaimer
This project is made for educational and ethical testing purposes only. Usage of Shennina for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

# Authors

- Mazin Ahmed (mazin@mazinahmed.net)
- Khaled Farah (khaled.a.farah@gmail.com)
