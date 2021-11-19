# SSL_Audit_Automation

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

1. About the project

What
- Copying databases containing credit card numbers.
Security risk
- Some hackers might attack the pin code of your credit card number. 
- Fraud transactions
- It might attack your pin as well as your CVV number. 
- Some hackers might fake your signature as well as your credit card number. 
- Anonymous attacks against the users as well as the business/ it might get sniffed by some stores across the network. 
- Your credit limit might be hacked by some other people. 
To copy personal informations 
- Proposed solution/ best practices (countermeasures)
- SSL uses encryption
- SSL also supports a sophisticated system for digital identification
- Authentication as well as Authorization
Encryption

Purpose

- We need to use the SSL in order for us to prevent hacking systems in every credit card that we have. 
- SSL protects sensitive information such as credit card details. 
- Use to prevent fraud across the internet. 
- Similarly, to prevent copying within your personal information. 
- SSL is used

2. Usage 

Command
-  sslyze --regular mail.google.com 
- sslyze -h 
- sslyze –version 
- sslyze –update_trust_stores 
- sslyze –regular www.vk9-sec.com 
- sslyze --regular www.vk9-sec.com --json_out=results.json 
- cat results.json
- sslyze - -regular www.vk9-sec.com - -slow_connection
- sslyze www.vk9-sec.com - -starttls=auto
- sslyze www.vk9-sec.com –tlsv1_1
- sslyze www.vk9-sec.com –openssl_ccs
- sslyze www.vk9-sec.com - -fallback 
- sslyze www.vk9-sec.com –sslv3
- sslyze www.vk9-sec.com --heartbleed
- sslyze www.vk9-sec.com --robot
- sslyze www.vk9-sec.com - -http_headers
- sslyze www.vk9-sec.com –early_data 
- sslyze www.vk9-sec.com –reneg
- sslyze www.vk9-sec.com –compression 
- sslyze www.vk9-sec.com –resum
- sslyze www.vk9-sec.com –tlsv1_3
- sslyze www.vk9-sec.com –sslv2
- sslyze www.vk9-sec.com –certinfo

3. License

Copyright (c) 2021 Alban Diquet

SSLyze is made available under the terms of the GNU Affero General Public License (AGPL). See LICENSE.txt for details and exceptions.

4. Contact

Email: jairavelasco2001@gmail.com

## References
* https://www.saltycrane.com/blog/2011/11/how-get-username-home-directory-and-hostname-python/
* https://docs.python.org/3/library/urllib.parse.html
* https://stackoverflow.com/questions/9530950/parsing-hostname-and-port-from-string-or-url
* https://github.com/nabla-c0d3/sslyze
* https://nabla-c0d3.github.io/sslyze/documentation/#installation
* https://pypi.org/project/sslyze/
* https://stackoverflow.com/questions/8370361/get-ip-address-of-url-in-python
* https://docs.python.org/3/library/urllib.parse.html
* https://intellipaat.com/community/19861/parsing-hostname-and-port-from-string-or-url
* https://pythonguides.com/python-get-an-ip-address/
* https://github.com/nabla-c0d3/sslyze
* https://markdownlivepreview.com/
