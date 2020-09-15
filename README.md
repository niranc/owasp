# owasp.py 
French project

# Install :

## pip3
sudo apt-get update && sudo apt-get -y install python3-pip

## Dependances

pip3 install -r requirements.txt

# Presentation :

![](https://jenesaispas/img/owasp-presentation.png)



## Usage :

`python3 owasp.py -d www.firstdomain.com,www.seconddomain.de -p 80,443,8080`


## Categories :
Brief overwiew of each OTG

Each OTG is composed of :
- A description
- A command / a process / an approach how to test it - sometimes it's automated sometimes not
- a conclusion (OK KO)

### OTG-INFO
- [X] OTG INFO 001 : Reco - Grab SHODAN results + associated vulns - Ideas of Google Dorks
- [X] OTG INFO 002 : Grab "Server","Via","X-Powered-By" headers
- [X] OTG INFO 003 : Grab /robots.txt file
- [X] OTG INFO 004 : Grab all services/open ports on domain (=> deprecated web app?)
- [X] OTG INFO 005 : Check for sensitive comments (specific banners, info)
- [ ] OTG INFO 006 : Abuse data inside POST / GET 
- [ ] OTG INFO 007 : Brute force directories and files in webservers (Launch Dirsearch extensions -e ~,doc,docx,pdf,php,xls,xlsx,rtf,odt,psw,ppt,pptx,sml,log,sql,mdb,html,htm,sh,sxw,bat,conf,config,ini,yaml,yml,txt,bak,backup,inc,js,ps,src,dev,old,inc,orig,tmp,tar,zip) - note : not correctly handled
- [X] OTG INFO 008 : Check for specific frameworks
- [X] OTG INFO 009 : Check App
- [X] OTG INFO 010 : Check Firewall (waafw00f)

### OTG-CONFIG
- [X] OTG CONFIG 001 : Check TCP Timestamps 
- [X] OTG CONFIG 002 : Search specific Config files (IIS, ASP)
- [ ] OTG CONFIG 003 : Info about Dirsearch output extensions
- [X] OTG CONFIG 004 : Search known unreferenced backup and config files
- [X] OTG CONFIG 005 : Check for admin panel
- [X] OTG CONFIG 006 : Check unauthorized HTTP methods like TRACE, PUT via NMAP
- [X] OTG_CONFIG_007 : Check HTTP Strict Transport Security header
- [X] OTG_CONFIG_008 : Abuse CORS (Cross Origin Ressources Sharing)
- [ ] OTG_CONFIG_009 : Correct file permissions (on the host... can't really test it)

### OTG-IDENT
- [ ] OTG IDENT 001 : Correct role permissions
- [ ] OTG IDENT 002 : Correct registration 
- [ ] OTG IDENT 003 : Correct users account check
- [ ] OTG IDENT 004 : Can't access user info disclose (aka account name during authent process)
- [ ] OTG IDENT 005 : Can't guess user account 

### OTG-AUTHN
- [ ] OTG AUTHN 001 : Authent via Secure chanel (aka https, sftp ...)
- [ ] OTG AUTHN 002 : Default password changed? Try admin/admin , guest/guest, test/test , nameApp/nameApp ...
- [ ] OTG AUTHN 003 : Anti bruteforce mecanism 
- [ ] OTG AUTHN 004 : Bypass authent
- [ ] OTG AUTHN 005 : Password inside user cookie
- [X] OTG AUTHN 006 : Sensitive data inside user cached browser + Check headers (Cache-Control: no-cache, no-store ) or (Expires: 0) or (Pragma: no-cache)
- [ ] OTG AUTHN 007 : Password complexity (toto123 isn't complex, 12 caracters min/maj/spec/number)
- [ ] OTG AUTHN 008 : Secret question
- [ ] OTG AUTHN 009 : Reinit password
- [ ] OTG AUTHN 010 : Other authent mecanism


### OTG-AUTHZ
- [ ] OTG AUTHZ 001 : LFI ?
- [ ] OTG AUTHZ 002 : Access data after log-off ?
- [ ] OTG AUTHZ 003 : User Priviledge Escalation ?
- [ ] OTG AUTHZ 004 : Sensitive files / functionalities without authorisation

### OTG-SESS
- [ ] OTG SESS 001 : Check Session - non persistent cookie
- [X] OTG SESS 002 : Cookie security attributes (domain, secure, HTTPOnly, path) -
- [ ] OTG SESS 003 : Session Fixation
- [ ] OTG SESS 004 : Session ID sent via secure chanel?
- [ ] OTG SESS 005 : CSRF 
- [ ] OTG SESS 006 : Log-out fonctionnality 
- [ ] OTG SESS 007 : Automatic disconnection 
- [ ] OTG SESS 008 : Correct session ID

### OTG-INPVAL
- [X] OTG INPVAL 001 : Looking for reflected XSS- XSS-strike
- [ ] OTG INPVAL 002 : Looking for stored XSS
- [X] OTG INPVAL 003 : Looking for non standard HTTP methods
- [ ] OTG INPVAL 004 : HTTP Parameter Pollution
- [ ] OTG INPVAL 005 : SQL injection
- [ ] OTG INPVAL 006 : LDAP injection
- [ ] OTG INPVAL 007 : ORM injection
- [ ] OTG INPVAL 008 : XML injection
- [X] OTG INPVAL 009 : Server-Side Includes (SSI)
- [ ] OTG INPVAL 010 : XPath Attaque
- [ ] OTG INPVAL 011 : IMAP et SMTP injection
- [ ] OTG INPVAL 012 : Code Injection
- [ ] OTG INPVAL 013 : OS command injection
- [ ] OTG INPVAL 014 : Buffer Overflow or  DOS
- [ ] OTG INPVAL 015 : Persistent attacks
- [ ] OTG INPVAL 016 : Splitting Smuggling (Splitting : add CR et LF  caracters (\%0d\%0a) in order to split requests) + bad agent parsing ; Smuggling : Bypass WAF app)
- [ ] OTG INPVAL 017 : Looking for input/output requests management 


### OTG-ERR
- [X] OTG ERR 001 : Code error verification
- [X] OTG ERR 002 : Trace system / debug info



### OTG-CRYPST

- [X] OTG CRYPST 001 : Looking for encryption (testssl.sh tool)
- [ ] OTG CRYPST 002 : Padding Oracle
- [ ] OTG CRYPST 003 : Sensitive data sent via non secure canal
- [ ] OTG CRYPST 004 : Weak encryption 

### OTG-BUSLOGIC
- [ ] OTG BUSLOGIC 001 : Verify data business logic
- [ ] OTG BUSLOGIC 002 : Non legitimate fonctions / change user ID
- [ ] OTG BUSLOGIC 003 : Inject data on hidden containers
- [ ] OTG BUSLOGIC 004 : Check server timeout
- [ ] OTG BUSLOGIC 005 : Check numer of time a fonctionnality coult be used
- [ ] OTG BUSLOGIC 006 : Bypass business logic
- [ ] OTG BUSLOGIC 007 : Check application alert
- [ ] OTG BUSLOGIC 008 : Check files extensions
- [ ] OTG BUSLOGIC 009 : Check upload malicious files

### OTG-CLIENT
- [ ] OTG CLIENT 001 : DOM based XSS
- [ ] OTG CLIENT 002 : Javascript execution
- [ ] OTG CLIENT 003 : HTML injection
- [ ] OTG CLIENT 004 : OPenredirect
- [ ] OTG CLIENT 005 : CSS injection
- [ ] OTG CLIENT 006 : User handling
- [ ] OTG CLIENT 007 : bad CORS config (Cross Origin Ressource Sharing)
- [ ] OTG CLIENT 008 : Cross Site Flashing
- [ ] OTG CLIENT 009 : Clickjacking
- [ ] OTG CLIENT 010 : Web Socket
- [ ] OTG CLIENT 011 : Web Messaging or Cross Document Messaging
- [ ] OTG CLIENT 012 : Test local storage 


## Recommendations :

 - [X] HTTP Headers :
 	* Content-Security-Policy
 	* Referrer-Policy
 	* X-Content-Type-Options 
 	* X-Frame-Options
 	* X-Permitted-Cross-Domain-Policies
 - [X] CMS Default files  :
 	* DRUPAL
 	* TYPO3

## Domains :

- [Sudomy](https://github.com/Screetsec/Sudomy)













