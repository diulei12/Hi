**NTP set time**
	
	sudo timedatectl set-timezone Asia/Kuala_Lumpur
	sudo timedatectl set-ntp true
	timedatectl status

**Data masking** 

	Need to end task appmclient and open back (refresh and relogin wont work)
	Bypass microsoft win11
	Shift + fn + f10 
	Type this 
	Start ms-cxh:localonly

**APPMClient 6.4.01 to 6.4.03**

	update appmclient_config set appmclient_version = '6.4.03';
	ALTER TABLE "APPM"."HOST" ADD ("PROXYFLAG" NUMBER(38,0) DEFAULT 0);
	ALTER TABLE "APPM"."HOST" ADD ("PROXYPORT" NUMBER(38,0));
	ALTER TABLE "APPM"."HOST" MODIFY ("DESCRIPTION" VARCHAR2(128));

**Mysql default_download**

	-sudo dnf install mariadb-connector-c-devel -y
	-pip install mysqlclient
	Recompile appmclient for user no need to insert ip direct pull from the pam web 

**Disk partition if cant delete from disk management**

	If already open bridge on vm still not up ip
	nmcli dev status
	sudo nmcli con add type ethernet ifname eth2 con-name eth2 ipv4.method auto
	sudo nmcli con up eth2

**How to check version 2.9 or 3.0**

	Check appm_client/upgrade
	If client 3.0.14 = 3.0 
	If client 2.9.x = 2.9

**2 AppmClient Guide**

**Remote side fresh install** 

	Find file path command
	Sudo find -name “appm.tar.gz”
	Reset rdp license
	Convert 96 hardening to ova 
	Set up RDS
	wClone Window Server, Change UNIQUE SID

**Check script version**

	strings ./appm_push_pwm | grep ver
	Window Server License Activation
	Choose Option 3 
	Then Option 5
	After cloning lvm entered emergency mode
	Go to /etc/lvm/lvm.conf change use_devicesfile = 0
	Updated script for oscap 93% (reboot enter grub add rd.break and enforcing =0 )
	mount -o remount,rw /sysroot
	chroot /sysroot
	passwd root

**Upload MSI in pam web**

	Tomcat API Push Password Change
	HA proxy script for mysql au3
	Password view 
	Policy > account group 
	User 
	Fix server need to manual start eth0 and 1 
	nmcli connection modify eth0 connection.autoconnect yes
	nmcli connection modify eth1 connection.autoconnect yes

	nmcli -f NAME,AUTOCONNECT connection show (verify)
	Temp fix 
	-just for refer can ignore (fimm)
	-systemctl status sshd
	Hardening 9.6 Size  

**RSAT**

	-Set up guide
	Rocky Ver9.2toVer9.6
	-Upgrade rocky 9.2 to 9.6 guide (offline)

**Command to check service**

	Ps -ef | grep remote 

**Putty cannot go in vi 50-cloud-init to yes and restart service (for hardening)
permanents**

**Checking server command**

	nproc (vcpu)
	free -g (system memory)
	Hostname 

**Command to reset uuid if u do cloned link for window server**

	Run : sysprep

**Permanent link for eth 0 and 1**

**Account Locked in pam**

	IRASS:
	#su
			#cd /root/.irass/*
	Delete all content
	Login with admin/admin
	
	Admin Account:
	#su -
	#mv .appm .appm.bak
	Then re-enter admin to create account

**Account Locked in Web**

	Cd sqlplus
	update person set locked = 0 where personid = 'admin2';

**Ssh linux:**

	Default passphrase key: 1234567890123456
	If ssh-rsa is unavailable, use ecdsa key
	Can check here to see ssh-rsa is able or not:
	#sudo grep 'sshd' /var/log/secure (This want may vary depending on os, but the point is to grep ssh, and see if it allow rsa key, or is it rejected)
	Generate key cmd (Both will prompt for passphrase):
	ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa
	ssh-keygen -t ecdsa -b 521 -f ~/.ssh/id_ecdsa
	On source machine:
	ls ~/.ssh/id_rsa.pub		(Find out where the public key is located)
	cat it
	On target machine:
	mkdir -p ~/.ssh
	chmod 700 ~/.ssh
	vi ~/.ssh/authorized_keys
	chmod 600 ~/.ssh/authorized_keys
	SAML for google log in 
	Hardened Rocky
	Proton Info
	Force the MAC address manually (temporary)
	sudo ip link set dev eth0 address 00:0c:29:77:d9:c4

**LDAP**

	CIMB appm oriss
	CIMB Securities VPN credentials 
	
	CBJ VPN IP - 60.54.116.58      (https:// 10.80.12.2:8443)
	admin2 : secureki@1099
	
	STQ VPN IP - 211.24.90.90     (https://10.60.12.2:8443)

SSMS 21.4.8 autoit 

**Copy all py file to a new folder command (use for platform)**

	mkdir testssms
	cp mssql/*.py testssms/
	Remove fan and power / usb (red color in vm) (sudo dnf -y install ipmitool)
	Admin console
	Setup
	(Y) Hardware Setup (Fan & Power)
	yes
	0
	0
	(R) Setup Cloud Server Mode (USB)
	1
	hmailServer set up

	-hmailserver set up on appm (if secureki smtp cannot use might try this)

**APPM client not showing in %appdata%**

	 explorer %appdata% in Run
	Patching for war file
	unzip <>.war -d /home/appm/webroot/appm/ROOT

**SecureKi Mobile Gateway**

	Pre-requisite folder (Provided by Luke, if unable to access can ask from him)
	Installation
	sudo su
	groupadd -g 200 dba;useradd -u 600 -g 200 appm;chmod 755 /home/appm;passwd appm
	vi /etc/profile , add:- 
	# umask 002S2
	sudo dnf install epel-release -y
	sudo dnf update -y
	sudo dnf install ntfs-3g -y
	dnf install ntfs-3g net-tools vim gcc tar zip telnet pip
	rm -rf /home/appm/.bash_profile
	Deploy mobilegw.tar.gz
	tar -xvzf mobilegw.tar.gz -C /
	ln -s /usr/local/lib/libnpcl_linux_64u.so /lib64/libnpcl_linux_64u.so
	Add to appm cronjob for auto start (optional)

**Configuration**

	1. Configure conf/appm_svr.conf
	Appm_sever = eth 1
	Mobile_gateway_server = none / ip has internet access
	cert_download _portnum = 1807
	2. Copy /home/appm/appm_client/certfile from APPM

**Restart services + Check logs**

	cd bin
	su to check log in pam
	sudo pkill appm_svr_mgate;./appm_svr_mgate to check log in mobile gateway

**Open config mode to view logs**

	cd conf and cat appm_svr.conf in pam 
	cd conf and cat appm_svr.conf in mobile gateway server
	ps aux | grep appm_svr
	systemctl status firewalld

**Block command can ,OTP command cannot keep promp OTP**

	otp issue go to su - irass check script use otp_auth.sh to check ,do patch if not same with .92
	
**Email cannot approve/reject on email**

	Cd mail conf file to swap ip and requester need to log out first to approve/reject 
	Cloud Agent
	Set up for window and linux cloud agent guide

**APPM Client stuck 85%**

	cd appm_client 
	sudo chown -R appm:dba ~/appm_client

**Check domain or not in window server**
	
	win+r
	sysdm.cpl
	GNS3
	GNS3 set up contact with local PC

**Yyp Command control**

	Go to Target host 
	Visudo 
	cytest1 ALL=(ALL)  NOPASSWD: ALL
	
	Yyp (copy current row)
	Dd (delete current row)
	Policy -> command control -> add ->   account group -> command control group id (account group)

**Zip and unzip specific folder only**

	tar -czvBpf webroot.tar.gz /home/appm/webroot/ (zip in source)
	tar -czvBpf otp.tar.gz /home/appm/otp/
	tar -czvBpf mail.tar.gz /home/appm/mail
	tar -czvBpf apachetomcat.tar.gz /home/appm/apache-tomcat
	tar -czvBpf irassscript.tar.gz /home/irass/script
	tar -czvBpf mobilegateway.tar.gz /home/appm/appm_svr
	tar -czvBpf installpackage.tar.gz /home/appm/install_package
	tar -czvBpf appm_client.tar.gz /home/appm/appm_client
	tar -czvBpf appmROOT.tar.gz /home/appm/webroot/appm/ROOT
	tar -czvBpf appmsvr.tar.gz /home/appm/bin/appm_svr

	sudo tar -xvpf webroot.tar.gz -C / (unzip in target )
	sudo tar -xvpf mail.tar.gz -C / 
	sudo tar -xvpf apachetomcat.tar.gz -C /
	sudo tar -xvpf mobilegate.tar.gz -C / 

**1VPN**
	
	Telnet x.x.x.x port 
	Tracert (x.x.x.x) PAM IP after connected to vpn 

**Fresh install**
	
	No need to run the delete lipway server section bcz it  will affect the veracrypt and cause usb error.

**Host server to download file** 
		
		Main server host server : python3 -m http.server 8080
		Then on another machine that wants to get files
		wget http://192.168.80.88:8080/irass.tar.gz
		wget http://192.168.80.88:8080/irassgw.tar.gz
		wget http://192.168.80.88:8080/irasstrace.tar.gz
		wget http://192.168.80.64:8080/start
		wget http://192.168.80.64:8080/others_scripts.tar.gz
		wget http://192.168.80.88:8080/appm.tar.gz
		wget http://192.168.80.64:8080/guacamole-server-1.3.0.tar.gz
		wget http://192.168.80.64:8080/others_contents.tar.gz
		wget http://192.168.80.64:8080/apache-tomcat.tar.gz

**JarScanner**

	Cd apache/tomcat /Context.xml
	<JarScanner>
	    <JarScanFilter defaultPluggabilityScan="false" />
	</JarScanner>

**Permanent mac address**

	sudo nmcli connection modify eth0 802-3-ethernet.cloned-mac-address "2c:ea:7f:5b:77:42";sudo nmcli connection down eth0;sudo nmcli connection up eth0
	sudo nmcli connection modify eth0 802-3-ethernet.cloned-mac-address "d0:94:66:86:f7:cf";sudo nmcli connection down eth0;sudo nmcli connection up eth0
	sudo nmcli connection modify eth0 802-3-ethernet.cloned-mac-address "2c:ea:7f:80:76:18";sudo nmcli connection down eth0;sudo nmcli connection up eth0

**After SetUp Server, Language Change:**

		For PAM website 
	#webroot/appm/ROOT/WEB-INF/classes/language_format

	For APPM rocky change language from korean to english 
	#vi .profile
	#LANG=en_US.UTF-8

**Mount DB:**

	#sudo cryptsetup luksOpen /dev/sda3 oracle
	sudo cryptsetup luksOpen /dev/nvme0n1p3 oracle
	sudo systemctl daemon-reload
	sudo mount /dev/mapper/oracle /home/oracle
	Upgrade / Patch APPM：
		从92获取:
	Go to /home/appm/tmp and create the package files

	APPM
	# tar czvBpf appm.tar.gz --exclude=/home/appm/apache-tomcat/logs --exclude=/home/appm/excel/log --exclude=/home/appm/mail/logs --exclude=/home/appm/function/appm-excel-importer/logs --exclude=/home/appm/function/appm-health-checker/logs --exclude=/home/appm/function/appm-slave-checker/logs --exclude=/home/appm/function/appm-db-synchronizer/logs --exclude=/home/appm/install_package/archive --exclude=/home/appm/security/insert_audit/log --exclude=/home/appm/script/log --exclude=/home/appm/script/logs --exclude=/home/appm/excel/logs --exclude=/home/appm/excel/prev --exclude=/home/appm/excel/done --exclude=/home/appm/squid/var/logs /home/appm/appm_svr /home/appm/appm_one_cmd /home/appm/crypto /home/appm/webroot/appm/ROOT /home/appm/webroot/guacamole/ROOT /home/appm/webroot/api/ROOT /home/appm/install_package /home/appm/appm_client/ /home/appm/bin /home/appm/script /home/appm/conf /home/appm/sql /home/appm/apache-tomcat /home/appm/platform /home/appm/otp /home/appm/mail /home/appm/autoMailingTmp /home/appm/excel /home/appm/squid /home/appm/guacamole-server-1.3.0 /home/appm/function /home/appm/security /home/appm/freerdp-2.7.0 /home/appm/haproxy

	IRASS
	#tar czvBpf irass.tar.gz /home/irass/bin /home/irass/sql /home/irass/script /home/irass/conf /home/irass/socks5 /usr/local/libexec/sshd-session /home/irass/tesseract

	IRASSGW
	#tar czvBpf irassgw.tar.gz /home/irassgw/conf /home/irassgw/bin /home/irassgw/script;tar czvBpf irasstrace.tar.gz --exclude=/home/irasstrace/oradiag_irasstrace /home/irasstrace
	
	在自己的机里面解压:

**To Extract / Untar in your VM**

	#sudo tar -xvpf appm.tar.gz -C /
	#sudo tar -xvpf irass.tar.gz -C /
	#sudo tar -xvpf irassgw.tar.gz -C /


	Run SQL upgrade6.13.1to6.14.1.sql

	Update DB
	Do Integrity Check & Update.

IMPORT and EXPORT DB
==============================
	Export DB
	$rm /opt/oracle/admin/XE/dpdump/expdat.dmp
	$ expdp
	$ sudo tar czvBpf oracle.tar.gz /opt/oracle/admin/XE/dpdump/expdat.dmp
	
	Login to TARGET appm
	Stop APPM services. Only start database
	Go to /home/appm/sql
	sqlplus / as sysdba
	    - alter session set "_ORACLE_SCRIPT"=true;
	    - DROP USER appm CASCADE;
	    - @create_user.sql;
	       
	Import DB (Move expdat.dmp to location /opt/oracle/admin/XE/dpdump/)
	    - sudo tar -xvpf oracle.tar.gz -C /
	    - sudo chown oracle:oinstall /opt/oracle/admin/XE/dpdump/expdat.dmp
	Check APPM DB Size
	    - IMPORT ALL :  impdp \"sys/password as sysdba\"

**Windows self create license 创建自签名证书:**

		# new-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname "ServerPC01.ski.com"
		# $pwd = ConvertTo-SecureString -String P@ssw0rd -Force -AsPlainText
		检查RDS许可证模式（应该是1或者是2）
		# get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core" -Name LicensingMode
	更改RDS许可证模式(以下是改为2）:
		# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core" -Name LicensingMode -Value 2
		然后重启 RDS 相关服务
		# Restart-Service TermService -Force
		# Restart-Service Tssdis -Force
		
**To Check when download account to see error:**

	# while true; do ps -ef | grep default_download | grep -v grep ; done 
	
**To Check when password change to see error:**

	# while true; do ps -ef | grep default_chpwd | grep -v grep; done
	
**Port Listening appm:**

	# sudo netstat -tulnp | grep :1808
	# sudo netstat -an | grep 1808
	Checks every second for the specific port is listening:
	# while true; do sudo netstat -tuln | grep :1808; sleep 1; done

**Check appm if process is running:**

	# pgrep -fl <process> 		e.g. pgrep -fl appm_svr

**Proxmox**

	nmap -p 8006 --open 192.168.80.0/24 (Command for searching open proxmox port 8006 in subnet 192.168.80.xx)	
	
	
	https://192.168.80.233:8006
	root/appmadmin
	
	https://192.168.80.137:8006
	root/secureki@1099

	APPM Server:
	192.168.80.61
	192.168.80.62

	Windows Server 2022(DC, DNS)
	192.168.80.63, domain name:ski.local
	ski\administrator / secureki@1099

	Windows Server 2022(Normal, MSSQL)
	192.168.80.64
	administrator / secureki@1099

	Fortigate
	192.168.80.65
	admin / secureki@1099

	Windows 11
	192.168.80.66
	AdminUser / Rkskfl12!@
	AnyDeskUser / SecureKi@1099
 
APPM ssh full trace Surveillance playback issue (irasstrace):
	# sudo update-crypto-policies --show
	# sudo update-crypto-policies --set DEFAULT:SHA1
	如果还是不行，检查/home/irasstrace/.ssh，里面有没有密钥
In easy term = su - irass 
Cd conf - > pem change to pem.bak 


**Mail Setting unable to save (Reason being missing 1 field in sql, thus, unable to process the data)**

	# INSERT INTO "APPM"."MAIL_SERVER_CONFIG" VALUES (DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT, DEFAULT);

**License Saving Setting:**

	# Insert into APPM.LICENSE_INFO (COMPANYNAME,HOSTNUMBER,LICENSE,LIC_EXPIRE_DATE,OTPNUMBER,OTP_LICENSE,OTP_LIC_EXPIRE_DATE,LICENSE2,OTP_LICENSE2,LOOKNUMBER,LOOK_LICENSE,LOOK_LIC_EXPIRE_DATE,LOOK_LICENSE2,IRASSNUMBER,IRASS_LICENSE,IRASS_LIC_EXPIRE_DATE,IRASS_LICENSE2,CLIENTNUMBER,CLIENT_LICENSE,CLIENT_LIC_EXPIRE_DATE,CLIENT_LICENSE2,HAVEROW,CLIENT_BIO_NUMBER,CLIENT_MOBILE_NUMBER,CCTV_LICENSE,CCTV_LICENSE2,CCTV_NUMBER,CCTV_LIC_EXPIRE_DATE,PC_LICENSE,PC_LICENSE2,PC_NUMBER,PC_LIC_EXPIRE_DATE) values (null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,1,null,null,null,null,null,null,null,null,null,null);
For Mail and License and future DB error:
	- Can try to query and see if there is multiple row in data, usually is incorrect if there is more than 1 total count after doing 
	# SELECT COUNT(*) FROM xxx 
To ensure language is in english codex and display all user in correct font cmd (For Windows):
	# chcp 437 && net user

**Onboard Linux account using public IP:**

	New Account:
		1. Create new sudo account
		2. Generate ssh key
		3. Deploy the public key
		4. Download the private key
		5. In `Web, download the account, then have the private key paste in the account.
		6. Finish

**Grab binary from 92 (When rdp security credential having problem, can try to use this to solve): **
	Using sudo -s
	# zip -r /tmp/92_binary.zip /home/appm/bin /home/appm/appm_svr /home/irass/bin /home/irassgw/bin

	At own pam
	# cd /home
	# unzip /tmp/92_binary.zip

**WinCloud:**

	# cd bin
	# pkill appm_svr;./appm_svr 	(To see cloud connection)
	- Always make sure to change device name after clone.
	- Ensure that domain account has domain admin rights. 

**Fortigate cmd:-**

	To get the ip address:
		# get system interface
	To change the ip interface:	
		# config system interface
		# edit <interface-name) 	e.g. port1
		# unset ip 			(if it is dynamic)
		# set mode static 		(if it is dynamic)
		# set ip <new-ip> <subnet-mask>
		# end
	To ping:
		# execute ping <ip-address>
	To view users:
		# config system admin
		# show
	To create users:
		# config system admin
		# edit <username>
		# set password <password>
		# set accprofile super_admin
		# next
		# end
	To set port: (Should be this problem to access web)
		# config system global
		# set admin-port 80
		# set admin-sport 8443
		# end
		Then use http://<ip>:80 to access fortigate web

**Window Group Policy**

	cmd:
	Update group policy after changes
	# gpupdate /force

HA:
	Master:
	1. Start all services
	2. Start Irass
	3. Startup VIP
	4. Startup failover service

	Slave:
	1. Startup DB
	2. Startup failover service 
	3. # cd log
	4. Check if connected to master,
		# tail -f appm_fo_slave.log

	DR:
	1. Startup DB

Import DB:-
	Make sure to snapshot first.
	1. Login as appm
	2. Stop APPM services. ONLY start database
	3. Go to /home/appm/sql --> 
sqlplus / as sysdba
	4. In SQL,
		# alter session set "_ORACLE_SCRIPT"=true;
		# DROP USER appm CASCADE;
			If fail drop user,
			# SELECT sid, serial# FROM v$session WHERE username = 'APPM';
			- sid and serial will be shown
			# ALTER SYSTEM KILL SESSION 'sid,serial#' IMMEDIATE; 
		# @create_user.sql; (Folder in SSD drive, DB folder, put into appm if does not exsists.)
	5. Import DB,
		# mv expdat.dmp /opt/oracle/admin/XE/dpdump/expdat.dmp
		# chown oracle:oinstall /opt/oracle/admin/XE/dpdump/expdat.dmp
		# cd /opt/oracle/admin/XE/dpdump/
		# impdp \"sys/password as sysdba\"

**Manual ssh web connection:**
	# ssh -F /home/irassgw/conf/ssh_config

**Check connection ssh on target:**
	1. Go root
	# cd /var/log tail -f auth.log

**Download Window Server fail** 
	SSL error:
	- Make sure IP address got Master IP

	TCP error: 
	- Check port inbound for port 7208

**When head to sudo -s:**
	1. Get source:
	#source /home/appm/.profile
	2. To check source:
	#!s

**DB脚本安装:
先安装依赖包**

	sudo dnf install python3-devel
	sudo dnf module enable mariadb:10.11(用sudo dnf module list mariadb来确认版本）
	sudo dnf install mariadb-devel
	然后就可以下载mysqlclient了
	pip install mysqlclient
	OS更换语言（去英文）
	nano .profile
	LANG=en_US.UTF-8

**apache找不到openSSL（缺少apr):**
	
	find / -name libtcnative-1.so -- 找到libtcnative-1.so的文件路径
	sudo nano /home/appm/apache-tomcat/bin/setenv.sh
	写入
	export CATALINA_OPTS="$CATALINA_OPTS -Djava.library.path=《文件路径》
	然后重启apache-tomcat
	./home/appm/apache-tomcat/bin/shutdown.sh
	./home/appm/apache-tomcat/bin/startup.sh

**将windows文件切换成unix文件**
	
	dos2unix 《文件名称》

**oracle数据库解锁用户**
	
	ALTER USER 《用户名》 ACCOUNT UNLOCK;

**检查一个kernel模块有没有被加载和使用**
	
	modinfo <模块名称> -- 可以检查系统有没有下载该模块
	lsmod | grep <模块名称> -- lsmod 命令可以显示当前加载的内核模块
	mount | grep <文件系统类型> -- 查某个文件系统类型是否被挂载	
	lsof | grep <文件系统模块> -- 进一步确认某个模块是否被某个进程使用

**卸载某个kernel模块**
	
	sudo modprobe -r <模块名称>

**以查找文件内容来查询文件的指令**
	
	grep -r "《内容》" 《位置》
	例子： grep -r "kernel.randomize_va_space" /etc/sysctl.d/

**检查包是否为被依赖包**
	
	rpm -q --whatrequires 《包的名称》
	APPM web RDP出现TLS/SSL错误
	i. 确保web功能关闭
	ii. cd /home/appm/freerdp-2.7.0
	iii. sudo sh install.sh
	压缩和解压指令（Linux)
	压缩
	tar czvBpf appm.tar.gz /home/appm/
	解压
	tar -xvpf appm.tar.gz -C /
	手动测试full trace功能
	ssh -i /home/irass/conf/irasstrace.pem irasstrace@127.0.0.1
	password verify sql 命令
	手动设置触发
	update account set vfy_nextpollflag=2,  VFY_NEXTPOLLDATE = TO_DATE('2024-12-23 14:39:00', 'YYYY-MM-DD HH24:MI:SS') where hostname='WinSvr01' and accountid='admin1';
	检查触发条件
	SELECT vfy_nextpollflag, TO_CHAR(vfy_nextpolldate, 'YYYY-MM-DD HH24:MI:SS') FROM account WHERE hostname = 'WinSvr01' AND accountid = 'admin1';
	永久更改 DNS (NetworkManager 管理网络)
	步骤 1：编辑 NetworkManager 配置文件：
	#sudo vi /etc/NetworkManager/NetworkManager.conf
	在文件的 [main] 部分下，确保有以下内容：
	[main]
	dns=none
	步骤 2：编辑相应的连接配置文件（通常位于 /etc/NetworkManager/system-connections/ 目录下），找到正在使用的网络连接配置文件。
	#sudo vi/etc/NetworkManager/system-connections/<your_connection_file>
	[ipv4]
	dns=8.8.8.8,8.8.4.4
	步骤 4：重新启动 NetworkManager 服务以应用更改：
	#sudo systemctl restart NetworkManager
	确保目标是Windows域控制器
		net user -- show local account
		net user /domain -- show domain controller information
		WMIC COMPUTERSYSTEM GET DOMAINROLE
		0-standalone workstation
		1-member wokstation
		2-standalone server
		3-member server
		4-backup domain controller
		
		5-primary domain controller
**查看温度传感器数据**
	
	sudo ipmitool sdr type temperature
	
**查看风扇速度**
	
	sudo ipmitool sdr type fan

**新脚本所需要的audit log属性**
	
	6.2版本：
	__Audit_log($url,$audit_path,$hWnd,"None",$bwlist,$hostname,$sid,$accountid)
	6.3版本：
    __Audit_log($url,$audit_path,$hWnd,$title="None",$bwlist="None",$hostname="None",$sid="None",$accountid="None")
	6.4版本：
	__Audit_log($url,$audit_path,$hWnd, "None", $bwlist, $hostname, $sid, $accountid)

**检查Shared Pool Usage**
	
	SELECT SUM(BYTES) AS TOTAL, SUM(CASE WHEN NAME = 'free memory' THEN BYTES ELSE 0 END) AS FREE, ROUND((SUM(BYTES) - SUM(CASE WHEN NAME = 'free memory' THEN BYTES ELSE 0 END)) / SUM(BYTES) * 100, 2) AS "USED (%)" FROM V$SGASTAT WHERE POOL = 'shared pool';
	do cronjob（为了定期清洗SHARED POOL)
	ALTER SYSTEM FLUSH SHARED_POOL;
	
**cmd测试端口**
	
	powershell Test-NetConnection <IP ADDRES> -Port <port num>
	
	example : powershell Test-NetConnection 192.168.146.153 -Port 13389
**rocky linux检查CPU**
	
	显示 CPU 型号、核心数、线程数、主频、缓存等信息
	lscpu 
	显示详细的 CPU 信息，包括每个核心的规格
	cat /proc/cpuinfo
	显示 BIOS 级别的 CPU 详细信息，包括 TDP、型号、支持的功能等
	dmidecode -t processor

**rocky linux检查内存**
	
	显示当前内存使用情况，包括已用、空闲、缓存等信息
	free -h
	显示更详细的内存参数，例如 Swap 使用情况、缓存大小等
	cat /proc/meminfo
	显示内存的物理规格，例如 容量、类型 (DDR4)、速度 (MHz)、制造商、插槽使用情况
	dmidecode -t memory
	监视 CPU 和 RAM 的动态负载情况
	top


**Installing RACADM / ISM**

	==============================
	sudo dnf config-manager --set-enabled crb
	curl -O https://linux.dell.com/repo/hardware/dsu/bootstrap.cgi
	sudo bash bootstrap.cgi
	sudo dnf install dell-system-update
	
	如果安装失败
	编辑 dell-system-update.repo，删除 [dell-system-update_dependent] 段落，或注释掉该部分。
	vi /etc/yum.repos.d/dell-system-update.repo
	remove all from dell-system-update_dependent
	
	wget -r -np -nH --cut-dirs=3 --accept "*.rpm" 		https://linux.dell.com/repo/hardware/dsu/os_dependent/RHEL9_64/
	cd os_dependent/RHEL9_64/srvadmin/
	sudo dnf install *
	
	cd os_dependent/RHEL9_64/metaRPMS/
	sudo dnf install *
	
	sudo dnf install srvadmin-all
	
	sudo systemctl enable dsm_om_connsvc
	sudo systemctl start dsm_om_connsvc

**racadm指令**

	关闭 iDRAC 的 IPv6：
	racadm set iDRAC.IPv6.Enable 0
	启用 iDRAC 网卡：
	racadm set iDRAC.NIC.Enable 1
	配置 IPv4 地址：
	racadm setniccfg -s 192.168.80.154 255.255.255.0 192.168.80.1
	《IP地址》 《子网掩饰码》 《网关》
	重启 iDRAC 以生效：
	racadm racreset
	查看iDRAC网络状态:
	racadm getniccfg

**Windows准证**

	https://massgrave.dev/

**Linux Server sudo无需密码设定**

	su root
	visudo
	username ALL=(ALL:ALL) NOPASSWD: ALL


**Linux Server not hostname设定**

	sudo vi /ect/resolv.conf
	删除一切


**sh脚本使用appm环境运行某个脚本**

	sudo -u appm bash --login -c "脚本名字"
	例子：
	sudo -u appm bash --login -c "/home/appm/script/slave_up_email_alert.sh"

**APPM ssh full trace 回放功能问题**

	sudo update-crypto-policies --set DEFAULT:SHA1
	如果还是不行，检查/home/irasstrace/.ssh，里面有没有密钥


**tar 命令 仅保留文件的权限，但不记录文件的绝对路径和拥有者信息**

	tar --no-same-owner --mode=go-w --create --file=backup.tar myfile

**文件从windows规格转换去linux规格**

	sed -i 's/\r$//' <文件名>
	例子： sed -i 's/\r$//' namelist.csv


**Windows创建自签名证书**

	New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname "RDS"
	$pwd = ConvertTo-SecureString -String P@ssw0rd -Force -AsPlainText


**强制Windows服务器更新GPO**

	gpupdate /force


**Windows重启RDP服务**

	Restart-Service TermService


**手动命令RDP连接RD Connection Broker（如果 /admin 可以连上，但普通 RDP 不能，说明 普通用户会话有问题）**

	mstsc /v:《域名或者IP》 /admin

**检查RDS许可证模式（应该是1或者是2）**

	Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core" -Name LicensingMode
	接着在mmc里进行部署
	
	更改RDS许可证模式(以下是改为2）
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core" -Name LicensingMode -Value 2
	然后重启 RDS 相关服务
	Restart-Service TermService -Force
	Restart-Service Tssdis -Force

**以Unzip的方式按照补丁**

	unzip 《.war补丁》 -d 《目的地》
	例子： 
	unzip 0304_appmui_i18n_Transformation-6.14.1_BETA.war -d /home/appm/webroot/appm/ROOT/

**ssh error code:519**

	irass没开

**Windows RDP权限**

	情况一，拥有域控制伺服器，且使用域规则
	在域控制伺服器使用gpmc.msc 进入Group Policy Management
	Default Domain Policy > Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Allow log on through Remote Desktop Services
	接着在目标伺服器使用gpupdate /force指令来更新域规则
	
	情况二，没有使用域规则
	在目标伺服器使用gpedit.msc进入Local Group Policy Editor
	Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Allow log on through Remote Desktop Services
	接着在目标伺服器使用gpupdate /force指令来更新本地域规则

**删除旧的 SSH 密钥**

	ssh-keygen -R 192.168.146.155

**清除 RDP 服务器的“信任列表”**

	HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client

**Proxmox上传ovf**

	qm importdisk VM的ID 名字.vmdk local-lvm --format qcow2

**下载SSL后导致ssh崩溃**

	sudo dnf clean all
	sudo dnf makecache
	sudo dnf install -y openssh-server openssh-clients

**Rocky Linux检查硬盘是 SSD 还是 HDD**

	cat /sys/block/*/queue/rotational
	返回 1 表示 HDD（机械硬盘）
	返回 0 表示 SSD（固态硬盘）

**dnf 自动解决依赖**

	dnf install -y --allowerasing 《名字》
RDS证书放入其他电脑受信任的根证书颁发机构 (Root)

# 找到当前 RDS 证书
	
	$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=RDS" }

**#导出证书到 C:\RDS_Certificate.cer (只包含公钥)**
	
	Export-Certificate -Cert $cert -FilePath C:\RDS_Certificate.cer -Type CERT

**#把证书导入到 受信任的根证书颁发机构 (Root)**

	Import-Certificate -FilePath "C:\RDS_Certificate.cer" -CertStoreLocation Cert:\LocalMachine\Root

**Fortigate设定**

	config system interface
	    edit port1
	        set mode static
	        set ip <你的静态IP> <子网掩码>
	        set allowaccess ping ssh http https
	    next
	end
	
	config route static
	    edit 1
	        set dst 0.0.0.0 0.0.0.0
	        set gateway <网关>
	        set device “port1”
	    next
	end

**APPM 关于SFTP Command Control的关键字**

	_upload 
	_download

**Rocky Linux，搜索其拥有的工具（dnf install），并生成其所有的下载指令**

	echo "#!/bin/bash" > install_packages.sh
	dnf list installed | awk '{print $1}' | grep -v '^Installed' | grep -v '^$' | awk '{print "dnf install -y --allowerasing "$1}' >> install_packages.sh
	chmod +x install_packages.sh


**Rocky Linux，搜索其拥有的python库（pip list），并生成其所有的下载指令**
	
	echo "#!/bin/bash" > install_python_packages.sh
	pip list --format=freeze | awk -F'==' '{print "pip install --no-cache-dir "$1}' >> install_python_packages.sh
	chmod +x install_python_packages.sh


**irass_sshd问题,手动启动irass_sshd，然后就会显示问题了**
	
	#/home/irass/bin/irass_sshd -f /home/irass/conf/sshd_config
	
	If say all key cant load, then check 92 or 31 at /usr/local/libexec and compare file, if missing copy over and give chmod 755. 

**irass自动回放，数据库设置相关**
	select LOGIN_TRANS_SEQ.nextval from dual;
	select AUDIT_TRAIL_SEQ.nextval from dual;
	select LOGIN_EVENTS_SEQ.nextval from dual;
	
	
	select MAX(SEQ) from login_trans;
	select MAX(SEQ) from audit_trail;
	select MAX(SEQ) from login_events;
	
	
	DROP SEQUENCE LOGIN_TRANS_SEQ;
	DROP SEQUENCE AUDIT_TRAIL_SEQ;
	DROP SEQUENCE LOGIN_EVENTS_SEQ;
	
	select count(*) from login_trans;
	select count(*) from audit_trail;
	select count(*) from login_events;
	
	CREATE
	SEQUENCE 
	"APPM"."LOGIN_TRANS_SEQ"  MINVALUE 1 MAXVALUE
	999999999999999999999999999 INCREMENT BY 1 START WITH 1545 NOCACHE  NOORDER 
	NOCYCLE  NOKEEP  NOSCALE 
	GLOBAL ;
	
	CREATE
	SEQUENCE 
	"APPM"."AUDIT_TRAIL_SEQ"  MINVALUE 1 MAXVALUE
	999999999999999999999999999 INCREMENT BY 1 START WITH 1545 NOCACHE  NOORDER 
	NOCYCLE  NOKEEP  NOSCALE 
	GLOBAL ;
	
	CREATE SEQUENCE "APPM"."LOGIN_TRANS_SEQ" MINVALUE 1 MAXVALUE 999999999999999999999999999 INCREMENT BY 1 START WITH 385 NOCACHE NOORDER NOCYCLE NOKEEP NOSCALE GLOBAL;
	
	CREATE SEQUENCE "APPM"."AUDIT_TRAIL_SEQ" MINVALUE 1 MAXVALUE 999999999999999999999999999 INCREMENT BY 1 START WITH 13196 NOCACHE NOORDER NOCYCLE NOKEEP NOSCALE GLOBAL;
	
	CREATE SEQUENCE "APPM"."LOGIN_EVENTS_SEQ" MINVALUE 1 MAXVALUE 999999999999999999999999999 INCREMENT BY 1 START WITH 13196 NOCACHE NOORDER NOCYCLE NOKEEP NOSCALE GLOBAL;

**APPM account使用key来ssh**
	1) Deploy a working key(no password), save into /home/irass/aws, as <hostip>_<useracc>.pem (Private)
	2) Drag this <hostip>_<useracc>.pem (Private) file, drop into web Account > Description.
	  Put <hostip>_<useracc>.pem.pub (Public) to target server .ssh/authorized_keys
	[irass ssh Checking]
	[Connect with ssh key check]
	ssh -i /home/irass/aws/192.168.8.131_michael.pem -F /home/irassgw/conf/ssh_config michael@192.168.8.131 -p 22
	[sshcopyid check]
	Ssh-copy-id -i <dest_ip>_<accountid>.pem  <userid>@<ip>






