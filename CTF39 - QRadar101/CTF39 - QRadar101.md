## Introduction 

Lien du challenge : https://cyberdefenders.org/blueteam-ctf-challenges/39#nav-questions

Ce guide est également publié sur Medium : https://medium.com/@martin.bois.23/ctf39-qradar101-03f347002cb5

Ce challenge nous place dans le rôle d'un analyste SOC chargé d'enquêter sur une compromission au sein d'une entreprise financière.
Pour ce faire nous allons prendre en main l'outil QRadar SIEM. je précise qu'il s'agit ici de ma première expérience avec l'outil. Je serai donc volontairement assez exhaustif dans les premières question sur les manipulation de l'outil puis de moins en mois. 
Attention, si vous avez déjà eu des expériences avec des SIEM de 3ème génération (Splunk, ELK), vous allez voir que QRadar semble plus rigide… Il va falloir s’accrocher sur son UX datée et rigide.

Conformément aux consignes, ce guide ne contiendra pas les valeurs des flags mais donnent toutes les clefs pour aller les trouver. 

Pour configurer Qradar, vous pouvez utiliser ce tutoriel mis en ligne par CyberDefenders : https://www.youtube.com/watch?v=4uM4JEhbEjI&ab_channel=CyberDefenders

### Source utiles : 
- https://www.ibm.com/docs/fr/SS42VS_7.4/pdf/b_qradar_aql.pdf
- https://systemweakness.com/list-of-sysmon-event-ids-for-threat-hunting-4250b47cd567
- https://attack.mitre.org/tactics/TA0003/

## Question 1 : How many log sources available?

Une fois le tutoriel réalisé, nous nous trouvons sur la page de recherche de QRadar avec une période de temps définie et des logs bruts :
![[Question_1_1.png]]
On identifie déjà certains paramètres clefs pour exploiter la plateforme et trouver le résultat :
1. Heure de début & Heure de fin : Il faut bien s'assurer de couvrir l'ensemble de la période (qui semble ici tourner sur les quelques jours autour du 10 novembre 2020)
2. Visualiser : Permet d'avoir des statistiques sur les logs étudiées en fonction des champs. La catégorie "Srce Journal" semble correspondre à l'énoncé.
3. Limite des résultats : Nombre e logs bruts remontés par la plateforme. Après modification. Cela ne change pas les valeurs des visualisations qui se font sur l'ensemble des données.
4. Filtres actuels : On voit que trois filtres sont en place pour éliminer des sources de logs. Pour cette question, il faut effacer ces filtres.

Une fois le paramétrage effectuées, on peut correctement visualiser les sources de logs :
![[Question_1_2.png]]

Attention, les graphiques affichent uniquement les top 10 des valeurs. Il faut donc soit les paramétrer pour afficher plus, soit compter le nombre de ligne du dernier tableau. 

## Question 2 : What is the IDS software used to monitor the network?

Pas besoin de relancer une recherche pour cette question. On peut identifier parmi les sources un IDS bien connu de la communauté open source qui tire son nom d'un animal curieux.

## Question 3 : What is the domain name used in the network?

Le nom de domaine est une information facilement trouvable dans les logs de l'Active Directory. Ici indexés dans la source "DC". 
Pour filtrer les logs DC depuis la vue précédente : Clic droit sur la ligne DC puis choisir "Filtrer sur Srce journal correspond à DC". 
Cette vue nous liste l'ensemble des logs AD. 
On observe au premier coup d'œil quelques événements d'authentification Kerberos ([EventID 4769](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4769)) qui contiennent le nom du domaine. Cependant, depuis la vue "Par Défaut" de QRadar, impossible d'avoir plus de détails... 
Pour visualiser l'intégralité d'un log, on peut double cliquer sur ce dernier. Cela nous donne tous les champs parsés par QRadar et qui nous seront potentiellement utiles par la suite. Le domaine s'y trouve bien : 
![[Question_2.png]]

## Question 4 : Multiple IPs were communicating with the malicious server. One of them ends with "20". Provide the full IP.

L'IP finissant en .20 est tout de suite identifiable dans les logs DC. Cependant, pour la retrouver avec la bonne méthode nous pouvons par exemple aller chercher les logs IDS (Filtre : Srce journal correspond à SO-Suricata). 
On remarque tout de suite des requetes depuis l'IP en .20 à destination d'une IP américaine externe sur le port 53 (DNS) qui ont déclenché une signature.

## Question 5 : What is the SID of the most frequent alert rule in the dataset?

le SID (Security IDentifier) fait référence à un identifiant unique associé à chaque règle de détection d'intrusion.
En visualisant les logs IDS, on remarque que le SID n'apparait pas. Pour l'ajouter dans l'output, il faut aller dans "Editer la recherche", section Définition de Colonne et ajouter "RULE SID" dans le tableau Grouper par. Je conseille également d'ajouter le champs "Rule Name" qui est plus parlant.
Une sort du lot avec 72 occurrence :
![[CTF39 - QRadar101/Pictures/Question_5.png]]
## Question 6 : What is the attacker's IP address?

En groupant par IP source, on identifie une IP externe qui est l'IP attaquante.

## Question 7 : The attacker was searching for data belonging to one of the company's projects, can you find the name of the project?

Ayant très peu de logs pour l'IP source de la question précédente, je me suis mis à rechercher de manière plus large sans beaucoup de succès.
Je me suis dit que j'allais tenter le tout pour le tout et chercher tout simplement le mot "project" dans les logs.
QRadar intègre un module "Filtrage rapide" qui ici renvoi une erreur : 
```
Des résultats partiels peuvent être retournés en raison d'index de contenu incomplets pendant l'intervalle spécifié. Pour vous assurer de pouvoir rechercher des enregistrements plus anciens dans le système, supprimez le filtre rapide et utilisez les filtres Le contenu comprend ou Le contenu correspond aux filtres d'expression régulière.
```

J'ai donc utilisé comme spécifié dans le message le filtre "Le contenu contient correspond à project" et trouve en résultat 4 logs de la source "HD-FIN-03". En ouvrant le premier et en regardant le payload, on tombe bien sur le nom du projet dans le nom d'un fichier .XLSX

## Question 8 : What is the IP address of the first infected machine?

Je suis revenu à la vue de la question 6 : Filtrer sur l'IP source identifié. La première machine infectée est la première machine contactée par l'IP source en question.
## Question 9 : What is the username of the infected employee using 192.168.10.15?

Une simple visualisation des noms d'utilisateurs sur 192.168.10.15 (IP source correspond à 192.168.10.15) en utilisant l'index DC nous donne le nom d'utilisateur recherché.
## Question 10 : Hackers do not like logging, what logging was the attacker checking to see if enabled?

En regardant les logs de la machine 192.168.10.15 - HD-FIN-03, on remarque que l'attaquant utilise une console Windows bien connu des pirates et des administrateurs. Il s'agit de la réponse.
Ayant été un peu frustré de ne pas avoir d'élément tangible, j'ai cherché comme savoir si le logging de cet outil était activé. Ayant trouvé deux façon possible, j'ai lancé dans les logs la recherche "Le contenu contient correspond à Logging" qui me permet de tomber sur ce log :

```
<13>Nov 09 01:25:53 DC AgentDevice=WindowsLog	AgentLogFile=Microsoft-Windows-Sysmon/Operational	PluginVersion=7.2.9.105	Source=Microsoft-Windows-Sysmon	Computer=DC.hackdefend.local	OriginatingComputer=192.168.20.20	User=SYSTEM	Domain=NT AUTHORITY	EventID=1	EventIDCode=1	EventType=4	EventCategory=1	RecordNumber=57242	TimeGenerated=1604913950	TimeWritten=1604913950	Level=Informational	Keywords=0x8000000000000000	Task=SysmonTask-SYSMON_CREATE_PROCESS	Opcode=Info	Message=Process Create: RuleName: - UtcTime: 2020-11-09 09:25:50.310 ProcessGuid: {BA754FAD-0B1E-5FA9-60FA-3B0200000000} ProcessId: 2556 Image: C:\Windows\System32\cmd.exe FileVersion: 6.3.9600.16384 (winblue_rtm.130821-1623) Description: Windows Command Processor Product: Microsoft® Windows® Operating System Company: Microsoft Corporation OriginalFileName: Cmd.Exe CommandLine: cmd.exe /Q /c reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging 1> \\127.0.0.1\ADMIN$\__1604913874.5822518 2>&1 CurrentDirectory: C:\ User: HA
```

Cette requête dans le registre montre que l'attaquant à bien cherché à savoir si notre module recherché à le logging d'activé.

A ce point je commence vraiment à me dire que je préfère Splunk et Kibana.
## Question 11 : Name of the second system the attacker targeted to cover up the employee?

En regardant les machines ayant des hits dans les logs IDS on en trouve deux, celle de la question 4 et une autre qui est la machine que nous recherchons.

## Question 12 : When was the first malicious connection to the domain controller (log start time - hh:mm:ss)?

J'ai commencé en cherchant les 4624 sur le Contrôleur de Domaine (192.168.20.20) mais cela ne m'a franchement pas aidé. En élargissant mes recherches, je suis tombé sur l'Event ID 3 qui correspond aux logs SYSMON (et non Windows comme le 4624) désactivé par défaut (https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90003) et correspond à une authentification réseau. 
L'avantage de cet Event ID est que l'EXE à la source du login est présent dans les logs.
On peut donc visualiser l'ensemble des connexion réseau ainsi que le processus source associé :
![[CTF39 - QRadar101/Pictures/Question_12.png]]

On remarque bien vite la présence de notepad.exe qui n'est pas sensé initier de connexion. L'heure du premier logon depuis notepad est notre flag. Attention, il faut une heure écrite sous format 12h et non 24h.

A partir de ce moment, je vais me servir de cette référence pour rechercher sur les différents Event ID Sysmon : https://systemweakness.com/list-of-sysmon-event-ids-for-threat-hunting-4250b47cd567
## Question 13 : What is the md5 hash of the malicious file?

J'ai identifié deux événements qui pourraient nous intéresser : 
- Event ID 11: FileCreate
- Event ID 15: FileCreateStreamHash

le 11 ne contient pas le hash du fichier. Je regarde donc le 15. 
Le premier fait mention d'un fichier ``C:\Users\nour.HACKDEFEND\Downloads\important_instructions.docx`` dont le hash MD5 commence bien par 9. 
![[Question_13.png]]
## Question 14 : What is the MITRE persistence technique ID used by the attacker?

Pour répondre à ce challenge, il faut aller voir les techniques associées à à la persistance [ici](https://attack.mitre.org/tactics/TA0003/). 
Parmi les techniques favorites, il y a l'usage des clefs de registres ou de fichiers dans le dossier de démarrage. Je recherche en particulier des modifications sur les clefs :
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce

Je vais donc vérifier les événements sysmon :
- Event ID 13: RegistryEvent (Value Set)
- Event ID 14: RegistryEvent (Key and Value Rename)

Et bingo, je tombe bien sur une modification de cette clef qui execute le fichier VBS C:\Windows\TEMP\PjvQTe.vbs depuis Powershell au démarrage : ![[Question_14.png]]

Il s'agit bien de la technique MITRE associée au clefs de registre "Run".

## Question 15 :   What protocol is used to perform host discovery?

On peut répondre à cette question avec un peu de logique (protocole commençant par "i" servant pour la reconnaissance, il n'y en a pas beaucoup).

On peut vérifier cela dans les journaux Zeek_conn en groupant sur le champs "Protocole" : 
![[Question_15.png]]
## Question 16 : What is the email service used by the company?(one word)

Comme pour la question précédente. Le résultat se devine avec un peu de culture IT (un fournisseur de service messagerie finissant par 5, il n'y en a pas beaucoup)
Pour le vérifier, j'ai tout d'abord cherché dans les logs Zeek_HTTP mais rien de concluant ici si ce n'est l'absence de requêtes vers des services de messagerie web (gmail par exemple). 
Je me suis donc servi des logs Firewall Zeek_conn relevant du traffic DNS (port 53) où j'ai trouvé mon bonheur en groupant les IP dest en vérifiant celles-ci sur des services comme VirusTotal.
## Question 17 : What is the name of the malicious file used for the initial infection?

Cette question aurait du être juste avant la Question 13 car il s'agit du nom du fichier dont nous avons trouvé le hash.
## Question 18 : What is the name of the new account added by the attacker? 

Une recherche rapide nous indique que l'Event ID de création de compte Windows est le 4720. En filtrant sur cet Event ID dans QRadar, nous obtenons un unique log qui correspond à la création du compte que nous cherchons. 
On peut également le trouver dans l'historique CMD ou ce compte a été ajouté dans le groupe des Administrateurs de Domaine AD : ![[Question_18.png]]
Pour accéder simplement à l'historique CMD, je recommande un filtre sur l'Event ID 1: Process Creation, de filtrer sur Image contient cmd et d'ajouter dans la vue le champs "Process CommandLine"
## Question 19 : What is the PID of the process that performed injection?

Nous allons cette fois ci regarder dans les Event ID Sysmon. La description de l'Event ID 8 : *CreateRemoteThread* indique que "*This technique is used by malware to inject code and hide in other processes*".
Sur les 11 resultats obtenus, un doit sortir du lot avec une TargetImage égale à  ``C:\Windows\SysWOW64\notepad.exe``. Le SourceProcessId est présent dans les détails du log :
![[Question_19.png]]
## Question 20 : What is the name of the tool used for lateral movement?

Après plusieurs recherches, j'ai pu exclure :
- **Event ID 1**: Process creation sur Powershell
- **Event ID 3**: Network connection
- **Event ID 17**: PipeEvent (Pipe Created) & Event ID 18: PipeEvent (Pipe Connected)

Je pense que sans l'indice (ou bien une expérience RedTeam préalable), il est très difficile de répondre à cette question.
L'indice indique qu'il s'agit d'un outil de la suite [impacket](https://github.com/fortra/impacket/tree/master) (une des nombreuses suites open-source pour effectuer des manipulation réseau).
En fouillant un peu, un fini par trouver dans le sous répertoire /example/ un script permettant d'exploiter l'interface de management Windows (WMI) qui est notre flag.
J'ai ensuite pu trouver sur [cet article de CrowdStrike](https://www.crowdstrike.com/blog/how-to-detect-and-prevent-impackets-wmiexec/) des commandes similaires à ce que l'on a observé dans nos logs :
![[Question_20.png]]
## Question 21 : Attacker exfiltrated one file, what is the name of the tool used for exfiltration?

En étudiant l'historique CMD, on tombe sur cette ligne avec la commande d'exfiltration du document sami.xlsx : 
![[Question_21.png]]
Il s'agit d'un outil bien connu des attaquants pour exfiltrer de l'information.

## Question 22 : Who is the other legitimate domain admin other than the administrator?

Cette information peut être retrouvée en analysant les [Event ID 4672 : privilèges spéciaux attribués à la nouvelle ouverture de session](https://learn.microsoft.com/fr-fr/windows/security/threat-protection/auditing/event-4672) qui est déclenché dans le cadre d'une authentification d'un compte Administrateur de Domaine entre autres.
En groupant par AccountName, deux comptes sortent du lot : celui de la question18 et le compte Administrateur de Domaine légitime :
![[Question_22.png]]

## Question 23 : The attacker used the host discovery technique to know how many hosts available in a certain network, what is the network the hacker scanned from the host IP 1 to 30?

En reprenant les information de scan de la question 9, on peut identifier le scope vers lequel l'IP malveillante effectue son scan.

## Question 24 : What is the name of the employee who hired the attacker?

Cette question se répond par déduction en fonction de l'indice et du fichier exfiltré à la question 21. C'est purement de la déduction sans preuve formelle.