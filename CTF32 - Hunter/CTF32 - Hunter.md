## Introduction 

Lien du challenge : https://cyberdefenders.org/blueteam-ctf-challenges/32#nav-walkthroughs 
Ce challenge propose de réaliser l'analyse forensic d'une image disque sur le poste de travail d'un employé ayant lancé des actions de scans, supposément suite au refus de la part du management d'accepter l'augmentation qu'il avait demandé.

Conformément aux consignes, ce guide ne contiendra pas les valeurs des flags mais donnent toutes les clefs pour aller les trouver. 

A noter : les questions 1 à 15 ont été réalisée sans Autopsy mais auraient très bien pu être réalisées grâce à cette suite performante.
### Outils utilisés 

- [FTK Imager](https://www.exterro.com/ftk-imager)
- [RegRipper3.0](https://github.com/keydet89/RegRipper3.0)
- [PECmd](https://ericzimmerman.github.io/#!index.md)
- [DB Browser for SQLite](https://sqlitebrowser.org/dl/)
- [JumpList Explorer](https://ericzimmerman.github.io/#!index.md)
- [Autopsy](https://www.autopsy.com/download/)
### Prise de contexte

Avant de démarrer l'analyse, il est intéressant de récolter du contexte autour de la capture.
Grâce au fichier `Hunter.ad1.txt` nous avons les informations suivantes :
- OS : Windows
- Solution de capture : AccessData® FTK® Imager 4.5.0.3 
- Liste des dossiers contenus dans l'extraction
J'ouvre ensuite le fichier `Hunter.ad1` dans un nouveau case sur [FTK Imager](https://www.exterro.com/ftk-imager) :
![[Introduction.png]]

## Question 1 : What is the computer name of the suspect machine?

Il s'agit typiquement d'une information disponible dans les registres de la machine. 
Pour extraire les registres :
1. Naviguer dans le répertoire `Windows\System32\config`,
2. Exporter les fichiers de registre `SAM`, `SECURITY`, `SOFTWARE` & `SYSTEM`. Ils nous seront utiles pour la suite. (Clic droit --> Export File)
Je les parcours ensuite avec [RegRipper3.0](https://github.com/keydet89/RegRipper3.0) qui me permet d'extraire le contenus de registre dans un fichier txt. Je sais que le nom de machine est stocké dans la clef `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName
Une recherche rapide avec les termes "ComputerName" dans la ruche (hive) `SYSTEM` me permet d'avoir la réponse à la question. 

## Question 2 : What is the computer IP?

Toujours dans le même fichier  `SYSTEM` , une recherche sur le terme "IPAddress" me donne la réponse à la question.

## Question 3 : What was the DHCP LeaseObtainedTime?

Toujours dans le même fichier  `SYSTEM` , une recherche sur le terme "LeaseObtainedTime" me donne la réponse à la question.

## Question 4 :  What is the computer SID? 

Cette valeur peut être trouvée dans la ruche `SAM`. Un petit coup de RegRipper sur le fichier plat pour une extraire le contenu nous donne les SID de tous les utilisateurs.
On voit que les SID on tous le même prefixe. Il n'y a que le suffixe (les trois derniers chiffres qui changent).
Une petite recherche internet nous permet de comprendre comment est constitué le SID : 

S | 1 | 5 | xx-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxx | xx
-- | -- | -- | -- | --
The string is an SID. | The revision level (the version of the SID specification). | The identifier authority value. | The subauthority value. In this case, a domain (21) with a unique 96 bit identifier. There may be more than one subauthority to encode values larger than 32 bits like in this example | A Relative ID (RID). Any group or user that is not created by default will have a Relative ID of 1000 or greater.  

Source : https://en.wikipedia.org/wiki/Relative_identifier

Il suffit donc de prendre les valeurs des 4 premières colonnes du tableau ci dessus pour avoir le résultat.

## Question 5 : What is the Operating System(OS) version?

Direction cette fois-ci dans la ruche `SOFTWARE`. La version de l'OS est supposé se trouver dans la clef de registre `hklm\software\microsoft\windows nt\currentversion`. Ma recherche sur ces termes n'ayant rien donné, j'ai recherché des termes associés aux différentes versions de Windows dans le fichier texte obtenus avec RegRipper. 
J'ai pu trouver la section associée à la commande [winver](https://fr.wikipedia.org/wiki/Winver) avec en prime la bonne version d'OS stockée dans la clef `ProductName` ! 

## Question 6 : What was the computer timezone?

Retour dans notre export de `SYSTEM` ! Une recherche sur le terme "timezone" nous donne le fuseau horaire de la machine. Une simple recherche Google suffit à l'avoir en format UTC+XX (Attention, grâce à la date du bail DHCP obtenue question 3, vous vous éviterez une erreur bête sur l'heure d'hiver ou l'heure d'été).

## Question 7 :  How many times did this user log on to the computer?

Réponse dans l'export de `SAM`. Nous savons que l'utilisateur se nomme `Hunter`. Il suffit de regarder le champs `Login Count`. 

## Question 8 : When was the last login time for the discovered account? Format: one-space between date and time

Réponse dans l'export de `SAM`. Nous savons que l'utilisateur se nomme `Hunter`. Il suffit de regarder le champs `Last Login Date`. 

## Fin de la partie 1 

Au fil de ces 8 questions nous, avons, simplement sur la base des registres, obtenus des informations intéressantes sur le contexte du cas :
- Hostname
- IP
- OS et sa version
- Utilisateurs configurés sur la machine et dernières connexions

Il est très important de ne pas négliger ces éléments lors d'un cas réel qui permettent de mieux contextualiser l'attaque.
En parlant d'attaque, il est temps de rentrer dans le vif du sujet, qu'en pensez vous ?

## Question 9 : There was a “Network Scanner” running on this computer, what was it? And when was the last time the suspect used it? Format: program.exe,YYYY-MM-DD HH:MM:SS UTC

Une recherche initial dans le fichier de registre `SOFTWARE` sur les scanners les plus utilisé du marché m'a permis d'imaginer de quoi il s'agissait.
J'ai ensuite cherché les événements 4688 et 4689 dans le journal Windows `Security.evtx` extrait du répertoire `Windows\System32\winevt\Logs` mais sans succès... la politique de journalisation ne devait pas être activée.
Je m'en suis donc allé voir dans les prefetchs (`Windows\Prefetchs`) qui permettent d'accélérer le chargement des process. Je trouve 2 scanners connus dont l'un des deux correspond avec le pattern du flag. 
L'usage de [PECmd](https://ericzimmerman.github.io/#!index.md) s'est révélé indispensable pour trouver la dernière date d'exécution.
La commande exécutée est la suivante :

```
.\PECmd.exe -f "C:\Path\to\extracted\file.pf"
```

La réponse est donnée dans le champs Last run. Nous savons également combien de fois a été exécuté le scanner. 

## Question 10 : When did the port scan end? (Example: Sat Jan 23 hh:mm:ss 2016)

Replongeons nous un peu dans FTK Imager maintenant que le scanner a été identifié.
Nous observons dans le répertoire de `Hunter` le dossier `.\zenmap`.
Le fichier `recent_scans.txt` fait référence à `C:\Users\Hunter\Desktop\nmapscan.xml`. En ouvrant le .xml dans Visual Studio Code et en le formatant, on trouve le champs  ```<finished timestr="Tue *** ** **:**:** 2016" time="**********"></finished>``` qui contient l'information recherchée.

## Question 11 : How many ports were scanned?

Toujours dans le fichier `C:\Users\Hunter\Desktop\nmapscan.xml`, cette fois ci au début, la clef `numservices` nous indique le nombre de ports scannés.

## Question 12 : What ports were found "open"?(comma-separated, ascending)

Toujours dans le fichier `C:\Users\Hunter\Desktop\nmapscan.xml`, La liste des ports ouverts est indiquée dans le resultat du scan :![[Question_12.png]]

Il suffit de lister ceux "open" pour valider le flag.

## Question 13 : What was the version of the network scanner running on this computer?

Toujours dans le fichier `C:\Users\Hunter\Desktop\nmapscan.xml`, il faut rechercher la clef nmaprun > version pour obtenir la réponse.

## Question 14 : The employee engaged in a Skype conversation with someone. What is the skype username of the other party?

Pour cette question, il faut se replonger dans la capture FTK Imager et un peu plus plonger dans les différents répertoires. 
En lien avec Skype, je trouve tout d'abord un fichier `Account.txt` sur le bureau de notre utilisateur qui contient son propre username Skype. Je garde cela sous le coude pour la suite.
Une recherche internet montre que les historiques Skype sont stockés dans la base de donnée `Users/UserName/AppData/Roaming/Skype/profilename/main.db` que l'on peut exporter depuis `Hunter.ad1`.
Le logiciel [DB Browser for SQLite](https://sqlitebrowser.org/dl/) me permet de parcourir la base de données et ses différentes tables.
![[Question_17.png]]

On identifie rapidement la table Chats qui contient dans la colonne `name` le nom de notre mystérieux interlocuteur. 

## Question 15 : What is the name of the application both parties agreed to use to exfiltrate data and provide remote access for the external attacker in their Skype conversation?

Cette fois-ci, il faut parcourir la table `Chats`. Je l'ai extraite en format CSV pour que ça soit plus simple à explorer et en regardant l'historique de chat, on tombe rapidement sur un outil bien connu des Threat Actors qui est le flag de cette question.

## Question 16 : What is the Gmail email address of the suspect employee?

Bon, le fichier `Account.txt` de la question 14 contenant une adresse gmail qui semblait correspondre mais il ne semble pas s'agir de cela... Je vais donc à la pêche aux informations. Logiquement, on pourrait imaginer que l'utilisateur s'est envoyé des emails depuis sa boite mail professionnelle (qui est très probablement Outlook). 
Outlook stock les historiques de mail dans un fichier PST qui est un format propriétaire de Microsoft. Pour la version d'OS de la machine. Ce fichier est sensé se trouver dans le répertoire `C:\Users\UserName\AppData\Local\Microsoft\Outlook`  qui... n'existe pas ici. Retour à la case départ.

Je pense quand même qu'il s'agit d'un fichier Outlook PST qui contient les éléments. FTK Imager n'ayant de fonction de recherche de fichier, je vais ouvrir l'image sur Autopsy qui est bien plus adapté à du forensic.
Après avoir tenté différentes méthode pour convertie le format AD1 en format utilisable par Autopsy, j'ai finalement monté le disque logique grâce à FTK Imager puis ai ouvert ce disque avec Autopsy. Il existe possiblement des méthodes plus efficaces mais le [plugin Autopsy AD1_Extractor](https://github.com/markmckinnon/Autopsy-Plugins/blob/master/AD1_Extractor/AD1_Extractor.py) supposé ouvrir les AD1 ne fonctionnait pas chez moi et ne renvoyait pas toutes les informations de l'image. 

J'ai donc fait comme ceci :
1. Monter l'image AD1 sur une VM avec FTK Imager (il est fortement déconseillé d'utiliser son OS pour ce genre de chose). Clic droit sur le fichier ad1 -> Image Mounting
2. Dans Autopsy, créer un nouveau case puis choisir en source Logical Drive et le disque ainsi créé.
3. Attendre qu'Autopsy analyse l'intégralité du disque (cela peur prendre plusieurs minutes).

Autopsy extrait ensuite automatiquement les emails trouvés et nous donne la réponse :
![[Question_17_1.png]]

Le fichier `Account.txt` était vraisemblablement légèrement obfusqué par l'utilisateur pour tromper les analystes !

## Question 17 : It looks like the suspect user deleted an important diagram after his conversation with the external attacker. What is the file name of the deleted diagram?

Autopsy est supposé parser les fichiers supprimer mais dans ce cas, cela n'a pas fonctionné :
![[Question_17_2.png]]

Par contre en analysant le contenu du file system, on peut restaurer un dossier de la corbeille contenant 3 fichiers :
![[Question_17_3.png]]
Un de ces fichiers est assez étrange (photo de chat qui semble contenir de l'information obfusquée). Pas de diagramme par contre donc l'information doit se trouver ailleurs.

En reprenant la question et en se concentrant sur le contexte (*conversation with the external attacker*), je reprend les éléments de la boite mail obtenus à la Q16. On remarque que 4 emails sont dans le dossier `\Trash`, Bingo ! L'information se trouve dans un des mails et il s'agit bien d'un diagramme réseau. 

On aurait pu aussi se passer d'Autopsy en trouvant le fichier `/Users/Hunter/Documents/Outlook Files/backup.pst` et en en analysant le contenu. 

## Question 18 : The user Documents' directory contained a PDF file discussing data exfiltration techniques. What is the name of the file?

En naviguant dans le dossier `Documents` et en explorant les différents PDF du dossier, on trouve facilement la réponse.

## Question 19 : What was the name of the Disk Encryption application Installed on the victim system? (two words space separated)

Cette question m'aura quand même un peu fait suer car je n'ai rien trouvé dans les Installed Programs, ni dans la liste des exécutables. Par contre le dossier `Program Files (x86)\.Jetico\BCWipe` m'a mis la puce à l'oreille. 
En effet, Il s'avère que Jetico est une suite offrant des solutions de protection des données. Parmi les softwares promus sur le site aucun ne correspond au pattern du flag. Je décide donc d'éplucher les fichier de ce répertoire.  
Le fichier `UnInstall.log`  est ici intéressant car si le soft a été désinstallé, cela justifie pourquoi il n'apparait pas dans la liste des programmes installés.  
En étudiant le fichier, on finit par trouver le nom de l'application recherchée.

## Question 20 : What are the serial numbers of the two identified USB storage?

Le dossier "USB Device Attached" contient les stockages USB utilisés sur le poste. Deux en particulier : un *Lexar Media* et un *Imation*. Le champs "Device ID" contient les deux numéros de série. 
Les informations sont issues du registre SYSTEM et peuvent aussi être retrouvées avec RegRipper.

## Question 21 : One of the installed applications is a file shredder. What is the name of the application? (two words space separated)

Un peu étrange que cette question arrive après la question 19 car la réponse est plus évidente. Il s'agit bien entendu du logiciel Jetico dont il est question ici. 

## Question 22 : How many prefetch files were discovered on the system?

Bon, cette question m'aura pas mal embêtée mais j'ai finalement trouvé. Après plusieurs méthode différentes, j'ai procédé à un export depuis FTK Imager du dossier `Windows\Preftech` (je ne trouvais pas le bon résultat avec Autopsy...).
Un petit coup de PECmd.exe m'aura permis de trouver la bonne solution : 

```
.\PECmd.exe -d "C:\Path\to\extracted\folder"

...

Processed xxx out of yyy files in z,zzzz seconds
```
La réponse est la valeur de xxx.

## Question 23 : How many times was the file shredder application executed?

On exporte le pretech du programme de shredding. Un coup d'œil rapide nous aiguille vers le fichier `BCWIPE.EXE-36F3F2DF.pf`. 
PECmd est encore une fois la clef pour obtenir le flag :
```
.\PECmd.exe -f "C:\Path\to\extracted\file\BCWIPE.EXE-36F3F2DF.pf"
```

La réponse est donnée dans l'output de la commande.

## Question 24 : How many times was the file shredder application executed?

Je ne comprends pas vraiment l'intérêt de la question dont le sujet a déjà été traitée dans la question 9...

## Question 25 : A JAR file for an offensive traffic manipulation tool was executed. What is the absolute path of the file?

Les fichiers JAR sont de manière plus spécifique des archives. Ca tombe bien, Autopsy nous permet d'extraire l'ensemble des archives de l'image :
![[Question_25.png]] 
En regardant la liste des archives JAR de la machine, un des fichiers doit sauter aux yeux. Le chemins se trouve dans les métadatas données par Autopsy.

## Question 26 : The suspect employee tried to exfiltrate data by sending it as an email attachment. What is the name of the suspected attachment? 

En reprenant les mails, 2 pièces jointes 7zip sortent du lot. On peut identifier la bonne en lisant le contenu des emails.

## Question 27 : Shellbags shows that the employee created a folder to include all the data he will exfiltrate. What is the full path of that folder?

Les Shellbags sont des clés de registre qui contiennent des informations sur les dossiers consultés par l'utilisateur, telles que sa taille, sa position, etc...
![[Question_27.png]]

Le logiciel [ShellBags Explorer](https://ericzimmerman.github.io/#!index.md) d'Eric Zimmerman peut nous aider à trouver la réponse mais j'ai trouvé la réponse sans, juste en explorant le dossier Autopsy.
On trouve un chemin dans lequel manque la dernière lettre de chaque nom de dossier qu'il faut corriger pour trouver le flag.
Pensez bien au nom de fichier de la question précédente ainsi qu'au faite que l'on enquête sur de l'exfiltration. 

## Question 28 : The user deleted two JPG files from the system and moved them to $Recycle-Bin. What is the file name that has the resolution of 1920x1200?

En regardant l'image, on tombe sur une photo modifiée de chat mignon :
![[Question_28_1.png]]

Je me souviens avoir vu en fouillant dans le stockage d'autres photos de chats. En reregardant ces photos, je tombe sur celle là :
![[Question_28_2.png]]
Le nom de ce fichier correspond au flag attendu dans la question.

## Question 29 : Provide the name of the directory where information about jump lists items (created automatically by the system) is stored? 

Une petite recherche internet nous permet de trouver la localisation de ces jump lists et leur nature : Les jump lists sont les menus qui apparaissent lors d'un clic droit sur une icône d'application dans la barre des tâches de Windows. Ils montrent des fichiers récents ou des actions rapides pour cette application spécifique. 
Les AutomaticDestinations et CustomDestinations sont les dossiers utilisés par Windows pour stocker les informations des jump lists.
- Les AutomaticDestinations contiennent des données automatiquement générées par Windows, comme les fichiers récemment utilisés et les actions fréquemment effectuées pour les applications. Ces informations sont générées et gérées par le système d'exploitation.
- Les CustomDestinations, quant à eux, stockent des éléments ajoutés manuellement par l'utilisateur, tels que des épingles personnalisées dans les jump lists. Ils permettent aux utilisateurs de personnaliser ces listes en ajoutant des éléments spécifiques en fonction de leurs besoins.

(Source : ChatGPT)

## Question 30 : Using JUMP LIST analysis, provide the full path of the application with the AppID of "aa28770954eaeaaa" used to bypass network security monitoring controls.

Pour cette question, nous allons utiliser [JumpList Explorer](https://ericzimmerman.github.io/#!index.md). Dans ce cas, contrairement à la question 29, il s'agit des CustomDestination. En ouvrant la jump list dans la GUI, on trouve le chemin de l'application. 
