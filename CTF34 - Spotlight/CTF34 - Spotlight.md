## Introduction 

Lien du challenge : https://cyberdefenders.org/blueteam-ctf-challenges/34#nav-questions
Ce challenge propose de réaliser l'analyse forensic d'une image disque MacOS.

Conformément aux consignes, ce guide ne contiendra pas les valeurs des flags mais donnent toutes les clefs pour aller les trouver. 
### Outils utilisés 

- [FTK Imager](https://www.exterro.com/ftk-imager)
- [Autopsy](https://www.autopsy.com/download/)
- [DB Browser for SQLite](https://sqlitebrowser.org/)
- [mac_apt](https://github.com/ydkhatri/mac_apt)
- [steghide](http://steghide.sourceforge.net/)
### Sources utiles 

- https://davidkoepi.wordpress.com/2013/07/06/macforensics4/
- https://www.swiftforensics.com/2018/02/reading-notes-database-on-macos.html
### Configuration du challenge

Le challenge met à disposition un fichier AT1 qui est le format propriétaire de FTK Imager pour les captures. Ce format n'est nativement pas analysable par Autopsy. Il est cependant possible de réaliser une analyse en suivant ces étapes :
1. Depuis FTK Imager, monter l'image AT1 sur une VM (ou son poste mais cela est déconseillé).
2. Depuis Autopsy, créer un nouveau case et ajouter en nouvelle source les "Logical Files" du disque monté.

## Question 1 : What version of macOS is running on this image?

Depuis Autopsy, naviguer dans le fichier `/System/Library/CoreServices/SystemVersion.plist`. La valeur de `<key>ProductVersion</key>` contient la réponse.

## Question 2 : What "competitive advantage" did Hansel lie about in the file AnotherExample.jpg? (two words)

Le fichier n'est pas très compliqué à retrouver, soit en naviguant dans le dossier `root/Users/Shared/`, soit directement en le recherchant dans la liste des images trouvées par Autopsy :

![[Question_2_1.png]]

Là où la question est assez fourbe est dans le fait que rien ne saute aux yeux sur l'image. J'avoue avoir essayé quelques combinaisons à tout hasard (free phone, fast phone....) mais ça ne fonctionnait pas. 
C'est là où l'explorateur Autopsy va être intéressant. En effet, je peux rapidement accéder à la retranscription textuelle de l'image et trouver le flag tout en bas :
![[Question_2_2.png]]
(Ca semble facile comme ça, mais il faut y penser.)

Le flag se trouve également dans le fichier `secret` du même répertoire.

## Question 3 : How many bookmarks are registered in safari?

Là encore, deux manières :
1. Se faire mâcher le travail par Autopsy qui extrait automatiquement les favoris dans les "Data Artifacts"
2. Aller jeter un coup d'oeil dans `/root/Users/hansel.apricot/Library/Safari/Bookmarks.plist` et compter le nombre de `WebBookmarkUUID` car il est toujours important de savoir d'où les logiciel d'automatisation tirent leurs informations.
## Question 4 : What's the content of the note titled "Passwords"? 

Même s'il est très facile de deviner le flag avec l'indice donné dans la case de réponse. C'est intéressant d'aller chercher la note par nous même.
Une recherche rapide sur Google nous indique d'aller chercher la base SQL des Notes MacOS. Il s'agit du fichier ``root/Users/hansel.apricot/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite``. 
[Cet article](https://www.swiftforensics.com/2018/02/reading-notes-database-on-macos.html)m'aura été très utile pour la suite des opérations. 

En effet, le contenus des notes est stocké en format GZIP. Il faut donc extraire le fichier en format BIN depuis DB Browser for SQLite puis le décompresser. 

Pour obtenir le contenus de la note :
1. Ouvrir le fichier dans DB Browser for SQLite
2. Identifier dans la table `ZICCLOUDSYNCINGOBJECT` le `Z_NOTEDATA` de la note ayant pour `ZTITLE1` "Passwords". Ici c'est 4.
3. Dans la table `ZICNOTEDATA`, extraire le champs `ZDATA` de la ligne `Z_PK` 4 en format BIN.
4. Décompresser le fichier BIN ainsi obtenus pour avoir la note et le flag.
## Question 5 : Provide the MAC address of the ethernet adapter for this machine.

Cette fois ci, je me serais aidé de [cet article](https://davidkoepi.wordpress.com/2013/07/06/macforensics4/) là.
Le fichier `/root/private/var/log/daily.out` contient les éléments relatifs au statut des interfaces réseau. 
## Question 6 : Name the data URL of the quarantined item.

La base de donnée de la quarantaine sur MacOS se trouve dans le sous répertoire utilisateur `/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 `. Cette fois ci, la quarantaine ne se trouvait pas dans le dossier utilisateur de `hansel.apricot` mais de l'utilisateur `sneaky` qui, à la vue de son user name, ne semble pas effectuer que des activités de bureautique... 
Le fichier de quarantaine ne comprend qu'une entrée qui est le flag que nous recherchons ici.

**Pro-hint** : Si comme moi, vous n'arrivez pas à trouver ce qui est devant vos yeux, vous pouvez lancer avec Autopsy un rapport qui va extraire dans un fichier texte plat l'ensemble noms de fichier et leur arborescence. Un petit Ctrl+F et le tour est joué !
## Question 7 : What app did the user "sneaky" try to install via a .dmg file? (one word)

Autant utiliser le rapport extrait précédemment pour trouver le fichier.  Ctrl+F sur ".dmg" nous permet de trouver immédiatement la réponse. 
## Question 8 : What was the file 'Examplesteg.jpg' renamed to? 

Autant il est très facile de deviner la réponse via l'indice donné, autant, trouver la réponse de manière légitime s'est avéré pour moi plus compliqué que prévu.
la réponse doit se trouver dans un des fichiers de la base fseventsd (`root/fseventsd/`). J'ai perdu beaucoup de temps à essayer de faire marcher le plugin [MacFSEvents](https://github.com/sleuthkit/autopsy_addon_modules/tree/master/IngestModules/MacFSEvents) sans succès. J'espère que ce plugin fonctionne avec des fichiers DMP plus traditionnels que notre import AD1.
Des recherches sur la chaine "Examplesteg.jpg" ne renvoyait pas non plus de résultats intéressants.

J'ai donc décidé de tenter ma chance avec [mac_apt](https://github.com/ydkhatri/mac_apt/wiki/Installation-for-Python3). Après une installation calamiteuse et non fonctionnelle sur Windows, je me suis finalement dirigé vers ma VM SIFT Linux (que je conseille à tous) sur laquelle l'installation aura été  beaucoup plus rapide.

J'ai extrait uniquement le dossier `/fseventsd/` sur lequel j'ai fait tourner la commande :

```
$ python3 mac_apt_artifact_only.py -i /path/to/folder/fseventsd/ -o /path/to/output/ FSEVENTS
```

Le résultat est une base de données SQLite nous permet d'identifier l'id du fichier :
![[Question_8_1.png]]
Une recherche sur l'id nous permet de trouver le fichier et son nouveau nom :
![[Question_8_2.png]]

## Question 9 : How much time was spent on mail.zoho.com on 4/20/2020?

Pour celle-ci, la méthode à utiliser est la fonction SCREENTIME de mac_apt

N'ayant pas trouvé beaucoup d'info la localisation de cette base sur Internet, je reprend mon export TXT de l'arborescence utilisé question 6. Une petite recherche sur le terme "screentime" nous permet d'identifier un répertoire intéressant contenant un fichier sqlite  `/root/private/var/folders/bf/r04p_gb17xxg37r9ksq855mh0000gn/0/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite` :
![[Question_9_1.png]]
Cette base contient beaucoup de tables et n'est pas exploitable en l'état dans DB Browser for SQLite. J'ai donc procédé à son extraction et ai effectué la fonction suivante avec mac_apt :

```
$ python3 mac_apt_artifact_only.py -i /path/to/file/RMAdminStore-Local.sqlite -o /path/to/output/ SCREENTIME
```

mac_apt nous extrait une belle base de donnée, cette fois-ci parfaitement navigable dans DB Browser for SQLite avec les infos que l'on recherche :
![[Question_9_2.png]]

## Question 10 : What's hansel.apricot's password hint? (two words)

Encore une fois, je ressort le [précieux article](https://davidkoepi.wordpress.com/2013/07/06/macforensics4/) de David Koepi qui indique que l'indice du mot de passe se trouve dans ce répertoire : `/private/var/db/dslocal/nodes/[user].plist`. Dans notre cas, le fichier se trouve ailleurs : `private/var/db/dslocal/nodes/Default/users/hansel.apricot.plist`  mais l'article nous met bien sur la voie. 
Le champ `hint` du fichier contient le flag.
## Question 11 : The main file that stores Hansel's iMessages had a few permissions changes. How many times did the permissions change?

Les chats IMessage sont stockés dans la base ``chat.db`` pour chaque utilisateur. Cette base est localisée dans le répertoire ``/root/Users/[UserName]/Library/Messages/chat.db``.
On se rend vite compte que le répertoire n'existe pas sur notre capture.
C'est là que nos connaissances acquises question 8 vont nous être utiles. 
On se doute bien qu'Hansel a essayé de camoufler ses traces et à donc du supprimer le fichier.
Une petite recherche dans la base `/.fseventsd` extraite avec mac_apt nous le confirme bien car nous voyons bien des opérations sur le fichier :  
![[Question_11.png]]

Il suffit de compter le nombre d'EventFlags "PermissionChange" pour trouver la solution. Par contre, je ne comprend pas pourquoi on n'a pas d'EventFlags "Removed" pour ce fichier ou même le dossier parent…

## Question 12 : What's the UID of the user who is responsible for connecting mobile devices? 

J'avoue y être allé un peu au culot pour celle là. 
Comme vu question 10, chaque utilisateur (humain ou machine) a un fichier PLIST dans le répertoire `private/var/db/dslocal/nodes/Default/users/.
En regardant un peu ce qui pouvait marcher (et après quelques échecs), je suis finalement tombé sur l'utilisateur en question (indice : il y a usb dans son nom). Une fois trouvé, il suffit d'entrer la valeur de la clef "UID" pour valider la question
## Question 13 : Find the flag in the GoodExample.jpg image. It's hidden with better tools.

Le challenge nous prend par la main pour cette question. Le fichier se trouve dans le dossier `root/Users/Shared/`. Dans l'onglet Details du challenge, il y a un lien vers l'outil [steghide](http://steghide.sourceforge.net/). A partir de là, il suffit de dérouler le readme.txt de l'outil :

```
.\steghide.exe extract -sf "C:\Users\Martin\Documents\Challenges Cyber\c18-Sptolight\Spotlight\Export\GoodExample.jpg"
Entrez la passphrase:
écriture des données extraites dans "steganopayload27635.txt".
```

Quid du mot de passe ? J'ai tenté plusieurs choses :
- Le contenu du fichier `secret` identifié question 2 
- le contenu de la note "Passwords" identifié question 4. 
Il s'avère qu'Hansel n'est finalement pas très malin car il ne s'est même pas donné la peine de donner un mot de passe lors de l'encodage des données. Il faut donc laisser la passphrase vide. 
## Question 14 : What was exactly typed in the Spotlight search bar on 4/20/2020 02:09:48

Retour dans mon fichier texte pour chercher ce que je trouve autour de Spotlight. J'identifie le dossier `/root/Users/sneaky/Library/Application Support/com.apple.spotlight/`. En regardant un peu les différents fichiers, j'identifie `com.apple.spotlight.Shortcuts` qui contient la réponse.

## Question 15 : What is hansel.apricot's Open Directory user UUID?

Retour dans le fichier `private/var/db/dslocal/nodes/Default/users/hansel.apricot.plist` qui nous donne immédiatement la réponse. 