## Introduction 

Lien du challenge : https://cyberdefenders.org/blueteam-ctf-challenges/68#nav-questions
Ce challenge nous met dans la peau d'un analyste SOC qui doit analyser une capture réseau pour identifier une compromission.

Conformément aux consignes, ce guide ne contiendra pas les valeurs des flags mais donnent toutes les clefs pour aller les trouver. 
### Outils utilisés 

- [Brim Security](https://www.brimdata.io/download/)
- [Wireshark](https://www.wireshark.org/download.html)
- [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [CyberChef](https://gchq.github.io/CyberChef/)
### Sources utiles 
- https://www.wireshark.org/docs/dfref/h/http.html
- https://tho-le.medium.com/techniques-and-tools-for-shellcode-analysis-9a49a1e15b2f
## Question 1 : Multiple systems were targeted. Provide the IP address of the highest one.

En étudiant le fichier avec BrimSecurity, on voit plusieurs protocoles utilisés (recherche `count() by _path`) : 
![[CTF44 - NukeTheBrowser/Pictures/Question_1.png]]
 Ce qui va nous intéresser ici sera les requêtes http (le challenge s'appelle NukeTheBrowser !) et pour cette question les IP sources dont le navigateur va surement se comporter de manière étrange. En faisant un filtre sur les IP sources, j'en trouve 4. 
 La réponse est bien la plus grande des 4 et non pas celle sur laquelle on aura vu le plus d'événements, la question peut porter à confusion.
## Question 2 : What protocol do you think the attack was carried over?

Si la question précédente ainsi que le contexte du challenge ont bien été compris, la réponse tombe sous le sens. Il s'agit d'un protocole web non chiffré bien connu.
## Question 3 : What was the URL for the page used to serve malicious executables (don't include URL parameters)?

Dans BrimSecurity, en étudiant un peu les logs http, on regarde un domaine étrange : `sploitme.com.cn`. Un champs resp_filenames indique quand l'url du log a permis de télécharger un fichier. 
On peut identifier un fichier `video.exe` téléchargé systématiquement depuis la même adresse qui est notre flag. 
J'ai également trouvé l'information dans NetworkMiner, dans l'onglet "Files".

## Question 4 : What is the number of the packet that includes a redirect to the french version of Google and probably is an indicator for Geo-based targeting?

La réponse attendue étant un numéro de paquet, nous allons devoir utiliser Wireshark. Une ressource utile est la liste des filtres disponibles pour le protocole http : https://www.wireshark.org/docs/dfref/h/http.html
Nous recherchons ici une redirection, qui correspond au HTTP Event Code 302 pour les redirections standards.
En cherchant dans Wireshark `http.response.code == 302`, on obtient 5 résultats dont celui que nous recherchons. 
J'ai optimisé la recherche en lui ajoutant un paramètre afin d'identifier le paquet recherché : `http.location contains "google.fr" && http.response.code == 302`. Son numéro correspond au flag.

## Question 5 : What was the CMS used to generate the page 'shop.honeynet.sg/catalog/'? (Three words, space in between) 

La recherche Wireshark `http.host contains "shop.honeynet"` permet d'obtenir la liste des échanges http avec le domaine. En faisait Clic droit > Suivre > HTTP Stream, on obtient le code source HTML de la page. La réponse est écrite dedans. 
Pour plus de facilité, j'ai utilisé VisualStudio Code pour analyser le HTML.

Attention, le challenge attend le nom précis du module et non pas le nom de l'éditeur qui est inscrit en bas du HTML, il faut chercher un peu dans le code source :
![[CTF44 - NukeTheBrowser/Pictures/Question_5.png]]

## Question 6 : What is the number of the packet that indicates that 'show.php' will not try to infect the same host twice?

Logiquement, si ce mécanisme est en place, on devrait avoir une requête vers cette page en échec pour un host déjà infecté.
J'ai trouvé la réponse dans Wireshark en identifiant une requête GET vers la page `/fg/show.php` qui renvoyait un code 200 dans le protocole HTTP et 404 écrit dans la réponse :
![[Question_6.png]]
En cliquant dessus, j'ai pu trouver le numéro du paquet concerné. 

## Question 7 :  One of the exploits being served targets a vulnerability in "msdds.dll". Provide the corresponding CVE number.

La méthode la plus simple est tout simplement de rechercher les CVE impactant le module sur Google et de les tenter pour identifier le flag.
Par chance la première fonctionne... 

## Question 8 : What is the name of the executable being served via 'http://sploitme.com.cn/fg/load.php?e=8' ?

On reprend le code javascript de la question précédent (voir fichier bad.js) 
J'ai remplacé la fonction eval par la fonction console.log pour pouvoir afficher le code désobfusqué dans un compilateur en ligne (celui là : https://onecompiler.com/javascript/) (voir fichier bad-2.js). 

le code comprend plusieurs shellcodes différents que l'on peut copier et extraire avec cyberchef. Une des composantes importantes de l'extraction est d'effectuer un "swap endianness" dans CyberChef puis une conversion depuis l'hexadécimal :

![[Question_8.png]]

On remarque à la fin du shellcode une url sploitme.com.cn. On peut jouer avec la valeur de "Word Length" pour trouver le bon code à reverser. 

On peut ensuite sauvegarder les shellcodes extraits avec Cyberchef en utilisant la fonction sauvegarder de l'outil. j'utilise cela car le copier coller ne permet pas d'utiliser le résultat.

Je me retrouve avec 4 fichiers .dat disponibles dans le répertoire "Code_extraction".

Allons les analyser dans l'outil 

## Question 10 : What is the name of the function that hosted the shellcode relevant to 'http://sploitme.com.cn/fg/load.php?e=3'?

Challenge résolu en travaillant sur la question 8.? En effet en analysant les différent codes dans CyberCHef, j'ai identifié la fonction liée aà "load.php?e=3".