## Introduction 

Lien du challenge : https://cyberdefenders.org/blueteam-ctf-challenges/68#nav-questions
Ce challenge nous met dans la peau d'un analyste SOC qui doit analyser une capture réseau pour identifier un potentiel insider.

Conformément aux consignes, ce guide ne contiendra pas les valeurs des flags mais donnent toutes les clefs pour aller les trouver. 
### Outils utilisés 

- [Brim Security](https://www.brimdata.io/download/)
- [Wireshark](https://www.wireshark.org/download.html)
- [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
### Prise de contexte

Grâce à Brim Security, nous allons pouvoir avoir rapidement quelques statistiques sur le PCAP : 
```
fuse | count() by _path
```
![[Introduction_1.png]]

Au niveau des échanges files :
```
_path=="files" | count() by filename
```
![[Introduction_2.png]]

Au niveau des échanges http :

```
_path=="http" | count() by host
```
![[Introduction_3.png]]

Au niveau DNS :
```
 _path=="dns" | count() by query | sort -r count
```
![[Introduction_4.png]]
--> On identifie déjà quelques requêtes étranges...

Pour utiliser NetworkMiner, il faut convertir le fichier PCAPNG en format PCAP qui est compatible avec la version gratuite de NetworkMiner.
Pour ce faire : 
- Ouvrez Wireshark.
- Allez dans "Fichier" > "Ouvrir" et sélectionnez votre fichier `.pcapng`.
- Une fois le fichier ouvert, allez dans "Fichier" > "Exporter les paquets spécifiés".
- Dans le menu déroulant "Enregistrer en tant que type", choisissez "Libpcap (*.pcap)" comme format de sortie.
- Entrez un nom de fichier et un emplacement pour le fichier `.pcap` converti.
- Cliquez sur "Enregistrer" pour convertir et sauvegarder le fichier au format `.pcap`.
(merci ChatGPT)

NetworkMiner va pouvoir nous extraire de nombreux artefacts pour la suite du challenge.
## Question 1 :  What is the FTP password?

Grâce à NetworkMiner nous allons pouvoir facilement répondre à ce challenge en allant dans l'onglet "Credentials" : 
![[Question_1.png]]
## Question 2 : What is the IPv6 address of the DNS server used by 192.168.1.26? (####::####:####:####:####)

Toujours sur NetworkMiner, nous pouvons identifier les session DNS dans l'onglet DNS :
![[CTF68 - PacketMaze/Pictures/Question_2_1.png]]

En cherchant l'IP 192.168.1.10 dans l'onglet "Hosts" et en étendant l'onglet "MAC: CA0BADAD20BA", on identifie l'IPv6 recherchée.
Il s'agit également de la seule IPv6 recevant des requêtes DNS donc logiquement c'est celle-ci.

## Question 3 : What domain is the user looking up in packet 15174?

La question se résout en allant voir le paquet en question dans Wireshark, bête comme chou. 
## Question 4 : How many UDP packets were sent from 192.168.1.26 to 24.39.217.246?

Cette recherche Wireshark permet de trouver la réponse :
```
ip.src == 192.168.1.26 && ip.dst == 24.39.217.246 && udp
```
Le nombre de paquets est affichés en bas de la fenêtre.
## Question 5 : What is the MAC address of the system being investigated in the PCAP?”

L'adresse IP investiguée est la 192.168.1.26. Si l'on en est pas convaincu, il est possible de générer un rapport depuis Wireshark : Statistiques > IPv4 Statistics > All Addresses :
![[Question_5.png]]
Dans l'onglet "Hosts" de NetworkMiner, on peut voir l'adresse MAC du poste.

## Question 6 : What was the camera model name used to take picture 20210429_152157.jpg ?

1. Dans NetworkMiner, naviguer dans l'onglet "Images". Il y a en a 2 dont une correspond.
2. Ouvrir l'image avec n'importe quelle galerie permettant d'afficher les information EXIF. J'utilise de mon côté la galerié Windows, comme ça, rien à installer.
3. Accéder aux informations qui contiennent le modèle de caméra.

## Question 7 : What is the server certificate public key that was used in TLS session: da4a0000342e4b73459d7360b4bea971cc303ac18d2

En épluchant la [documentation Wireshark TLS](https://www.wireshark.org/docs/dfref/t/tls.html) à la recherche de filtre utile pour rechercher un id de session, j'ai identifié ce champs : `tls.handshake.session_id`.
La recherche Wireshark à effectuer est donc : 
```
tls.handshake.session_id == da4a0000342e4b73459d7360b4bea971cc303ac18d2
```

Un unique paquet correspond aux critère dans la recherche et la clef publique du certificat est écrite dans la clef `Transport Layer Protocol > TLSv1.2 Record Layer: Handshake Protocol: Multiple Handshake Messages > HandshakeProtocol: Server Key Exchange > EC Diffie-Hellman Server Params > Pubkey`.

## Question 8 : What is the first TLS 1.3 client random that was used to establish a connection with protonmail.com?

Toujours dans la  [documentation Wireshark TLS](https://www.wireshark.org/docs/dfref/t/tls.html), le champs tls.handshake.extensions_server_name semble intéressant. 
La recherche Wireshark à effectuer est donc : 
```
tls.handshake.extensions_server_name == "protonmail.com"
```

Cette fois ci, le flag correspond à la valeur de la clef `Transport Layer Protocol > TLSv1.3 Record Layer: Handshake Protocol: Client Hello > HandshakeProtocol: Client Hello > Random`.

## Question 9 : What country is the MAC address of the FTP server registered in? (two words, one space in between)

L'IP du server FTP est 192.168.1.20. Cela est facilement visualisable dans BrimSecurity ou WireShark.
Dans NetworkMiner, on trouve la MAC associée (MAC: 080027A61F86).
Un petit tour sur des moteurs de recherche de plage MAC tels que [MAC Address Data Feed](https://mac-address.alldatafeeds.com/mac-address-lookup/v2YPO6oERb)nous permet de trouver la réponse (champs Country Code).

## Question 10 : What time was a non-standard folder created on the FTP server on the 20th of April? (hh:mm) 

Retour dans Wireshark pour cette question qui nécessite un peu de se creuser les méninges. 
En analysant un peu les échanges entre la machine source (192.168.1.26) et le serveur FTP (192.168.1.20) avec la recherche adéquate (`ip.addr == "192.168.1.20"`) par exemple on peut trouver la réponse. Il suffit de faire Clic droit > Suivre > TCP stream et de naviguer dans les échange pour trouver un dossier étrange à un moment où l'arborescence est communiquée :
![[Question_10.png]]
## Question 11 : What domain was the user connected to in packet 27300?

On remarque assez vite que l'échange 27300 est un échange TCP vers l'IP "172.67.162.206". S'agissant d'une IP privée, un petit coup de nslookup ne suffira pas. Par contre dans NetworkMiner, le nom de domaine associé à cette IP est correctement identifié (onglet "Hosts", toujours). Il s'agit du flag.
Cette information provient des échanges DNS. 