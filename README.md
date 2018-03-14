#### Sécurité des réseaux sans fil 2018
# Laboratoire 802.11 MAC

`Iando Rafidimalala Thévoz` & `Yosra Harbaoui`

#### 1. Détecter si un ou plusieurs clients 802.11 spécifiques sont à
Voir fichier `xxx.py`
Le script se lance comme suit :  
`./monitorOn.sh`  
`cd [dossier_ou_se_trouve_sniffingMacSta.py]`  
`python sniffingMacSta.py [MAC_Addess]`
###### * Qestion 1: quel type de trames sont nécessaires pour détecter les clients de manière passive ?
Les `prob rquest` sont les trames envoyées par les clients pour demander des informations, soit à l'AP (spécifié par SSID), soit à tous les APs disponibles (spécifiés avec le broadcast SSID).  
###### * Qestion 2: pourquoi le suivi n’est-il plus possible sur iPhone depuis iOS 8 ?

A partir de la version 8 de l'IOS, iPhone utilise la `MAC randomization`. En effet, ce processus cache la MAC réelle du dispositif en envoyant des adresses MAC d'une manière aléatoire. La création de l'adresse MAC se fait localement par l'OS. Le but est que l'iphone ne peut pas être tracké tant qu'il n'est pas connecté à un AP.   


#### 2. Clients WiFi bavards
Voir fichier `xxx.py`
Le script se lance comme suit :  
`./monitorOn.sh`  
`cd [dossier_ou_se_trouve_xxx.py]`  
`python xxx.py`
