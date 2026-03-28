Equipe 2: Lenny Sabine, Marwa Dadjo, Ludivine Bonnafous, Maël Damour, Mathis Fontanié

Les dossiers "build" et "obj" sont nécessaires au bon fonctionnement du projet.
Merci de les créer s'ils ne le sont pas déjà.
Vous aurez aussi besoin des librairies gmp, python3-pip et python3-flask.

Pour executer les tests des phases 1 et 2 positionnez vous à la racine du projet puis:
-"make phase[1 ou 2]"
-"./build/phase[1 ou 2]_test"

Pour l'interprète:
-"make phase3"
-"./build/phase3"

"make clean" permet de supprimer tous les fichiers créés par la commande make.

Pour l'application Python positionnez vous dans le répertoire "python_blockchain_app-master" puis
utilisez la commande "pip3 install -r requirements.txt" pour installer le nécessaire à l'utilisation
de l'application. 

Pour executer les tests des évènements, ouvrez 2 terminaux et positionnez vous dans le répertoire
de l'application puis executez dans le premier: 
-"export FLASK_APP=node_server.py"
-"flask run --port 8000"

Dans le second:
-"python3 test.py"


