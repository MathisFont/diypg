#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <phase1.h>
#include <phase2.h>
#include <rsa_common_header.h>
#include <stdint.h>

#define MAX_KEYS 100       // Nombre maximum de clés stockables
#define MAX_CONTACTS 100   // Nombre maximum de contacts stockables

// Types et structures de données
typedef enum {
    SIGNATURE,      // Clé utilisée pour la signature
    ENCRYPTION      // Clé utilisée pour le chiffrement
} KeyType;

// Structure représentant une clé RSA avec son type
typedef struct {
    int id;                // Identifiant unique de la clé
    KeyType type;         // Type de la clé (SIGNATURE ou ENCRYPTION)
    keyPair_t key_pair;   // Paire de clés RSA (publique/privée)
} Key;

// Structure représentant un contact
typedef struct {
    int id;               // Identifiant unique du contact
    KeyType type;        // Type par défaut des clés du contact
    char* name;          // Nom du contact
    char* first_name;    // Prénom du contact
    char* comment;       // Commentaire/description
    Key* keys;          // Tableau des clés associées au contact
    int key_count;      // Nombre de clés du contact
} Contact;

// Variables globales pour le stockage
Key keys[MAX_KEYS];            // Tableau des clés
int key_count = 0;            // Nombre de clés stockées
Contact contacts[MAX_CONTACTS]; // Tableau des contacts
int contact_count = 0;        // Nombre de contacts stockés

// Clés par défaut utilisées pour la sauvegarde/chargement
const rsaKey_t public_key = { .N = 33, .E = 3 };
const rsaKey_t private_key = { .N = 33, .E = 7 };
const keyPair_t key_pair = { .pubKey = public_key, .privKey = private_key };


/**
 * Recherche l'index d'un contact dans le tableau de contacts
 * @param contact_id Identifiant du contact à rechercher
 * @return Index du contact dans le tableau, -1 si non trouvé
 */
int find_contact_index(const int contact_id) {
    for (int i = 0; i < contact_count; i++) {
        if (contacts[i].id == contact_id) {
            return i;
        }
    }
    return -1;
}

/**
 * Recherche l'index d'un contact par son nom
 * @param name Nom du contact à rechercher
 * @return Index du contact dans le tableau, -1 si non trouvé
 */
int find_contact_by_name(const char* name) {
    for (int i = 0; i < contact_count; i++) {
        if (strcmp(contacts[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

/**
 * Recherche l'index d'une clé dans le tableau de clés
 * @param key_id Identifiant de la clé à rechercher
 * @return Index de la clé dans le tableau, -1 si non trouvée
 */
int find_key_index(const int key_id) {
    for (int i = 0; i < key_count; i++) {
        if (keys[i].id == key_id) {
            return i;
        }
    }
    return -1;
}

/**
 * Affiche la liste des clés stockées dans le système
 * @param key_id Identifiant spécifique à afficher, -1 pour toutes les clés
 */
void list_keys(const int key_id) {
    if (key_id == -1) {
        printf("Key List:\n");
        for (int i = 0; i < key_count; i++) {
            printf("- %d [%d]\n", keys[i].id, keys[i].type);
        }
    } else {
        for (int i = 0; i < key_count; i++) {
            if (keys[i].id == key_id) {
                printf("- %d [%d]\n", keys[i].id, keys[i].type);
            }
        }
    }
}

/**
 * Supprime une clé du système
 * @param key_id Identifiant de la clé à supprimer
 * Décale les clés restantes pour combler le trou
 */
void remove_keys(const int key_id) {
    int key_index = find_key_index(key_id);
    if (key_index == -1) {
        fprintf(stderr, "Error: The key wasn't found.\n");
        return;
    }

    for (int i = key_index; i < key_count - 1; i++) {
        keys[i] = keys[i+1];
    }
    key_count--;
}

void new_keys(const int key_id, const KeyType key_type) {
    if (key_count >= MAX_KEYS) {
        fprintf(stderr, "Error: Maximum number of keys reached.\n");
        return;
    }

    if (find_key_index(key_id) != -1) {
        fprintf(stderr, "Error: The key already exists.\n");
        return;
    }

    keys[key_count].id = key_id;
    keys[key_count].type = key_type;
    
    keyPair_t key_pair;
    genKeysRabin(&key_pair.pubKey, &key_pair.privKey, MAX_PRIME);
    keys[key_count].key_pair = key_pair;

    key_count++;

    printf("Key pair created successfully.\n");
}

/**
 * Chiffre un fichier avec une clé RSA
 * @param file_in Fichier à chiffrer
 * @param file_out Fichier chiffré de sortie
 * @param key_id Identifiant de la clé de chiffrement à utiliser
 * @return void
 * 
 * Vérifie que:
 * - La clé existe
 * - La clé est de type ENCRYPTION
 * - Les fichiers sont valides
 * Puis chiffre le fichier bloc par bloc
 */
void crypt(FILE* file_in, FILE* file_out, const int key_id){
    Key key = keys[find_key_index(key_id)];
    if (key.id == -1) {
        fprintf(stderr, "Error: Key not found.\n");
        return;
    }
    
    if (key.type != ENCRYPTION) {
        fprintf(stderr, "Error: The key is not of type ENCRYPTION.\n");
        return;
    }
    
    if (file_in == NULL || file_out == NULL) {
        fprintf(stderr, "Error: Invalid file pointers.\n");
        return;
    }

    encrypt_message_by_block_from_file(file_in, file_out, &key.key_pair.pubKey);
    printf("Message encrypted successfully.\n");
}

/**
 * Déchiffre un fichier avec une clé RSA privée
 * @param file_in Fichier chiffré en entrée
 * @param file_out Fichier déchiffré en sortie
 * @param key_id Identifiant de la clé de déchiffrement
 * @return void
 * 
 * Vérifie que:
 * - La clé existe
 * - La clé est de type ENCRYPTION
 * - Les fichiers sont valides
 * Puis déchiffre le fichier bloc par bloc
 */
void uncrypt(FILE* file_in, FILE* file_out, const int key_id){
    Key key = keys[find_key_index(key_id)];
    if (key.id == -1) {
        fprintf(stderr, "Error: Key not found.\n");
        return;
    }
    if (key.type != ENCRYPTION) {
        fprintf(stderr, "Error: The key is not of type ENCRYPTION.\n");
        return;
    }
    if (file_in == NULL || file_out == NULL) {
        fprintf(stderr, "Error: Invalid file pointers.\n");
        return;
    }

  decrypt_message_by_block_from_file(file_in, file_out, &key.key_pair.privKey);
  printf("Message decrypted successfully.\n"); 
}

/**
 * Convertit un fichier binaire en base64
 * @param file_in Fichier binaire en entrée
 * @param file_out Fichier base64 en sortie
 * @return void
 * 
 * Vérifie que les fichiers sont valides puis effectue la conversion
 */
void bin_to_base64(FILE* file_in, FILE* file_out) {
    if (file_in == NULL || file_out == NULL) {
        fprintf(stderr, "Error: Invalid file pointers.\n");
        return;
    }

    convert_encrypted_to_base64(file_in, file_out);
    printf("Binary data converted to Base64 successfully.\n");
}

/**
 * Convertit un fichier base64 en binaire
 * @param file_in Fichier base64 en entrée
 * @param file_out Fichier binaire en sortie
 * @return void
 * 
 * Vérifie que les fichiers sont valides puis effectue la conversion
 */
void base64_to_bin(FILE* file_in, FILE* file_out) {
    if (file_in == NULL || file_out == NULL) {
        fprintf(stderr, "Error: Invalid file pointers.\n");
        return;
    }

    convert_base64_to_binary(file_in, file_out);
    printf("Base64 data converted to binary successfully. \n");
}

/**
 * Sauvegarde l'état du système (clés et contacts)
 * @param file_out Fichier de sortie
 * @return void
 * 
 * Format de sauvegarde:
 * - Section KEYS: liste des clés avec leur type et valeurs
 * - Section CONTACTS: liste des contacts avec leurs informations et clés associées
 * - Séparateurs ---- entre chaque entrée
 */
void save(FILE* file_out) {
    fprintf(file_out, "KEYS:\n");
    for (int i = 0; i < key_count; i++) {
        Key* k = &keys[i];
        fprintf(file_out, "ID:%d TYPE:%s\n", k->id, k->type == ENCRYPTION ? "ENCRYPTION" : "SIGNATURE");
        fprintf(file_out, "PUB:%lu %lu\n", k->key_pair.pubKey.E, k->key_pair.pubKey.N);
        fprintf(file_out, "PRIV:%lu %lu\n", k->key_pair.privKey.E, k->key_pair.privKey.N);
        fprintf(file_out, "----\n");
    }

    fprintf(file_out, "CONTACTS:\n");
    for (int i = 0; i < contact_count; i++) {
        Contact* c = &contacts[i];
        fprintf(file_out, "CONTACT_ID:%d\n", c->id);
        fprintf(file_out, "NAME:%s\n", c->name);
        fprintf(file_out, "FIRST_NAME:%s\n", c->first_name);
        fprintf(file_out, "COMMENT:%s\n", c->comment);
        fprintf(file_out, "KEYS:\n");
        for (int j = 0; j < c->key_count; j++) {
            fprintf(file_out, "KEY_ID:%d TYPE:%s\n", c->keys[j].id,
                    c->keys[j].type == ENCRYPTION ? "ENCRYPTION" : "SIGNATURE");
        }
        fprintf(file_out, "----\n");
    }
}

void savepub(const int key_id, FILE* file) {
    int index = find_key_index(key_id);
    if (index < 0 || index >= key_count) {
        fprintf(stderr, "Error: key ID %d not found\n", key_id);
        return;
    }

    Key* key = &keys[index];
    encode_key_base64(&key->key_pair.pubKey, file);
}

void load(FILE* file_in) {
    FILE* temp = tmpfile();
    if (!temp) {
        fprintf(stderr, "Error: Could not create temporary file.\n");
        return;
    }

    decrypt_message_by_block_from_file(file_in, temp, &private_key);

    fseek(temp, 0, SEEK_SET);

    char line[256];

    key_count = 0;
    contact_count = 0;

    Key current_key;
    Contact current_contact;
    int parsing_key = 0;
    int parsing_contact = 0;
    int in_contacts_section = 0;

    while (fgets(line, sizeof(line), temp)) {
        line[strcspn(line, "\n")] = 0;

        if (strcmp(line, "CONTACTS:") == 0) {
            in_contacts_section = 1;
            continue;
        }

        if (!in_contacts_section) {
            if (strncmp(line, "ID:", 3) == 0) {
                parsing_key = 1;
                char type_str[20];
                sscanf(line, "ID:%d TYPE:%s", &current_key.id, type_str);
                current_key.type = (strcmp(type_str, "ENCRYPTION") == 0) ? ENCRYPTION : SIGNATURE;
            } 
            else if (strncmp(line, "PUB:", 4) == 0) {
                sscanf(line, "PUB:%lx %lx", 
                    &current_key.key_pair.pubKey.E, 
                    &current_key.key_pair.pubKey.N);
            }
            else if (strncmp(line, "PRIV:", 5) == 0) {
                sscanf(line, "PRIV:%lx %lx", 
                    &current_key.key_pair.privKey.E, 
                    &current_key.key_pair.privKey.N);
            }
            else if (strcmp(line, "----") == 0 && parsing_key) {
                keys[key_count++] = current_key;
                parsing_key = 0;
            }
        } else {
            if (strncmp(line, "CONTACT_ID:", 11) == 0) {
                parsing_contact = 1;
                sscanf(line, "CONTACT_ID:%d", &current_contact.id);
                current_contact.key_count = 0;
                current_contact.keys = malloc(MAX_KEYS * sizeof(Key));
            } 
            else if (strncmp(line, "NAME:", 5) == 0) {
                sscanf(line, "NAME:%s", current_contact.name);
            }
            else if (strncmp(line, "FIRST_NAME:", 11) == 0) {
                sscanf(line, "FIRST_NAME:%s", current_contact.first_name);
            }
            else if (strncmp(line, "COMMENT:", 8) == 0) {
                sscanf(line, "COMMENT:%s", current_contact.comment);
            }
            else if (strncmp(line, "KEY_ID:", 7) == 0) {
                if (current_contact.key_count >= MAX_KEYS) {
                    fprintf(stderr, "Error: Maximum number of keys for this contact reached.\n");
                    continue;
                }
                int key_id;
                char type_str[20];
                sscanf(line, "KEY_ID:%d TYPE:%s", &key_id, type_str);
                current_contact.keys[current_contact.key_count].id = key_id;
                current_contact.keys[current_contact.key_count].type = (strcmp(type_str, "ENCRYPTION") == 0) ? ENCRYPTION : SIGNATURE;
                current_contact.key_count++;
            }
            else if (strcmp(line, "----") == 0 && parsing_contact) {
                contacts[contact_count++] = current_contact;
                parsing_contact = 0;
            }
        }
    }
    
    if (parsing_key) {
        keys[key_count++] = current_key;
    }

    if (parsing_contact) {
        contacts[contact_count++] = current_contact;
    }
}

void show(const int id, int show_pub, int show_priv, int is_contact) {
    if (is_contact) {
        int index = find_contact_index(id);
        if (index == -1) {
            fprintf(stderr, "Error: Contact ID %d not found\n", id);
            return;
        }

        Contact* c = &contacts[index];
        printf("Contact ID: %d\n", c->id);
        printf("Name: %s %s\n", c->name, c->first_name);
        printf("Comment: %s\n", c->comment);
        printf("Keys:\n");
        for (int i = 0; i < c->key_count; i++) {
            printf("- Key ID: %d [%s]\n", c->keys[i].id,
                   c->keys[i].type == ENCRYPTION ? "ENCRYPTION" : "SIGNATURE");
        }
    } else {
        int index = find_key_index(id);
        if (index < 0 || index >= key_count) {
            fprintf(stderr, "Error: key ID %d not found\n", id);
            return;
        }

        Key* k = &keys[index];

        printf("ID: %d TYPE: %s\n",k->id,k->type == ENCRYPTION ? "ENCRYPTION" : "SIGNATURE");

        if (show_pub) {
            printf("PUB: E = 0x%lx, N = 0x%lx\n",
                    k->key_pair.pubKey.E,k->key_pair.pubKey.N);
        }

        if (show_priv) {
            printf("PRIV: E = 0x%lx, N = 0x%lx\n",
                    k->key_pair.privKey.E,k->key_pair.privKey.N);
        }

        if (!show_pub && !show_priv) {
            printf("PUB: E = 0x%lX, N = 0x%lX\n",
                   k->key_pair.pubKey.E, k->key_pair.pubKey.N);
            printf("PRIV: E = 0x%lX, N = 0x%lX\n",
                   k->key_pair.privKey.E, k->key_pair.privKey.N);
        }
    }
}

void signtext(FILE* file_in, FILE* file_out, const int key_id) {
    Key key = keys[find_key_index(key_id)];
    if (key.id == -1) {
        fprintf(stderr, "Error: Key not found.\n");
        return;
    }
    if (key.type != SIGNATURE) {
        fprintf(stderr, "Error: The key is not of type SIGNATURE.\n");
        return;
    }
    if (file_in == NULL || file_out == NULL) {
        fprintf(stderr, "Error: Invalid file pointers.\n");
        return;
    }

    FILE* temp = tmpfile();
    if (!temp) {
        fprintf(stderr, "Error: Could not create temporary file.\n");
        return;
    }

    encrypt_message_by_block_from_file(file_in, temp, &key.key_pair.privKey);
    
    fseek(temp, 0, SEEK_SET);
    convert_encrypted_to_base64(temp, file_out);
    
    fclose(temp);
    printf("Text signed successfully.\n");
}

void verifysign(FILE* file_in, FILE* fileSign, const int key_id) {
    Key key = keys[find_key_index(key_id)];
    if (key.id == -1) {
        fprintf(stderr, "Error: Key not found.\n");
        return;
    }
    if (key.type != SIGNATURE) {
        fprintf(stderr, "Error: The key is not of type SIGNATURE.\n");
        return;
    }
    if (file_in == NULL || fileSign == NULL) {
        fprintf(stderr, "Error: Invalid file pointers.\n");
        return;
    }

    FILE* tempBin = tmpfile();
    FILE* tempDecrypted = tmpfile();
    if (!tempBin || !tempDecrypted) {
        fprintf(stderr, "Error: Could not create temporary files.\n");
        return;
    }

    convert_base64_to_binary(fileSign, tempBin);
    
    fseek(tempBin, 0, SEEK_SET);
    
    decrypt_message_by_block_from_file(tempBin, tempDecrypted, &key.key_pair.pubKey);
    
    fseek(file_in, 0, SEEK_SET);
    fseek(tempDecrypted, 0, SEEK_SET);
    
    int ch1, ch2;
    while ((ch1 = fgetc(file_in)) != EOF && (ch2 = fgetc(tempDecrypted)) != EOF) {
        if (ch1 != ch2) {
            printf("Signature verification failed.\n");
            fclose(tempBin);
            fclose(tempDecrypted);
            return;
        }
    }
    
    if (ch1 == ch2) {
        printf("Signature verified successfully.\n");
    } else {
        printf("Signature verification failed.\n");
    }
    
    fclose(tempBin);
    fclose(tempDecrypted);
}

void certify(const int key_id) {
    int index = find_key_index(key_id);
    if (index < 0 || index >= key_count) {
        fprintf(stderr, "Error: key ID %d not found\n", key_id);
        return;
    }

    FILE* certFile = fopen("certification_requests.txt", "a");
    if (!certFile) {
        perror("Failed to open certification requests file");
        return;
    }

    Key* k = &keys[index];
    fprintf(certFile, "CERTIFY REQUEST:\n");
    fprintf(certFile, "ID:%d TYPE:%s\n", k->id, k->type == ENCRYPTION ? "ENCRYPTION" : "SIGNATURE");
    fprintf(certFile, "PUB:0x%lx 0x%lx\n", k->key_pair.pubKey.E, k->key_pair.pubKey.N);
    fprintf(certFile, "----\n");

    fclose(certFile);
    printf("Certification request sent for key %d\n", key_id);
}

void revoke(const int key_id) {
    int index = find_key_index(key_id);
    if (index < 0 || index >= key_count) {
        fprintf(stderr, "Error: key ID %d not found\n", key_id);
        return;
    }

    FILE* revokeFile = fopen("revocation_requests.txt", "a");
    if (!revokeFile) {
        perror("Failed to open revocation requests file");
        return;
    }

    Key* k = &keys[index];
    fprintf(revokeFile, "REVOKE REQUEST:\n");
    fprintf(revokeFile, "ID:%d TYPE:%s\n", k->id, k->type == ENCRYPTION ? "ENCRYPTION" : "SIGNATURE");
    fprintf(revokeFile, "PUB:0x%lx 0x%lx\n", k->key_pair.pubKey.E, k->key_pair.pubKey.N);
    fprintf(revokeFile, "----\n");

    fclose(revokeFile);
    printf("Revocation request sent for key %d\n", key_id);
}

/**
 * Liste tous les contacts ou un contact spécifique
 * @param contact_id ID du contact à lister (-1 pour tous)
 * @param name Nom du contact à rechercher (NULL pour tous)
 * 
 * Format d'affichage:
 * ID: <id>
 * Name: <name> <first_name>
 * Comment: <comment>
 * Keys: liste des clés associées
 */
void list_contacts(const int contact_id, const char* name) {
    printf("Contact List:\n");
    
    if (contact_id != -1) {
        int index = find_contact_index(contact_id);
        if (index != -1) {
            Contact* c = &contacts[index];
            printf("ID: %d\nName: %s %s\nComment: %s\nKeys:\n", 
                   c->id, c->name, c->first_name, c->comment);
            for (int j = 0; j < c->key_count; j++) {
                printf("- %d [%s]\n", c->keys[j].id, 
                       c->keys[j].type == ENCRYPTION ? "ENCRYPTION" : "SIGNATURE");
            }
        }
        return;
    }
    
    if (name != NULL) {
        int index = find_contact_by_name(name);
        if (index != -1) {
            Contact* c = &contacts[index];
            printf("ID: %d\nName: %s %s\nComment: %s\nKeys:\n", 
                   c->id, c->name, c->first_name, c->comment);
            for (int j = 0; j < c->key_count; j++) {
                printf("- %d [%s]\n", c->keys[j].id, 
                       c->keys[j].type == ENCRYPTION ? "ENCRYPTION" : "SIGNATURE");
            }
        }
        return;
    }

    for (int i = 0; i < contact_count; i++) {
        Contact* c = &contacts[i];
        printf("ID: %d\nName: %s %s\nComment: %s\nKeys:\n", 
               c->id, c->name, c->first_name, c->comment);
        for (int j = 0; j < c->key_count; j++) {
            printf("- %d [%s]\n", c->keys[j].id, 
                   c->keys[j].type == ENCRYPTION ? "ENCRYPTION" : "SIGNATURE");
        }
        printf("----\n");
    }
}

/**
 * Ajoute un nouveau contact au système
 * @param contact_id Identifiant unique du contact
 * 
 * Demande interactivement:
 * - Nom
 * - Prénom
 * - Commentaire
 * Vérifie que:
 * - L'ID n'existe pas déjà
 * - La limite MAX_CONTACTS n'est pas atteinte
 */
void add_contact(const int contact_id) {
    if (contact_count >= MAX_CONTACTS) {
        fprintf(stderr, "Error: Maximum number of contacts reached.\n");
        return;
    }

    if (find_contact_index(contact_id) != -1) {
        fprintf(stderr, "Error: Contact ID already exists.\n");
        return;
    }

    Contact* c = &contacts[contact_count];
    c->id = contact_id;
    c->key_count = 0;
    c->keys = NULL;

    char buffer[256];
    printf("Enter contact information:\n");
    
    printf("Name: ");
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        perror("fgets");
        exit(EXIT_FAILURE);
    }
    buffer[strcspn(buffer, "\n")] = 0;
    c->name = strdup(buffer);

    printf("First name: ");
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        perror("fgets");
        exit(EXIT_FAILURE);
    }
    buffer[strcspn(buffer, "\n")] = 0;
    c->first_name = strdup(buffer);

    printf("Comment: ");
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        perror("fgets");
        exit(EXIT_FAILURE);
    }
    buffer[strcspn(buffer, "\n")] = 0;
    c->comment = strdup(buffer);

    contact_count++;
    printf("Contact added successfully.\n");
}

/**
 * Modifie les informations d'un contact existant
 * @param contact_id ID du contact à modifier
 * 
 * Menu interactif permettant de modifier:
 * - Nom
 * - Prénom
 * - Commentaire
 * Les clés sont gérées séparément via addkeys/rmkeys
 */
void modify_contact(const int contact_id) {
    int index = find_contact_index(contact_id);
    if (index == -1) {
        fprintf(stderr, "Error: Contact not found.\n");
        return;
    }

    Contact* c = &contacts[index];
    char buffer[256];
    int choice;

    while (1) {
        printf("\nModify Contact Menu:\n");
        printf("1. Name (current: %s)\n", c->name);
        printf("2. First name (current: %s)\n", c->first_name);
        printf("3. Comment (current: %s)\n", c->comment);
        printf("4. Done\n");
        printf("Enter choice (1-4): ");

        if (!fgets(buffer, sizeof(buffer), stdin)) break;
        choice = atoi(buffer);

        switch (choice) {
            case 1:
                printf("Enter new name: ");
                if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                    perror("fgets");
                    exit(EXIT_FAILURE);
                }
                buffer[strcspn(buffer, "\n")] = 0;
                free(c->name);
                c->name = strdup(buffer);
                break;
            case 2:
                printf("Enter new first name: ");
                if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                    perror("fgets");
                    exit(EXIT_FAILURE);
                }
                buffer[strcspn(buffer, "\n")] = 0;
                free(c->first_name);
                c->first_name = strdup(buffer);
                break;
            case 3:
                printf("Enter new comment: ");
                if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                    perror("fgets");
                    exit(EXIT_FAILURE);
                }
                buffer[strcspn(buffer, "\n")] = 0;
                free(c->comment);
                c->comment = strdup(buffer);
                break;
            case 4:
                return;
            default:
                printf("Invalid choice.\n");
        }
    }
}

/**
 * Ajoute une clé à un contact
 * @param id_str ID ou nom du contact (recherche les deux)
 * 
 * Demande l'ID de la clé à ajouter
 * Vérifie que:
 * - Le contact existe
 * - La clé existe
 * - La mémoire est suffisante
 */
void add_keys_to_contact(const char* id_str) {
    int contact_id;
    char* ptr;
    contact_id = strtol(id_str, &ptr, 10);
    
    int index = -1;
    if (ptr == id_str) {
        index = find_contact_by_name(id_str);
    } else {
        index = find_contact_index(contact_id);
    }

    if (index == -1) {
        fprintf(stderr, "Error: Contact not found.\n");
        return;
    }

    Contact* c = &contacts[index];
    
    char buffer[256];
    printf("Enter key ID: ");
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        perror("fgets");
        exit(EXIT_FAILURE);
    }
    int key_id = atoi(buffer);

    int key_index = find_key_index(key_id);
    if (key_index == -1) {
        fprintf(stderr, "Error: Key not found.\n");
        return;
    }

    Key* new_keys = realloc(c->keys, (c->key_count + 1) * sizeof(Key));
    if (!new_keys) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        return;
    }
    c->keys = new_keys;

    c->keys[c->key_count] = keys[key_index];
    c->key_count++;

    printf("Key added successfully to contact.\n");
}

/**
 * Retire une clé d'un contact
 * @param contact_id ID du contact
 * @param key_id ID de la clé à retirer
 * 
 * Vérifie que:
 * - Le contact existe
 * - La clé existe dans le contact
 * Libère la mémoire si nécessaire
 * Met à jour le tableau de clés du contact
 */
void remove_key_from_contact(const int contact_id, const int key_id) {
    int contact_index = find_contact_index(contact_id);
    if (contact_index == -1) {
        fprintf(stderr, "Error: Contact not found.\n");
        return;
    }

    Contact* c = &contacts[contact_index];
    int key_index = -1;
    
    for (int i = 0; i < c->key_count; i++) {
        if (c->keys[i].id == key_id) {
            key_index = i;
            break;
        }
    }

    if (key_index == -1) {
        fprintf(stderr, "Error: Key not found in contact.\n");
        return;
    }

    for (int i = key_index; i < c->key_count - 1; i++) {
        c->keys[i] = c->keys[i + 1];
    }
    c->key_count--;

    if (c->key_count > 0) {
        Key* new_keys = realloc(c->keys, c->key_count * sizeof(Key));
        if (new_keys) {
            c->keys = new_keys;
        }
    } else {
        free(c->keys);
        c->keys = NULL;
    }

    printf("Key removed successfully from contact.\n");
}

void help() {
    printf("\nDIYPG - Liste des commandes disponibles:\n\n");
    
    printf("Gestion des clés:\n");
    printf("  listkeys [<key_id>]                    Liste toutes les clés ou une clé spécifique\n");
    printf("  newkeys <keyid> <type>                 Crée une nouvelle paire de clés (ENCRYPTION/SIGNATURE)\n");
    printf("  rmkeys <keyid>                         Supprime une clé\n");
    printf("  show <id> [\"pub\"] [\"priv\"]           Affiche les détails d'une clé\n");
    
    printf("\nGestion des contacts:\n");
    printf("  listcontacts [<id>] [<name>]          Liste tous les contacts ou un contact spécifique\n");
    printf("  addcontact <id>                       Ajoute un nouveau contact\n");
    printf("  modifycontact <id>                    Modifie un contact existant\n");
    printf("  rmcontact <id>                        Supprime un contact\n");
    printf("  addkeys <id/name>                     Ajoute une clé à un contact\n");
    printf("  rmkeys <contactid> <keyid>            Supprime une clé d'un contact\n");
    printf("  show <id> \"contact\"                   Affiche les détails d'un contact\n");

    printf("\nCryptographie:\n");
    printf("  crypt <input_file> <output_file> <keyid>      Chiffre un fichier\n");
    printf("  uncrypt <input_file> <output_file> <keyid>    Déchiffre un fichier\n");
    printf("  signtext <filein> <keyid> <fileout>           Signe un fichier\n");
    printf("  verifysign <filein> <filesign> <keyid>        Vérifie une signature\n");

    printf("\nGestion des fichiers:\n");
    printf("  save [<file_out>]                     Sauvegarde l'état (clés et contacts)\n");
    printf("  savepub <keyid> <file>                Sauvegarde une clé publique\n");
    printf("  load <file_in>                        Charge un fichier d'état\n");
    printf("  bin-2b64 <input> <output>             Convertit un fichier binaire en base64\n");
    printf("  b64-2bin <input> <output>             Convertit un fichier base64 en binaire\n");

    printf("\nCertification:\n");
    printf("  certify <id>                          Demande de certification d'une clé\n");
    printf("  revoke <id>                           Demande de révocation d'une clé\n");

    printf("\nAutres:\n");
    printf("  help                                  Affiche cette aide\n");
    printf("  quit                                  Quitte le programme\n\n");
}

void execute_command(char* line) {
    int argc = 0;
    char* parameter;
    char** argv = NULL;

    line[strcspn(line, "\n")] = '\0';

    parameter = strtok(line, " ");
    while (parameter != NULL) {
        argv = realloc(argv, sizeof(char*) * (argc + 1));
        if (!argv) {
            perror("Failed to reallocate memory using realloc");
            exit(EXIT_FAILURE);
        }

        argv[argc++] = parameter;
        parameter = strtok(NULL, " ");
    }

    if (argc == 0) return;

    if (strcmp(argv[0], "quit") == 0) {
        free(argv);

        exit(0);
    } 
    
    else if (strcmp(argv[0], "listkeys") == 0) {
        if (argc > 2) {
            free(argv);

            fprintf(stderr, "Usage: listkeys [<key_id>]\n");
            return;
        }

        int key_id = -1;

        if (argc == 2) key_id = atoi(argv[1]);

        list_keys(key_id);
    }

    else if (strcmp(argv[0], "newkeys") == 0) {
        if (argc != 3) {
            free(argv);

            fprintf(stderr, "Usage: newkeys <keyid> <type>\n");
            return;
        }

        int key_id = atoi(argv[1]);
        KeyType key_type;
        if (strcmp(argv[2], "ENCRYPTION") == 0) {
            key_type = ENCRYPTION;
        } else if (strcmp(argv[2], "SIGNATURE") == 0) {
            key_type = SIGNATURE;
        } else {
            free(argv);

            fprintf(stderr, "Error: The given key type is invalid. Expected: 'ENCRYPTION' or 'SIGNATURE'.\n");
            return;
        }

        new_keys(key_id, key_type);
    }

    else if (strcmp(argv[0], "crypt") == 0) {
        if (argc != 4) {
            free(argv);

            fprintf(stderr, "Usage: crypt <input_file> <output_file> <keyid>\n");
            return;
        }

        FILE* file_in = fopen(argv[1], "rb");
        FILE* file_out = fopen(argv[2], "wb");
        int key_id = atoi(argv[3]);
        
        crypt(file_in, file_out, key_id);

        fclose(file_in);
        fclose(file_out);
    }

    else if (strcmp(argv[0], "uncrypt") == 0) {
        if (argc != 4) {
            free(argv);

            fprintf(stderr, "Usage: uncrypt <input_file> <output_file> <keyid>\n");
            return;
        }

        int key_id = atoi(argv[3]);
        FILE* file_in = fopen(argv[1], "rb");
        FILE* file_out = fopen(argv[2], "wb");
        
        uncrypt(file_in, file_out, key_id);

        fclose(file_in);
        fclose(file_out);
    }

    else if (strcmp(argv[0], "bin-2b64") == 0) {
        if (argc != 3) {
            free(argv);

            fprintf(stderr, "Usage: bin-2b64 <keyid> <type>\n");
            return;
        }

        FILE* file_in = fopen(argv[1], "rb");
        FILE* file_out = fopen(argv[2], "wb");

        bin_to_base64(file_in, file_out);

        fclose(file_in);
        fclose(file_out);
    }

    else if (strcmp(argv[0], "b64-2bin") == 0) {
        if (argc != 3) {
            free(argv);

            fprintf(stderr, "Usage: b64-2bin <keyid> <type>\n");
            return;
        }

        FILE* file_in = fopen(argv[1], "rb");
        FILE* file_out = fopen(argv[2], "wb");

        base64_to_bin(file_in, file_out);

        fclose(file_in);
        fclose(file_out);
    }

    else if (strcmp(argv[0], "save") == 0) {
        if (argc > 2) {
            free(argv);
            fprintf(stderr, "Usage: save [<file_out>]\n");
            return;
        }

        FILE* file_out = NULL;
        
        if (argc == 1) {
            file_out = fopen("./files/default.txt", "w");
        } else {
            file_out = fopen(argv[1], "w");
        }

        FILE* fileTmp = tmpfile();

        if (!file_out || !fileTmp) {
            if (file_out) fclose(file_out);
            free(argv);
            perror("Failed to open file");
            return;
        }

        save(fileTmp);
        fseek(fileTmp, 0, SEEK_SET);
        encrypt_message_by_block_from_file(fileTmp, file_out, &public_key);

        fclose(file_out);
        fclose(fileTmp);
    }

    else if (strcmp(argv[0],"savepub")==0) {
        if (argc != 3) {
            free(argv);

            fprintf(stderr, "Usage: savepub <keyid> <file>\n");
            return;
        }

        FILE* file = fopen(argv[2], "w");
        if(!file) {
            free(argv);

            perror("Failed to open file");
            return;
        }
        int key_id = atoi(argv[1]);

        savepub(key_id,file);

        fclose(file);
    }

    else if (strcmp(argv[0], "load") == 0) {
        if (argc != 2) {
            free(argv);

            fprintf(stderr, "Usage: load <file_in>\n");
            return;
        }

        FILE* file_in = fopen(argv[1], "r");
        if (!file_in) {
            free(argv);

            perror("Failed to open file");
            return;
        }

        load(file_in);
        fclose(file_in);
    }

    else if (strcmp(argv[0], "show") == 0) {
        if (argc < 2 || argc > 5) {
            free(argv);
            fprintf(stderr, "Usage: show <id> [\"pub\"] [\"priv\"] [\"contact\"]\n");
            return;
        }

        int id = atoi(argv[1]);
        int show_pub = 0, show_priv = 0, is_contact = 0;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "pub") == 0) show_pub = 1;
            else if (strcmp(argv[i], "priv") == 0) show_priv = 1;
            else if (strcmp(argv[i], "contact") == 0) is_contact = 1;
        }

        if (argc == 2) {
            show_pub = 1;
            show_priv = 1;
        }

        show(id, show_pub, show_priv, is_contact);
    }

    else if (strcmp(argv[0], "signtext") == 0) {
        if (argc != 4) {
            free(argv);
            fprintf(stderr, "Usage: signtext <filein> <keyid> <fileout>\n");
            return;
        }

        FILE* file_in = fopen(argv[1], "rb");
        FILE* file_out = fopen(argv[3], "wb");
        if (!file_in || !file_out) {
            if (file_in) fclose(file_in);
            if (file_out) fclose(file_out);
            free(argv);
            perror("Failed to open file");
            return;
        }

        signtext(file_in, file_out, atoi(argv[2]));
        fclose(file_in);
        fclose(file_out);
    }

    else if (strcmp(argv[0], "verifysign") == 0) {
        if (argc != 4) {
            free(argv);
            fprintf(stderr, "Usage: verifysign <filein> <filesign> <keyid>\n");
            return;
        }

        FILE* file_in = fopen(argv[1], "rb");
        FILE* fileSign = fopen(argv[2], "rb");
        if (!file_in || !fileSign) {
            if (file_in) fclose(file_in);
            if (fileSign) fclose(fileSign);
            free(argv);
            perror("Failed to open file");
            return;
        }

        verifysign(file_in, fileSign, atoi(argv[3]));
        fclose(file_in);
        fclose(fileSign);
    }

    else if (strcmp(argv[0], "certify") == 0) {
        if (argc != 2) {
            free(argv);
            fprintf(stderr, "Usage: certify <id>\n");
            return;
        }

        certify(atoi(argv[1]));
    }

    else if (strcmp(argv[0], "revoke") == 0) {
        if (argc != 2) {
            free(argv);
            fprintf(stderr, "Usage: revoke <id>\n");
            return;
        }

        revoke(atoi(argv[1]));
    }

    else if (strcmp(argv[0], "listcontacts") == 0) {
        if (argc > 2) {
            free(argv);
            fprintf(stderr, "Usage: listcontacts [<id>] [<name>]\n");
            return;
        }

        int contact_id = -1;
        char* name = NULL;

        if (argc == 2) {
            contact_id = atoi(argv[1]);
        } else if (argc == 3) {
            name = argv[1];
        }

        list_contacts(contact_id, name);
    }

    else if (strcmp(argv[0], "addcontact") == 0) {
        if (argc != 2) {
            free(argv);
            fprintf(stderr, "Usage: addcontact <id>\n");
            return;
        }
        add_contact(atoi(argv[1]));
    }

    else if (strcmp(argv[0], "rmcontact") == 0) {
        if (argc != 2) {
            free(argv);
            fprintf(stderr, "Usage: rmcontact <id>\n");
            return;
        }
        remove_contact(atoi(argv[1]));
    }

    else if (strcmp(argv[0], "modifycontact") == 0) {
        if (argc != 2) {
            free(argv);
            fprintf(stderr, "Usage: modifycontact <id>\n");
            return;
        }
        modify_contact(atoi(argv[1]));
    }

    else if (strcmp(argv[0], "addkeys") == 0) {
        if (argc != 2) {
            free(argv);
            fprintf(stderr, "Usage: addkeys <id/name>\n");
            return;
        }
        add_keys_to_contact(argv[1]);
    }

    else if (strcmp(argv[0], "rmkeys") == 0) {
        if (argc == 2) {
            remove_keys(atoi(argv[1]));
        }
        else if (argc == 3) {
            remove_key_from_contact(atoi(argv[1]), atoi(argv[2]));
        }
        else {
            free(argv);
            fprintf(stderr, "Usage: rmkeys <keyid> or rmkeys <contactid> <keyid>\n");
            return;
        }
    }

    else if (strcmp(argv[0], "help") == 0) {
        help();
    }

    free(argv);
}

int main(void) {
    printf("DIYPG - Interprete de Commande (v2)\n");

    char line[256];
    while (1) {
        printf("> ");
        
        if (!fgets(line, sizeof(line), stdin)) break;
        
        execute_command(line);
    }

    return 0;
}