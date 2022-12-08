# Primitive AES 128

Il s'agit dans ce repos de l'implémentation en langage C de la primitive de chiffrement **AES 128**. On retrouve principalement 03 fichiers :

* `aes.h` : qui est le header et contient tous les prototypes de fonctions et certaines contanstes importantes.
* `aes.c` : qui contient la définition de toutes les fonctions utiles au chiffrement AES.
* `main.c` : qui contient le programme principale et donne un exemple d'appel à la fonction `AESEncrypt ( uint8_t ciphertext[DATA_SIZE], uint8_t plaintext[DATA_SIZE] , uint8_t key [DATA_SIZE]);`