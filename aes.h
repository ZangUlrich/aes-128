# ifndef AES_H
# define AES_H
# define DATA_SIZE 16
# define STATE_ROW_SIZE 4
# define STATE_COL_SIZE 4
# define ROUND_COUNT 10
# include <stdint.h>
// the round that will trigger
extern uint8_t targeted_round ;

void initialize_aes_sbox(uint8_t sbox[256]);

uint8_t*** malloc_roundKeys();

void free_roundKeys(uint8_t*** roundkeys);

void AESEncrypt_state(uint8_t **state, uint8_t ***roundkeys);

void AESEncrypt ( uint8_t *ciphertext, uint8_t *plaintext , uint8_t key [DATA_SIZE ]);
void AddRoundKey ( uint8_t **state, uint8_t **roundkey);
void SubBytes ( uint8_t **state);
void ShiftRows ( uint8_t **state);
void MixColumns ( uint8_t **state);
void KeyGen ( uint8_t ***roundkeys, uint8_t **master_key);
// fill the first column of a given round key
void ColumnFill ( uint8_t ***roundkeys, int round );

// fill the other 3 columns of a given round key
void OtherColumnsFill ( uint8_t ***roundkeys, int round );

void GetRoundKey ( uint8_t **roundkey, uint8_t ***roundkeys, int round );
void MessageToState ( uint8_t ** state, uint8_t message [DATA_SIZE ]);
void StateToMessage ( uint8_t *message, uint8_t **state);
void MCMatrixColumnProduct ( uint8_t colonne [ STATE_COL_SIZE ]);

uint8_t gmul ( uint8_t a, uint8_t b);



extern const uint8_t rcon [10];
extern const uint8_t sboxtab [256];
extern const uint8_t invsbox [256];
# endif