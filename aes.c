#include <stdio.h>
#include <stdlib.h>
#include "aes.h"

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))


const uint8_t rcon [10] = {0x01, 0x02, 0x04, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
const uint8_t sboxtab [256] = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x1, 0x67, 0x2b, 0xfe, 0xd7,
                                0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
                                0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
                                0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x4, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x5, 0x9a,
                                0x7, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x9, 0x83, 0x2c, 0x1a, 0x1b, 0x6e,
                                0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x0, 0xed,
                                0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef,
                                0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x2, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                                0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
                                0xf3, 0xd2, 0xcd, 0xc, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
                                0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
                                0xb8, 0x14, 0xde, 0x5e, 0xb, 0xdb, 0xe0, 0x32, 0x3a, 0xa, 0x49, 0x6, 0x24, 0x5c,
                                0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
                                0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x8, 0xba, 0x78, 0x25, 0x2e,
                                0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
                                0xb5, 0x66, 0x48, 0x3, 0xf6, 0xe, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                                0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
                                0x28, 0xdf, 0x8c, 0xa1, 0x89, 0xd, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0xf, 0xb0,
                                0x54, 0xbb, 0x16
                              };


const uint8_t invsbox[256] = { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                               0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
                               0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
                               0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
                               0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                               0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
                               0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
                               0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
                               0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
                               0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                               0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
                               0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
                               0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
                               0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
                               0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
                               0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
                             };



void affiche(uint8_t roundKeys[][STATE_ROW_SIZE][STATE_COL_SIZE]) {
	for (int round = 0; round <= ROUND_COUNT; round++) {

		for (int i = 0; i < STATE_ROW_SIZE; ++i) {
			for (int j = 0; j < STATE_COL_SIZE; ++j) {
				printf("0x%x  ", roundKeys[round][j][i] );
			}
			printf("\n\n");
		}
		printf("\n----------------------\n");

	}
}

void affiche_state(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {

	for (int i = 0; i < STATE_ROW_SIZE; ++i) {
		for (int j = 0; j < STATE_COL_SIZE; ++j) {
			printf("0x%x  ", state[j][i] );
		}
		printf("\n\n");
	}
	printf("\n----------------------\n");

}


//initialisation de sbox
void initialize_aes_sbox(uint8_t sbox[256]) {
	uint8_t p = 1, q = 1;

	/* loop invariant: p * q == 1 in the Galois field */
	do {
		/* multiply p by 3 */
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

		/* divide q by 3 (equals multiplication by 0xf6) */
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		/* compute the affine transformation */
		uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

		sbox[p] = xformed ^ 0x63;
	} while (p != 1);

	/* 0 is a special case since it has no inverse */
	sbox[0] = 0x63;
}



/*
	Moi je considere roundKeys sous un prisme de colonne-ligne (et non de ligne-colonne)
*/

uint8_t*** malloc_roundKeys() {

	uint8_t*** roundKeys;

	roundKeys = malloc(sizeof(uint8_t**) * (ROUND_COUNT + 1));

	for (int i = 0; i <= ROUND_COUNT; ++i) {
		roundKeys[i] = malloc(sizeof(uint8_t*) * STATE_COL_SIZE);
	}

	for (int i = 0; i <= ROUND_COUNT; ++i) {
		for (int j = 0; j < STATE_COL_SIZE; ++j) {
			roundKeys[i][j] = malloc(sizeof(uint8_t) * STATE_ROW_SIZE);
		}
	}

	return roundKeys;
}

void free_roundKeys(uint8_t*** roundKeys) {

	for (int i = 0; i <= ROUND_COUNT; ++i) {
		for (int j = 0; j < STATE_COL_SIZE; ++j) {
			free(roundKeys[i][j]);
		}
	}


	for (int i = 0; i <= ROUND_COUNT; ++i) {
		free(roundKeys[i]);
	}


	free(roundKeys);
}


void ColumnFill ( uint8_t roundkeys [][STATE_ROW_SIZE][STATE_COL_SIZE] , int round ) {

	uint8_t temp_column[STATE_ROW_SIZE];

	//rot word
	uint8_t temp_value = roundkeys[round][3][0];
	temp_column[0] = roundkeys[round][3][1];
	temp_column[1] = roundkeys[round][3][2];
	temp_column[2] = roundkeys[round][3][3];
	temp_column[3] = temp_value;


	//subBytes
	uint8_t firstByte, secondByte;
	for (int i = 0; i < STATE_COL_SIZE; ++i) {
		firstByte = temp_column[i] >> STATE_ROW_SIZE;
		secondByte = temp_column[i] & 0x0f;
		temp_column[i] = sboxtab[16 * firstByte + secondByte];
	}

	// xor with W_i-4 and Rcon
	roundkeys[round + 1][0][0] = roundkeys[round][0][0] ^ temp_column[0] ^ rcon[round];
	for (int i = 0; i < STATE_ROW_SIZE - 1; ++i) {
		roundkeys[round + 1][0][i + 1] = roundkeys[round][0][i + 1] ^ temp_column[i + 1] ^ 0x00;
	}

}


void OtherColumnsFill ( uint8_t roundkeys [][STATE_ROW_SIZE][STATE_COL_SIZE], int round ) {


	// xor with W_i-4
	for (int i = 1; i < STATE_COL_SIZE; ++i) {

		for (int j = 0; j < STATE_ROW_SIZE; ++j) {
			roundkeys[round + 1][i][j] = roundkeys[round][i][j] ^ roundkeys[round + 1][i - 1][j];
		}

	}


}

void KeyGen ( uint8_t roundkeys [][STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t master_key [STATE_ROW_SIZE][STATE_COL_SIZE]) {

	for (int i = 0; i < STATE_COL_SIZE; ++i) {
		for (int j = 0; j < STATE_ROW_SIZE ; ++j)
		{
			roundkeys[0][i][j] = master_key[i][j];
		}
	}


	for (int round = 0; round < ROUND_COUNT; round++) {
		ColumnFill (roundkeys, round);
		OtherColumnsFill(roundkeys, round);
	}

}


void GetRoundKey ( uint8_t roundkey [STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t roundkeys [][STATE_ROW_SIZE][STATE_COL_SIZE], int round ) {
	for (int i = 0; i < STATE_COL_SIZE; ++i) {
		for (int j = 0; j < STATE_COL_SIZE; ++j) {

			roundkey[i][j] = roundkeys[round][i][j];

		}
	}
}

void AddRoundKey ( uint8_t state [STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t roundkey [STATE_ROW_SIZE][STATE_COL_SIZE]) {

	//xor with the roundkey
	for (int i = 0; i < STATE_COL_SIZE; ++i) {
		for (int j = 0; j < STATE_ROW_SIZE; ++j) {

			state[i][j] ^= roundkey[i][j];

		}
	}
}


void SubBytes ( uint8_t state [STATE_ROW_SIZE][STATE_COL_SIZE]) {

	//subBytes
	uint8_t firstByte, secondByte;
	for (int i = 0; i < STATE_COL_SIZE; ++i) {
		for (int j = 0; j < STATE_ROW_SIZE; ++j) {

			firstByte = state[i][j] >> STATE_ROW_SIZE;
			secondByte = state[i][j] & 0x0f;
			state[i][j] = sboxtab[16 * firstByte + secondByte];

		}
	}

}

void ShiftRows ( uint8_t state [STATE_ROW_SIZE][STATE_COL_SIZE]) {
	uint8_t temp;
	int k = 0; //nombre de rotation à chaque ligne

	//pour chaque j ligne on fait une j rotation
	for (int j = 1; j < STATE_ROW_SIZE; ++j) {
		for (k = 0; k < j; ++k) {
			temp = state[0][j];
			for (int i = 0; i < STATE_COL_SIZE - 1; ++i) {
				state[i][j] = state[i + 1][j];
			}
			state[3][j] = temp;
		}

		k = 0;
	}

}


uint8_t gmul(uint8_t a, uint8_t b) {
	uint8_t p = 0;

	for (int counter = 0; counter < 8; counter++) {
		if ((b & 1) != 0) {
			p ^= a;
		}

		uint8_t hi_bit_set = (a & 0x80) != 0; // on test si le premier bit de a est 1
		a <<= 1;
		if (hi_bit_set) {
			a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
		}
		b >>= 1;
	}

	return p;
}

void MixColumns(uint8_t state [STATE_ROW_SIZE][STATE_COL_SIZE]) {

	uint8_t temp[4];

	for (int i = 0; i < 4; i++) {
		temp[0] = gmul(0x02, state[i][0]) ^ gmul(0x03, state[i][1]) ^ state[i][2] ^ state[i][3];
		temp[1] = state[i][0] ^ gmul(0x02, state[i][1]) ^ gmul(0x03, state[i][2]) ^ state[i][3];
		temp[2] = state[i][0] ^ state[i][1] ^ gmul(0x02, state[i][2]) ^ gmul(0x03, state[i][3]);
		temp[3] = gmul(0x03, state[i][0]) ^ state[i][1] ^ state[i][2] ^ gmul(0x02, state[i][3]);
		state[i][0] = temp[0];
		state[i][1] = temp[1];
		state[i][2] = temp[2];
		state[i][3] = temp[3];
	}

}

void AESEncrypt_state(uint8_t state [STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t roundKeys[][STATE_ROW_SIZE][STATE_COL_SIZE]) {

	AddRoundKey(state, roundKeys[0]);

	for (int round = 0; round < 9; ++round) {
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, roundKeys[round + 1]);
	}

	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, roundKeys[10]);

}

void StateToMessage ( uint8_t message[DATA_SIZE], uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {
	for (int i = 0; i < STATE_COL_SIZE; ++i) {
		for (int j = 0; j < STATE_ROW_SIZE; ++j) {
			message[i * 4 + j] = state[i][j];
		}
	}
}


void MessageToState ( uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t message[DATA_SIZE ]) {


	for (int i = 0; i < STATE_COL_SIZE; ++i) {
		for (int j = 0; j < STATE_ROW_SIZE; ++j) {
			state[i][j] = message[(i * 4) + j];
		}
	}


}


void AESEncrypt ( uint8_t ciphertext[DATA_SIZE], uint8_t plaintext[DATA_SIZE] , uint8_t key [DATA_SIZE]) {

	//state
	uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE];

	//master_key
	uint8_t master_key[STATE_ROW_SIZE][STATE_COL_SIZE]; 


	//Definition of roundKeys
	uint8_t roundKeys[ROUND_COUNT + 1][STATE_ROW_SIZE][STATE_COL_SIZE];

	//format Master key
	MessageToState(master_key, key);
	/*printf("Master key format : \n");
	affiche_state(master_key);
	*/

	//generation of the roundKeys
	KeyGen(roundKeys, master_key);
	//affiche(roundKeys);

	//format plaintext
	MessageToState(state, plaintext);
	/*printf("plaintext format : \n");
	affiche_state(state);*/

	//aes cypher of the state
	AESEncrypt_state(state, roundKeys);
	/*printf("cypher text format : \n");
	affiche_state(state);*/
	//format the ciphertext
	StateToMessage(ciphertext, state);


}