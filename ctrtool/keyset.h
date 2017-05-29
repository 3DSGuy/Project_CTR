#ifndef _KEYSET_H_
#define _KEYSET_H_

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
	KEY_ERR_LEN_MISMATCH,
	KEY_ERR_INVALID_NODE,
	KEY_OK
} keystatus;

typedef enum
{
	RSAKEY_INVALID,
	RSAKEY_PRIV,
	RSAKEY_PUB
} rsakeytype;

typedef struct
{
	u8 title_id[8];
	u8 seed[0x10];
	u8 padding[0x8];
} seeddb_entry;

typedef struct
{
	u8 n_entries[4];
	u8 padding[0xC];
} seeddb_header;


typedef struct
{
	unsigned char n[256];
	unsigned char e[3];
	unsigned char d[256];
	unsigned char p[128];
	unsigned char q[128];
	unsigned char dp[128];
	unsigned char dq[128];
	unsigned char qp[128];
	rsakeytype keytype;
} rsakey2048;

typedef struct
{
	unsigned char data[16];
	int valid;
} key128;

typedef struct
{
	u32 seed_num;
	seeddb_entry* seed_db;

	key128 titlekey;
	key128 commonkeyX;
	key128 commonkeyY_zero;
	key128 ncchfixedsystemkey;
	key128 ncchkeyX_old;
	key128 ncchkeyX_seven;
	key128 ncchkeyX_ninethree;
	key128 ncchkeyX_ninesix;
	rsakey2048 ncsdrsakey;
	rsakey2048 ncchrsakey;
	rsakey2048 ncchdescrsakey;
	rsakey2048 firmrsakey;
} keyset;

void keyset_init(keyset* keys, u32 actions);
int keyset_load(keyset* keys, const char* fname, int verbose);
void keyset_merge(keyset* keys, keyset* src);
void keyset_parse_commonkeyX(keyset* keys, char* keytext, int keylen);
void keyset_parse_commonkeyY_zero(keyset* keys, char* keytext, int keylen);
void keyset_parse_titlekey(keyset* keys, char* keytext, int keylen);
void keyset_parse_ncchkeyX_old(keyset* keys, char* keytext, int keylen);
void keyset_parse_ncchfixedsystemkey(keyset* keys, char* keytext, int keylen);
void keyset_parse_ncchkeyX_seven(keyset* keys, char* keytext, int keylen);
void keyset_parse_ncchkeyX_ninethree(keyset* keys, char* keytext, int keylen);
void keyset_parse_ncchkeyX_ninesix(keyset* keys, char* keytext, int keylen);
void keyset_parse_seeddb(keyset* keys, char* path);
void keyset_dump(keyset* keys);

#ifdef __cplusplus
}
#endif


#endif // _KEYSET_H_
