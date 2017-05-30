#include <stdio.h>
#include "keyset.h"
#include "utils.h"
#include "tinyxml/tinyxml.h"

static void keyset_set_key128(key128* key, unsigned char* keydata);
static void keyset_parse_key128(key128* key, char* keytext, int keylen);
static int keyset_parse_key(const char* text, unsigned int textlen, unsigned char* key, unsigned int size, int* valid);
static int keyset_load_rsakey2048(TiXmlElement* elem, rsakey2048* key);
static int keyset_load_key128(TiXmlHandle node, key128* key);
static int keyset_load_key(TiXmlHandle node, unsigned char* key, unsigned int maxsize, int* valid);

static int ishex(char c)
{
	if (c >= '0' && c <= '9')
		return 1;
	if (c >= 'A' && c <= 'F')
		return 1;
	if (c >= 'a' && c <= 'f')
		return 1;
	return 0;

}

static unsigned char hextobin(char c)
{
	if (c >= '0' && c <= '9')
		return c-'0';
	if (c >= 'A' && c <= 'F')
		return c-'A'+0xA;
	if (c >= 'a' && c <= 'f')
		return c-'a'+0xA;
	return 0;
}

void keyset_init(keyset* keys, u32 actions)
{
	const key128 defaultkeys_retail[] = {
		// common keyX
		{{0x61, 0x70, 0x85, 0x71, 0x9b, 0x7c, 0xfb, 0x31, 0x6d, 0xf4, 0xdf, 0x2e, 0x83, 0x62, 0xc6, 0xe2}, 1},		
		// common keyY 0
		{{0xd0, 0x7b, 0x33, 0x7f, 0x9c, 0xa4, 0x38, 0x59, 0x32, 0xa2, 0xe2, 0x57, 0x23, 0x23, 0x2e, 0xb9}, 1},
		// fixed system key - unknown if used/correct?
		{{0x52, 0x7c, 0xe6, 0x30, 0xa9, 0xca, 0x30, 0x5f, 0x36, 0x96, 0xf3, 0xcd, 0xe9, 0x54, 0x19, 0x4b}, 1},
		// NCCH 0x2c keyX
		{{0xb9, 0x8e, 0x95, 0xce, 0xca, 0x3e, 0x4d, 0x17, 0x1f, 0x76, 0xa9, 0x4d, 0xe9, 0x34, 0xc0, 0x53}, 1},
		// NCCH 0x25 keyX 7.x
		{{0xce, 0xe7, 0xd8, 0xab, 0x30, 0xc0, 0x0d, 0xae, 0x85, 0x0e, 0xf5, 0xe3, 0x82, 0xac, 0x5a, 0xf3}, 1},
		// NCCH 0x18 keyX N9.3
		{{0x82, 0xe9, 0xc9, 0xbe, 0xbf, 0xb8, 0xbd, 0xb8, 0x75, 0xec, 0xc0, 0xa0, 0x7d, 0x47, 0x43, 0x74}, 1},
		// NCCH 0x1B keyX N9.6
		{{0x45, 0xad, 0x04, 0x95, 0x39, 0x92, 0xc7, 0xc8, 0x93, 0x72, 0x4a, 0x9a, 0x7b, 0xce, 0x61, 0x82}, 1}
	};
	const key128 defaultkeys_dev[] = {
		// common keyX
		{{0xbd, 0x4f, 0xe7, 0xe7, 0x33, 0xc7, 0x55, 0xfc, 0xe7, 0x54, 0x0e, 0xab, 0xbd, 0x8a, 0xc3, 0x0d}, 1},
		// common keyY 0
		{{0x85, 0x21, 0x5e, 0x96, 0xcb, 0x95, 0xa9, 0xec, 0xa4, 0xb4, 0xde, 0x60, 0x1c, 0xb5, 0x62, 0xc7}, 1},
		// fixed system key
		{{0x52, 0x7c, 0xe6, 0x30, 0xa9, 0xca, 0x30, 0x5f, 0x36, 0x96, 0xf3, 0xcd, 0xe9, 0x54, 0x19, 0x4b}, 1},
		// NCCH 0x2c keyX
		{{0x51, 0x02, 0x07, 0x51, 0x55, 0x07, 0xcb, 0xb1, 0x8e, 0x24, 0x3d, 0xcb, 0x85, 0xe2, 0x3a, 0x1d}, 1},
		// NCCH 0x25 keyX 7.x
		{{0x81, 0x90, 0x7a, 0x4b, 0x6f, 0x1b, 0x47, 0x32, 0x3a, 0x67, 0x79, 0x74, 0xce, 0x4a, 0xd7, 0x1b}, 1},
		// NCCH 0x18 keyX N9.3
		{{0x30, 0x4b, 0xf1, 0x46, 0x83, 0x72, 0xee, 0x64, 0x11, 0x5e, 0xbd, 0x40, 0x93, 0xd8, 0x42, 0x76}, 1},
		// NCCH 0x1B keyX N9.6
		{{0x6c, 0x8b, 0x29, 0x44, 0xa0, 0x72, 0x60, 0x35, 0xf9, 0x41, 0xdf, 0xc0, 0x18, 0x52, 0x4f, 0xb6}, 1}
	};

	memset(keys, 0, sizeof(keyset));

	if (actions & PlainFlag)
		return;

	if (!(actions & DevFlag)) {
		memcpy(&keys->commonkeyX, &defaultkeys_retail[0], sizeof(key128));
		memcpy(&keys->commonkeyY_zero, &defaultkeys_retail[1], sizeof(key128));
		memcpy(&keys->ncchfixedsystemkey, &defaultkeys_retail[2], sizeof(key128));
		memcpy(&keys->ncchkeyX_old, &defaultkeys_retail[3], sizeof(key128));
		memcpy(&keys->ncchkeyX_seven, &defaultkeys_retail[4], sizeof(key128));
		memcpy(&keys->ncchkeyX_ninethree, &defaultkeys_retail[5], sizeof(key128));
		memcpy(&keys->ncchkeyX_ninesix, &defaultkeys_retail[6], sizeof(key128));
	} else {
		memcpy(&keys->commonkeyX, &defaultkeys_dev[0], sizeof(key128));
		memcpy(&keys->commonkeyY_zero, &defaultkeys_dev[1], sizeof(key128));
		memcpy(&keys->ncchfixedsystemkey, &defaultkeys_dev[2], sizeof(key128));
		memcpy(&keys->ncchkeyX_old, &defaultkeys_dev[3], sizeof(key128));
		memcpy(&keys->ncchkeyX_seven, &defaultkeys_dev[4], sizeof(key128));
		memcpy(&keys->ncchkeyX_ninethree, &defaultkeys_dev[5], sizeof(key128));
		memcpy(&keys->ncchkeyX_ninesix, &defaultkeys_dev[6], sizeof(key128));
	}
}

int keyset_load_key(TiXmlHandle node, unsigned char* key, unsigned int size, int* valid)
{
	TiXmlElement* elem = node.ToElement();

	if (valid)
		*valid = 0;

	if (!elem)
		return 0;

	const char* text = elem->GetText();
	unsigned int textlen = strlen(text);

	int status = keyset_parse_key(text, textlen, key, size, valid);

	if (status == KEY_ERR_LEN_MISMATCH)
	{
		fprintf(stderr, "Error size mismatch for key \"%s/%s\"\n", elem->Parent()->Value(), elem->Value());
		return 0;
	}
	
	return 1;
}


int keyset_parse_key(const char* text, unsigned int textlen, unsigned char* key, unsigned int size, int* valid)
{
	unsigned int i, j;
	unsigned int hexcount = 0;


	if (valid)
		*valid = 0;

	for(i=0; i<textlen; i++)
	{
		if (ishex(text[i]))
			hexcount++;
	}

	if (hexcount != size*2)
	{
		fprintf(stdout, "Error, expected %d hex characters when parsing text \"", size*2);
		for(i=0; i<textlen; i++)
			fprintf(stdout, "%c", text[i]);
		fprintf(stdout, "\"\n");
		
		return KEY_ERR_LEN_MISMATCH;
	}

	for(i=0, j=0; i<textlen; i++)
	{
		if (ishex(text[i]))
		{
			if ( (j&1) == 0 )
				key[j/2] = hextobin(text[i])<<4;
			else
				key[j/2] |= hextobin(text[i]);
			j++;
		}
	}

	if (valid)
		*valid = 1;
	
	return KEY_OK;
}

int keyset_load_key128(TiXmlHandle node, key128* key)
{
	return keyset_load_key(node, key->data, sizeof(key->data), &key->valid);
}

int keyset_load_rsakey2048(TiXmlHandle node, rsakey2048* key)
{
	key->keytype = RSAKEY_INVALID;

	if (!keyset_load_key(node.FirstChild("N"), key->n, sizeof(key->n), 0))
		goto clean;
	if (!keyset_load_key(node.FirstChild("E"), key->e, sizeof(key->e), 0))
		goto clean;
	key->keytype = RSAKEY_PUB;

	if (!keyset_load_key(node.FirstChild("D"), key->d, sizeof(key->d), 0))
		goto clean;
	if (!keyset_load_key(node.FirstChild("P"), key->p, sizeof(key->p), 0))
		goto clean;
	if (!keyset_load_key(node.FirstChild("Q"), key->q, sizeof(key->q), 0))
		goto clean;
	if (!keyset_load_key(node.FirstChild("DP"), key->dp, sizeof(key->dp), 0))
		goto clean;
	if (!keyset_load_key(node.FirstChild("DQ"), key->dq, sizeof(key->dq), 0))
		goto clean;
	if (!keyset_load_key(node.FirstChild("QP"), key->qp, sizeof(key->qp), 0))
		goto clean;

	key->keytype = RSAKEY_PRIV;
clean:
	return (key->keytype != RSAKEY_INVALID);
}

int keyset_load(keyset* keys, const char* fname, int verbose)
{
	TiXmlDocument doc(fname);
	bool loadOkay = doc.LoadFile();

	if (!loadOkay)
	{
		if (verbose)
			fprintf(stderr, "Could not load keyset file \"%s\", error: %s.\n", fname, doc.ErrorDesc() );

		return 0;
	}

	TiXmlHandle root = doc.FirstChild("document");

	keyset_load_rsakey2048(root.FirstChild("ncsdrsakey"), &keys->ncsdrsakey);
	keyset_load_rsakey2048(root.FirstChild("ncchrsakey"), &keys->ncchrsakey);
	keyset_load_rsakey2048(root.FirstChild("ncchdescrsakey"), &keys->ncchdescrsakey);
	keyset_load_rsakey2048(root.FirstChild("firmrsakey"), &keys->firmrsakey);
	keyset_load_key128(root.FirstChild("commonkeyx"), &keys->commonkeyX);
	keyset_load_key128(root.FirstChild("commonkeyyzero"), &keys->commonkeyY_zero);
	keyset_load_key128(root.FirstChild("ncchfixedsystemkey"), &keys->ncchfixedsystemkey);
	keyset_load_key128(root.FirstChild("ncchkeyxold"), &keys->ncchkeyX_old);
	keyset_load_key128(root.FirstChild("ncchkeyxseven"), &keys->ncchkeyX_seven);
	keyset_load_key128(root.FirstChild("ncchkeyxninethree"), &keys->ncchkeyX_ninethree);
	keyset_load_key128(root.FirstChild("ncchkeyxninesix"), &keys->ncchkeyX_ninesix);


	return 1;
}


void keyset_merge(keyset* keys, keyset* src)
{
#define COPY_IF_VALID(v) do {\
	if (src->v.valid && !keys->v.valid)\
		keyset_set_key128(&keys->v, src->v.data);\
} while (0)

	COPY_IF_VALID(titlekey);
	COPY_IF_VALID(commonkeyX);
	COPY_IF_VALID(commonkeyY_zero);
	COPY_IF_VALID(ncchfixedsystemkey);
	COPY_IF_VALID(ncchkeyX_old);
	COPY_IF_VALID(ncchkeyX_seven);
	COPY_IF_VALID(ncchkeyX_ninethree);
	COPY_IF_VALID(ncchkeyX_ninesix);
	if (src->seed_num > 0)
	{
		keys->seed_num = src->seed_num;
		keys->seed_db = (seeddb_entry*)calloc(src->seed_num, sizeof(seeddb_entry));
		memcpy(keys->seed_db, src->seed_db, src->seed_num * sizeof(seeddb_entry));
	}

#undef COPY_IF_VALID
}

void keyset_set_key128(key128* key, unsigned char* keydata)
{
	memcpy(key->data, keydata, 16);
	key->valid = 1;
}

void keyset_parse_key128(key128* key, char* keytext, int keylen)
{
	keyset_parse_key(keytext, keylen, key->data, 16, &key->valid);
}

void keyset_parse_commonkeyX(keyset* keys, char* keytext, int keylen)
{
	keyset_parse_key128(&keys->commonkeyX, keytext, keylen);
}

void keyset_parse_commonkeyY_zero(keyset* keys, char* keytext, int keylen)
{
	keyset_parse_key128(&keys->commonkeyY_zero, keytext, keylen);
}

void keyset_parse_titlekey(keyset* keys, char* keytext, int keylen)
{
	keyset_parse_key128(&keys->titlekey, keytext, keylen);
}

void keyset_parse_ncchkeyX_old(keyset* keys, char* keytext, int keylen)
{
	keyset_parse_key128(&keys->ncchkeyX_old, keytext, keylen);
}

void keyset_parse_ncchfixedsystemkey(keyset* keys, char* keytext, int keylen)
{
	keyset_parse_key128(&keys->ncchfixedsystemkey, keytext, keylen);
}

void keyset_parse_ncchkeyX_seven(keyset* keys, char* keytext, int keylen)
{
	keyset_parse_key128(&keys->ncchkeyX_seven, keytext, keylen);
}

void keyset_parse_ncchkeyX_ninethree(keyset* keys, char* keytext, int keylen)
{
	keyset_parse_key128(&keys->ncchkeyX_ninethree, keytext, keylen);
}

void keyset_parse_ncchkeyX_ninesix(keyset* keys, char* keytext, int keylen)
{
	keyset_parse_key128(&keys->ncchkeyX_ninesix, keytext, keylen);
}

void keyset_parse_seeddb(keyset* keys, char* path)
{
	//keyset_parse_key128(&keys->seed, keytext, keylen);
	FILE* fp = fopen(path, "rb");
	if (fp == NULL)
	{
		printf("[ERROR] Failed to load SeedDB (failed to open file)\n");
		return;
	}

	seeddb_header hdr;
	fread(&hdr, sizeof(seeddb_header), 1, fp);

	keys->seed_num = getle32(hdr.n_entries);
	for (u32 i = 0; i < 0xC; i++)
	{
		if (hdr.padding[i] != 0x00)
		{
			printf("[ERROR] SeedDB is corrupt. (padding malformed)\n");
			return;
		}
	}
	
	keys->seed_db = (seeddb_entry*)calloc(keys->seed_num, sizeof(seeddb_entry));
	fread(keys->seed_db, keys->seed_num * sizeof(seeddb_entry), 1, fp);
}

void keyset_dump_rsakey(rsakey2048* key, const char* keytitle)
{
	if (key->keytype == RSAKEY_INVALID)
		return;


	fprintf(stdout, "%s\n", keytitle);

	memdump(stdout, "Modulus: ", key->n, 256);
	memdump(stdout, "Exponent: ", key->e, 3);

	if (key->keytype == RSAKEY_PRIV)
	{
		memdump(stdout, "P: ", key->p, 128);
		memdump(stdout, "Q: ", key->q, 128);
	}
	fprintf(stdout, "\n");
}

void keyset_dump_key128(key128* key, const char* keytitle)
{
	if (key->valid)
	{
		fprintf(stdout, "%s\n", keytitle);
		memdump(stdout, "", key->data, 16);
		fprintf(stdout, "\n");
	}
}

void keyset_dump(keyset* keys)
{
#define DUMP_KEY(n, s) do {\
	keyset_dump_key128(&keys->n, (s));\
} while(0)
	fprintf(stdout, "Current keyset:          \n");
	DUMP_KEY(ncchkeyX_old, "NCCH OLD KEYX");
	DUMP_KEY(ncchkeyX_seven, "NCCH 7.0 KEYX");
	DUMP_KEY(ncchkeyX_ninethree, "NCCH N9.3 KEYX");
	DUMP_KEY(ncchkeyX_ninesix, "NCCH N9.6 KEYX");
	DUMP_KEY(ncchfixedsystemkey, "NCCH FIXEDSYSTEMKEY");
	DUMP_KEY(commonkeyX, "COMMON KEYX");
	DUMP_KEY(commonkeyY_zero, "COMMON KEYY ZERO");
#undef DUMP_KEY

	keyset_dump_rsakey(&keys->ncsdrsakey, "NCSD RSA KEY");
	keyset_dump_rsakey(&keys->ncchdescrsakey, "NCCH DESC RSA KEY");

	fprintf(stdout, "\n");
}

