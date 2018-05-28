#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "types.h"
#include "ncch.h"
#include "utils.h"
#include "ctr.h"
#include "settings.h"
#include "aes_keygen.h"
#include <inttypes.h>

static int programid_is_system(u8 programid[8])
{
	u32 hiprogramid = getle32(programid+4);
	
	if ( ((hiprogramid >> 14) == 0x10) && (hiprogramid & 0x10) )
		return 1;
	else
		return 0;
}


void ncch_init(ncch_context* ctx)
{
	memset(ctx, 0, sizeof(ncch_context));
	exefs_init(&ctx->exefs);
}

void ncch_set_usersettings(ncch_context* ctx, settings* usersettings)
{
	ctx->usersettings = usersettings;
}

void ncch_set_offset(ncch_context* ctx, u64 offset)
{
	ctx->offset = offset;
}

void ncch_set_size(ncch_context* ctx, u64 size)
{
	ctx->size = size;
}

void ncch_set_file(ncch_context* ctx, FILE* file)
{
	ctx->file = file;
}

void ncch_get_counter(ncch_context* ctx, u8 counter[16], u8 type)
{
	u32 version = getle16(ctx->header.version);
	u32 mediaunitsize = (u32) ncch_get_mediaunit_size(ctx);
	u8* titleid = ctx->header.titleid;
	u32 i;
	u64 x = 0;

	memset(counter, 0, 16);

	if (version == 2 || version == 0)
	{
		for(i=0; i<8; i++)
			counter[i] = titleid[7-i];
		counter[8] = type;
	}
	else if (version == 1)
	{
		if (type == NCCHTYPE_EXHEADER)
			x = 0x200;
		else if (type == NCCHTYPE_EXEFS)
			x = getle32(ctx->header.exefsoffset) * mediaunitsize;
		else if (type == NCCHTYPE_ROMFS)
			x = getle32(ctx->header.romfsoffset) * mediaunitsize;

		for(i=0; i<8; i++)
			counter[i] = titleid[i];
		for(i=0; i<4; i++)
			counter[12+i] = (u8) (x>>((3-i)*8));
	}
}


/* this is broken */
int ncch_extract_prepare(ncch_context* ctx, u32 type, u32 flags)
{
	u64 offset = 0;
	u64 size = 0;
	u8 counter[16];


	switch(type)
	{	
		case NCCHTYPE_EXEFS:
		{
			offset = ncch_get_exefs_offset(ctx);
			size = ncch_get_exefs_size(ctx);
			ctr_init_key(&ctx->aes, ctx->key[0]);
		}
		break;

		case NCCHTYPE_ROMFS:
		{
			offset = ncch_get_romfs_offset(ctx);
			size = ncch_get_romfs_size(ctx);
			ctr_init_key(&ctx->aes, ctx->key[1]);
		}
		break;

		case NCCHTYPE_EXHEADER:
		{
			offset = ncch_get_exheader_offset(ctx);
			size = ncch_get_exheader_size(ctx) * 2;
			ctr_init_key(&ctx->aes, ctx->key[0]);
		}
		break;
	
		case NCCHTYPE_LOGO:
		{
			offset = ncch_get_logo_offset(ctx);
			size = ncch_get_logo_size(ctx);
		}
		break;

		case NCCHTYPE_PLAINRGN:
		{
			offset = ncch_get_plainrgn_offset(ctx);
			size = ncch_get_plainrgn_size(ctx);
		}
		break;

		default:
		{
			fprintf(stderr, "Error invalid NCCH type\n");
			goto clean;
		}
		break;
	}

	ctx->extractsize = size;
	ctx->extractflags = flags;
	fseeko64(ctx->file, offset, SEEK_SET);
	ncch_get_counter(ctx, counter, type);
	
	ctr_init_counter(&ctx->aes, counter);

	return 1;

clean:
	return 0;
}

int ncch_extract_buffer(ncch_context* ctx, u8* buffer, u32 buffersize, u32* outsize, u8 nocrypto)
{
	u32 read_len = buffersize;

	if (read_len > ctx->extractsize)
		read_len = (u32) ctx->extractsize;

	*outsize = read_len;

	if (ctx->extractsize)
	{
		if (read_len != fread(buffer, 1, read_len, ctx->file))
		{
			fprintf(stdout, "Error reading input file\n");
			goto clean;
		}

		if (ctx->encrypted && !nocrypto)
			ctr_crypt_counter(&ctx->aes, buffer, buffer, read_len);

		ctx->extractsize -= read_len;
	}

	return 1;

clean:
	return 0;
}

void ncch_save(ncch_context* ctx, u32 type, u32 flags)
{
	FILE* fout = 0;
	filepath* path = 0;
	u8 buffer[16*1024];
	exefs_header exefs_hdr;


	if (0 == ncch_extract_prepare(ctx, type, flags))
		goto clean;

	switch(type)
	{	
		case NCCHTYPE_EXEFS: path = settings_get_exefs_path(ctx->usersettings); break;
		case NCCHTYPE_ROMFS: path = settings_get_romfs_path(ctx->usersettings); break;
		case NCCHTYPE_EXHEADER: path = settings_get_exheader_path(ctx->usersettings); break;
		case NCCHTYPE_LOGO: path = settings_get_logo_path(ctx->usersettings); break;
		case NCCHTYPE_PLAINRGN: path = settings_get_plainrgn_path(ctx->usersettings); break;
	}

	if (path == 0 || path->valid == 0)
		goto clean;

	fout = fopen(path->pathname, "wb");
	if (0 == fout)
	{
		fprintf(stdout, "Error opening out file %s\n", path->pathname);
		goto clean;
	}

	switch(type)
	{
		case NCCHTYPE_EXEFS: fprintf(stdout, "Saving ExeFS...\n"); break;
		case NCCHTYPE_ROMFS: fprintf(stdout, "Saving RomFS...\n"); break;
		case NCCHTYPE_EXHEADER: fprintf(stdout, "Saving Extended Header...\n"); break;
		case NCCHTYPE_LOGO: fprintf(stdout, "Saving Logo...\n"); break;
		case NCCHTYPE_PLAINRGN: fprintf(stdout, "Saving Plain Region...\n"); break;
	}

	// special crypto considerations for exefs when two keys are used
	if (type == NCCHTYPE_EXEFS && ctx->header.flags[3] > 0 && ctx->encrypted)
	{
		u32 read_len;

		// read header
		if (0 == ncch_extract_buffer(ctx, (u8*)&exefs_hdr, sizeof(exefs_hdr), &read_len, 0))
			goto clean;

		if (read_len != fwrite(&exefs_hdr, 1, read_len, fout))
		{
			fprintf(stdout, "Error writing output file\n");
			goto clean;
		}

		for (int i = 0; i < 8; i++)
		{
			
			// get section size
			u32 section_size = getle32(exefs_hdr.section[i].size);
			u32 section_padding = align(section_size, 0x200)-section_size;

			// skip empty sections
			if (section_size == 0)
				continue;

			// select correct key
			if (strncmp((char*)exefs_hdr.section[i].name, "icon", 8) == 0 || strncmp((char*)exefs_hdr.section[i].name, "banner", 8) == 0)
				ctr_init_key(&ctx->aes, ctx->key[0]);
			else
				ctr_init_key(&ctx->aes, ctx->key[1]);

			// set counter
			u8 ctr[16];
			ncch_get_counter(ctx, ctr, NCCHTYPE_EXEFS);
			ctr_init_counter(&ctx->aes, ctr);
			ctr_add_counter(&ctx->aes, (getle32(exefs_hdr.section[i].offset) + sizeof(exefs_header)) / 0x10);

			// extract data
			while (section_size > 0)
			{
				read_len = sizeof(buffer);
				if (read_len > section_size)
					read_len = section_size;


				if (read_len != fread(buffer, 1, read_len, ctx->file))
				{
					fprintf(stdout, "Error reading input file\n");
					goto clean;
				}

				ctr_crypt_counter(&ctx->aes, buffer, buffer, read_len);

				if (read_len != fwrite(buffer, 1, read_len, fout))
				{
					fprintf(stdout, "Error writing output file\n");
					goto clean;
				}


				section_size -= read_len;
			}

			// skip the padding
			if (section_padding)
			{
				fseeko64(ctx->file, section_padding, SEEK_CUR);
				memset(buffer, 0, section_padding);
				if (section_padding != fwrite(buffer, 1, section_padding, fout))
				{
					fprintf(stdout, "Error writing output file\n");
					goto clean;
				}

			}

			ctx->extractsize -= section_size + section_padding;
		}
	}
	else
	{
		while (1)
		{
			u32 read_len;

			if (0 == ncch_extract_buffer(ctx, buffer, sizeof(buffer), &read_len, (type == NCCHTYPE_LOGO || type == NCCHTYPE_PLAINRGN)))
				goto clean;

			if (read_len == 0)
				break;

			if (read_len != fwrite(buffer, 1, read_len, fout))
			{
				fprintf(stdout, "Error writing output file\n");
				goto clean;
			}
		}
	}
	
clean:
	if (fout)
		fclose(fout);
	return;
}

void ncch_verify(ncch_context* ctx, u32 flags)
{
	u32 mediaunitsize = (u32) ncch_get_mediaunit_size(ctx);
	u32 exefshashregionsize = getle32(ctx->header.exefshashregionsize) * mediaunitsize;
	u32 romfshashregionsize = getle32(ctx->header.romfshashregionsize) * mediaunitsize;
	u32 exheaderhashregionsize = getle32(ctx->header.extendedheadersize);
	u32 logohashregionsize = getle32(ctx->header.logosize) * mediaunitsize;
	u8* exefshashregion = 0;
	u8* romfshashregion = 0;
	u8* exheaderhashregion = 0;
	u8* logohashregion = 0;
	u8* tmphash = 0;
	rsakey2048 ncchrsakey;

	if (exefshashregionsize >= SIZE_128MB || romfshashregionsize >= SIZE_128MB || exheaderhashregionsize >= SIZE_128MB || logohashregionsize >= SIZE_128MB)
		goto clean;

	exefshashregion = malloc(exefshashregionsize);
	romfshashregion = malloc(romfshashregionsize);
	exheaderhashregion = malloc(exheaderhashregionsize);
	logohashregion = malloc(logohashregionsize);


	if (ctx->usersettings)
	{
		if ( (ctx->header.flags[5] & 3) == 1)
			ctx->headersigcheck = ncch_signature_verify(ctx, &ctx->usersettings->keys.ncchrsakey);
		else 
		{
			ctr_rsa_init_key_pubmodulus(&ncchrsakey, ctx->exheader.header.accessdesc.ncchpubkeymodulus);
			ctx->headersigcheck =  ncch_signature_verify(ctx, &ncchrsakey);
		}
	}

	if (exefshashregionsize)
	{
		if (0 == ncch_extract_prepare(ctx, NCCHTYPE_EXEFS, flags))
			goto clean;
		if (0 == ncch_extract_buffer(ctx, exefshashregion, exefshashregionsize, &exefshashregionsize,0))
			goto clean;
		ctx->exefshashcheck = ctr_sha_256_verify(exefshashregion, exefshashregionsize, ctx->header.exefssuperblockhash);
	}
	if (romfshashregionsize)
	{
		if (0 == ncch_extract_prepare(ctx, NCCHTYPE_ROMFS, flags))
			goto clean;
		if (0 == ncch_extract_buffer(ctx, romfshashregion, romfshashregionsize, &romfshashregionsize,0))
			goto clean;
		ctx->romfshashcheck = ctr_sha_256_verify(romfshashregion, romfshashregionsize, ctx->header.romfssuperblockhash);
	}
	if (exheaderhashregionsize)
	{
		if (0 == ncch_extract_prepare(ctx, NCCHTYPE_EXHEADER, flags))
			goto clean;
		if (0 == ncch_extract_buffer(ctx, exheaderhashregion, exheaderhashregionsize, &exheaderhashregionsize,0))
			goto clean;
		ctx->exheaderhashcheck = ctr_sha_256_verify(exheaderhashregion, exheaderhashregionsize, ctx->header.extendedheaderhash);
	}
	if (logohashregionsize)
	{
		if (0 == ncch_extract_prepare(ctx, NCCHTYPE_LOGO, flags))
			goto clean;
		if (0 == ncch_extract_buffer(ctx, logohashregion, logohashregionsize, &logohashregionsize,1))
			goto clean;
		ctx->logohashcheck = ctr_sha_256_verify(logohashregion, logohashregionsize, ctx->header.logohash);
	}


	free(exefshashregion);
	free(romfshashregion);
	free(exheaderhashregion);
	free(logohashregion);
clean:
	return;
}


void ncch_process(ncch_context* ctx, u32 actions)
{
	u8 exheadercounter[16];
	u8 exefscounter[16];
	u8 romfscounter[16];
	int result = 1;


	fseeko64(ctx->file, ctx->offset, SEEK_SET);
	fread(&ctx->header, 1, 0x200, ctx->file);

	if (getle32(ctx->header.magic) != MAGIC_NCCH)
	{
		fprintf(stdout, "Error, NCCH segment corrupted\n");
		return;
	}

	if (getle32(ctx->header.extendedheadersize) != 0x400)
	{
		fprintf(stdout, "Error, exheader is 0x%02x bytes long, expected 0x0400\n", getle32(ctx->header.extendedheadersize));
		return;
	}

	ncch_determine_key(ctx, actions);

	ncch_get_counter(ctx, exheadercounter, NCCHTYPE_EXHEADER);
	ncch_get_counter(ctx, exefscounter, NCCHTYPE_EXEFS);
	ncch_get_counter(ctx, romfscounter, NCCHTYPE_ROMFS);

	if (actions & ShowKeysFlag)
	{
		fprintf(stdout, "Counter(s):\n");
		memdump(stdout, "  exheader: ", exheadercounter, 0x10);
		memdump(stdout, "  ExeFS: ", exefscounter, 0x10);
		memdump(stdout, "  RomFS: ", romfscounter, 0x10);
	}


	exheader_set_file(&ctx->exheader, ctx->file);
	exheader_set_offset(&ctx->exheader, ncch_get_exheader_offset(ctx) );
	exheader_set_size(&ctx->exheader, ncch_get_exheader_size(ctx) );
	exheader_set_usersettings(&ctx->exheader, ctx->usersettings);
	exheader_set_titleid(&ctx->exheader, ctx->header.titleid);
	exheader_set_programid(&ctx->exheader, ctx->header.programid);
	exheader_set_hash(&ctx->exheader, ctx->header.extendedheaderhash);
	exheader_set_counter(&ctx->exheader, exheadercounter);
	exheader_set_key(&ctx->exheader, ctx->key[0]);
	exheader_set_encrypted(&ctx->exheader, ctx->encrypted);

	exefs_set_file(&ctx->exefs, ctx->file);
	exefs_set_offset(&ctx->exefs, ncch_get_exefs_offset(ctx) );
	exefs_set_size(&ctx->exefs, ncch_get_exefs_size(ctx) );
	exefs_set_titleid(&ctx->exefs, ctx->header.titleid);
	exefs_set_usersettings(&ctx->exefs, ctx->usersettings);
	exefs_set_counter(&ctx->exefs, exefscounter);
	exefs_set_keys(&ctx->exefs, ctx->key[0], ctx->key[1]);
	exefs_set_encrypted(&ctx->exefs, ctx->encrypted);

	romfs_set_file(&ctx->romfs, ctx->file);
	romfs_set_offset(&ctx->romfs, ncch_get_romfs_offset(ctx));
	romfs_set_size(&ctx->romfs, ncch_get_romfs_size(ctx));
	romfs_set_usersettings(&ctx->romfs, ctx->usersettings);
	romfs_set_counter(&ctx->romfs, romfscounter);
	romfs_set_key(&ctx->romfs, ctx->key[1]);
	romfs_set_encrypted(&ctx->romfs, ctx->encrypted);

	exheader_read(&ctx->exheader, actions);


	if (actions & VerifyFlag)
		ncch_verify(ctx, actions);

	if (actions & InfoFlag)
		ncch_print(ctx);		

	if (ctx->encrypted == NCCHCRYPTO_BROKEN)
	{
		fprintf(stderr, "Error, NCCH encryption broken.\n");
		return;
	}

	if ((actions & ShowKeysFlag) && ctx->encrypted)
	{
		fprintf(stdout, "Using key(s):\n");
		if (ctx->encrypted == NCCHCRYPTO_FIXED)
		{
			memdump(stdout, "  Key:  ", ctx->key[0], 0x10);
		}
		else
		{
			memdump(stdout, "  0x2C: ", ctx->key[0], 0x10);
			if (memcmp(ctx->key[0], ctx->key[1], 0x10) != 0)
			{
				fprintf(stdout, "  special (%02x): ", ctx->header.flags[3]);
				memdump(stdout, "", ctx->key[1], 0x10);
			}
		}
	}

	if (actions & ExtractFlag)
	{
		ncch_save(ctx, NCCHTYPE_EXEFS, actions);
		ncch_save(ctx, NCCHTYPE_ROMFS, actions);
		ncch_save(ctx, NCCHTYPE_EXHEADER, actions);
		ncch_save(ctx, NCCHTYPE_LOGO, actions);
		ncch_save(ctx, NCCHTYPE_PLAINRGN, actions);
	}


	if (result && ncch_get_exheader_size(ctx))
	{
		if (!exheader_hash_valid(&ctx->exheader))
			return;

		result = exheader_process(&ctx->exheader, actions);
	} 

	if (result && ncch_get_exefs_size(ctx))
	{
		if(ncch_get_exheader_size(ctx))
			exefs_set_compressedflag(&ctx->exefs, exheader_get_compressedflag(&ctx->exheader));
		exefs_process(&ctx->exefs, actions);
	}

	if (result && ncch_get_romfs_size(ctx))
	{
		romfs_process(&ctx->romfs, actions);
	}
}

int ncch_signature_verify(ncch_context* ctx, rsakey2048* key)
{
	u8 hash[0x20];

	ctr_sha_256(ctx->header.magic, 0x100, hash);
	return ctr_rsa_verify_hash(ctx->header.signature, hash, key);
}


u64 ncch_get_exefs_offset(ncch_context* ctx)
{
	return ctx->offset + getle32(ctx->header.exefsoffset) * ncch_get_mediaunit_size(ctx);
}

u64 ncch_get_exefs_size(ncch_context* ctx)
{
	return getle32(ctx->header.exefssize) * ncch_get_mediaunit_size(ctx);
}

u64 ncch_get_romfs_offset(ncch_context* ctx)
{
	return ctx->offset + getle32(ctx->header.romfsoffset) * ncch_get_mediaunit_size(ctx);
}

u64 ncch_get_romfs_size(ncch_context* ctx)
{
	return getle32(ctx->header.romfssize) * ncch_get_mediaunit_size(ctx);
}

u64 ncch_get_exheader_offset(ncch_context* ctx)
{
	return ctx->offset + 0x200;
}

u64 ncch_get_exheader_size(ncch_context* ctx)
{
	return getle32(ctx->header.extendedheadersize);
}

u64 ncch_get_logo_offset(ncch_context* ctx)
{
	return ctx->offset + getle32(ctx->header.logooffset) * ncch_get_mediaunit_size(ctx);
}

u64 ncch_get_logo_size(ncch_context* ctx)
{
	return getle32(ctx->header.logosize) * ncch_get_mediaunit_size(ctx);
}

u64 ncch_get_plainrgn_offset(ncch_context* ctx)
{
	return ctx->offset + getle32(ctx->header.plainregionoffset) * ncch_get_mediaunit_size(ctx);
}

u64 ncch_get_plainrgn_size(ncch_context* ctx)
{
	return getle32(ctx->header.plainregionsize) * ncch_get_mediaunit_size(ctx);
}


u64 ncch_get_mediaunit_size(ncch_context* ctx)
{
	unsigned int mediaunitsize = settings_get_mediaunit_size(ctx->usersettings);

	if (mediaunitsize == 0)
	{
		unsigned short version = getle16(ctx->header.version);
		if (version == 1)
			mediaunitsize = 1;
		else if (version == 2 || version == 0)
			mediaunitsize = 1 << (ctx->header.flags[6] + 9);
	}

	return mediaunitsize;
}


void ncch_determine_key(ncch_context* ctx, u32 actions)
{
	u8 exheader_buffer[0x400];
	u8 seedbuf[0x20];
	u8* seed;
	u8* keyX = NULL;
	u8 hash[0x20];
	ctr_ncchheader* header = &ctx->header;	
	struct sNcchKeyslot
	{
		u8 x[0x10];
		u8 y[0x10];
		u8 key[0x10];
	} key[2];


	// Check if the NCCH is already decrypted, by checking if the exheader hash matches
	// Otherwise, use determination rules
	fseeko64(ctx->file, ncch_get_exheader_offset(ctx), SEEK_SET);
	memset(exheader_buffer, 0, 0x400);
	fread(exheader_buffer, 1, 0x400, ctx->file);
	ctr_sha_256(exheader_buffer, 0x400, hash);
	if (!memcmp(hash, header->extendedheaderhash, 32))
	{
		// exheader hash matches, so probably decrypted
		ctx->encrypted = NCCHCRYPTO_NONE;
		if (!(header->flags[7] & 4))
			fprintf(stderr, "Warning, exheader is decrypted but the NCCH says it isn't.\n"
				"This NCCH will likely break on console.\n");
		return;
	}

	// if not plain flag set and not ncch unencrypted flag set
	// determine the keys
	if (!(actions & PlainFlag) && !(header->flags[7] & 4))
	{
		// fixed key crypto
		if (header->flags[7] & 1)
		{
			ctx->encrypted = NCCHCRYPTO_FIXED;
			if (programid_is_system(header->programid))
			{
				if (settings_get_ncch_fixedsystemkey(ctx->usersettings) == NULL)
				{
					fprintf(stderr, "Error, could not read system fixed key.\n");
					ctx->encrypted = NCCHCRYPTO_BROKEN;
					return;
				}

				memcpy(key[0].key, settings_get_ncch_fixedsystemkey(ctx->usersettings), 0x10);
			}
			else
			{
				memset(key[0].key, 0x00, 0x10);
			}

			memcpy(key[1].key, key[0].key, 0x10);
		}
		// secure crypto
		else
		{
			ctx->encrypted = NCCHCRYPTO_SECURE;
			if (settings_get_ncchkeyX_old(ctx->usersettings) == NULL)
			{
				fprintf(stderr, "Error, could not read NCCH base keyX.\n");
				ctx->encrypted = NCCHCRYPTO_BROKEN;
				return;
			}

			// setup regular keyslot seeds (exheader, exefs:icon|banner)
			memcpy(key[0].x, settings_get_ncchkeyX_old(ctx->usersettings), 0x10);
			memcpy(key[0].y, header->signature, 0x10);

			// setup second keyslot seed (romfs, exefs:!(icon|banner))
			// - get keyX

			switch (header->flags[3])
			{
			case(0):
				keyX = settings_get_ncchkeyX_old(ctx->usersettings);
				break;
			case(1):
				keyX = settings_get_ncchkeyX_seven(ctx->usersettings);
				break;
			case(10):
				keyX = settings_get_ncchkeyX_ninethree(ctx->usersettings);
				break;
			case(11):
				keyX = settings_get_ncchkeyX_ninesix(ctx->usersettings);
				break;
			default:
				fprintf(stderr, "Warning, unknown NCCH crypto method.\n");
				ctx->encrypted = NCCHCRYPTO_BROKEN;
				return;
			}

			if (keyX == NULL)
			{
				fprintf(stderr, "Error, could not read NCCH keyX.\n");
				ctx->encrypted = NCCHCRYPTO_BROKEN;
				return;
			}

			memcpy(key[1].x, keyX, 0x10);

			// - get keyY
			if (header->flags[7] & 0x20)
			{
				seed = settings_get_seed(ctx->usersettings, getle64(header->programid));
				if (!seed)
				{
					fprintf(stderr, "This title uses seed crypto, but no seed is set, unable to decrypt.\n"
						"Use -p to avoid decryption or use --seeddb=dbfile or --seed=SEEDHERE.\n");
					ctx->encrypted = NCCHCRYPTO_BROKEN;
					return;
				}

				memcpy(seedbuf, seed, 0x10);
				// Assumes running on little endian
				memcpy(seedbuf + 0x10, header->programid, sizeof(header->programid));
				ctr_sha_256(seedbuf, 0x18, hash);
				if (memcmp(hash, header->seedcheck, sizeof(header->seedcheck))) {
					fprintf(stderr, "Seed check mismatch. (Got: %02x%02x%02x%02x, expected: %02x%02x%02x%02x)\n",
						hash[0], hash[1], hash[2], hash[3],
						header->seedcheck[0], header->seedcheck[1], header->seedcheck[2], header->seedcheck[3]);
					ctx->encrypted = NCCHCRYPTO_BROKEN;
					return;
				}

				memcpy(seedbuf, header->signature, 0x10);
				memcpy(seedbuf + 0x10, seed, 0x10);
				ctr_sha_256(seedbuf, 0x20, hash);
				memcpy(key[1].y, hash, 0x10);
			}
			else
			{
				memcpy(key[1].y, key[0].y, 0x10);
			}


			// generate keys
			ctr_aes_keygen(key[0].x, key[0].y, key[0].key);
			ctr_aes_keygen(key[1].x, key[1].y, key[1].key);
		}

		// save keys
		memcpy(ctx->key[0], key[0].key, 0x10);
		memcpy(ctx->key[1], key[1].key, 0x10);
	}
	else
	{
		ctx->encrypted = NCCHCRYPTO_NONE;
	}
}

static const char* formtypetostring(unsigned char flags)
{
	unsigned char formtype = flags & 3;

	switch(formtype)
	{
	case 0: return "Not assigned";
	case 1: return "Simple content";
	case 2: return "Executable content without RomFS";
	case 3: return "Executable content";
	default: return "Unknown";
	}
}

static const char* contenttypetostring(unsigned char flags)
{
	unsigned char contenttype = flags>>2;

	switch(contenttype)
	{
	case 0: return "Application";
	case 1: return "System Update";
	case 2: return "Manual";
	case 3: return "Child";
	case 4: return "Trial";
	case 5: return "Extended System Update";
	default: return "Unknown";
	}
}

static const char* contentplatformtostring(unsigned char platform)
{
	switch (platform)
	{
	case 1: return "CTR";
	case 2: return "SNAKE";
	default: return "Unknown";
	}
}



void ncch_print(ncch_context* ctx)
{
	ctr_ncchheader *header = &ctx->header;
	u64 offset = ctx->offset;
	u64 mediaunitsize = ncch_get_mediaunit_size(ctx);

	fprintf(stdout, "\nNCCH:\n");

	fprintf(stdout, "Header:                 %.4s\n", header->magic);
	if (ctx->headersigcheck == Unchecked)
		memdump(stdout, "Signature:              ", header->signature, 0x100);
	else if (ctx->headersigcheck == Good)
		memdump(stdout, "Signature (GOOD):       ", header->signature, 0x100);
	else
		memdump(stdout, "Signature (FAIL):       ", header->signature, 0x100);
	fprintf(stdout, "Content size:           0x%08"PRIx64"\n", getle32(header->contentsize)*mediaunitsize);
	fprintf(stdout, "Title id:               %016"PRIx64"\n", getle64(header->titleid));
	fprintf(stdout, "Maker code:             %.2s\n", header->makercode);
	fprintf(stdout, "Version:                %d\n", getle16(header->version));
	fprintf(stdout, "Title seed check:       %08x\n", getle32(header->seedcheck));
	fprintf(stdout, "Program id:             %016"PRIx64"\n", getle64(header->programid));
	if(ctx->logohashcheck == Unchecked)
		memdump(stdout, "Logo hash:              ", header->logohash, 0x20);
	else if(ctx->logohashcheck == Good)
		memdump(stdout, "Logo hash (GOOD):       ", header->logohash, 0x20);
	else
		memdump(stdout, "Logo hash (FAIL):       ", header->logohash, 0x20);
	fprintf(stdout, "Product code:           %.16s\n", header->productcode);
	fprintf(stdout, "Exheader size:          00000400\n"); //this is always the same
	if (ctx->exheaderhashcheck == Unchecked)
		memdump(stdout, "Exheader hash:          ", header->extendedheaderhash, 0x20);
	else if (ctx->exheaderhashcheck == Good)
		memdump(stdout, "Exheader hash (GOOD):   ", header->extendedheaderhash, 0x20);
	else
		memdump(stdout, "Exheader hash (FAIL):   ", header->extendedheaderhash, 0x20);
	fprintf(stdout, "Flags:                  %016"PRIx64"\n", getle64(header->flags));
	fprintf(stdout, " > Mediaunit size:      0x%x\n", (u32)mediaunitsize);
	if (header->flags[7] & 4)
		fprintf(stdout, " > Crypto key:          None\n");
	else if (header->flags[7] & 1)
		fprintf(stdout, " > Crypto key:          %s\n", programid_is_system(header->programid)? "Fixed":"Zeros");
	else
		fprintf(stdout, " > Crypto key:          Secure (%d)%s\n", header->flags[3], header->flags[7] & 32? " (KeyY seeded)" : "");
	fprintf(stdout, " > Form type:           %s\n", formtypetostring(header->flags[5]));
	fprintf(stdout, " > Content type:        %s\n", contenttypetostring(header->flags[5]));
	fprintf(stdout, " > Content platform:    %s\n", contentplatformtostring(header->flags[4]));
	if (header->flags[7] & 2)
		fprintf(stdout, " > No RomFS mount\n");


	fprintf(stdout, "Plain region offset:    0x%08"PRIx64"\n", getle32(header->plainregionsize)? offset+getle32(header->plainregionoffset)*mediaunitsize : 0);
	fprintf(stdout, "Plain region size:      0x%08"PRIx64"\n", getle32(header->plainregionsize)*mediaunitsize);
	fprintf(stdout, "Logo offset:            0x%08"PRIx64"\n", getle32(header->logosize)? offset+getle32(header->logooffset)*mediaunitsize : 0);
	fprintf(stdout, "Logo size:              0x%08"PRIx64"\n", getle32(header->logosize)*mediaunitsize);
	fprintf(stdout, "ExeFS offset:           0x%08"PRIx64"\n", getle32(header->exefssize)? offset+getle32(header->exefsoffset)*mediaunitsize : 0);
	fprintf(stdout, "ExeFS size:             0x%08"PRIx64"\n", getle32(header->exefssize)*mediaunitsize);
	fprintf(stdout, "ExeFS hash region size: 0x%08"PRIx64"\n", getle32(header->exefshashregionsize)*mediaunitsize);
	fprintf(stdout, "RomFS offset:           0x%08"PRIx64"\n", getle32(header->romfssize)? offset+getle32(header->romfsoffset)*mediaunitsize : 0);
	fprintf(stdout, "RomFS size:             0x%08"PRIx64"\n", getle32(header->romfssize)*mediaunitsize);
	fprintf(stdout, "RomFS hash region size: 0x%08"PRIx64"\n", getle32(header->romfshashregionsize)*mediaunitsize);
	if (ctx->exefshashcheck == Unchecked)
		memdump(stdout, "ExeFS Hash:             ", header->exefssuperblockhash, 0x20);
	else if (ctx->exefshashcheck == Good)
		memdump(stdout, "ExeFS Hash (GOOD):      ", header->exefssuperblockhash, 0x20);
	else
		memdump(stdout, "ExeFS Hash (FAIL):      ", header->exefssuperblockhash, 0x20);
	if (ctx->romfshashcheck == Unchecked)
		memdump(stdout, "RomFS Hash:             ", header->romfssuperblockhash, 0x20);
	else if (ctx->romfshashcheck == Good)
		memdump(stdout, "RomFS Hash (GOOD):      ", header->romfssuperblockhash, 0x20);
	else
		memdump(stdout, "RomFS Hash (FAIL):      ", header->romfssuperblockhash, 0x20);
}
