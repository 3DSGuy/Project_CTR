#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"
#include "utils.h"
#include "cia.h"
#include <inttypes.h>


void cia_init(cia_context* ctx)
{
	memset(ctx, 0, sizeof(cia_context));

	tik_init(&ctx->tik);
	tmd_init(&ctx->tmd);
}

void cia_set_file(cia_context* ctx, FILE* file)
{
	ctx->file = file;
}

void cia_set_offset(cia_context* ctx, u64 offset)
{
	ctx->offset = offset;
}

void cia_set_size(cia_context* ctx, u64 size)
{
	ctx->size = size;
}


void cia_set_usersettings(cia_context* ctx, settings* usersettings)
{
	ctx->usersettings = usersettings;
}


void cia_save(cia_context* ctx, u32 type, u32 flags)
{
	u64 offset;
	u64 size;
	u16 contentflags;
	u16 contentindex;
	u8 docrypto;
	filepath* path = 0;
	ctr_tmd_body *body;
	ctr_tmd_contentchunk *chunk;
	unsigned int i;
	char tmpname[255];

	switch(type)
	{
		case CIATYPE_CERTS:
			offset = ctx->offsetcerts;
			size = ctx->sizecert;
			path = settings_get_certs_path(ctx->usersettings);
		break;

		case CIATYPE_TIK:
			offset = ctx->offsettik;
			size = ctx->sizetik;
			path = settings_get_tik_path(ctx->usersettings);
		break;

		case CIATYPE_TMD:
			offset = ctx->offsettmd;
			size = ctx->sizetmd;
			path = settings_get_tmd_path(ctx->usersettings);
		break;
		
		case CIATYPE_CONTENT:
			offset = ctx->offsetcontent;
			size = ctx->sizecontent;
			path = settings_get_content_path(ctx->usersettings);
			
		break;

		case CIATYPE_META:
			offset = ctx->offsetmeta;
			size = ctx->sizemeta;
			path = settings_get_meta_path(ctx->usersettings);;
		break;

		default:
			fprintf(stderr, "Error, unknown CIA type specified\n");
			return;	
		break;
	}

	if (path == 0 || path->valid == 0)
		return;

	switch(type)
	{
		case CIATYPE_CERTS: fprintf(stdout, "Saving certs to %s\n", path->pathname); break;
		case CIATYPE_TIK: fprintf(stdout, "Saving tik to %s\n", path->pathname); break;
		case CIATYPE_TMD: fprintf(stdout, "Saving tmd to %s\n", path->pathname); break;
		case CIATYPE_CONTENT:

			body  = tmd_get_body(&ctx->tmd);
			chunk = (ctr_tmd_contentchunk*)(body->contentinfo + (sizeof(ctr_tmd_contentinfo) * TMD_MAX_CONTENTS));

			for(i = 0; i < getbe16(body->contentcount); i++) {
				contentflags = getbe16(chunk->type);
				contentindex = getbe16(chunk->index);
				docrypto = (contentflags & 1) && !(flags & PlainFlag);

				if(ctx->header.contentindex[contentindex >> 3] & (0x80 >> (contentindex & 7))) {
					sprintf(tmpname, "%s.%04x.%08x", path->pathname, contentindex, getbe32(chunk->id));
					fprintf(stdout, "Saving content #%04x to %s\n", contentindex, tmpname);
					
					if(docrypto) // Decrypt if needed
					{
						ctx->iv[0] = (contentindex >> 8) & 0xff;
						ctx->iv[1] = contentindex & 0xff;

						ctr_init_cbc_decrypt(&ctx->aes, ctx->titlekey, ctx->iv);
					}

					cia_save_blob(ctx, tmpname, offset, getbe64(chunk->size) & 0xffffffff, docrypto);

					offset += getbe64(chunk->size) & 0xffffffff;
				}
				chunk++;
			}

			memset(ctx->iv, 0, 16);

			return;
		break;

		case CIATYPE_META: fprintf(stdout, "Saving meta to %s\n", path->pathname); break;
	}

	cia_save_blob(ctx, path->pathname, offset, size, 0);
}

void cia_save_blob(cia_context *ctx, char *out_path, u64 offset, u64 size, int do_cbc) 
{
	FILE *fout = 0;
	u8 buffer[16*1024];

	fseeko64(ctx->file, ctx->offset + offset, SEEK_SET);

	fout = fopen(out_path, "wb");
	if (fout == NULL)
	{
		fprintf(stdout, "Error opening out file %s\n", out_path);
		goto clean;
	}

	while(size)
	{
		u32 max = sizeof(buffer);
		if (max > size)
			max = (u32) size;

		if (max != fread(buffer, 1, max, ctx->file))
		{
			fprintf(stdout, "Error reading file\n");
			goto clean;
		}

		if (do_cbc == 1)
			ctr_decrypt_cbc(&ctx->aes, buffer, buffer, max);

		if (max != fwrite(buffer, 1, max, fout))
		{
			fprintf(stdout, "Error writing file\n");
			goto clean;
		}

		size -= max;
	}

clean:
	if (fout)
		fclose(fout);
}


void cia_process(cia_context* ctx, u32 actions)
{	
	fseeko64(ctx->file, 0, SEEK_SET);

	if (fread(&ctx->header, 1, sizeof(ctr_ciaheader), ctx->file) != sizeof(ctr_ciaheader))
	{
		fprintf(stderr, "Error reading CIA header\n");
		goto clean;
	}

	ctx->sizeheader = getle32(ctx->header.headersize);
	ctx->sizecert = getle32(ctx->header.certsize);
	ctx->sizetik = getle32(ctx->header.ticketsize);
	ctx->sizetmd = getle32(ctx->header.tmdsize);
	ctx->sizecontent = getle64(ctx->header.contentsize);
	ctx->sizemeta = getle32(ctx->header.metasize);
	
	ctx->offsetcerts = align(ctx->sizeheader, 64);
	ctx->offsettik = align((u32) (ctx->offsetcerts + ctx->sizecert), 64);
	ctx->offsettmd = align((u32) (ctx->offsettik + ctx->sizetik), 64);
	ctx->offsetcontent = align((u32) (ctx->offsettmd + ctx->sizetmd), 64);
	ctx->offsetmeta = align64(ctx->offsetcontent + ctx->sizecontent, 64);

	if (actions & InfoFlag)
		cia_print(ctx);


	tik_set_file(&ctx->tik, ctx->file);
	tik_set_offset(&ctx->tik, ctx->offsettik);
	tik_set_size(&ctx->tik, ctx->sizetik);
	tik_set_usersettings(&ctx->tik, ctx->usersettings);

	tik_process(&ctx->tik, actions);
	memset(ctx->iv, 0, 16);
		
	if (tik_get_titlekey(&ctx->tik))
		memcpy(ctx->titlekey, tik_get_titlekey(&ctx->tik), 16);
	else if (settings_get_title_key(ctx->usersettings))
		memcpy(ctx->titlekey, settings_get_title_key(ctx->usersettings), 16);

	tmd_set_file(&ctx->tmd, ctx->file);
	tmd_set_offset(&ctx->tmd, ctx->offsettmd);
	tmd_set_size(&ctx->tmd, ctx->sizetmd);
	tmd_set_usersettings(&ctx->tmd, ctx->usersettings);
	tmd_process(&ctx->tmd, (actions & ~InfoFlag));

	if (actions & VerifyFlag)
	{
		cia_verify_contents(ctx, actions);
	}

	if (actions & InfoFlag || actions & VerifyFlag)
		tmd_print(&ctx->tmd);

	if (actions & ExtractFlag)
	{
		cia_save(ctx, CIATYPE_CERTS, actions);
		cia_save(ctx, CIATYPE_TMD, actions);
		cia_save(ctx, CIATYPE_TIK, actions);
		cia_save(ctx, CIATYPE_META, actions);
		cia_save(ctx, CIATYPE_CONTENT, actions);
	}

clean:
	return;
}

void cia_verify_contents(cia_context *ctx, u32 actions)
{
	u16 contentflags;
	u16 contentindex;
	ctr_tmd_body *body;
	ctr_tmd_contentchunk *chunk;
	u8 *verify_buf;
	u32 content_size=0;
	unsigned i;

	// verify TMD content hashes, requires decryption ..
	body  = tmd_get_body(&ctx->tmd);
	chunk = (ctr_tmd_contentchunk*)(body->contentinfo + (sizeof(ctr_tmd_contentinfo) * TMD_MAX_CONTENTS));

	fseeko64(ctx->file, ctx->offset + ctx->offsetcontent, SEEK_SET);
	for(i = 0; i < getbe16(body->contentcount); i++) 
	{
		contentindex = getbe16(chunk->index);

		if(ctx->header.contentindex[contentindex >> 3] & (0x80 >> (contentindex & 7)))
		{
			content_size = getbe64(chunk->size) & 0xffffffff;

			contentflags = getbe16(chunk->type);

			verify_buf = malloc(content_size);
			fread(verify_buf, content_size, 1, ctx->file);

			if(contentflags & 1 && !(actions & PlainFlag)) // Decrypt if needed
			{
				ctx->iv[0] = (contentindex >> 8) & 0xff;
				ctx->iv[1] = contentindex & 0xff;

				ctr_init_cbc_decrypt(&ctx->aes, ctx->titlekey, ctx->iv);
			
				ctr_decrypt_cbc(&ctx->aes, verify_buf, verify_buf, content_size);
			}

			if (ctr_sha_256_verify(verify_buf, content_size, chunk->hash) == Good)
				ctx->tmd.content_hash_stat[i] = 1;
			else
				ctx->tmd.content_hash_stat[i] = 2;

			free(verify_buf);
		}
		chunk++;
	}
}

void cia_print(cia_context* ctx)
{
	ctr_ciaheader* header = &ctx->header;

	fprintf(stdout, "Header size             0x%08x\n", getle32(header->headersize));
	fprintf(stdout, "Type                    %04x\n", getle16(header->type));
	fprintf(stdout, "Version                 %04x\n", getle16(header->version));
	fprintf(stdout, "Certificates offset:    0x%"PRIx64"\n", ctx->offsetcerts);
	fprintf(stdout, "Certificates size:      0x%x\n", ctx->sizecert);
	fprintf(stdout, "Ticket offset:          0x%"PRIx64"\n", ctx->offsettik);
	fprintf(stdout, "Ticket size             0x%x\n", ctx->sizetik);
	fprintf(stdout, "TMD offset:             0x%"PRIx64"\n", ctx->offsettmd);
	fprintf(stdout, "TMD size:               0x%x\n", ctx->sizetmd);
	fprintf(stdout, "Meta offset:            0x%"PRIx64"\n", ctx->offsetmeta);
	fprintf(stdout, "Meta size:              0x%x\n", ctx->sizemeta);
	fprintf(stdout, "Content offset:         0x%"PRIx64"\n", ctx->offsetcontent);
	fprintf(stdout, "Content size:           0x%"PRIx64"\n", ctx->sizecontent);
}
