#pragma once
#include "cia.h"

// Enums
typedef enum
{
	CIA_NO_NCCH0 = -1,
	CIA_INVALID_NCCH0 = -2,
	CIA_CONFILCTING_CONTENT_IDS = -3,
} cia_errors;

typedef struct
{
	u8 *inFile;
	u64 inFileSize;

	FILE *out;
	
	rsf_settings *rsf;
	keys_struct *keys;

	bool verbose;
	
	struct{
		bool useCxiRemasterVersion;
		u64 titleId;
		u16 titleVerMajor;
		u16 titleVerMinor;
		u16 titleVerMicro;
		u8 titleKey[16];
	} common;
	

	struct{
		u8 caCrlVersion;
		u8 signerCrlVersion;
	} cert;

	struct{
		u8 issuer[0x40];
		u8 formatVersion;

		u16 version;
		
		u64 ticketId;
		u32 deviceId;
		u8 licenceType;
		u8 audit;
		u32 eshopAccId;
	} tik;

	struct{
		u8 issuer[0x40];
		u8 formatVersion;

		u16 version;
		u32 accessRights;
		
		u32 titleType;
		u32 savedataSize;
		u32 privSavedataSize;
		u8 twlFlag;
	} tmd;

	struct{
		bool IsCfa;
		bool IsDlc;
		bool encryptCia;
		bool includeUpdateNcch; // for cci -> cia conversions

		bool keyFound;

		u64 fileSize[CIA_MAX_CONTENT];

		/* Misc Records */
		u16 count;
		u64 offset[CIA_MAX_CONTENT];
		u64 totalSize;

		/* Content Chunk Records */
		u64 size[CIA_MAX_CONTENT];
		u16 index[CIA_MAX_CONTENT];
		u16 flags[CIA_MAX_CONTENT];
		u32 id[CIA_MAX_CONTENT];
		u8 hash[CIA_MAX_CONTENT][0x20];		
	} content;

	struct{
		buffer_struct ciaHdr;
		
		u32 certChainOffset;
		buffer_struct certChain;

		u32 tikOffset;
		buffer_struct tik;

		u32 tmdOffset;
		buffer_struct tmd;

		u32 metaOffset;
		buffer_struct meta;

		u64 contentOffset;
		buffer_struct content;
	} ciaSections;
} cia_settings;

// Public Prototypes
int build_CIA(user_settings *usrset);