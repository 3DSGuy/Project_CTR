#pragma once
#include "ncch.h"

typedef struct
{
	buffer_struct *out;
	keys_struct *keys;
	rsf_settings *rsfSet;

	struct
	{
		u32 blockSize;
		u32 pageSize;
		bool verbose;
		bool IncludeExeFsLogo;
		bool CompressCode;
		bool UseOnSD;
		bool Encrypt;
		bool FreeProductCode;
		bool IsCfa;
		bool IsBuildingCodeSection;
		bool UseRomFS;
		bool noCodePadding;
		bool baremetal;

		bool useSecCrypto;
		u8 keyXID;
	} options;

	struct
	{
		FILE *elf;
		u64 elfSize;

		FILE *banner;
		u64 bannerSize;

		FILE *icon;
		u64 iconSize;

		FILE *logo;
		u64 logoSize;

		FILE *code;
		u64 codeSize;

		FILE *exhdr;
		u64 exhdrSize;

		FILE *romfs;
		u64 romfsSize;

		FILE *plainregion;
		u64 plainregionSize;
	} componentFilePtrs;

	struct
	{
		buffer_struct code;
		buffer_struct banner;
		buffer_struct icon;
	} exefsSections;

	struct
	{
		u32 textAddress;
		u32 textSize;
		u32 textMaxPages;
		u32 roAddress;
		u32 roSize;
		u32 roMaxPages;
		u32 rwAddress;
		u32 rwSize;
		u32 rwMaxPages;
		u32 bssSize;
		u32 stackSize;
	} codeDetails;

	struct
	{
		buffer_struct exhdr;
		buffer_struct acexDesc;
		buffer_struct logo;
		buffer_struct plainRegion;
		buffer_struct exeFs;
	} sections;
	
	ncch_info cryptoDetails;
} ncch_settings;

// NCCH Build Functions
int build_NCCH(user_settings *usrset);
