#pragma once

typedef enum
{
	NCCH_MEMERROR = -1,
	SAVE_DATA_TOO_LARGE = -2,
	NCCH_SECTION_NOT_EXIST = -3,
	UNABLE_TO_LOAD_NCCH_KEY = -4,
	NCCH_EXPORT_BUFFER_TOO_SMALL = -5,
	NO_ROMFS_IN_CFA = -6,
	NO_EXHEADER_IN_CXI = -7,
	NO_EXEFS_IN_CXI = -8,
	// SigCheck Errors
	CXI_CORRUPT = -9,
	ACCESSDESC_SIG_BAD = -10,
	NCCH_HDR_SIG_BAD = -11,
	// HashCheck Errors
	EXHDR_CORRUPT = -12,
	LOGO_CORRUPT = -13,
	EXEFS_CORRUPT = -14,
	ROMFS_CORRUPT = -15,
	// Others
	NCCH_BAD_RSF_SET = -16,
	DATA_POS_DNE = -17,
} ncch_errors;

typedef enum
{
	ncch_exhdr = 1,
	ncch_exefs,
	ncch_romfs,
} ncch_section;

typedef enum
{
	ncchflag_CONTENT_KEYX = 3,
	ncchflag_CONTENT_PLATFORM = 4,
	ncchflag_CONTENT_TYPE = 5,
	ncchflag_CONTENT_BLOCK_SIZE = 6,
	ncchflag_OTHER_FLAG = 7
} ncch_flags;

typedef enum
{
	otherflag_Clear = 0,
	otherflag_FixedCryptoKey = (1 << 0),
	otherflag_NoMountRomFs = (1 << 1),
	otherflag_NoCrypto = (1 << 2),
} ncch_otherflag_bitmask;

typedef enum
{
	content_None = 0,
	content_HasRomFS = 1,
	content_Application = 2,
	content_SystemUpdate = 4,
	content_Manual = 8,
	content_Child = 16,
	content_Trial = 32,
	content_ExtendedSystemUpdate = 64,
} ncch_flag_content_type;

typedef enum
{
	platform_CTR = 0x1,
	platform_SNAKE = 0x2
} ncch_platform;

typedef enum
{
	keyx_regular = 0x00,
	keyx_7_0 = 0x01,
	keyx_9_3 = 0x0A,
	keyx_9_6 = 0x0B,
} ncch_keyx_id;

typedef struct
{
	u16 formatVersion;
	u32 exhdrOffset;
	u32 exhdrSize;
	u32 acexOffset;
	u32 acexSize;
	u64 logoOffset;
	u64 logoSize;
	u64 plainRegionOffset;
	u64 plainRegionSize;
	u64 exefsOffset;
	u64 exefsSize;
	u64 exefsHashDataSize;
	u64 romfsOffset;
	u64 romfsSize;
	u64 romfsHashDataSize;
	u64 titleId;
	u64 programId;
} ncch_info;

typedef struct
{
	u8 signature[0x100];
	u8 magic[4];
	u8 ncchSize[4];
	u8 titleId[8];
	u8 makerCode[2];
	u8 formatVersion[2];
	u8 padding0[4];
	u8 programId[8];
	u8 padding1[0x10];
	u8 logoHash[0x20]; // SHA-256 over the entire logo region
	u8 productCode[0x10];
	u8 exhdrHash[0x20]; // SHA-256 over exhdrSize of the exhdr region
	u8 exhdrSize[4];
	u8 padding2[4];
	u8 flags[8];
	u8 plainRegionOffset[4];
	u8 plainRegionSize[4];
	u8 logoOffset[4];
	u8 logoSize[4];
	u8 exefsOffset[4];
	u8 exefsSize[4];
	u8 exefsHashSize[4];
	u8 padding4[4];
	u8 romfsOffset[4];
	u8 romfsSize[4];
	u8 romfsHashSize[4];
	u8 padding5[4];
	u8 exefsHash[0x20];
	u8 romfsHash[0x20];
} ncch_hdr;

// NCCH Read Functions
int VerifyNcch(u8 *ncch, keys_struct *keys, bool checkHash, bool suppressOutput);

int ModifyNcchIds(u8 *ncch, u8 *titleId, u8 *programId, keys_struct *keys);

void ReadNcchHdr(ncch_hdr *hdr, FILE *fp);
u8* GetNcchHdrSig(ncch_hdr *hdr);
u8* GetNcchHdrData(ncch_hdr *hdr);
u32 GetNcchHdrSigLen(ncch_hdr *hdr);
u32 GetNcchHdrDataLen(ncch_hdr *hdr);
bool IsNcch(FILE *fp, u8 *buf);
bool IsCfa(ncch_hdr* hdr);
bool IsUpdateCfa(ncch_hdr* hdr);
u32 GetNcchBlockSize(ncch_hdr* hdr);
u64 GetNcchSize(ncch_hdr* hdr);
bool IsNcchEncrypted(ncch_hdr *hdr);
bool SetNcchKeys(keys_struct *keys, ncch_hdr *hdr);
int GetNcchInfo(ncch_info *ctx, ncch_hdr *header);
void GetNcchAesCounter(u8 ctr[16], u64 titleId, u8 type);
void CryptNcchRegion(u8 *buffer, u64 size, u64 src_pos, u64 titleId, u8 key[16], u8 type);