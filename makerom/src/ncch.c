#include "lib.h"
#include "aes_keygen.h"
#include "ncch_build.h"
#include "exheader_build.h"
#include "exheader_read.h"
#include "code.h"
#include "exefs_build.h"
#include "exefs_read.h"
#include "romfs.h"
#include "titleid.h"

#include "ncch_logo.h" // Contains Logos

const u32 NCCH_BLOCK_SIZE = 0x200;
const char *DEFAULT_PRODUCT_CODE = "CTR-P-CTAP";
const char *DEFAULT_MAKER_CODE = "00";

// Private Prototypes
int SignCFA(ncch_hdr *hdr, keys_struct *keys);
int CheckCFASignature(ncch_hdr *hdr, keys_struct *keys);
int SignCXI(ncch_hdr *hdr, keys_struct *keys);
int CheckCXISignature(ncch_hdr *hdr, u8 *pubk);

void FreeNcchSettings(ncch_settings *set);
int GetNcchSettings(ncch_settings *ncchset, user_settings *usrset);
int GetBasicOptions(ncch_settings *ncchset, user_settings *usrset);
int CreateInputFilePtrs(ncch_settings *ncchset, user_settings *usrset);
int ImportNonCodeExeFsSections(ncch_settings *ncchset);	
int ImportLogo(ncch_settings *ncchset);

int SetupNcch(ncch_settings *ncchset, romfs_buildctx *romfs);
int FinaliseNcch(ncch_settings *ncchset);
int SetCommonHeaderBasicData(ncch_settings *ncchset, ncch_hdr *hdr);
bool IsValidProductCode(char *ProductCode, bool FreeProductCode);

// Code
int SignCFA(ncch_hdr *hdr, keys_struct *keys)
{
	if (Rsa2048Key_CanSign(&keys->rsa.cciCfa) == false)
	{
		printf("[NCCH WARNING] Failed to sign CFA header (key was incomplete)\n");
		memset(GetNcchHdrSig(hdr), 0xFF, 0x100);
		return 0;
	}

	int rsa_ret = RsaSignVerify(GetNcchHdrData(hdr), GetNcchHdrDataLen(hdr), GetNcchHdrSig(hdr), keys->rsa.cciCfa.pub, keys->rsa.cciCfa.pvt, RSA_2048_SHA256, CTR_RSA_SIGN);
	if (rsa_ret != 0)
	{
		printf("[NCCH WARNING] Failed to sign CFA header (mbedtls error = -0x%x)\n", -rsa_ret);
		memset(GetNcchHdrSig(hdr), 0xFF, 0x100);
		return 0;
	}

	return 0;
}

int CheckCFASignature(ncch_hdr *hdr, keys_struct *keys)
{
	return RsaSignVerify(GetNcchHdrData(hdr),GetNcchHdrDataLen(hdr),GetNcchHdrSig(hdr), keys->rsa.cciCfa.pub, keys->rsa.cciCfa.pvt, RSA_2048_SHA256,CTR_RSA_VERIFY);
}

int SignCXI(ncch_hdr *hdr, keys_struct *keys)
{
	if (Rsa2048Key_CanSign(&keys->rsa.cxi) == false)
	{
		printf("[NCCH WARNING] Failed to sign CXI header (key was incomplete)\n");
		memset(GetNcchHdrSig(hdr), 0xFF, 0x100);
		return 0;
	}

	int rsa_ret = RsaSignVerify(GetNcchHdrData(hdr), GetNcchHdrDataLen(hdr), GetNcchHdrSig(hdr), keys->rsa.cxi.pub, keys->rsa.cxi.pvt, RSA_2048_SHA256, CTR_RSA_SIGN);
	if (rsa_ret != 0)
	{
		printf("[NCCH WARNING] Failed to sign CXI header (mbedtls error = -0x%x)\n", -rsa_ret);
		memset(GetNcchHdrSig(hdr), 0xFF, 0x100);
		return 0;
	}

	return 0;
}

int CheckCXISignature(ncch_hdr *hdr, u8 *pubk)
{
	return RsaSignVerify(GetNcchHdrData(hdr), GetNcchHdrDataLen(hdr), GetNcchHdrSig(hdr), pubk, NULL, RSA_2048_SHA256, CTR_RSA_VERIFY);
}

// NCCH Build Functions

int build_NCCH(user_settings *usrset)
{
	int result;

	// Init Settings
	ncch_settings *ncchset = calloc(1,sizeof(ncch_settings));
	if(!ncchset) {
		fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}

	// Get Settings
	result = GetNcchSettings(ncchset,usrset);
	if(result) {
		fprintf(stderr,"[NCCH ERROR] Failed to initialize context.\n");
		goto finish;
	}

	// Import Data
	result = ImportNonCodeExeFsSections(ncchset);
	if(result) {
		fprintf(stderr,"[NCCH ERROR] Failed to import non-code ExeFs sections\n");
		goto finish;
	}
	
	result = ImportLogo(ncchset);
	if(result) {
		fprintf(stderr,"[NCCH ERROR] Failed to import Logo\n");
		goto finish;
	}

	if(!ncchset->options.IsCfa){ // CXI Specific Sections
		// Build ExeFs Code Section\n");
		result = BuildExeFsCode(ncchset);
		if(result) {
			fprintf(stderr,"[NCCH ERROR] Failed to build ExeFs code\n");
			goto finish;
		}
	
		// Build ExHeader\n");
		result = BuildExHeader(ncchset);
		if(result) {
			fprintf(stderr,"[NCCH ERROR] Failed to build ExHeader\n");
			goto finish;
		}
	}	

	
	// Build ExeFs\n");
	result = BuildExeFs(ncchset);
	if(result) {
		fprintf(stderr,"[NCCH ERROR] Failed to build ExeFs\n");
		goto finish;
	}

	
	// Prepare for RomFs\n");
	romfs_buildctx romfs;
	memset(&romfs,0,sizeof(romfs_buildctx));
	result = SetupRomFs(ncchset,&romfs);
	if(result) {
		fprintf(stderr,"[NCCH ERROR] Failed to setup RomFs\n");
		goto finish;
	}

	
	// Setup NCCH including final memory allocation\n");
	result = SetupNcch(ncchset,&romfs);
	if(result) {
		fprintf(stderr,"[NCCH ERROR] Failed to setup NCCH\n");
		goto finish;
	}

	// Build RomFs\n");
	result = BuildRomFs(&romfs);
	if(result) {
		fprintf(stderr,"[NCCH ERROR] Failed to build RomFs\n");
		goto finish;
	}
	
	// Finalise NCCH (Hashes/Signatures and crypto)\n");
	result = FinaliseNcch(ncchset);
	if(result) {
		fprintf(stderr,"[NCCH ERROR] Failed to finalize NCCH\n");
		goto finish;
	}

finish:
	if(result) 
		fprintf(stderr,"[NCCH ERROR] NCCH Build Process Failed\n");
	FreeNcchSettings(ncchset);
	return result;
}

void FreeNcchSettings(ncch_settings *set)
{
	if(set->componentFilePtrs.elf) fclose(set->componentFilePtrs.elf);
	if(set->componentFilePtrs.banner) fclose(set->componentFilePtrs.banner);
	if(set->componentFilePtrs.icon) fclose(set->componentFilePtrs.icon);
	if(set->componentFilePtrs.logo) fclose(set->componentFilePtrs.logo);
	if(set->componentFilePtrs.code) fclose(set->componentFilePtrs.code);
	if(set->componentFilePtrs.exhdr) fclose(set->componentFilePtrs.exhdr);
	if(set->componentFilePtrs.romfs) fclose(set->componentFilePtrs.romfs);
	if(set->componentFilePtrs.plainregion) fclose(set->componentFilePtrs.plainregion);

	if(set->exefsSections.code.size) free(set->exefsSections.code.buffer);
	if(set->exefsSections.banner.size) free(set->exefsSections.banner.buffer);
	if(set->exefsSections.icon.size) free(set->exefsSections.icon.buffer);

	if(set->sections.exhdr.size) free(set->sections.exhdr.buffer);
	if(set->sections.logo.size) free(set->sections.logo.buffer);
	if(set->sections.plainRegion.size) free(set->sections.plainRegion.buffer);
	if(set->sections.exeFs.size) free(set->sections.exeFs.buffer);

	memset(set,0,sizeof(ncch_settings));

	free(set);
}

int GetNcchSettings(ncch_settings *ncchset, user_settings *usrset)
{
	int result = 0;
	ncchset->out = &usrset->common.workingFile;
	
	ncchset->rsfSet = &usrset->common.rsfSet;
	ncchset->keys = &usrset->common.keys;

	result = GetBasicOptions(ncchset,usrset);
	if(result) return result;
	result = CreateInputFilePtrs(ncchset,usrset);
	if(result) return result;
	

	return 0;
}

int GetBasicOptions(ncch_settings *ncchset, user_settings *usrset)
{
	int result = 0;

	/* Options */
	ncchset->options.blockSize = NCCH_BLOCK_SIZE;
	ncchset->options.verbose = usrset->common.verbose;
	ncchset->options.IncludeExeFsLogo = usrset->ncch.includeExefsLogo;
	ncchset->options.CompressCode = ncchset->rsfSet->Option.EnableCompress;
	ncchset->options.UseOnSD = ncchset->rsfSet->Option.UseOnSD;
	ncchset->options.Encrypt = ncchset->rsfSet->Option.EnableCrypt;
	ncchset->options.FreeProductCode = ncchset->rsfSet->Option.FreeProductCode;
	ncchset->options.IsCfa = (usrset->ncch.ncchType == CFA);
	ncchset->options.IsBuildingCodeSection = (usrset->ncch.elfPath != NULL);
	ncchset->options.UseRomFS = ((ncchset->rsfSet->RomFs.RootPath && strlen(ncchset->rsfSet->RomFs.RootPath) > 0) || usrset->ncch.romfsPath);
	ncchset->options.noCodePadding = usrset->ncch.noCodePadding;
	ncchset->options.baremetal = usrset->ncch.baremetal;
	ncchset->options.pageSize = usrset->ncch.pageSize;
	ncchset->options.useSecCrypto = usrset->ncch.useSecCrypto;
	ncchset->options.keyXID = usrset->ncch.keyXID;
	
	if(ncchset->options.IsCfa && !ncchset->options.UseRomFS){
		fprintf(stderr,"[NCCH ERROR] \"Rom/HostRoot\" must be set\n");
		return NCCH_BAD_RSF_SET;
	}

	return result;
}

int CreateInputFilePtrs(ncch_settings *ncchset, user_settings *usrset)
{
	if(usrset->ncch.romfsPath){
		ncchset->componentFilePtrs.romfsSize = GetFileSize64(usrset->ncch.romfsPath);
		ncchset->componentFilePtrs.romfs = fopen(usrset->ncch.romfsPath,"rb");
		if(!ncchset->componentFilePtrs.romfs){
			fprintf(stderr,"[NCCH ERROR] Failed to open RomFs file '%s'\n",usrset->ncch.romfsPath);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->ncch.elfPath){
		ncchset->componentFilePtrs.elfSize = GetFileSize64(usrset->ncch.elfPath);
		ncchset->componentFilePtrs.elf = fopen(usrset->ncch.elfPath,"rb");
		if(!ncchset->componentFilePtrs.elf){
			fprintf(stderr,"[NCCH ERROR] Failed to open elf file '%s'\n",usrset->ncch.elfPath);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->ncch.bannerPath){
		ncchset->componentFilePtrs.bannerSize = GetFileSize64(usrset->ncch.bannerPath);
		ncchset->componentFilePtrs.banner = fopen(usrset->ncch.bannerPath,"rb");
		if(!ncchset->componentFilePtrs.banner){
			fprintf(stderr,"[NCCH ERROR] Failed to open banner file '%s'\n",usrset->ncch.bannerPath);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->ncch.iconPath){
		ncchset->componentFilePtrs.iconSize = GetFileSize64(usrset->ncch.iconPath);
		ncchset->componentFilePtrs.icon = fopen(usrset->ncch.iconPath,"rb");
		if(!ncchset->componentFilePtrs.icon){
			fprintf(stderr,"[NCCH ERROR] Failed to open icon file '%s'\n",usrset->ncch.iconPath);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->ncch.logoPath){
		ncchset->componentFilePtrs.logoSize = GetFileSize64(usrset->ncch.logoPath);
		ncchset->componentFilePtrs.logo = fopen(usrset->ncch.logoPath,"rb");
		if(!ncchset->componentFilePtrs.logo){
			fprintf(stderr,"[NCCH ERROR] Failed to open logo file '%s'\n",usrset->ncch.logoPath);
			return FAILED_TO_IMPORT_FILE;
		}
	}

	if(usrset->ncch.codePath){
		ncchset->componentFilePtrs.codeSize = GetFileSize64(usrset->ncch.codePath);
		ncchset->componentFilePtrs.code = fopen(usrset->ncch.codePath,"rb");
		if(!ncchset->componentFilePtrs.code){
			fprintf(stderr,"[NCCH ERROR] Failed to open ExeFs Code file '%s'\n",usrset->ncch.codePath);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->ncch.exheaderPath){
		ncchset->componentFilePtrs.exhdrSize = GetFileSize64(usrset->ncch.exheaderPath);
		ncchset->componentFilePtrs.exhdr = fopen(usrset->ncch.exheaderPath,"rb");
		if(!ncchset->componentFilePtrs.exhdr){
			fprintf(stderr,"[NCCH ERROR] Failed to open ExHeader file '%s'\n",usrset->ncch.exheaderPath);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->ncch.plainRegionPath){
		ncchset->componentFilePtrs.plainregionSize = GetFileSize64(usrset->ncch.plainRegionPath);
		ncchset->componentFilePtrs.plainregion = fopen(usrset->ncch.plainRegionPath,"rb");
		if(!ncchset->componentFilePtrs.plainregion){
			fprintf(stderr,"[NCCH ERROR] Failed to open PlainRegion file '%s'\n",usrset->ncch.plainRegionPath);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	return 0;
}

int ImportNonCodeExeFsSections(ncch_settings *set)
{
	if(set->componentFilePtrs.banner){
		set->exefsSections.banner.size = set->componentFilePtrs.bannerSize;
		set->exefsSections.banner.buffer = malloc(set->exefsSections.banner.size);
		if(!set->exefsSections.banner.buffer) {
			fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
			return MEM_ERROR;
		}
		ReadFile64(set->exefsSections.banner.buffer,set->exefsSections.banner.size,0,set->componentFilePtrs.banner);
	}
	if(set->componentFilePtrs.icon){
		set->exefsSections.icon.size = set->componentFilePtrs.iconSize;
		set->exefsSections.icon.buffer = malloc(set->exefsSections.icon.size);
		if(!set->exefsSections.icon.buffer) {
			fprintf(stderr,"[NCCH ERROR] Not enough memory\n");
			return MEM_ERROR;
		}
		ReadFile64(set->exefsSections.icon.buffer,set->exefsSections.icon.size,0,set->componentFilePtrs.icon);
	}
	return 0;
}

int ImportLogo(ncch_settings *set)
{
	if(set->componentFilePtrs.logo){
		set->sections.logo.size = align(set->componentFilePtrs.logoSize,set->options.blockSize);
		set->sections.logo.buffer = malloc(set->sections.logo.size);
		if(!set->sections.logo.buffer) {
			fprintf(stderr,"[NCCH ERROR] Not enough memory\n");
			return MEM_ERROR;
		}
		memset(set->sections.logo.buffer,0,set->sections.logo.size);
		ReadFile64(set->sections.logo.buffer,set->componentFilePtrs.logoSize,0,set->componentFilePtrs.logo);
	}
	else if(set->rsfSet->BasicInfo.Logo){
		if(strcasecmp(set->rsfSet->BasicInfo.Logo,"nintendo") == 0){
			set->sections.logo.size = 0x2000;
			set->sections.logo.buffer = malloc(set->sections.logo.size);
			if(!set->sections.logo.buffer) {
				fprintf(stderr,"[NCCH ERROR] Not enough memory\n");
				return MEM_ERROR;
			}
			memcpy(set->sections.logo.buffer,Nintendo_LZ,0x2000);
		}
		else if(strcasecmp(set->rsfSet->BasicInfo.Logo,"licensed") == 0){
			set->sections.logo.size = 0x2000;
			set->sections.logo.buffer = malloc(set->sections.logo.size);
			if(!set->sections.logo.buffer) {
				fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
				return MEM_ERROR;
			}
			memcpy(set->sections.logo.buffer,Nintendo_LicensedBy_LZ,0x2000);
		}
		else if(strcasecmp(set->rsfSet->BasicInfo.Logo,"distributed") == 0){
			set->sections.logo.size = 0x2000;
			set->sections.logo.buffer = malloc(set->sections.logo.size);
			if(!set->sections.logo.buffer) {
				fprintf(stderr,"[NCCH ERROR] Not enough memory\n");
				return MEM_ERROR;
			}
			memcpy(set->sections.logo.buffer,Nintendo_DistributedBy_LZ,0x2000);
		}
		else if(strcasecmp(set->rsfSet->BasicInfo.Logo,"ique") == 0){
			set->sections.logo.size = 0x2000;
			set->sections.logo.buffer = malloc(set->sections.logo.size);
			if(!set->sections.logo.buffer) {
				fprintf(stderr,"[NCCH ERROR] Not enough memory\n");
				return MEM_ERROR;
			}
			memcpy(set->sections.logo.buffer,iQue_with_ISBN_LZ,0x2000);
		}
		else if(strcasecmp(set->rsfSet->BasicInfo.Logo,"iqueforsystem") == 0){
			set->sections.logo.size = 0x2000;
			set->sections.logo.buffer = malloc(set->sections.logo.size);
			if(!set->sections.logo.buffer) {
				fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
				return MEM_ERROR;
			}
			memcpy(set->sections.logo.buffer,iQue_without_ISBN_LZ,0x2000);
		}
		else if (strcasecmp(set->rsfSet->BasicInfo.Logo, "homebrew") == 0) {
			set->sections.logo.size = 0x2000;
			set->sections.logo.buffer = malloc(set->sections.logo.size);
			if (!set->sections.logo.buffer) {
				fprintf(stderr, "[NCCH ERROR] Not enough memory\n");
				return MEM_ERROR;
			}
			memcpy(set->sections.logo.buffer, Homebrew_LZ, 0x2000);
		}
		else if (strcasecmp(set->rsfSet->BasicInfo.Logo, "homebrewlegacy") == 0) {
			set->sections.logo.size = 0x2000;
			set->sections.logo.buffer = malloc(set->sections.logo.size);
			if (!set->sections.logo.buffer) {
				fprintf(stderr, "[NCCH ERROR] Not enough memory\n");
				return MEM_ERROR;
			}
			memcpy(set->sections.logo.buffer, HomebrewLegacy_LZ, 0x2000);
		}
		else if(strcasecmp(set->rsfSet->BasicInfo.Logo,"none") != 0){
			fprintf(stderr,"[NCCH ERROR] Invalid logo name\n");
			return NCCH_BAD_RSF_SET;
		}
	}
	return 0;
}

int SetupNcch(ncch_settings *set, romfs_buildctx *romfs)
{
	u64 ncchSize = 0;
	u64 exhdrSize,acexSize,logoSize,plnRgnSize,exefsSize,romfsSize;
	u64 exhdrOffset,acexOffset = 0,logoOffset,plnRgnOffset,exefsOffset,romfsOffset;
	u32 exefsHashSize,romfsHashSize;

	ncchSize += sizeof(ncch_hdr); // Sig+Hdr
	
	// Sizes for NCCH hdr
	if(set->sections.exhdr.size){
		exhdrSize = set->sections.exhdr.size;
		exhdrOffset = ncchSize;
		ncchSize += exhdrSize;
	}
	else
		exhdrSize = 0;
		
	if(set->sections.acexDesc.size){
		acexSize = set->sections.acexDesc.size;
		acexOffset = ncchSize;
		ncchSize += acexSize;
	}
	else
		acexSize = 0;

	if(set->sections.logo.size && set->options.IncludeExeFsLogo == false){
		logoSize = set->sections.logo.size;
		logoOffset = align(ncchSize,set->options.blockSize);
		ncchSize = logoOffset + logoSize;
	}
	else
		logoSize = 0;

	if(set->sections.plainRegion.size){
		plnRgnSize = align(set->sections.plainRegion.size,set->options.blockSize);
		plnRgnOffset = align(ncchSize,set->options.blockSize);
		ncchSize = plnRgnOffset + plnRgnSize;
	}
	else
		plnRgnSize = 0;

	if(set->sections.exeFs.size){
		exefsHashSize = align(sizeof(exefs_hdr),set->options.blockSize);
		exefsSize = align(set->sections.exeFs.size,set->options.blockSize);
		exefsOffset = align(ncchSize,set->options.blockSize);
		ncchSize = exefsOffset + exefsSize;
	}
	else
		exefsSize = 0;

	if(romfs->romfsSize){
		romfsHashSize = align(romfs->romfsHeaderSize,set->options.blockSize);
		romfsSize = align(romfs->romfsSize,set->options.blockSize);
		//romfsOffset = align(ncchSize,set->options.blockSize); // Old makerom method, SDK 2.x and prior
		romfsOffset = align(ncchSize,0x1000);
		ncchSize = romfsOffset + romfsSize;
	}
	else
		romfsSize = 0;



	// Aligning Total NCCH Size
	ncchSize = align(ncchSize,set->options.blockSize);
	
	u8 *ncch = calloc(1,ncchSize);
	if(!ncch){
		fprintf(stderr,"[NCCH ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	
	// Setting up hdr\n");
	ncch_hdr *hdr = (ncch_hdr*)ncch;
	int ret = SetCommonHeaderBasicData(set,hdr);
	if(ret != 0){
		free(ncch);
		return ret;
	}
	u32_to_u8(hdr->ncchSize,ncchSize/set->options.blockSize,LE);


	// Copy already built sections to ncch
	if(exhdrSize){
		memcpy((u8*)(ncch+exhdrOffset),set->sections.exhdr.buffer,set->sections.exhdr.size);
		free(set->sections.exhdr.buffer);
		set->sections.exhdr.buffer = NULL;
		u32_to_u8(hdr->exhdrSize,exhdrSize,LE);
	}
	if(acexSize){
		memcpy((u8*)(ncch+acexOffset),set->sections.acexDesc.buffer,set->sections.acexDesc.size);
		free(set->sections.acexDesc.buffer);
		set->sections.acexDesc.buffer = NULL;
	}

	if(logoSize){
		memcpy((u8*)(ncch+logoOffset),set->sections.logo.buffer,set->sections.logo.size);
		free(set->sections.logo.buffer);
		set->sections.logo.buffer = NULL;
		u32_to_u8(hdr->logoOffset,logoOffset/set->options.blockSize,LE);
		u32_to_u8(hdr->logoSize,logoSize/set->options.blockSize,LE);
	}

	if(plnRgnSize){		
		memcpy((u8*)(ncch+plnRgnOffset),set->sections.plainRegion.buffer,set->sections.plainRegion.size);
		free(set->sections.plainRegion.buffer);
		set->sections.plainRegion.buffer = NULL;
		u32_to_u8(hdr->plainRegionOffset,plnRgnOffset/set->options.blockSize,LE);
		u32_to_u8(hdr->plainRegionSize,plnRgnSize/set->options.blockSize,LE);
	}

	if(exefsSize){	
		memcpy((u8*)(ncch+exefsOffset),set->sections.exeFs.buffer,set->sections.exeFs.size);
		free(set->sections.exeFs.buffer);
		
		set->sections.exeFs.buffer = NULL;
		
		u32_to_u8(hdr->exefsOffset,exefsOffset/set->options.blockSize,LE);
		
		u32_to_u8(hdr->exefsSize,exefsSize/set->options.blockSize,LE);
		
		u32_to_u8(hdr->exefsHashSize,exefsHashSize/set->options.blockSize,LE);
		
	}

	// Point Romfs CTX to output buffer, if exists\n");
	if(romfsSize){
		romfs->output = ncch + romfsOffset;
		u32_to_u8(hdr->romfsOffset,romfsOffset/set->options.blockSize,LE);
		u32_to_u8(hdr->romfsSize,romfsSize/set->options.blockSize,LE);
		u32_to_u8(hdr->romfsHashSize,romfsHashSize/set->options.blockSize,LE);
	}
	
	set->out->buffer = ncch;
	set->out->size = ncchSize;

	GetNcchInfo(&set->cryptoDetails,hdr);

	return 0;
}

int FinaliseNcch(ncch_settings *set)
{
	u8 *ncch = set->out->buffer;

	ncch_hdr *hdr = (ncch_hdr*)ncch;
	u8 *exhdr = (u8*)(ncch + set->cryptoDetails.exhdrOffset);
	u8 *acexDesc = (u8*)(ncch + set->cryptoDetails.acexOffset);
	u8 *logo = (u8*)(ncch + set->cryptoDetails.logoOffset);
	u8 *exefs = (u8*)(ncch + set->cryptoDetails.exefsOffset);
	u8 *romfs = (u8*)(ncch + set->cryptoDetails.romfsOffset);

	// Taking Hashes
	if(set->cryptoDetails.exhdrSize)
		ShaCalc(exhdr,set->cryptoDetails.exhdrSize,hdr->exhdrHash,CTR_SHA_256);
	if(set->cryptoDetails.logoSize)
		ShaCalc(logo,set->cryptoDetails.logoSize,hdr->logoHash,CTR_SHA_256);
	if(set->cryptoDetails.exefsHashDataSize)
		ShaCalc(exefs,set->cryptoDetails.exefsHashDataSize,hdr->exefsHash,CTR_SHA_256);
	if(set->cryptoDetails.romfsHashDataSize)
		ShaCalc(romfs,set->cryptoDetails.romfsHashDataSize,hdr->romfsHash,CTR_SHA_256);

	// Signing NCCH
	int sig_result = Good;
	if(set->options.IsCfa) 
		sig_result = SignCFA(hdr,set->keys);
	else 
		sig_result = SignCXI(hdr,set->keys);
	if(sig_result != Good){
		fprintf(stderr,"[NCCH ERROR] Failed to sign %s header\n",set->options.IsCfa ? "CFA" : "CXI");
		return sig_result;
	}


	// Crypting NCCH\n");
	if(IsNcchEncrypted(hdr)){
		if(!SetNcchKeys(set->keys, hdr)){
			fprintf(stderr,"[NCCH ERROR] Failed to load NCCH AES key\n");
			return -1;
		}

		if(set->options.verbose){
			printf("[NCCH] NCCH AES keys:\n");
			memdump(stdout," > key0: ",set->keys->aes.ncchKey0,AES_128_KEY_SIZE);
			memdump(stdout," > key1: ",set->keys->aes.ncchKey1,AES_128_KEY_SIZE);
		}

		// Crypting Exheader/AcexDesc
		if(set->cryptoDetails.exhdrSize){
			if (set->options.verbose)
				printf("[NCCH] Encypting Exheader... ");
			CryptNcchRegion(exhdr,set->cryptoDetails.exhdrSize,0x0,set->cryptoDetails.titleId,set->keys->aes.ncchKey0,ncch_exhdr);
			CryptNcchRegion(acexDesc,set->cryptoDetails.acexSize,set->cryptoDetails.exhdrSize,set->cryptoDetails.titleId,set->keys->aes.ncchKey0,ncch_exhdr);
			if (set->options.verbose)
				printf("Done!\n");
		}			

		// Crypting ExeFs Files
		if(set->cryptoDetails.exefsSize){
			if (set->options.verbose)
				printf("[NCCH] Encrypting ExeFS... ");

			exefs_hdr *exefsHdr = (exefs_hdr*)exefs;
			for(int i = 0; i < MAX_EXEFS_SECTIONS; i++){
				u8 *key = NULL;
				if(strncmp(exefsHdr->fileHdr[i].name,"icon",8) == 0 || strncmp(exefsHdr->fileHdr[i].name,"banner",8) == 0)
					key = set->keys->aes.ncchKey0;
				else
					key = set->keys->aes.ncchKey1;
								
				u32 offset = u8_to_u32(exefsHdr->fileHdr[i].offset,LE) + sizeof(exefs_hdr);
				u32 size = u8_to_u32(exefsHdr->fileHdr[i].size,LE);

				if(size)
					CryptNcchRegion((exefs+offset),align(size,set->options.blockSize),offset,set->cryptoDetails.titleId,key,ncch_exefs);

			}
			// Crypting ExeFs Header
			CryptNcchRegion(exefs,sizeof(exefs_hdr),0x0,set->cryptoDetails.titleId,set->keys->aes.ncchKey0,ncch_exefs);

			if (set->options.verbose)
				printf("Done!\n");
		}

		// Crypting RomFs
		if (set->cryptoDetails.romfsSize) {
			if (set->options.verbose)
				printf("[NCCH] Encrypting RomFS... ");
			CryptNcchRegion(romfs, set->cryptoDetails.romfsSize, 0x0, set->cryptoDetails.titleId, set->keys->aes.ncchKey1, ncch_romfs);
			if (set->options.verbose)
				printf("Done!\n");
		}
	}

	return 0;
}

int SetCommonHeaderBasicData(ncch_settings *set, ncch_hdr *hdr)
{
	/* NCCH Magic */
	memcpy(hdr->magic,"NCCH",4);

	/* NCCH Format Version */
	if(!set->options.IsCfa)
		u16_to_u8(hdr->formatVersion,0x2,LE);

	
	/* Setting ProgramId/TitleId */
	u64 programId = 0;
	int result = GetProgramID(&programId,set->rsfSet,false); 
	if(result) return result;

	u64_to_u8(hdr->programId,programId,LE);
	u64_to_u8(hdr->titleId,programId,LE);

	/* Get Product Code and Maker Code */
	if(set->rsfSet->BasicInfo.ProductCode){
		if(!IsValidProductCode((char*)set->rsfSet->BasicInfo.ProductCode,set->options.FreeProductCode)){
			fprintf(stderr,"[NCCH ERROR] Invalid Product Code\n");
			return NCCH_BAD_RSF_SET;
		}
		strncpy((char*)hdr->productCode,set->rsfSet->BasicInfo.ProductCode, 16);
	}
	else
		strncpy((char*)hdr->productCode, DEFAULT_PRODUCT_CODE, 16);

	if(set->rsfSet->BasicInfo.CompanyCode){
		if(strlen((char*)set->rsfSet->BasicInfo.CompanyCode) != 2){
			fprintf(stderr,"[NCCH ERROR] CompanyCode length must be 2\n");
			return NCCH_BAD_RSF_SET;
		}
		strncpy((char*)hdr->makerCode, set->rsfSet->BasicInfo.CompanyCode, 2);
	}
	else
		strncpy((char*)hdr->makerCode, DEFAULT_MAKER_CODE, 2);

	// Setting Encryption Settings
	if(!set->options.Encrypt)
		hdr->flags[ncchflag_OTHER_FLAG] = (otherflag_NoCrypto|otherflag_FixedCryptoKey);
	else if(set->options.useSecCrypto){
		hdr->flags[ncchflag_OTHER_FLAG] = otherflag_Clear;
		hdr->flags[ncchflag_CONTENT_KEYX] = set->options.keyXID;
	}
	else
		hdr->flags[ncchflag_OTHER_FLAG] = otherflag_FixedCryptoKey;	
		
	if(!SetNcchKeys(set->keys,hdr) && set->options.Encrypt){
		hdr->flags[ncchflag_OTHER_FLAG] = (otherflag_NoCrypto|otherflag_FixedCryptoKey);
		hdr->flags[ncchflag_CONTENT_KEYX] = 0;
		set->options.Encrypt = false;
		fprintf(stderr,"[NCCH WARNING] NCCH AES Key could not be loaded, NCCH will not be encrypted\n");
	}

	/* Set ContentUnitSize */
	hdr->flags[ncchflag_CONTENT_BLOCK_SIZE] = GetCtrBlockSizeFlag(set->options.blockSize);

	/* Setting ContentPlatform */
	if(set->rsfSet->TitleInfo.Platform){
		if(strcasecmp(set->rsfSet->TitleInfo.Platform, "ctr") == 0)
			hdr->flags[ncchflag_CONTENT_PLATFORM] = platform_CTR;
		else if (strcasecmp(set->rsfSet->TitleInfo.Platform, "snake") == 0)
			hdr->flags[ncchflag_CONTENT_PLATFORM] = platform_SNAKE;
		else{
			fprintf(stderr, "[NCCH ERROR] Invalid Platform '%s'\n", set->rsfSet->TitleInfo.Platform);
			return NCCH_BAD_RSF_SET;
		}
	}
	else
		hdr->flags[ncchflag_CONTENT_PLATFORM] = platform_CTR;

	/* Setting OtherFlag */
	if(!set->options.UseRomFS) 
		hdr->flags[ncchflag_OTHER_FLAG] |= otherflag_NoMountRomFs;


	/* Setting FormType */
	hdr->flags[ncchflag_CONTENT_TYPE] = form_Unassigned;
	if(set->options.IsCfa)
		hdr->flags[ncchflag_CONTENT_TYPE] = form_SimpleContent;
	else if (set->options.UseRomFS)
		hdr->flags[ncchflag_CONTENT_TYPE] = form_Executable;
	else
		hdr->flags[ncchflag_CONTENT_TYPE] = form_ExecutableWithoutRomfs;
	
	/* Setting ContentType */
	if(set->rsfSet->BasicInfo.ContentType){
		if(strcmp(set->rsfSet->BasicInfo.ContentType,"Application") == 0) hdr->flags[ncchflag_CONTENT_TYPE] |= (content_Application << 2);
		else if(strcmp(set->rsfSet->BasicInfo.ContentType,"SystemUpdate") == 0) hdr->flags[ncchflag_CONTENT_TYPE] |= (content_SystemUpdate << 2);
		else if(strcmp(set->rsfSet->BasicInfo.ContentType,"Manual") == 0) hdr->flags[ncchflag_CONTENT_TYPE] |= (content_Manual << 2);
		else if(strcmp(set->rsfSet->BasicInfo.ContentType,"Child") == 0) hdr->flags[ncchflag_CONTENT_TYPE] |= (content_Child << 2);
		else if(strcmp(set->rsfSet->BasicInfo.ContentType,"Trial") == 0) hdr->flags[ncchflag_CONTENT_TYPE] |= (content_Trial << 2);
		else if (strcmp(set->rsfSet->BasicInfo.ContentType, "ExtendedSystemUpdate") == 0) hdr->flags[ncchflag_CONTENT_TYPE] |= (content_ExtendedSystemUpdate << 2);
		else{
			fprintf(stderr,"[NCCH ERROR] Invalid ContentType '%s'\n",set->rsfSet->BasicInfo.ContentType);
			return NCCH_BAD_RSF_SET;
		}
	}
	else 
		hdr->flags[ncchflag_CONTENT_TYPE] |= (content_Application << 2);

	return 0;
}

bool IsValidProductCode(char *ProductCode, bool FreeProductCode)
{
	if(strlen(ProductCode) > 16) 
		return false;

	if(FreeProductCode)
		return true;
		
	if(strlen(ProductCode) < 10) 
		return false;
		
	if(strncmp(ProductCode,"CTR",3) != 0 && strncmp(ProductCode, "KTR", 3) != 0)
		return false;
	
	for(int i = 3; i < 10; i++){
		if(i == 3 || i == 5){
			if(ProductCode[i] != '-') 
				return false;
		}
		else{
			if(!isdigit(ProductCode[i]) && !isupper(ProductCode[i])) 
				return false;
		}
	}

	return true;
}

// NCCH Read Functions

int VerifyNcch(u8 *ncch, keys_struct *keys, bool CheckHash, bool SuppressOutput)
{
	// Setup
	ncch_hdr* hdr = (ncch_hdr*)ncch;

	ncch_info *ncchInfo = calloc(1,sizeof(ncch_info));
	if(!ncchInfo){ 
		fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
		return MEM_ERROR; 
	}
	GetNcchInfo(ncchInfo,hdr);

	if(!SetNcchKeys(keys, hdr)){
		fprintf(stderr,"[NCCH ERROR] Failed to load ncch aes key\n");
		return UNABLE_TO_LOAD_NCCH_KEY;
	}

	if(IsCfa(hdr)){
		if(CheckCFASignature(hdr,keys) != Good){
			if(!SuppressOutput) 
				fprintf(keys->ignore_sign ? stdout :stderr,"[NCCH %s] CFA Sigcheck Failed\n", keys->ignore_sign ? "WARNING" : "ERROR");
			if (!keys->ignore_sign)
			{
				free(ncchInfo);
				return NCCH_HDR_SIG_BAD;
			}
		}
		if(!ncchInfo->romfsSize){
			if(!SuppressOutput) 
				fprintf(stderr,"[NCCH ERROR] CFA is corrupt\n");
			free(ncchInfo);
			return NO_ROMFS_IN_CFA;
		}
	}
	else{ // IsCxi
		// Checking for necessary sections
		if(!ncchInfo->exhdrSize){
			if(!SuppressOutput) 
				fprintf(stderr,"[NCCH ERROR] CXI is corrupt\n");
			free(ncchInfo);
			return NO_EXHEADER_IN_CXI;
		}
		if(!ncchInfo->exefsSize){
			if(!SuppressOutput) 
				fprintf(stderr,"[NCCH ERROR] CXI is corrupt\n");
			free(ncchInfo);
			return NO_EXEFS_IN_CXI;
		}
		// Get ExHeader/AcexDesc
		extended_hdr *exHdr = malloc(ncchInfo->exhdrSize);
		if(!exHdr){ 
			fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
			free(ncchInfo);
			return MEM_ERROR; 
		}
		memcpy(exHdr,ncch+ncchInfo->exhdrOffset,ncchInfo->exhdrSize);
		if(IsNcchEncrypted(hdr))
			CryptNcchRegion((u8*)exHdr,ncchInfo->exhdrSize,0,ncchInfo->titleId,keys->aes.ncchKey0,ncch_exhdr);

		// Checking Exheader Hash to see if decryption was sucessful
		if(!VerifySha256(exHdr, ncchInfo->exhdrSize, hdr->exhdrHash)){
			//memdump(stdout,"Expected Hash: ",hdr->extended_header_sha_256_hash,0x20);
			//memdump(stdout,"Actual Hash:   ",Hash,0x20);
			//memdump(stdout,"Exheader:      ",(u8*)exHdr,0x400);
			if(!SuppressOutput) {
				fprintf(stderr,"[NCCH ERROR] ExHeader Hashcheck Failed\n");
				fprintf(stderr,"[NCCH ERROR] CXI is corrupt\n");
			}
			free(ncchInfo);
			free(exHdr);
			return EXHDR_CORRUPT;
		}
		free(exHdr);
		
		// Checking RSA Sigs
		access_descriptor *acexDesc = malloc(ncchInfo->acexSize);
		if(!acexDesc){ 
			fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
			free(ncchInfo);
			return MEM_ERROR; 
		}
		memcpy(acexDesc,ncch+ncchInfo->acexOffset,ncchInfo->acexSize);
		if(IsNcchEncrypted(hdr))
			CryptNcchRegion((u8*)acexDesc,ncchInfo->acexSize,ncchInfo->exhdrSize,ncchInfo->titleId,keys->aes.ncchKey0,ncch_exhdr);


		if(CheckAccessDescSignature(acexDesc,keys) != Good){
			if (!SuppressOutput) 
				fprintf(keys->ignore_sign ? stdout : stderr, "[NCCH %s] AccessDesc Sigcheck Failed\n", keys->ignore_sign ? "WARNING" : "ERROR");
			if (!keys->ignore_sign)
			{
				free(ncchInfo);
				free(acexDesc);
				return ACCESSDESC_SIG_BAD;
			}
		}
				
		if(CheckCXISignature(hdr,GetAcexNcchPubKey(acexDesc)) != Good){
			if (!SuppressOutput) 
				fprintf(keys->ignore_sign ? stdout : stderr,"[NCCH %s] CXI Header Sigcheck Failed\n", keys->ignore_sign ? "WARNING" : "ERROR");
			if (!keys->ignore_sign)
			{
				free(ncchInfo);
				free(acexDesc);
				return NCCH_HDR_SIG_BAD;
			}	
		}
		
	}

	if(!CheckHash)
		return 0;

	/* Checking ExeFs Hash, if present */
	if(ncchInfo->exefsSize)
	{
		u8 *exefs = malloc(ncchInfo->exefsHashDataSize);
		if(!exefs){ 
			fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
			free(ncchInfo);
			return MEM_ERROR; 
		}
		memcpy(exefs,ncch+ncchInfo->exefsOffset,ncchInfo->exefsHashDataSize);
		if(IsNcchEncrypted(hdr))
			CryptNcchRegion(exefs,ncchInfo->exefsHashDataSize,0,ncchInfo->titleId,keys->aes.ncchKey0,ncch_exefs);
		if(!VerifySha256(exefs, ncchInfo->exefsHashDataSize, hdr->exefsHash)){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] ExeFs Hashcheck Failed\n");
			free(ncchInfo);
			free(exefs);
			return EXEFS_CORRUPT;
		}
		free(exefs);
	}

	/* Checking RomFs hash, if present */
	if(ncchInfo->romfsSize){
		u8 *romfs = malloc(ncchInfo->romfsHashDataSize);
		if(!romfs){ 
			fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
			free(ncchInfo);
			return MEM_ERROR; 
		}
		memcpy(romfs,ncch+ncchInfo->romfsOffset,ncchInfo->romfsHashDataSize);
		if(IsNcchEncrypted(hdr))
			CryptNcchRegion(romfs,ncchInfo->romfsHashDataSize,0,ncchInfo->titleId,keys->aes.ncchKey1,ncch_romfs);
		if(!VerifySha256(romfs,ncchInfo->romfsHashDataSize,hdr->romfsHash)){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] RomFs Hashcheck Failed\n");
			free(ncchInfo);
			free(romfs);
			return ROMFS_CORRUPT;
		}
		free(romfs);
	}

	/* Checking the Logo Hash, if present */
	if(ncchInfo->logoSize){
		u8 *logo = (ncch+ncchInfo->logoOffset);
		if(!VerifySha256(logo,ncchInfo->logoSize,hdr->logoHash)){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] Logo Hashcheck Failed\n");
			free(ncchInfo);
			return LOGO_CORRUPT;
		}
	} 
	
	
	free(ncchInfo);
	return 0;
}

int ModifyNcchIds(u8 *ncch, u8 *titleId, u8 *programId, keys_struct *keys)
{
	if(!IsNcch(NULL,ncch))
		return -1;
		
	ncch_hdr *hdr = (ncch_hdr*)ncch;
	
	bool titleIdMatches = titleId == NULL? true : memcmp(titleId,hdr->titleId,8) == 0;
	bool programIdMatches = programId == NULL? true : memcmp(programId,hdr->programId,8) == 0;

	if(titleIdMatches && programIdMatches) 
		return 0;// if no modification is required don't do anything

	if(/*keys->rsa.requiresPresignedDesc && */!IsCfa(hdr)){
		fprintf(stderr,"[NCCH ERROR] CXI's ID cannot be modified without the ability to resign the AccessDesc\n"); // Not yet yet, requires AccessDesc Privk, may implement anyway later
		return -1;
	}

	ncch_info ncchInfo;
	u8 *romfs = NULL;
	
	//Decrypting if necessary
	if(IsNcchEncrypted(hdr)){
		GetNcchInfo(&ncchInfo,hdr);
		romfs = (ncch+ncchInfo.romfsOffset);
		if(!SetNcchKeys(keys, hdr)){
			fprintf(stderr,"[NCCH ERROR] Failed to load ncch aes key\n");
			return -1;
		}
		CryptNcchRegion(romfs,ncchInfo.romfsSize,0,ncchInfo.titleId,keys->aes.ncchKey1,ncch_romfs);
	}
	
	// Editing data and resigning
	if(titleId)
		memcpy(hdr->titleId,titleId,8);
	if(programId)
		memcpy(hdr->programId,programId,8);
	SignCFA(hdr,keys);
	
	// Re-encrypting if necessary
	if(IsNcchEncrypted(hdr)){
		GetNcchInfo(&ncchInfo,hdr);
		romfs = (ncch+ncchInfo.romfsOffset);
		if(!SetNcchKeys(keys, hdr)){
			fprintf(stderr,"[NCCH ERROR] Failed to load ncch aes key\n");
			return -1;
		}
		CryptNcchRegion(romfs,ncchInfo.romfsSize,0,ncchInfo.titleId,keys->aes.ncchKey1,ncch_romfs);
	}

	return 0;
}


void ReadNcchHdr(ncch_hdr *hdr, FILE *fp)
{
	if(!fp || !hdr)
		return;
		
	ReadFile64(hdr,sizeof(ncch_hdr),0,fp);
	
	return;
}

u8* GetNcchHdrSig(ncch_hdr *hdr)
{
	return (u8*)hdr->signature;
}

u8* GetNcchHdrData(ncch_hdr *hdr)
{
	return (u8*)hdr->magic;
}

u32 GetNcchHdrSigLen(ncch_hdr *hdr)
{
	return 0x100;
}

u32 GetNcchHdrDataLen(ncch_hdr *hdr)
{
	return 0x100;
}

bool IsNcch(FILE *fp, u8 *buf)
{
	if(!fp && !buf) 
		return false;
		
	ncch_hdr *hdr;
	bool result;
	
	if(fp) {
		hdr = malloc(sizeof(ncch_hdr));
		ReadNcchHdr(hdr,fp);
		result = (memcmp(hdr->magic,"NCCH",4) == 0);
		free(hdr);
	}
	else {
		hdr = (ncch_hdr*)buf;
		result = (memcmp(hdr->magic,"NCCH",4) == 0);
	}
	return result;
}

bool IsCfa(ncch_hdr* hdr)
{
	return (hdr->flags[ncchflag_CONTENT_TYPE] & 3) == form_SimpleContent;
}

bool IsUpdateCfa(ncch_hdr* hdr)
{
	return (hdr->flags[ncchflag_CONTENT_TYPE] >> 2) == content_SystemUpdate || (hdr->flags[ncchflag_CONTENT_TYPE] >> 2) == content_ExtendedSystemUpdate;
}

u32 GetNcchBlockSize(ncch_hdr* hdr)
{
	/*
	u16 formatVersion = u8_to_u16(hdr->formatVersion,LE);
	if (formatVersion == 1)
		return 1;
	*/
	return GetCtrBlockSize(hdr->flags[ncchflag_CONTENT_BLOCK_SIZE]); //formatVersion == 2 || formatVersion == 0
}

u64 GetNcchSize(ncch_hdr* hdr)
{
	return (u64)u8_to_u32(hdr->ncchSize,LE) * (u64)GetNcchBlockSize(hdr);
}

bool IsNcchEncrypted(ncch_hdr *hdr)
{
	return (hdr->flags[ncchflag_OTHER_FLAG] & otherflag_NoCrypto) != otherflag_NoCrypto;
}

bool SetNcchKeys(keys_struct *keys, ncch_hdr *hdr)
{
	if (!IsNcchEncrypted(hdr))
		return true;

	if ((hdr->flags[ncchflag_OTHER_FLAG] & otherflag_FixedCryptoKey) == otherflag_FixedCryptoKey) {
		if ((hdr->programId[4] & 0x10) == 0x10) {
			if (!keys->aes.systemFixedKey)
				return false;
			memcpy(keys->aes.ncchKey0, keys->aes.systemFixedKey, AES_128_KEY_SIZE);
			memcpy(keys->aes.ncchKey1, keys->aes.systemFixedKey, AES_128_KEY_SIZE);
			return true;
		}
		else {
			if (!keys->aes.normalKey)
				return false;
			memcpy(keys->aes.ncchKey0, keys->aes.normalKey, AES_128_KEY_SIZE);
			memcpy(keys->aes.ncchKey1, keys->aes.normalKey, AES_128_KEY_SIZE);
			return true;
		}
	}

	u8 ncch_keyx_index = 0;
	switch (hdr->flags[ncchflag_CONTENT_KEYX])
	{
	case (keyx_7_0):
		ncch_keyx_index = 1;
		break;
	case (keyx_9_3):
		ncch_keyx_index = 2;
		break;
	case (keyx_9_6):
		ncch_keyx_index = 3;
		break;
	default:
		ncch_keyx_index = 0;
	}

	if(keys->aes.ncchKeyX[0])
		ctr_aes_keygen(keys->aes.ncchKeyX[0],hdr->signature,keys->aes.ncchKey0);
	else
		return false;

	if(keys->aes.ncchKeyX[ncch_keyx_index])
		ctr_aes_keygen(keys->aes.ncchKeyX[ncch_keyx_index], hdr->signature, keys->aes.ncchKey1);
	else
		return false;
		
	return true;
}

int GetNcchInfo(ncch_info *info, ncch_hdr *hdr)
{
	clrmem(info, sizeof(ncch_info));

	info->titleId = u8_to_u64(hdr->titleId,LE);
	info->programId = u8_to_u64(hdr->programId,LE);

	u64 block_size = GetNcchBlockSize(hdr);
	
	info->formatVersion = u8_to_u16(hdr->formatVersion,LE);
	if(!IsCfa(hdr)){
		info->exhdrOffset = sizeof(ncch_hdr);
		info->exhdrSize = u8_to_u32(hdr->exhdrSize,LE);
		info->acexOffset = (info->exhdrOffset + info->exhdrSize);
		info->acexSize = sizeof(access_descriptor);
		info->plainRegionOffset = ((u64)u8_to_u32(hdr->plainRegionOffset,LE))*block_size;
		info->plainRegionSize = ((u64)u8_to_u32(hdr->plainRegionSize,LE))*block_size;
	}

	info->logoOffset = ((u64)u8_to_u32(hdr->logoOffset,LE))*block_size;
	info->logoSize = ((u64)u8_to_u32(hdr->logoSize,LE))*block_size;
	info->exefsOffset = ((u64)u8_to_u32(hdr->exefsOffset,LE))*block_size;
	info->exefsSize = ((u64)u8_to_u32(hdr->exefsSize,LE))*block_size;
	info->exefsHashDataSize = ((u64)u8_to_u32(hdr->exefsHashSize,LE))*block_size;
	info->romfsOffset = ((u64)u8_to_u32(hdr->romfsOffset,LE))*block_size;
	info->romfsSize = ((u64)u8_to_u32(hdr->romfsSize,LE))*block_size;
	info->romfsHashDataSize = ((u64)u8_to_u32(hdr->romfsHashSize,LE))*block_size;
	return 0;
}

void GetNcchAesCounter(u8 ctr[16], u64 titleId, u8 type)
{
	clrmem(ctr,16);	
	u64_to_u8(ctr,titleId,BE);
	ctr[8] = type;
}

void CryptNcchRegion(u8 *buffer, u64 size, u64 src_pos, u64 titleId, u8 key[16], u8 type)
{
	u8 ctr[0x10];
	GetNcchAesCounter(ctr,titleId,type);	
	AesCtrCrypt(key,ctr,buffer,buffer,size,src_pos);
	return;
}
