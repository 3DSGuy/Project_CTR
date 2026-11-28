#include "lib.h"

#include "ncch_read.h"
#include "exheader_read.h"
#include "tik_read.h"
#include "tmd_read.h"
#include "cia_read.h"

#include "ncsd_build.h"
#include "cardinfo.h"
#include "titleid.h"

const int NCCH0_OFFSET = 0x4000;
const int CCI_BLOCK_SIZE = 0x200;

const char MEDIA_SIZE_STR[10][6] = {"128MB","256MB","512MB","1GB","2GB","4GB","8GB","16GB","32GB"};

void ImportCciSettings(cci_settings *set, user_settings *usrset);
void FreeCciSettings(cci_settings *set);
int ImportCciNcch(cci_settings *set);
int ProcessNcchForCci(cci_settings *set);
int GenCciHdr(cci_settings *set);
int CheckRomConfig(cci_settings *set);
void WriteCciDataToOutput(cci_settings *set);

int build_CCI(user_settings *usrset)
{
	int result = 0;
	cci_settings *set = calloc(1,sizeof(cci_settings));
	if(!set){
		fprintf(stderr,"[CCI ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	ImportCciSettings(set,usrset);
	
	if(ImportCciNcch(set)){
		result = FAILED_TO_IMPORT_FILE;
		goto finish;
	}
		
	if(ProcessNcchForCci(set)){
		result = FAILED_TO_IMPORT_FILE;
		goto finish;
	}
	
	if(GenCciHdr(set)){
		result = GEN_HDR_FAIL;
		goto finish;
	}
	
	if(GenCardInfoHdr(set)){
		result = GEN_HDR_FAIL;
		goto finish;
	}
	
	if(CheckRomConfig(set)){
		result = CCI_CONFIG_FAIL;
		goto finish;
	}
	
	set->out = fopen(usrset->common.outFileName,"wb");
	if(!set->out){
		fprintf(stderr,"[CCI ERROR] Failed to create '%s'\n",usrset->common.outFileName);
		result = FAILED_TO_CREATE_OUTFILE;
		goto finish;
	}
	
	WriteCciDataToOutput(set);
	
finish:
	FreeCciSettings(set);
	return result;
}

void ImportCciSettings(cci_settings *set, user_settings *usrset)
{
	set->keys = &usrset->common.keys;
	set->rsf = &usrset->common.rsfSet;
	
	set->content.data = usrset->common.workingFile.buffer;
	set->content.dataLen = usrset->common.workingFile.size;
	set->content.dataType = usrset->common.workingFileType;
	
	set->content.path = usrset->common.contentPath;
	set->content.dSize = usrset->common.contentSize;
	
	usrset->common.workingFile.buffer = NULL;
	usrset->common.workingFile.size = 0;
	
	set->options.verbose = usrset->common.verbose;
	set->options.padCci = set->rsf->Option.MediaFootPadding;
	set->options.noModTid = usrset->cci.dontModifyNcchTitleID;
	set->options.useExternalSdkCardInfo = usrset->cci.useSDKStockData;
	set->options.closeAlignWR = usrset->cci.closeAlignWritableRegion;
	
	set->options.cverDataType = usrset->cci.cverDataType;
	set->options.cverDataPath = usrset->cci.cverDataPath;
	
	set->romInfo.blockSize = CCI_BLOCK_SIZE;
	set->romInfo.saveSize = 0;
}

void FreeCciSettings(cci_settings *set)
{
	free(set->options.tmdHdr);
	free(set->content.data);
	free(set->headers.ccihdr.buffer);
	free(set->headers.cardinfohdr.buffer);
	if(set->out)
		fclose(set->out);
	free(set);
}

int ImportNcchForCci(cci_settings *set)
{
	for(int i = 0; i < CCI_MAX_CONTENT; i++){
		if(i == 0){
			set->content.active[i] = true;
			set->content.dSize[i] = set->content.dataLen;
			set->content.dOffset[i] = 0;
		}
		else if(set->content.dSize[i] && set->content.path[i]){
			set->content.active[i] = true;
			set->content.dOffset[i] = set->content.dataLen;
			set->content.dataLen += set->content.dSize[i];
		}
		else
			set->content.active[i] = false;
	}

	set->content.data = realloc(set->content.data,set->content.dataLen);
	if(!set->content.data){
		fprintf(stderr,"[CCI ERROR] Not enough memory\n");
		return MEM_ERROR;
	}

	FILE *ncch;
	for(int i = 1; i < CCI_MAX_CONTENT; i++){
		if(!set->content.active[i])
			continue;

		u8 *ncchpos = (u8*)(set->content.data+set->content.dOffset[i]);

		ncch = fopen(set->content.path[i],"rb");
		
		ReadFile64(ncchpos, set->content.dSize[i], 0, ncch);
		
		fclose(ncch);
	}
	
	return 0;
}

bool CanCiaBeCci(u64 titleId, u16 count, tmd_content_chunk *content)
{
	if(GetTidCategory(titleId) != PROGRAM_ID_CATEGORY_APPLICATION)
		return false;
		
	if(count > CCI_MAX_CONTENT)
		return false;
		
	for(int i = 0; i < count; i++){
		if(GetTmdContentIndex(content[i]) >= CCI_MAX_CONTENT)
			return false;
	}
	
	return true;
}

int ProcessCiaForCci(cci_settings *set)
{
	if(!IsCia(set->content.data)){
		fprintf(stderr,"[CCI ERROR] CIA is corrupt\n");
		return FAILED_TO_IMPORT_FILE;
	}
		
	tik_hdr *tik = GetTikHdr(GetCiaTik(set->content.data));
	tmd_hdr *tmd = GetTmdHdr(GetCiaTmd(set->content.data));
	tmd_content_chunk *contentInfo = GetTmdContentInfo(GetCiaTmd(set->content.data));
	u64 contentOffset = GetCiaContentOffset((cia_hdr*)set->content.data);
	
	u16 contentCount = GetTmdContentCount(tmd);
	set->romInfo.saveSize = GetTmdSaveSize(tmd);
	
	if(!CanCiaBeCci(GetTmdTitleId(tmd),contentCount,contentInfo)){
		fprintf(stderr,"[CCI ERROR] This CIA cannot be converted to CCI\n");
		return INCOMPAT_CIA;
	}
		
	bool canDecrypt;
	u8 titleKey[AES_128_KEY_SIZE];
	canDecrypt = GetTikTitleKey(titleKey,tik,set->keys);
	if(set->options.verbose){
		if(canDecrypt)
			memdump(stdout,"[CCI] CIA title key: ",titleKey,AES_128_KEY_SIZE);
		else
			fprintf(stdout,"[CCI] CIA title key could not be decrypted\n");
	}
	
	for(u16 i = 0; i < contentCount; i++){
		u16 index = GetTmdContentIndex(contentInfo[i]);
		set->content.active[index] = true;
		set->content.dOffset[index] = contentOffset;
		set->content.dSize[index] = GetTmdContentSize(contentInfo[i]);
		u8 *content = set->content.data + contentOffset;
		if(IsTmdContentEncrypted(contentInfo[i])){
			if(canDecrypt)
				CryptContent(content,content,set->content.dSize[index],titleKey,i,DEC);
			else{
				fprintf(stderr,"[CCI ERROR] Failed to decrypt CIA content: 0x%08x\n",GetTmdContentId(contentInfo[i]));
				return INCOMPAT_CIA;
			}
		}
		if(!ValidateTmdContent(content,contentInfo[i])){
			fprintf(stderr,"[CCI ERROR] CIA content: 0x%08x is corrupt\n",GetTmdContentId(contentInfo[i]));
			return NCSD_INVALID_NCCH;
		}
		
		contentOffset += set->content.dSize[index];
	}
	
	return 0;
}

/* This need to be more automagical */
void GetTitleSaveSize(cci_settings *set)
{
	if(set->rsf->SystemControlInfo.SaveDataSize)
		GetSaveDataSizeFromString(&set->romInfo.saveSize,set->rsf->SystemControlInfo.SaveDataSize,"CCI");
		
	// Adjusting save size
	if(set->romInfo.saveSize > 0 && set->romInfo.saveSize < (u64)(128*KB))
		set->romInfo.saveSize = (u64)(128*KB);
	else if(set->romInfo.saveSize > (u64)(128*KB) && set->romInfo.saveSize < (u64)(512*KB))
		set->romInfo.saveSize = (u64)(512*KB);
	else if(set->romInfo.saveSize > (u64)(512*KB))
		set->romInfo.saveSize = align(set->romInfo.saveSize,MB);
}

int ImportCciNcch(cci_settings *set)
{
	int ret = 0;

	if(set->content.dataType == infile_ncch)
		ret = ImportNcchForCci(set);
	else if(set->content.dataType == infile_cia)
		ret = ProcessCiaForCci(set);
	else{
		fprintf(stderr,"[CCI ERROR] Unrecognised input data type\n");	
		return FAILED_TO_IMPORT_FILE;
	}
	
	GetTitleSaveSize(set);
	
	return ret;
}

int ProcessCverDataForCci(cci_settings *set)
{
	u64 tmdSize,tmdOffset;
	
	u64 dataSize = GetFileSize64(set->options.cverDataPath);
	FILE *data = fopen(set->options.cverDataPath,"rb");
	
	
	if(set->options.cverDataType == CVER_DTYPE_CIA){
		cia_hdr *ciaHdr = calloc(1,sizeof(cia_hdr));
		ReadFile64(ciaHdr,sizeof(cia_hdr),0,data);
	
		tmdSize = GetCiaTmdSize(ciaHdr);
		tmdOffset = GetCiaTmdOffset(ciaHdr);
		
		free(ciaHdr);
	}
	else{
		tmdSize = dataSize;
		tmdOffset = 0;
	}
	
	u8 *tmd = calloc(1,tmdSize);
	
	ReadFile64(tmd,tmdSize,tmdOffset,data);
	fclose(data);
	
	tmd_hdr *tmdHdr = GetTmdHdr(tmd);
	if(!tmdHdr){
		fprintf(stderr,"[CCI ERROR] Corrupt cver TMD\n");
		free(tmd);
		return FAILED_TO_IMPORT_FILE;
	}
	
	set->options.tmdHdr = calloc(1,sizeof(tmd_hdr));
	memcpy(set->options.tmdHdr,tmdHdr,sizeof(tmd_hdr));
	
	free(tmd);

	return 0;
}

void GetNewNcchIdForCci(u8 *newTid, u8 *srcTid, u8 index, tmd_hdr *tmdHdr)
{
	u64 titleId = u8_to_u64(srcTid,LE) & 0xffffffffffff;
	if(tmdHdr && index == 7)
		titleId |= (u64)(GetTmdVersion(tmdHdr)) << 48;
	else
		titleId |= (u64)(index+4) << 48;
		
	u64_to_u8(newTid,titleId,LE);
}

int ProcessNcchForCci(cci_settings *set)
{
	u8 *ncch;
	ncch_hdr *hdr;
	
	u8 titleId[8];
	u8 srcId[8];
	
	if(set->options.cverDataPath && set->content.active[7]){
		if(ProcessCverDataForCci(set))
			return FAILED_TO_IMPORT_FILE;
	}
	
	for(int i = 0; i < CCI_MAX_CONTENT; i++){
		if(set->content.active[i]){
			ncch = set->content.data + set->content.dOffset[i];
			if(!IsNcch(NULL,ncch)){
				fprintf(stderr,"[CCI ERROR] NCCH %d is corrupt\n",i);
				return NCSD_INVALID_NCCH;
			}
			hdr = (ncch_hdr*)ncch;
			if(i > 0 && !set->options.noModTid){
				if(set->options.verbose){
					printf("[CCI] Modifying NCCH %d IDs\n",i);
					printf("[Old Ids]\n");
					memdump(stdout," > TitleId:   0x",hdr->titleId,8);
					memdump(stdout," > ProgramId: 0x",hdr->programId,8);
				}
				GetNewNcchIdForCci(titleId,srcId,i,set->options.tmdHdr);
				if(ModifyNcchIds(ncch, titleId, srcId, set->keys))
					return -1;
				if(set->options.verbose){
					printf("[New Ids]\n");
					memdump(stdout," > TitleId:   0x",hdr->titleId,8);
					memdump(stdout," > ProgramId: 0x",hdr->programId,8);
				}
			}
			set->content.titleId[i] = u8_to_u64(hdr->titleId,LE);
			if(i == 0)
				memcpy(srcId,hdr->titleId,8);
		}
	}
	
	return 0;
}

void SetCciNcchInfo(cci_hdr *hdr, cci_settings *set)
{
	u64 ncchSize,ncchOffset;
	
	ncchOffset = NCCH0_OFFSET;
	
	for(int i = 0; i < CCI_MAX_CONTENT; i++){
		if(set->content.active[i]){
			set->content.cOffset[i] = ncchOffset;
			ncchSize = align(set->content.dSize[i],set->romInfo.blockSize);
			
			u32_to_u8(hdr->offset_sizeTable[i].offset,(ncchOffset/set->romInfo.blockSize),LE);
			u32_to_u8(hdr->offset_sizeTable[i].size,(ncchSize/set->romInfo.blockSize),LE);
			u64_to_u8(hdr->ncchIdTable[i],set->content.titleId[i],LE);
			
			ncchOffset += ncchSize;
		}
	}
	
	set->romInfo.usedSize = ncchOffset;
	
	return;
}

int SetMediaSize(u8 *mediaSize, cci_settings *set)
{	
	char *str = set->rsf->CardInfo.MediaSize;
	if(str){
		if(strcasecmp(str,"128MB") == 0) set->romInfo.mediaSize = (u64)MB*128;
		else if(strcasecmp(str,"256MB") == 0) set->romInfo.mediaSize = (u64)MB*256;
		else if(strcasecmp(str,"512MB") == 0) set->romInfo.mediaSize = (u64)MB*512;
		else if(strcasecmp(str,"1GB") == 0) set->romInfo.mediaSize = (u64)GB*1;
		else if(strcasecmp(str,"2GB") == 0) set->romInfo.mediaSize = (u64)GB*2;
		else if(strcasecmp(str,"4GB") == 0) set->romInfo.mediaSize = (u64)GB*4;
		else if(strcasecmp(str,"8GB") == 0) set->romInfo.mediaSize = (u64)GB*8;
		//else if(strcasecmp(str,"16GB") == 0) set->romInfo.mediaSize = (u64)GB*16;
		//else if(strcasecmp(str,"32GB") == 0) set->romInfo.mediaSize = (u64)GB*32;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid MediaSize: %s\n",str);
			return INVALID_RSF_OPT;
		}
	}
	else{
		u64 dataSize = set->romInfo.usedSize + (set->romInfo.saveSize >= MB ? set->romInfo.saveSize : 0);
		if(dataSize < (u64)MB*128)
			set->romInfo.mediaSize = (u64)MB*128;
		else if(dataSize < (u64)MB*256)
			set->romInfo.mediaSize = (u64)MB*256;
		else if(dataSize < (u64)MB*512)
			set->romInfo.mediaSize = (u64)MB*512;
		else if(dataSize < (u64)GB*1)
			set->romInfo.mediaSize = (u64)GB*1;
		else if(dataSize < (u64)GB*2)
			set->romInfo.mediaSize = (u64)GB*2;
		else if(dataSize < (u64)GB*4)
			set->romInfo.mediaSize = (u64)GB*4;
		else if(dataSize < (u64)GB*8)
			set->romInfo.mediaSize = (u64)GB*8;
		//else if(dataSize < (u64)GB*16)
		//	set->romInfo.mediaSize = (u64)GB*16;
		//else if(dataSize < (u64)GB*32)
		//	set->romInfo.mediaSize = (u64)GB*32;
		else {
			fprintf(stderr,"[CCI ERROR] NCCH Partitions are too large\n");
			return INVALID_RSF_OPT;
		}
	}
		
	u32_to_u8(mediaSize,(set->romInfo.mediaSize/set->romInfo.blockSize),LE);

	return 0;
}

int SetBackupWriteWaitTime(u8 *flag, rsf_settings *rsf)
{
	char *str = rsf->CardInfo.BackupWriteWaitTime;
	if(!str)
		*flag = 0;
	else{
		u32 waitTime = strtoul(str,NULL,0);
		if(waitTime > 255){
			fprintf(stderr,"[CCI ERROR] Invalid Card BackupWriteWaitTime (%d) : must 0-255\n",waitTime);
			return INVALID_RSF_OPT;
		}
		*flag = (u8)waitTime;
	}
	
	return 0;
}

int SetMediaType(u8 *flag, cci_settings *set)
{
	char *str = set->rsf->CardInfo.MediaType;

	if(str){
		if(strcasecmp(str,"Card1") == 0) 
			*flag = mediatype_CARD1;
		else if(strcasecmp(str,"Card2") == 0)
			*flag = mediatype_CARD2;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid MediaType: %s\n",str);
			return INVALID_RSF_OPT;
		}
	}
	else{
		if(set->romInfo.saveSize >= (u64)1*MB)
			*flag = mediatype_CARD2;
		else
			*flag = mediatype_CARD1;
	}
	
	return 0;
}

int SetCardDevice(u8 *flags, u64 saveSize, rsf_settings *rsf)
{
	u8 saveCrypto;

	if(!rsf->CardInfo.SaveCrypto) 
		saveCrypto = 3;
	else{
		if(strcasecmp(rsf->CardInfo.SaveCrypto,"fw1") == 0 || strcasecmp(rsf->CardInfo.SaveCrypto,"ctr fail") == 0 ) saveCrypto = 1;
		else if(strcasecmp(rsf->CardInfo.SaveCrypto,"fw2") == 0) saveCrypto = 2;
		else if(strcasecmp(rsf->CardInfo.SaveCrypto,"fw3") == 0) saveCrypto = 3;
		else if(strcasecmp(rsf->CardInfo.SaveCrypto,"fw6") == 0) saveCrypto = 6;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid SaveCrypto: %s\n",rsf->CardInfo.SaveCrypto);
			return INVALID_RSF_OPT;
		}
	}
	

	/* FW6x SaveCrypto */
	if(saveCrypto == 6)
		flags[cciflag_FW6_SAVE_CRYPTO] = 1;
	else
		flags[cciflag_FW6_SAVE_CRYPTO] = 0;

	/* CardDevice */
	u8 cardDevice = 0;
	if(rsf->CardInfo.CardDevice){
		if(strcmp(rsf->CardInfo.CardDevice,"NorFlash") == 0)
			cardDevice = carddevice_NOR_FLASH;
		else if(strcmp(rsf->CardInfo.CardDevice,"None") == 0) 
			cardDevice = carddevice_NONE;
		else if(strcmp(rsf->CardInfo.CardDevice,"BT") == 0) 
			cardDevice = carddevice_BT;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid CardDevice: %s\n",rsf->CardInfo.CardDevice);
			return INVALID_RSF_OPT;
		}
	}
	else{
		if(saveSize == 0 || saveSize >= (u64)1*MB)
			cardDevice = carddevice_NONE;
		else
			cardDevice = carddevice_NOR_FLASH;
	}
	
	if(flags[cciflag_MEDIA_TYPE] == mediatype_CARD1){
		if(saveSize != (u64)(128*KB) && saveSize != (u64)(512*KB) && cardDevice == carddevice_NOR_FLASH){
			fprintf(stderr,"[CCI ERROR] 'CardDevice: NorFlash' can only be used with save-data sizes: 128K & 512K\n");
			return INVALID_RSF_OPT;
		}
	}
	if(flags[cciflag_MEDIA_TYPE] == mediatype_CARD2){
		if(cardDevice == carddevice_NOR_FLASH){
			fprintf(stderr,"[CCI WARNING] 'CardDevice: NorFlash' is invalid for Card2\n");
			cardDevice = carddevice_NONE;
		}
	}
	
	if(saveCrypto > 1)
		flags[saveCrypto == 2? cciflag_CARD_DEVICE_OLD : cciflag_CARD_DEVICE] = cardDevice;
	
	return 0;
}

int SetCciFlags(u8 *flags, cci_settings *set)
{
	// Backup Write Wait Time
	if(SetBackupWriteWaitTime(&flags[cciflag_BACKUP_WRITE_WAIT_TIME], set->rsf))
		return INVALID_RSF_OPT;
	// Platform
	flags[cciflag_MEDIA_PLATFORM] = cciplatform_CTR;
	// Card Type
	if(SetMediaType(&flags[cciflag_MEDIA_TYPE], set))
		return INVALID_RSF_OPT;
	// Media Unit
	flags[cciflag_MEDIA_BLOCK_SIZE] = GetCtrBlockSizeFlag(set->romInfo.blockSize);
	// Card Device
	if(SetCardDevice(flags, set->romInfo.saveSize, set->rsf))
		return INVALID_RSF_OPT;
	
	set->romInfo.mediaType = flags[cciflag_MEDIA_TYPE];
	set->romInfo.cardDevice = flags[cciflag_CARD_DEVICE] | flags[cciflag_CARD_DEVICE_OLD];
	
	return 0;
}

int GenCciHdr(cci_settings *set)
{
	set->headers.ccihdr.size = sizeof(cci_hdr);
	set->headers.ccihdr.buffer = calloc(1,set->headers.ccihdr.size);
	if(!set->headers.ccihdr.buffer){
		set->headers.ccihdr.size = 0;
		fprintf(stderr,"[CCI ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	
	cci_hdr *hdr = (cci_hdr*)set->headers.ccihdr.buffer;
	
	// Magic & TitleId
	memcpy(hdr->magic,"NCSD",4);
	u64_to_u8(hdr->titleId,set->content.titleId[0],LE);
	
	
	SetCciNcchInfo(hdr,set);
	if(SetMediaSize(hdr->mediaSize,set))
		return GEN_HDR_FAIL;
	if(SetCciFlags(hdr->flags,set))
		return GEN_HDR_FAIL;
	
	
	// Sign Header
	if (Rsa2048Key_CanSign(&set->keys->rsa.cciCfa) == false)
	{
		printf("[NCSD WARNING] Failed to sign header (key was incomplete)\n");
		memset(hdr->signature, 0xFF, 0x100);
		return 0;
	}

	int rsa_ret = RsaSignVerify(&hdr->magic, sizeof(cci_hdr) - RSA_2048_KEY_SIZE, hdr->signature, set->keys->rsa.cciCfa.pub, set->keys->rsa.cciCfa.pvt, RSA_2048_SHA256, CTR_RSA_SIGN);
	if (rsa_ret != 0)
	{
		printf("[NCSD WARNING] Failed to sign header (mbedtls error = -0x%x)\n", -rsa_ret);
		memset(hdr->signature, 0xFF, 0x100);
		return 0;
	}

	return 0;
}

char* GetMediaSizeStr(u64 mediaSize)
{
	//MEDIA_SIZE_STR
	switch(mediaSize){
		case (u64)MB*128: return (char*)MEDIA_SIZE_STR[0];
		case (u64)MB*256: return (char*)MEDIA_SIZE_STR[1];
		case (u64)MB*512: return (char*)MEDIA_SIZE_STR[2];
		case (u64)GB*1: return (char*)MEDIA_SIZE_STR[3];
		case (u64)GB*2: return (char*)MEDIA_SIZE_STR[4];
		case (u64)GB*4: return (char*)MEDIA_SIZE_STR[5];
		case (u64)GB*8: return (char*)MEDIA_SIZE_STR[6];
		default: return 0;
	}
}

int CheckRomConfig(cci_settings *set)
{		
	u64 cciUsedSize;
	if(set->romInfo.mediaType == mediatype_CARD2)
		cciUsedSize = set->romInfo.card2SaveOffset + set->romInfo.saveSize;
	else
		cciUsedSize = set->romInfo.usedSize;
		
	if(cciUsedSize > set->romInfo.mediaSize){			
		fprintf(stderr,"[CCI ERROR] MediaSize '%s' is insufficient for the CCI data\n",GetMediaSizeStr(set->romInfo.mediaSize));
		return CCI_CONFIG_FAIL;
	}
	return 0;
}

void WriteCciDataToOutput(cci_settings *set)
{
	if (set->options.verbose) {
		printf("[CCI] Writing header to file... ");
	}

	// NCSD Header
	WriteBuffer(set->headers.ccihdr.buffer, set->headers.ccihdr.size, 0, set->out);
	// Card Info Header
	WriteBuffer(set->headers.cardinfohdr.buffer, set->headers.cardinfohdr.size, set->headers.ccihdr.size, set->out);
	
	// Dummy data between header and first NCCH
	u64 len = set->content.cOffset[0] - (set->headers.ccihdr.size + set->headers.cardinfohdr.size);
	u8 *dummy_data = malloc(len);
	if(set->headers.cardinfohdr.size > sizeof(cardinfo_hdr)) // additional debug header data exists
		memset(dummy_data, 0x00, len);
	else // normal production cci image
		memset(dummy_data, 0xff, len);
	WriteBuffer(dummy_data, len, (set->headers.ccihdr.size + set->headers.cardinfohdr.size),set->out);	
	free(dummy_data);

	if (set->options.verbose) {
		printf("Done!\n");
	}
	
	// NCCH Partitions
	u8 *ncch;
	for(int i = 0; i < CCI_MAX_CONTENT; i++){
		if(set->content.active[i]){
			if (set->options.verbose) {
				printf("[CCI] Writing content %d to file... ", i);
			}

			ncch = set->content.data + set->content.dOffset[i];
			WriteBuffer(ncch, set->content.dSize[i], set->content.cOffset[i], set->out);

			if (set->options.verbose) {
				printf("Done!\n");
			}
		}
	}	
	
	// Cci Padding
	if(set->options.padCci){
		if (set->options.verbose) {
			printf("[CCI] Writing padding to file... ");
		}

		fseek_64(set->out,set->romInfo.usedSize);

		// Determining Size of Padding
		u64 len = set->romInfo.mediaSize - set->romInfo.usedSize;
		
		// Create Padding chunk
		u8 *pad = malloc(set->romInfo.blockSize);
		memset(pad,0xff,set->romInfo.blockSize);
		
		// Writing Dummy Bytes to file
		for(u64 i = 0; i < len; i += set->romInfo.blockSize)
			fwrite(pad,set->romInfo.blockSize,1,set->out);
			
		free(pad);

		if (set->options.verbose) {
			printf("Done!");
		}
	}
	
	return;
}

bool IsCci(u8 *ncsd)
{
	cci_hdr *hdr = (cci_hdr*)ncsd;
	if(!hdr) return false;
	if(memcmp(hdr->magic,"NCSD",4)!=0) return false;
	if(hdr->flags[cciflag_MEDIA_PLATFORM] != cciplatform_CTR) return false;
	if(hdr->flags[cciflag_MEDIA_TYPE] != mediatype_CARD1 && hdr->flags[cciflag_MEDIA_TYPE] != mediatype_CARD2) return false;

	return true;
}

u64 GetPartitionOffset(u8 *ncsd, u8 index)
{
	cci_hdr *hdr = (cci_hdr*)ncsd;
	return (u64)u8_to_u32(hdr->offset_sizeTable[index].offset,LE) * (u64)GetCtrBlockSize(hdr->flags[cciflag_MEDIA_BLOCK_SIZE]);
}

u64 GetPartitionSize(u8 *ncsd, u8 index)
{
	cci_hdr *hdr = (cci_hdr*)ncsd;
	return (u64)u8_to_u32(hdr->offset_sizeTable[index].size,LE) * (u64)GetCtrBlockSize(hdr->flags[cciflag_MEDIA_BLOCK_SIZE]);
}

u8* GetPartition(u8 *ncsd, u8 index)
{
	return ncsd + GetPartitionOffset(ncsd,index);
}