#include "lib.h"

#include "srl.h"
#include "ncsd_read.h"
#include "ncch_read.h"
#include "exheader_read.h"
#include "exefs_read.h"

#include "cia_build.h"
#include "cia_read.h"
#include "tik_build.h"
#include "tmd_build.h"
#include "titleid.h"
#include "titlever.h"
#include "certs.h"

const int CIA_ALIGN_SIZE = 0x40;
const int CIA_CONTENT_ALIGN = 0x10;

// Private Prototypes
void FreeCiaSettings(cia_settings *set);
int GetCiaSettings(cia_settings *ciaset, user_settings *usrset);

int GetSettingsFromUsrset(cia_settings *ciaset, user_settings *usrset);
int GetSettingsFromNcch0(cia_settings *ciaset, u32 ncch0_offset);
int GetTmdDataFromNcch(cia_settings *ciaset, u8 *ncch, ncch_info *ncch_ctx, u8 *key);
int GetMetaRegion(cia_settings *ciaset, u8 *ncch, ncch_info *ncch_ctx, u8 *key);
int ProcessContentFiles(cia_settings *ciaset, user_settings *usrset);
int ImportNcchContent(cia_settings *ciaset, user_settings *usrset);
int GetSettingsFromSrl(cia_settings *ciaset);
int GetSettingsFromCci(cia_settings *ciaset);

void GetContentHashes(cia_settings *ciaset);
void EncryptContent(cia_settings *ciaset);

int BuildCiaCertChain(cia_settings *ciaset);
int BuildCiaHdr(cia_settings *ciaset);

int WriteCiaToFile(cia_settings *ciaset);


int build_CIA(user_settings *usrset)
{
	int result = 0;

	// Init Settings
	cia_settings *ciaset = calloc(1,sizeof(cia_settings));
	if(!ciaset) {
		fprintf(stderr,"[CIA ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}

	// Get Settings
	result = GetCiaSettings(ciaset,usrset);
	if(result) {
		fprintf(stderr,"[CIA ERROR] Failed to initialize context.\n");
		goto finish;
	}

	// Create Output File
	ciaset->out = fopen(usrset->common.outFileName,"wb");
	if(!ciaset->out){
		fprintf(stderr,"[CIA ERROR] Failed to create \"%s\"\n",usrset->common.outFileName);
		result = FAILED_TO_CREATE_OUTFILE;
		goto finish;
	}

	// Create CIA Sections

	/* Certificate Chain */
	result = BuildCiaCertChain(ciaset);
	if(result) {
		fprintf(stderr,"[CIA ERROR] Failed to build Certificate Chain\n");
		goto finish;
	}

	/* Ticket */
	result = BuildTicket(ciaset);
	if(result) {
		fprintf(stderr,"[CIA ERROR] Failed to build Ticket\n");
		goto finish;
	}

	/* Title Metadata */
	result = BuildTMD(ciaset);
	if(result) {
		fprintf(stderr,"[CIA ERROR] Failed to build Title Metadata\n");
		goto finish;
	}

	/* CIA Header */
	result = BuildCiaHdr(ciaset);
	if(result) {
		fprintf(stderr,"[CIA ERROR] Failed to build CIA Header\n");
		goto finish;
	}
	
	/* Write To File */
	result = WriteCiaToFile(ciaset);
	if(result) {
		fprintf(stderr,"[CIA ERROR] Failed to write CIA to file\n");
		goto finish;
	}

finish:
	if(result != FAILED_TO_CREATE_OUTFILE && ciaset->out) 
		fclose(ciaset->out);

	FreeCiaSettings(ciaset);

	return result;
}

void FreeCiaSettings(cia_settings *set)
{
	free(set->ciaSections.certChain.buffer);
	free(set->ciaSections.tik.buffer);
	free(set->ciaSections.tmd.buffer);
	free(set->ciaSections.meta.buffer);
	free(set->ciaSections.content.buffer);

	memset(set,0,sizeof(cia_settings));

	free(set);
}

int GetCiaSettings(cia_settings *ciaset, user_settings *usrset)
{
	int result = 0;

	// Transfering data from usrset
	result = GetSettingsFromUsrset(ciaset,usrset);

	if(usrset->common.workingFileType == infile_ncch){
		if((result = GetSettingsFromNcch0(ciaset,0)) != 0) 
			return result;
		if((result = ProcessContentFiles(ciaset,usrset)) != 0) 
			return result;
		if((result = ImportNcchContent(ciaset,usrset)) != 0) 
			return result;
	}

	else if(usrset->common.workingFileType == infile_srl){
		if((result = GetSettingsFromSrl(ciaset)) != 0) 
			return result;
	}

	else if(usrset->common.workingFileType == infile_ncsd){
		if((result = GetSettingsFromCci(ciaset)) != 0) 
			return result;
	}
	
	GetContentHashes(ciaset);

	if(ciaset->content.encryptCia)
		EncryptContent(ciaset);

	return 0;
}

int GetSettingsFromUsrset(cia_settings *ciaset, user_settings *usrset)
{
	// General Stuff
	ciaset->keys = &usrset->common.keys;
	ciaset->rsf = &usrset->common.rsfSet;
	ciaset->ciaSections.content.buffer = usrset->common.workingFile.buffer;
	ciaset->ciaSections.content.size = usrset->common.workingFile.size;
	usrset->common.workingFile.buffer = NULL;
	usrset->common.workingFile.size = 0;
	ciaset->content.includeUpdateNcch = usrset->cia.includeUpdateNcch;
	ciaset->verbose = usrset->common.verbose;
	
	ciaset->tmd.titleType = TYPE_CTR;
	ciaset->content.encryptCia = usrset->common.rsfSet.Option.EnableCrypt || usrset->cia.titleKey != NULL;
	ciaset->content.IsDlc = usrset->cia.DlcContent;
	if(ciaset->keys->aes.commonKey[ciaset->keys->aes.currentCommonKey] == NULL && ciaset->content.encryptCia){
		fprintf(stderr,"[CIA WARNING] Common Key could not be loaded, CIA will not be encrypted\n");
		ciaset->content.encryptCia = false;
	}
	
	ciaset->cert.caCrlVersion = 0;
	ciaset->cert.signerCrlVersion = 0;

	ciaset->common.useCxiRemasterVersion = !usrset->cia.useFullTitleVer;
	ciaset->common.titleVerMajor = usrset->cia.titleVerMajor;
	ciaset->common.titleVerMinor = usrset->cia.titleVerMinor;
	ciaset->common.titleVerMicro = usrset->cia.titleVerMicro;

	// Ticket Data
	ciaset->tik.ticketId = 0x0004000000000000 | (u64GetRand() & 0x0000FFFFFFFFFFFF);
	ciaset->tik.deviceId = usrset->cia.deviceId;
	ciaset->tik.eshopAccId = usrset->cia.eshopAccId;
	ciaset->tik.licenceType = lic_Permanent;
	ciaset->tik.audit = 0;
	
	if(usrset->cia.randomTitleKey)
		rndset(ciaset->common.titleKey,AES_128_KEY_SIZE);
	else if(usrset->cia.titleKey){
		for (size_t count = 0; count < sizeof(ciaset->common.titleKey)/sizeof(ciaset->common.titleKey[0]); count++) {
			sscanf(usrset->cia.titleKey, "%2hhx", &ciaset->common.titleKey[count]);
			usrset->cia.titleKey += 2;
		}
	}
	else
		clrmem(ciaset->common.titleKey,AES_128_KEY_SIZE);

	if(ciaset->verbose)
		memdump(stdout,"[CIA] CIA title key: ",ciaset->common.titleKey,AES_128_KEY_SIZE);
		
	ciaset->tik.formatVersion = 1;

	GenCertChildIssuer(ciaset->tik.issuer,ciaset->keys->certs.xsCert);
	
	// Tmd Stuff
	if(usrset->cia.contentId[0] > MAX_U32)
		ciaset->content.id[0] = u32GetRand();
	else 
		ciaset->content.id[0] = usrset->cia.contentId[0];

	ciaset->tmd.formatVersion = 1;
	ciaset->tmd.accessRights = 0;
	GenCertChildIssuer(ciaset->tmd.issuer,ciaset->keys->certs.cpCert);
	return 0;
}

int GetSettingsFromNcch0(cia_settings *ciaset, u32 ncch0_offset)
{
	/* Sanity Checks */
	if(!ciaset->ciaSections.content.buffer) 
		return CIA_NO_NCCH0;

	u8 *ncch0 = (u8*)(ciaset->ciaSections.content.buffer+ncch0_offset);

	if(!IsNcch(NULL,ncch0)){
		fprintf(stderr,"[CIA ERROR] Content0 is not NCCH\n");
		return CIA_INVALID_NCCH0;
	}

	/* Get Ncch0 Header */
	ncch_hdr *hdr = (ncch_hdr*)ncch0;
	ciaset->content.IsCfa = IsCfa(hdr);

	ciaset->content.offset[0] = 0;
	ciaset->content.size[0] = align(GetNcchSize(hdr),0x10);
	ciaset->content.totalSize = ciaset->content.size[0];

	/* Get Ncch0 Import Context */
	ncch_info *info = calloc(1,sizeof(ncch_info));
	if(!info){ 
		fprintf(stderr,"[CIA ERROR] Not enough memory\n"); 
		return MEM_ERROR; 
	}
	GetNcchInfo(info,hdr);

	/* Verify Ncch0 (Sig&Hash Checks) */
	ciaset->content.keyFound = true;
	int result = VerifyNcch(ncch0, ciaset->keys, false, ciaset->verbose == false);
	if(result == UNABLE_TO_LOAD_NCCH_KEY){
		ciaset->content.keyFound = false;
		ciaset->common.useCxiRemasterVersion = false;
		if(!ciaset->content.IsCfa){
			fprintf(stderr,"[CIA WARNING] CXI AES Key could not be loaded\n");
			fprintf(stderr,"      Meta Region, SaveDataSize, Remaster Version cannot be obtained\n");
		}
	}
	else if(result != 0){
		fprintf(stderr,"[CIA ERROR] Content 0 Is Corrupt (res = %d)\n",result);
		return CIA_INVALID_NCCH0;
	}

	/* Gen Settings From Ncch0 */
	ciaset->common.titleId = u8_to_u64(hdr->titleId,LE);


	/* Getting NCCH key */
	u8 *ncchkey = NULL;
	if(ciaset->content.keyFound && IsNcchEncrypted(hdr)){
		SetNcchKeys(ciaset->keys,hdr);
		ncchkey = ciaset->keys->aes.ncchKey0;
		if(ciaset->verbose){
			printf("[CIA] NCCH AES keys:\n");
			memdump(stdout," > key0: ",ciaset->keys->aes.ncchKey0,AES_128_KEY_SIZE);
			memdump(stdout," > key1: ",ciaset->keys->aes.ncchKey1,AES_128_KEY_SIZE);
		}
	}

	/* Get TMD Data from NCCH */
	result = GetTmdDataFromNcch(ciaset,ncch0,info,ncchkey);
	if(result) goto finish;
	/* Get Meta Region from NCCH */
	result = GetMetaRegion(ciaset,ncch0,info,ncchkey);
	/* Finish */
finish:
	/* Return */
	free(info);
	return result;	
}

int GetTmdDataFromNcch(cia_settings *ciaset, u8 *ncch, ncch_info *ncch_ctx, u8 *key)
{
	int result = 0;
	extended_hdr *exhdr = NULL;

	if(!ciaset->content.IsCfa && ciaset->content.keyFound){
		exhdr = malloc(sizeof(extended_hdr));
		memcpy(exhdr,ncch+ncch_ctx->exhdrOffset,sizeof(extended_hdr));
		if(key != NULL)
			CryptNcchRegion((u8*)exhdr,sizeof(extended_hdr),0,ncch_ctx->titleId,key,ncch_exhdr);
	}
		
	// If this title is a Patch or a CFA SaveData size cannot be set in TMD
	if( IsPatch(GetTidCategory(ciaset->common.titleId)) || ciaset->content.IsCfa ) 
		ciaset->tmd.savedataSize = 0;
	// Otherwise read Savedata size from exheader, but only first word of savesize is read
	else if(ciaset->content.keyFound) 
		ciaset->tmd.savedataSize = (u32)(GetSaveDataSize_frm_exhdr(exhdr) & MAX_U32);
	// if it's a title which can have save data, but save data size could not be read from exhdr
	else if(ciaset->rsf->SystemControlInfo.SaveDataSize){
		u64 size = 0;
		GetSaveDataSizeFromString(&size,ciaset->rsf->SystemControlInfo.SaveDataSize,"CIA");
		ciaset->tmd.savedataSize = (u32)(size & MAX_U32);
	}
	// the user has neglected to provide any means of determining the savedata size
	else
		ciaset->tmd.savedataSize = 0;
		
	// Process title version
	// If this is a CXI, and we have to pull version major from exheader...
	if(!ciaset->content.IsCfa && ciaset->common.useCxiRemasterVersion){
		// Setting remaster ver
		ciaset->common.titleVerMajor = GetRemasterVersion_frm_exhdr(exhdr);
	}
	
	// Calculate u16 title version
	ciaset->tmd.version = ciaset->tik.version = SetupVersion(ciaset->common.titleVerMajor,ciaset->common.titleVerMinor,ciaset->common.titleVerMicro);

	free(exhdr);
	return result;
}

int GetMetaRegion(cia_settings *ciaset, u8 *ncch, ncch_info *info, u8 *key)
{
	extended_hdr *exhdr;
	exefs_hdr *exefsHdr;
	cia_metadata *hdr;
	u32 icon_size, icon_offset;
	
	// Do not proceed if this is a CFA or can't be decrypted
	if(ciaset->content.IsCfa || !ciaset->content.keyFound) 
		return 0;

	// Obtain (&decrypt) exheader
	exhdr = malloc(sizeof(extended_hdr));
	memcpy(exhdr,ncch+info->exhdrOffset,sizeof(extended_hdr));
	if(key != NULL)
		CryptNcchRegion((u8*)exhdr,sizeof(extended_hdr),0,info->titleId,key,ncch_exhdr);

	// Obtain (&decrypt) exefs header
	exefsHdr = malloc(sizeof(exefs_hdr));
	memcpy(exefsHdr,ncch+info->exefsOffset,sizeof(exefs_hdr));
	if(key != NULL)
		CryptNcchRegion((u8*)exefsHdr,sizeof(exefs_hdr),0,info->titleId,key,ncch_exefs);

	// Only continue if icon exists
	if(!DoesExeFsSectionExist("icon",(u8*)exefsHdr))
		goto cleanup;
		
	icon_size = GetExeFsSectionSize("icon",(u8*)exefsHdr);
	icon_offset = GetExeFsSectionOffset("icon",(u8*)exefsHdr);
	
	// Allocating memory for Meta region
	ciaset->ciaSections.meta.size = sizeof(cia_metadata) + icon_size;
	ciaset->ciaSections.meta.buffer = calloc(1,ciaset->ciaSections.meta.size);
	if(!ciaset->ciaSections.meta.buffer){
		fprintf(stderr,"[CIA ERROR] Not enough memory\n");
		return MEM_ERROR; 
	}

	// Writing Dependency List & Core Version to Meta region
	hdr = (cia_metadata*)ciaset->ciaSections.meta.buffer;
	GetDependencyList_frm_exhdr(hdr->dependencyList,exhdr);
	GetCoreVersion_frm_exhdr(hdr->coreVersion,exhdr);
	
	// Writing Icon data to Meta region
	u8 *iconPos = (ciaset->ciaSections.meta.buffer + sizeof(cia_metadata));
	memcpy(iconPos,ncch+info->exefsOffset+icon_offset,icon_size);
	if(key != NULL)
		CryptNcchRegion(iconPos,icon_size,icon_offset,info->titleId,key,ncch_exefs);
		
cleanup:
	free(exefsHdr);
	free(exhdr);
	return 0;
}

int ProcessContentFiles(cia_settings *ciaset, user_settings *usrset)
{
	FILE* tmpFilePtr = NULL;

	// process content files 
	int j = 1;
	ncch_hdr *hdr = malloc(sizeof(ncch_hdr));
	for(int i = 1; i < CIA_MAX_CONTENT; i++){
		if(usrset->common.contentPath[i]){
			if(!AssertFile(usrset->common.contentPath[i])){ 
				fprintf(stderr,"[CIA ERROR] Failed to open \"%s\"\n",usrset->common.contentPath[i]); 
				return FAILED_TO_OPEN_FILE; 
			}

			// get content file size
			ciaset->content.fileSize[j] = GetFileSize64(usrset->common.contentPath[i]);
			
			// get content id
			if(usrset->cia.contentId[i] > MAX_U32)
				ciaset->content.id[j] = u32GetRand(); 
			else 
				ciaset->content.id[j] = (u32)usrset->cia.contentId[i];

			// get content index
			ciaset->content.index[j] = (u16)i;

			// Get Data from NCCH HDR
			tmpFilePtr = fopen(usrset->common.contentPath[i],"rb");
			if(!tmpFilePtr){
				fprintf(stderr,"[CIA ERROR] Failed to open \"%s\"\n",usrset->common.contentPath[i]); 
				return FAILED_TO_OPEN_FILE; 
			}
			ReadNcchHdr(hdr,tmpFilePtr);
			fclose(tmpFilePtr);
			tmpFilePtr = NULL;

			// Get Size from NCCH HDR
			u64 calcSize = GetNcchSize(hdr);
			if(calcSize != ciaset->content.fileSize[j]){
				fprintf(stderr,"[CIA ERROR] \"%s\" is corrupt\n",usrset->common.contentPath[i]); 
				return FAILED_TO_OPEN_FILE; 
			}

			// calculate content size & offset in CIA
			ciaset->content.size[j] = align(calcSize,CIA_CONTENT_ALIGN);
			ciaset->content.offset[j] = ciaset->content.totalSize;

			// update CIA total content size
			ciaset->content.totalSize += ciaset->content.size[j];
			
			// Finish get next content
			j++;
		}
	}
	free(hdr);
	ciaset->content.count = j;

	// Check Conflicting IDs
	for(int i = 0; i < ciaset->content.count; i++){
		for(j = i+1; j < ciaset->content.count; j++){
			if(ciaset->content.id[j] == ciaset->content.id[i]){
				fprintf(stderr,"[CIA ERROR] CIA Content %d and %d, have conflicting IDs\n",ciaset->content.index[j],ciaset->content.index[i]);
				return CIA_CONFILCTING_CONTENT_IDS;
			}
		}
	}
	return 0;
}

int ImportNcchContent(cia_settings *ciaset, user_settings *usrset)
{
	FILE* tmpFilePtr = NULL;
	
	ciaset->ciaSections.content.buffer = realloc(ciaset->ciaSections.content.buffer,ciaset->content.totalSize);
	if(!ciaset->ciaSections.content.buffer){
		fprintf(stderr,"[CIA ERROR] Not enough memory\n");
		return MEM_ERROR;
	}

	ncch_hdr *ncch0hdr = (ncch_hdr*)ciaset->ciaSections.content.buffer;
	for(int i = 1; i < ciaset->content.count; i++){
		// Import NCCH into memory
		u8 *ncchpos = (u8*)(ciaset->ciaSections.content.buffer+ciaset->content.offset[i]);
		
		// open/read/close file
		tmpFilePtr = fopen(usrset->common.contentPath[i], "rb");
		ReadFile64(ncchpos, ciaset->content.fileSize[i], 0, tmpFilePtr);
		fclose(tmpFilePtr);
		
		// Edit NCCH ID if required
		if(ModifyNcchIds(ncchpos, NULL, ncch0hdr->programId, ciaset->keys) != 0)
			return -1;

		// Set Additional Flags
		if(ciaset->content.IsDlc)
			ciaset->content.flags[i] |= content_Optional;

		//if(unknown condition)
		//	ciaset->content.flags[i] |= content_Shared;
	}

	ciaset->ciaSections.content.size = ciaset->content.totalSize;
	return 0;
}

int GetSettingsFromSrl(cia_settings *ciaset)
{
	srl_hdr *hdr = (srl_hdr*)ciaset->ciaSections.content.buffer;
	if(!hdr || ciaset->ciaSections.content.size < sizeof(srl_hdr)) {
		fprintf(stderr,"[CIA ERROR] Invalid TWL SRL File\n");
		return FAILED_TO_IMPORT_FILE;
	}

	// Check if TWL SRL File
	if(u8_to_u16(&hdr->title_id[6],LE) != 0x0003){
		fprintf(stderr,"[CIA ERROR] Invalid TWL SRL File\n");
		return FAILED_TO_IMPORT_FILE;
	}

	// Generate and store Converted TitleID
	ciaset->common.titleId = ConvertTwlIdToCtrId(u8_to_u64(hdr->title_id,LE));

	// Get TWL Flag
	ciaset->tmd.twlFlag = ((hdr->reserved_flags[3] & 6) >> 1);

	// Get Remaster Version
	u16 version = SetupVersion(hdr->romVersion,ciaset->common.titleVerMinor,0);
	ciaset->tik.version = version;
	ciaset->tmd.version = version;

	// Get SaveDataSize (Public and Private)
	ciaset->tmd.savedataSize = u8_to_u32(hdr->pubSaveDataSize,LE);
	ciaset->tmd.privSavedataSize = u8_to_u32(hdr->privSaveDataSize,LE);

	// Setting CIA Content Settings
	ciaset->content.count = 1;
	ciaset->content.offset[0] = 0;
	ciaset->content.size[0] = ciaset->ciaSections.content.size;
	ciaset->content.totalSize = ciaset->ciaSections.content.size;

	return 0;
}

int GetSettingsFromCci(cia_settings *ciaset)
{
	int result = 0;

	if(!IsCci(ciaset->ciaSections.content.buffer)){
		fprintf(stderr,"[CIA ERROR] Invalid CCI file\n");
		return FAILED_TO_IMPORT_FILE;
	}
	
	u32 ncch0_offset = GetPartitionOffset(ciaset->ciaSections.content.buffer,0);
	if(!ncch0_offset){
		fprintf(stderr,"[CIA ERROR] Invalid CCI file (invalid ncch0)\n");
		return FAILED_TO_IMPORT_FILE;
	}

	result = GetSettingsFromNcch0(ciaset, ncch0_offset);
	if(result){
		fprintf(stderr,"Import of Ncch 0 failed(%d)\n",result);	
		return result;
	}
	int j = 1;
	
	u64 cciContentOffsets[CCI_MAX_CONTENT];
	cciContentOffsets[0] = ncch0_offset;
	for(int i = 1; i < 8; i++){
		if(GetPartitionSize(ciaset->ciaSections.content.buffer,i)){
			ncch_hdr *ncchHdr = (ncch_hdr*)GetPartition(ciaset->ciaSections.content.buffer, i);
			
			if(IsUpdateCfa(ncchHdr) && !ciaset->content.includeUpdateNcch)
				continue;
			
			cciContentOffsets[j] = GetPartitionOffset(ciaset->ciaSections.content.buffer,i);
			
			// Get Size
			ciaset->content.size[j] =  GetPartitionSize(ciaset->ciaSections.content.buffer,i);
			ciaset->content.offset[j] = ciaset->content.totalSize;
			
			ciaset->content.totalSize += ciaset->content.size[j];
			
			// Get ID
			ciaset->content.id[j] = u32GetRand();

			// Get Index
			ciaset->content.index[j] = i;

			// Increment Content Count
			j++;
		}
	}
	ciaset->content.count = j;

	for(int i = 0; i < ciaset->content.count; i++){ // Re-organising content positions in memory
		u8 *cci_pos = (ciaset->ciaSections.content.buffer + cciContentOffsets[i]);
		u8 *cia_pos = (ciaset->ciaSections.content.buffer + ciaset->content.offset[i]);
		memcpy(cia_pos,cci_pos,ciaset->content.size[i]);
	}
	ciaset->ciaSections.content.size = ciaset->content.totalSize;
	return 0;
}

void GetContentHashes(cia_settings *ciaset)
{
	for (int i = 0; i < ciaset->content.count; i++) {
		if (ciaset->verbose)
			printf("[CIA] Hashing content %d... ", i);
		ShaCalc(ciaset->ciaSections.content.buffer + ciaset->content.offset[i], ciaset->content.size[i], ciaset->content.hash[i], CTR_SHA_256);
		if (ciaset->verbose)
			printf("Done!\n");
	}
}

void EncryptContent(cia_settings *ciaset)
{
	for(int i = 0; i < ciaset->content.count; i++){
		if (ciaset->verbose)
			printf("[CIA] Encrypting content %d... ", i);

		ciaset->content.flags[i] |= content_Encrypted;
		u8 *content = ciaset->ciaSections.content.buffer+ciaset->content.offset[i];
		CryptContent(content, content, ciaset->content.size[i], ciaset->common.titleKey, i, ENC);

		if (ciaset->verbose)
			printf("Done!\n");
	}
}

int BuildCiaCertChain(cia_settings *ciaset)
{
	ciaset->ciaSections.certChain.size = GetCertSize(ciaset->keys->certs.caCert) + GetCertSize(ciaset->keys->certs.xsCert) + GetCertSize(ciaset->keys->certs.cpCert);
	ciaset->ciaSections.certChain.buffer = malloc(ciaset->ciaSections.certChain.size);
	if(!ciaset->ciaSections.certChain.buffer) {
		fprintf(stderr,"[CIA ERROR] Not enough memory\n");
		return MEM_ERROR; 
	}
	memcpy(ciaset->ciaSections.certChain.buffer,ciaset->keys->certs.caCert,GetCertSize(ciaset->keys->certs.caCert));
	memcpy((ciaset->ciaSections.certChain.buffer+GetCertSize(ciaset->keys->certs.caCert)),ciaset->keys->certs.xsCert,GetCertSize(ciaset->keys->certs.xsCert));
	memcpy((ciaset->ciaSections.certChain.buffer+GetCertSize(ciaset->keys->certs.caCert)+GetCertSize(ciaset->keys->certs.xsCert)),ciaset->keys->certs.cpCert,GetCertSize(ciaset->keys->certs.cpCert));
	return 0;
}

int BuildCiaHdr(cia_settings *ciaset)
{
	// Allocating memory for header
	ciaset->ciaSections.ciaHdr.size = sizeof(cia_hdr);
	ciaset->ciaSections.ciaHdr.buffer = malloc(ciaset->ciaSections.ciaHdr.size);
	if(!ciaset->ciaSections.ciaHdr.buffer){
		fprintf(stderr,"[CIA ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	
	cia_hdr *hdr = (cia_hdr*)ciaset->ciaSections.ciaHdr.buffer;

	// Clearing 
	memset(hdr,0,sizeof(cia_hdr));

	// Setting Data
	u32_to_u8(hdr->hdrSize,sizeof(cia_hdr),LE);
	u16_to_u8(hdr->type,0x0,LE);
	u16_to_u8(hdr->version,0x0,LE);
	u32_to_u8(hdr->certChainSize,ciaset->ciaSections.certChain.size,LE);
	u32_to_u8(hdr->tikSize,ciaset->ciaSections.tik.size,LE);
	u32_to_u8(hdr->tmdSize,ciaset->ciaSections.tmd.size,LE);
	u32_to_u8(hdr->metaSize,ciaset->ciaSections.meta.size,LE);
	u64_to_u8(hdr->contentSize,ciaset->content.totalSize,LE);

	// Recording Offsets
	ciaset->ciaSections.certChainOffset = align(sizeof(cia_hdr),0x40);
	ciaset->ciaSections.tikOffset = align(ciaset->ciaSections.certChainOffset+ciaset->ciaSections.certChain.size,0x40);
	ciaset->ciaSections.tmdOffset = align(ciaset->ciaSections.tikOffset+ciaset->ciaSections.tik.size,0x40);
	ciaset->ciaSections.contentOffset = align(ciaset->ciaSections.tmdOffset+ciaset->ciaSections.tmd.size,0x40);
	ciaset->ciaSections.metaOffset = align(ciaset->ciaSections.contentOffset+ciaset->content.totalSize,0x40);
	
	for(int i = 0; i < ciaset->content.count; i++)
		hdr->contentIndex[ciaset->content.index[i]/8] |= 0x80 >> (ciaset->content.index[i] & 7);
		
	return 0;
}

int WriteCiaToFile(cia_settings *ciaset)
{
	if (ciaset->verbose) {
		printf("[CIA] Writing to file... ");
	}
	WriteBuffer(ciaset->ciaSections.ciaHdr.buffer,ciaset->ciaSections.ciaHdr.size,0,ciaset->out);
	WriteBuffer(ciaset->ciaSections.certChain.buffer,ciaset->ciaSections.certChain.size,ciaset->ciaSections.certChainOffset,ciaset->out);
	WriteBuffer(ciaset->ciaSections.tik.buffer,ciaset->ciaSections.tik.size,ciaset->ciaSections.tikOffset,ciaset->out);
	WriteBuffer(ciaset->ciaSections.tmd.buffer,ciaset->ciaSections.tmd.size,ciaset->ciaSections.tmdOffset,ciaset->out);
	WriteBuffer(ciaset->ciaSections.content.buffer,ciaset->ciaSections.content.size,ciaset->ciaSections.contentOffset,ciaset->out);
	WriteBuffer(ciaset->ciaSections.meta.buffer,ciaset->ciaSections.meta.size,ciaset->ciaSections.metaOffset,ciaset->out);

	if (ciaset->verbose) {
		printf("Done!\n");
	}

	return 0;
}


int CryptContent(u8 *input, u8 *output, u64 size, u8 *title_key, u16 index, u8 mode)
{
	//generating IV
	u8 iv[16];
	clrmem(&iv,16);
	iv[0] = (index >> 8) & 0xff;
	iv[1] = index & 0xff;
	//Crypting content
	AesCbcCrypt(title_key,iv,input,output,size,mode);
	return 0;
}

bool IsCia(u8 *cia)
{
	if(!cia)
		return false;
	
	cia_hdr *hdr = (cia_hdr*)cia;
	
	if(u8_to_u32(hdr->hdrSize,LE) != sizeof(cia_hdr) || u8_to_u16(hdr->type,LE) != 0 || u8_to_u16(hdr->version,LE) != 0)
		return false;
	
	if(!GetCiaCertSize(hdr) || !GetCiaTikSize(hdr) || !GetCiaTmdSize(hdr) || !GetCiaContentSize(hdr))
		return false;
		
	return true;
}

u64 GetCiaCertOffset(cia_hdr *hdr)
{
	u64 hdrSize = u8_to_u32(hdr->hdrSize,LE);
	return align(hdrSize,CIA_ALIGN_SIZE);
}

u64 GetCiaCertSize(cia_hdr *hdr)
{
	return u8_to_u32(hdr->certChainSize,LE);
}

u64 GetCiaTikOffset(cia_hdr *hdr)
{
	u64 certOffset = GetCiaCertOffset(hdr);
	u64 certSize = GetCiaCertSize(hdr);
	return align(certOffset + certSize,CIA_ALIGN_SIZE);
}

u64 GetCiaTikSize(cia_hdr *hdr)
{
	return u8_to_u32(hdr->tikSize,LE);
}

u64 GetCiaTmdOffset(cia_hdr *hdr)
{
	u64 tikOffset = GetCiaTikOffset(hdr);
	u64 tikSize = GetCiaTikSize(hdr);
	return align(tikOffset + tikSize,CIA_ALIGN_SIZE);
}

u64 GetCiaTmdSize(cia_hdr *hdr)
{
	return u8_to_u32(hdr->tmdSize,LE);
}

u64 GetCiaContentOffset(cia_hdr *hdr)
{
	u64 tmdOffset = GetCiaTmdOffset(hdr);
	u64 tmdSize = GetCiaTmdSize(hdr);
	return align(tmdOffset + tmdSize,CIA_ALIGN_SIZE);
}

u64 GetCiaContentSize(cia_hdr *hdr)
{
	return u8_to_u64(hdr->contentSize,LE);
}

u64 GetCiaMetaOffset(cia_hdr *hdr)
{
	u64 contentOffset = GetCiaContentOffset(hdr);
	u64 contentSize = GetCiaContentSize(hdr);
	return align(contentOffset + contentSize,CIA_ALIGN_SIZE);
}

u64 GetCiaMetaSize(cia_hdr *hdr)
{
	return u8_to_u32(hdr->metaSize,LE);
}

u8* GetCiaCert(u8 *cia)
{
	return cia + GetCiaCertOffset((cia_hdr*)cia);
}

u8* GetCiaTik(u8 *cia)
{
	return cia + GetCiaTikOffset((cia_hdr*)cia);
}

u8* GetCiaTmd(u8 *cia)
{
	return cia + GetCiaTmdOffset((cia_hdr*)cia);
}

u8* GetCiaContent(u8 *cia)
{
	return cia + GetCiaContentOffset((cia_hdr*)cia);
}

u8* GetCiaMeta(u8 *cia)
{
	if(GetCiaMetaSize((cia_hdr*)cia))
		return cia + GetCiaMetaOffset((cia_hdr*)cia);
	else
		return NULL;
}