#include "lib.h"
#include "ncch_build.h"
#include "exheader_build.h"
#include "accessdesc.h"
#include "titleid.h"

const char *DEFAULT_EXHEADER_NAME = "CtrApp";

/* Prototypes */
void free_ExHeaderSettings(exheader_settings *exhdrset);
int get_ExHeaderSettingsFromNcchset(exheader_settings *exhdrset, ncch_settings *ncchset);
int get_ExHeaderSettingsFromRsf(exheader_settings *exhdrset);

int get_ExHeaderCodeSetInfo(exhdr_CodeSetInfo *CodeSetInfo, rsf_settings *rsf);
int get_ExHeaderDependencyList(u8 *depList, rsf_settings *rsf);
int get_ExHeaderSystemInfo(exhdr_SystemInfo *systemInfo, rsf_settings *rsf);
int get_ExHeaderARM11SystemLocalInfo(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
int get_ExHeaderARM11SystemLocalInfoLimited(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
int SetARM11SystemLocalInfoFlags(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
int GetAppType(rsf_settings *rsf);
int SetARM11ResLimitDesc(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
int SetARM11StorageInfo(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
void SetARM11StorageInfoSystemSaveDataId(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
int SetARM11StorageInfoFsAccessInfo(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
void SetARM11StorageInfoExtSaveDataId(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
void SetARM11StorageInfoOtherUserSaveData(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
bool CheckCondiditionsForNewAccessibleSaveDataIds(rsf_settings *rsf);
void SetARM11StorageInfoAccessibleSaveDataIds(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
int SetARM11ServiceAccessControl(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
int get_ExHeaderARM11KernelInfo(exhdr_ARM11KernelCapabilities *arm11, rsf_settings *rsf);
int SetARM11KernelDescSysCallControl(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
int GetARM11SysCalls(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
void EnableSystemCall(ARM11KernelCapabilityDescriptor *desc, int sysCall);
void DisableSystemCall(ARM11KernelCapabilityDescriptor *desc, int SysCall);
int SetARM11KernelDescInteruptNumList(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
int GetARM11Interupts(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
void EnableInterupt(ARM11KernelCapabilityDescriptor *desc, int Interrupt, int i);
int SetARM11KernelDescAddressMapping(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
int GetARM11IOMappings(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
int GetARM11StaticMappings(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
bool IsEndAddress(u32 Address);
bool IsStartAddress(u32 Address);
u32 GetIOMappingDesc(u32 address);
u32 GetStaticMappingDesc(u32 address, bool IsReadOnly);
u32 GetMappingDesc(u32 address, u32 prefixVal, s32 numPrefixBits, bool IsRO);
int SetARM11KernelDescOtherCapabilities(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
int SetARM11KernelDescHandleTableSize(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
int SetARM11KernelDescReleaseKernelVersion(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
void SetARM11KernelDescValue(ARM11KernelCapabilityDescriptor *desc, u16 index, u32 value);
void SetARM11KernelDescBitmask(ARM11KernelCapabilityDescriptor *desc, u32 bitmask);
void AllocateARM11KernelDescMemory(ARM11KernelCapabilityDescriptor *desc, u16 num);
u32 GetDescPrefixMask(int numPrefixBits);
u32 GetDescPrefixBits(int numPrefixBits, u32 prefixVal);
int get_ExHeaderARM9AccessControlInfo(exhdr_ARM9AccessControlInfo *arm9, rsf_settings *rsf);

/* ExHeader Signature Functions */
int SignAccessDesc(access_descriptor *acexDesc, keys_struct *keys)
{
	u8 *data = (u8*) &acexDesc->ncchRsaPubKey;
	u8 *sign = (u8*) &acexDesc->signature;
	return RsaSignVerify(data, 0x300, sign, keys->rsa.acex.pub, keys->rsa.acex.pvt, RSA_2048_SHA256, CTR_RSA_SIGN);
}

int CheckAccessDescSignature(access_descriptor *acexDesc, keys_struct *keys)
{
	u8 *data = (u8*) &acexDesc->ncchRsaPubKey;
	u8 *sign = (u8*) &acexDesc->signature;
	return RsaSignVerify(data,0x300,sign,keys->rsa.acex.pub,NULL,RSA_2048_SHA256,CTR_RSA_VERIFY);
}

/* ExHeader Build Functions */
int BuildExHeader(ncch_settings *ncchset)
{
	int result = 0;

	if(ncchset->options.IsCfa)
		return 0;

	exheader_settings *exhdrset = calloc(1,sizeof(exheader_settings));
	if(!exhdrset) {
		fprintf(stderr,"[EXHEADER ERROR] Not enough memory\n");
		return MEM_ERROR;
	}

	// Get Settings
	result = get_ExHeaderSettingsFromNcchset(exhdrset,ncchset);
	if(result) goto finish;

	result = get_ExHeaderSettingsFromRsf(exhdrset);
	if(result) goto finish;

	result = set_AccessDesc(exhdrset);
	if(result) goto finish;

finish:
	if(result) fprintf(stderr,"[EXHEADER ERROR] Failed to create ExHeader\n");
	free_ExHeaderSettings(exhdrset);
	return result;
}

void free_ExHeaderSettings(exheader_settings *exhdrset)
{
	free(exhdrset);
}

int get_ExHeaderSettingsFromNcchset(exheader_settings *exhdrset, ncch_settings *ncchset)
{
	/* Transfer settings */
	exhdrset->keys = ncchset->keys;
	exhdrset->rsf = ncchset->rsfSet;
	exhdrset->useAccessDescPreset = ncchset->keys->accessDescSign.presetType != desc_NotSpecified;

	/* Creating Output Buffer */
	ncchset->sections.exhdr.size = sizeof(extended_hdr);
	ncchset->sections.exhdr.buffer = calloc(1,ncchset->sections.exhdr.size);
	if(!ncchset->sections.exhdr.buffer) {
		fprintf(stderr,"[EXHEADER ERROR] Not enough memory\n");
		return MEM_ERROR;
	}

	ncchset->sections.acexDesc.size = sizeof(access_descriptor);
	ncchset->sections.acexDesc.buffer = calloc(1,ncchset->sections.acexDesc.size);
	if(!ncchset->sections.acexDesc.buffer) {
		fprintf(stderr,"[EXHEADER ERROR] Not enough memory\n");
		return MEM_ERROR;
	}

	/* Create ExHeader Struct for output */
	exhdrset->exHdr = (extended_hdr*)ncchset->sections.exhdr.buffer;
	exhdrset->acexDesc = (access_descriptor*)ncchset->sections.acexDesc.buffer;

	/* Data */
	u32_to_u8(exhdrset->exHdr->codeSetInfo.data.address,ncchset->codeDetails.rwAddress,LE);
	u32_to_u8(exhdrset->exHdr->codeSetInfo.data.codeSize,ncchset->codeDetails.rwSize,LE);
	u32_to_u8(exhdrset->exHdr->codeSetInfo.data.numMaxPages,ncchset->codeDetails.rwMaxPages,LE);
	/* RO */
	u32_to_u8(exhdrset->exHdr->codeSetInfo.rodata.address,ncchset->codeDetails.roAddress,LE);
	u32_to_u8(exhdrset->exHdr->codeSetInfo.rodata.codeSize,ncchset->codeDetails.roSize,LE);
	u32_to_u8(exhdrset->exHdr->codeSetInfo.rodata.numMaxPages,ncchset->codeDetails.roMaxPages,LE);
	/* Text */
	u32_to_u8(exhdrset->exHdr->codeSetInfo.text.address,ncchset->codeDetails.textAddress,LE);
	u32_to_u8(exhdrset->exHdr->codeSetInfo.text.codeSize,ncchset->codeDetails.textSize,LE);
	u32_to_u8(exhdrset->exHdr->codeSetInfo.text.numMaxPages,ncchset->codeDetails.textMaxPages,LE);
	/* BSS Size */
	u32_to_u8(exhdrset->exHdr->codeSetInfo.bssSize, ncchset->codeDetails.bssSize, LE);
	/* Stack Size */
	u32_to_u8(exhdrset->exHdr->codeSetInfo.stackSize, ncchset->codeDetails.stackSize, LE);

	/* Set Simple Flags */
	if(ncchset->options.CompressCode)
		exhdrset->exHdr->codeSetInfo.compressExeFs0 = true;
	if (ncchset->options.UseOnSD)
		exhdrset->exHdr->codeSetInfo.useOnSd = true;
	if(!ncchset->options.UseRomFS)
		exhdrset->exHdr->arm11SystemLocalCapabilities.storageInfo.otherAttributes |= attribute_NOT_USE_ROMFS;

	return 0;
}

int get_ExHeaderSettingsFromRsf(exheader_settings *exhdrset)
{
	int result = 0;
	if(!exhdrset->useAccessDescPreset){
		if((result = get_ExHeaderCodeSetInfo(&exhdrset->exHdr->codeSetInfo, exhdrset->rsf)))
			goto finish;
		if((result = get_ExHeaderDependencyList((u8*)exhdrset->exHdr->dependencyList, exhdrset->rsf)))
			goto finish;
		if((result = get_ExHeaderSystemInfo(&exhdrset->exHdr->systemInfo, exhdrset->rsf)))
			goto finish;
		if((result = get_ExHeaderARM11SystemLocalInfo(&exhdrset->exHdr->arm11SystemLocalCapabilities, exhdrset->rsf)))
			goto finish;
		if((result = get_ExHeaderARM11KernelInfo(&exhdrset->exHdr->arm11KernelCapabilities, exhdrset->rsf)))
			goto finish;
		if((result = get_ExHeaderARM9AccessControlInfo(&exhdrset->exHdr->arm9AccessControlInfo, exhdrset->rsf)))
			goto finish;
	}
	else{
		if((result = get_ExHeaderCodeSetInfo(&exhdrset->exHdr->codeSetInfo, exhdrset->rsf)))
			goto finish;
		if((result = get_ExHeaderSystemInfo(&exhdrset->exHdr->systemInfo, exhdrset->rsf)))
			goto finish;
		if((result = get_ExHeaderARM11SystemLocalInfoLimited(&exhdrset->exHdr->arm11SystemLocalCapabilities, exhdrset->rsf)))
			goto finish;
		if((result = get_ExHeaderARM9AccessControlInfo(&exhdrset->exHdr->arm9AccessControlInfo, exhdrset->rsf)))
			goto finish;
	}

finish:
	return result;
}

int get_ExHeaderCodeSetInfo(exhdr_CodeSetInfo *CodeSetInfo, rsf_settings *rsf)
{
	/* Name */
	if (rsf->BasicInfo.Title)
		strncpy((char*)CodeSetInfo->name, rsf->BasicInfo.Title, 8);
	else
		strncpy((char*)CodeSetInfo->name, DEFAULT_EXHEADER_NAME, 8);

	/* Remaster Version */
	if(rsf->SystemControlInfo.RemasterVersion)
		u16_to_u8(CodeSetInfo->remasterVersion, strtol(rsf->SystemControlInfo.RemasterVersion,NULL,0), LE);
	else
		u16_to_u8(CodeSetInfo->remasterVersion, 0, LE);

	return 0;
}

int get_ExHeaderDependencyList(u8 *depList, rsf_settings *rsf)
{
	if(rsf->SystemControlInfo.DependencyNum > 0x30){
		fprintf(stderr,"[EXHEADER ERROR] Too Many Dependency IDs\n");
		return EXHDR_BAD_RSF_OPT;
	}
	for(int i = 0; i < rsf->SystemControlInfo.DependencyNum; i++){
		u8 *pos = (depList + 0x8*i);
		u64_to_u8(pos, strtoull(rsf->SystemControlInfo.Dependency[i],NULL,0), LE);
	}
	return 0;
}

int get_ExHeaderSystemInfo(exhdr_SystemInfo *systemInfo, rsf_settings *rsf)
{
	/* SaveDataSize */
	if(rsf->SystemControlInfo.SaveDataSize){
		u64 saveSize = 0;
		if(GetSaveDataSizeFromString(&saveSize,rsf->SystemControlInfo.SaveDataSize,"EXHEADER"))
			return EXHDR_BAD_RSF_OPT;
		u64_to_u8(systemInfo->savedataSize, saveSize, LE);
	}
	else
		u64_to_u8(systemInfo->savedataSize,0,LE);

	/* Jump Id */
	if(rsf->SystemControlInfo.JumpId)
		u64_to_u8(systemInfo->jumpId, strtoull(rsf->SystemControlInfo.JumpId,NULL,0), LE);

	else{
		u64 jumpId = 0;
		if(GetProgramID(&jumpId,rsf,false))
			return EXHDR_BAD_RSF_OPT;
		u64_to_u8(systemInfo->jumpId,jumpId,LE);
	}
	return 0;
}

int get_ExHeaderARM11SystemLocalInfo(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	/* Program Id */
	u64 programId = 0;
	if(GetProgramID(&programId,rsf,true))
		return EXHDR_BAD_RSF_OPT;
	u64_to_u8(arm11->programId,programId,LE);

	/* Flags */
	if(SetARM11SystemLocalInfoFlags(arm11, rsf))
		return EXHDR_BAD_RSF_OPT;

	/* Resource Limit Descriptors */
	if(SetARM11ResLimitDesc(arm11, rsf))
		return EXHDR_BAD_RSF_OPT;

	/* Storage Info */
	if(SetARM11StorageInfo(arm11, rsf))
		return EXHDR_BAD_RSF_OPT;

	/* Service Access Control */
	if(SetARM11ServiceAccessControl(arm11, rsf))
		return EXHDR_BAD_RSF_OPT;

	/* Resource Limit Category */
	if(rsf->AccessControlInfo.ResourceLimitCategory){
		if(strcasecmp(rsf->AccessControlInfo.ResourceLimitCategory,"application") == 0) arm11->resourceLimitCategory = resrc_limit_APPLICATION;
		else if(strcasecmp(rsf->AccessControlInfo.ResourceLimitCategory,"sysapplet") == 0) arm11->resourceLimitCategory = resrc_limit_SYS_APPLET;
		else if(strcasecmp(rsf->AccessControlInfo.ResourceLimitCategory,"libapplet") == 0) arm11->resourceLimitCategory = resrc_limit_LIB_APPLET;
		else if(strcasecmp(rsf->AccessControlInfo.ResourceLimitCategory,"other") == 0) arm11->resourceLimitCategory = resrc_limit_OTHER;
	}

	/* Finish */
	return 0;
}

int get_ExHeaderARM11SystemLocalInfoLimited(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	/* Program Id */
	u64 programId = 0;
	if(GetProgramID(&programId,rsf,true))
		return EXHDR_BAD_RSF_OPT;
	u64_to_u8(arm11->programId,programId,LE);

	/* Storage Info */
	if(SetARM11StorageInfo(arm11, rsf))
		return EXHDR_BAD_RSF_OPT;

	/* Finish */
	return 0;
}

int SetARM11SystemLocalInfoFlags(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	/* Core Version */
	if(rsf->AccessControlInfo.CoreVersion)
		u32_to_u8(arm11->coreVersion,strtoul(rsf->AccessControlInfo.CoreVersion,NULL,0),LE);
	else{
		ErrorParamNotFound("AccessControlInfo/CoreVersion");
		return EXHDR_BAD_RSF_OPT;
	}

	/* Defaults */
	arm11->enableL2Cache = false;
	arm11->cpuSpeed = cpuspeed_268MHz;
	arm11->systemModeExt = sysmode_ext_LEGACY;
	arm11->affinityMask = 0;
	arm11->idealProcessor = 0;
	arm11->systemMode = sysmode_64MB;

	/* flag[0] */
	arm11->enableL2Cache |= rsf->AccessControlInfo.EnableL2Cache;

	if (rsf->AccessControlInfo.CpuSpeed) {
		if(strcasecmp(rsf->AccessControlInfo.CpuSpeed, "268mhz") == 0)
			arm11->cpuSpeed |= cpuspeed_268MHz;
		else if(strcasecmp(rsf->AccessControlInfo.CpuSpeed, "804mhz") == 0)
			arm11->cpuSpeed |= cpuspeed_804MHz;
		else {
			fprintf(stderr, "[EXHEADER ERROR] Invalid cpu speed: 0x%s\n", rsf->AccessControlInfo.CpuSpeed);
			return EXHDR_BAD_RSF_OPT;
		}
	}

	/* flag[1] (SystemModeExt) */
	if (rsf->AccessControlInfo.SystemModeExt) {
		if (strcasecmp(rsf->AccessControlInfo.SystemModeExt, "Legacy") == 0)
			arm11->systemModeExt = sysmode_ext_LEGACY;
		else if (strcasecmp(rsf->AccessControlInfo.SystemModeExt, "124MB") == 0)
			arm11->systemModeExt = sysmode_ext_124MB;
		else if (strcasecmp(rsf->AccessControlInfo.SystemModeExt, "178MB") == 0)
			arm11->systemModeExt = sysmode_ext_178MB;

		else {
			fprintf(stderr, "[EXHEADER ERROR] Unexpected SystemModeExt: %s\n", rsf->AccessControlInfo.SystemModeExt);
			return EXHDR_BAD_RSF_OPT;
		}
	}

	/* flag[2] */
	if(rsf->AccessControlInfo.AffinityMask){
		arm11->affinityMask = strtol(rsf->AccessControlInfo.AffinityMask,NULL,0);
		if(arm11->affinityMask > 3){
			fprintf(stderr,"[EXHEADER ERROR] Unexpected AffinityMask: %d. Expected range: 0x0 - 0x3\n", arm11->affinityMask);
			return EXHDR_BAD_RSF_OPT;
		}
	}
	if(rsf->AccessControlInfo.IdealProcessor){
		arm11->idealProcessor = strtol(rsf->AccessControlInfo.IdealProcessor,NULL,0);
		if(arm11->idealProcessor > 1){
			fprintf(stderr,"[EXHEADER ERROR] Unexpected IdealProcessor: %d. Expected range: 0x0 - 0x1\n", arm11->idealProcessor);
			return EXHDR_BAD_RSF_OPT;
		}
	}
	if(rsf->AccessControlInfo.SystemMode){
		if (strcasecmp(rsf->AccessControlInfo.SystemMode, "64MB") == 0 || strcasecmp(rsf->AccessControlInfo.SystemMode, "prod") == 0)
			arm11->systemMode = sysmode_64MB;
		//else if (strcasecmp(rsf->AccessControlInfo.SystemMode, "UNK") == 0 || strcasecmp(rsf->AccessControlInfo.SystemMode, "null") == 0)
		//	arm11->systemMode = sysmode_UNK;
		else if (strcasecmp(rsf->AccessControlInfo.SystemMode, "96MB") == 0 || strcasecmp(rsf->AccessControlInfo.SystemMode, "dev1") == 0)
			arm11->systemMode = sysmode_96MB;
		else if (strcasecmp(rsf->AccessControlInfo.SystemMode, "80MB") == 0 || strcasecmp(rsf->AccessControlInfo.SystemMode, "dev2") == 0)
			arm11->systemMode = sysmode_80MB;
		else if (strcasecmp(rsf->AccessControlInfo.SystemMode, "72MB") == 0 || strcasecmp(rsf->AccessControlInfo.SystemMode, "dev3") == 0)
			arm11->systemMode = sysmode_72MB;
		else if (strcasecmp(rsf->AccessControlInfo.SystemMode, "32MB") == 0 || strcasecmp(rsf->AccessControlInfo.SystemMode, "dev4") == 0)
			arm11->systemMode = sysmode_32MB;

		else {
			fprintf(stderr, "[EXHEADER ERROR] Unexpected SystemMode: %s\n", rsf->AccessControlInfo.SystemMode);
			return EXHDR_BAD_RSF_OPT;
		}
	}

	/* flag[3] (Thread Priority) */
	if(rsf->AccessControlInfo.Priority){
		arm11->threadPriority = strtoul(rsf->AccessControlInfo.Priority,NULL,0);
		if(GetAppType(rsf) == processtype_APPLICATION)
			arm11->threadPriority += 32;
		if(arm11->threadPriority < 0){
			fprintf(stderr,"[EXHEADER ERROR] Invalid Priority: %d\n", arm11->threadPriority);
			return EXHDR_BAD_RSF_OPT;
		}
	}
	else{
		ErrorParamNotFound("AccessControlInfo/Priority");
		return EXHDR_BAD_RSF_OPT;
	}

	return 0;
}

int GetAppType(rsf_settings *rsf)
{
	if(rsf->SystemControlInfo.AppType){
		if(strcasecmp(rsf->SystemControlInfo.AppType,"application") == 0)
			return processtype_APPLICATION;
		else if(strcasecmp(rsf->SystemControlInfo.AppType,"system") == 0)
			return processtype_SYSTEM;
	}
	return processtype_APPLICATION;
}

int SetARM11ResLimitDesc(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	for(int i = 0; i < 16; i++){
		if(i == 0){
			/* MaxCpu */
			// N's makerom actually reads this from the pre-made accessdesc. Damn cheaters. But we can improvise
			if(rsf->AccessControlInfo.MaxCpu){
				arm11->resourceLimitDescriptor[i][0] = strtol(rsf->AccessControlInfo.MaxCpu,NULL,0);
			}
		}
	}

	return 0;
}

int SetARM11StorageInfo(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	if(rsf->AccessControlInfo.AccessibleSaveDataIds){
		/* Accessible SaveData IDs */
		if(!CheckCondiditionsForNewAccessibleSaveDataIds(rsf))
			return EXHDR_BAD_RSF_OPT;
		SetARM11StorageInfoAccessibleSaveDataIds(arm11,rsf);
	}
	else{
		/* Extdata Id */
		SetARM11StorageInfoExtSaveDataId(arm11,rsf);
		/* OtherUserSaveData */
		SetARM11StorageInfoOtherUserSaveData(arm11,rsf);
	}

	/* System Savedata Id */
	SetARM11StorageInfoSystemSaveDataId(arm11,rsf);

	/* FileSystem Access Info */
	return SetARM11StorageInfoFsAccessInfo(arm11,rsf);
}

int SetARM11StorageInfoFsAccessInfo(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	u32 accessInfo = 0;
	for(int i = 0; i < rsf->AccessControlInfo.FileSystemAccessNum; i++){
		if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CategorySystemApplication") == 0)
			accessInfo |= fsaccess_CATEGORY_SYSTEM_APPLICATION;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CategoryHardwareCheck") == 0)
			accessInfo |= fsaccess_CATEGORY_HARDWARE_CHECK;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CategoryFileSystemTool") == 0)
			accessInfo |= fsaccess_CATEGORY_FILE_SYSTEM_TOOL;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"Debug") == 0)
			accessInfo |= fsaccess_DEBUG;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"TwlCardBackup") == 0)
			accessInfo |= fsaccess_TWL_CARD_BACKUP;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"TwlNandData") == 0)
			accessInfo |= fsaccess_TWL_NAND_DATA;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"Boss") == 0)
			accessInfo |= fsaccess_BOSS;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"DirectSdmc") == 0)
			accessInfo |= fsaccess_DIRECT_SDMC;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"Core") == 0)
			accessInfo |= fsaccess_CORE;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CtrNandRo") == 0)
			accessInfo |= fsaccess_CTR_NAND_RO;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CtrNandRw") == 0)
			accessInfo |= fsaccess_CTR_NAND_RW;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CtrNandRoWrite") == 0)
			accessInfo |= fsaccess_CTR_NAND_RO_WRITE;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CategorySystemSettings") == 0)
			accessInfo |= fsaccess_CATEGORY_SYSTEM_SETTINGS;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CardBoard") == 0)
			accessInfo |= fsaccess_CARD_BOARD;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"ExportImportIvs") == 0)
			accessInfo |= fsaccess_EXPORT_IMPORT_IVS;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"DirectSdmcWrite") == 0)
			accessInfo |= fsaccess_DIRECT_SDMC_WRITE;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"SwitchCleanup") == 0)
			accessInfo |= fsaccess_SWITCH_CLEANUP;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"SaveDataMove") == 0)
			accessInfo |= fsaccess_SAVE_DATA_MOVE;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"Shop") == 0)
			accessInfo |= fsaccess_SHOP;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"Shell") == 0)
			accessInfo |= fsaccess_SHELL;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CategoryHomeMenu") == 0)
			accessInfo |= fsaccess_CATEGORY_HOME_MENU;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"SeedDB") == 0)
			accessInfo |= fsaccess_SEEDDB;
		else{
			fprintf(stderr,"[EXHEADER ERROR] Invalid FileSystemAccess Name: \"%s\"\n",rsf->AccessControlInfo.FileSystemAccess[i]);
			return EXHDR_BAD_RSF_OPT;
		}
	}
	u32_to_u8(arm11->storageInfo.accessInfo,accessInfo,LE);

	return 0;
}

void SetARM11StorageInfoSystemSaveDataId(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	if(rsf->AccessControlInfo.SystemSaveDataId1)
		u32_to_u8(arm11->storageInfo.systemSavedataId[0], strtoul(rsf->AccessControlInfo.SystemSaveDataId1,NULL,0), LE);

	if(rsf->AccessControlInfo.SystemSaveDataId2)
		u32_to_u8(arm11->storageInfo.systemSavedataId[1], strtoul(rsf->AccessControlInfo.SystemSaveDataId2,NULL,0), LE);
}

void SetARM11StorageInfoExtSaveDataId(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	if (rsf->AccessControlInfo.UseExtSaveData || rsf->AccessControlInfo.ExtSaveDataId) {
		if (rsf->AccessControlInfo.ExtSaveDataId)
			u64_to_u8(arm11->storageInfo.extSavedataId, strtoull(rsf->AccessControlInfo.ExtSaveDataId, NULL, 0), LE);
		else
			u32_to_u8(arm11->storageInfo.extSavedataId, GetTidUniqueId(u8_to_u64(arm11->programId,LE)), LE);
	}

}

void SetARM11StorageInfoOtherUserSaveData(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	u64 value = 0;
	if(rsf->AccessControlInfo.OtherUserSaveDataId1)
		value = 0xffffff & strtoul(rsf->AccessControlInfo.OtherUserSaveDataId1,NULL,0);
	value = value << 20;
	if(rsf->AccessControlInfo.OtherUserSaveDataId2)
		value |= 0xffffff & strtoul(rsf->AccessControlInfo.OtherUserSaveDataId2,NULL,0);
	value = value << 20;
	if(rsf->AccessControlInfo.OtherUserSaveDataId3)
		value |= 0xffffff & strtoul(rsf->AccessControlInfo.OtherUserSaveDataId3,NULL,0);

	/* UseOtherVariationSaveData Flag */
	if(rsf->AccessControlInfo.UseOtherVariationSaveData)
		value |= 0x1000000000000000;

	u64_to_u8(arm11->storageInfo.storageAccessableUniqueIds,value,LE);
}

bool CheckCondiditionsForNewAccessibleSaveDataIds(rsf_settings *rsf)
{
	if(rsf->AccessControlInfo.AccessibleSaveDataIdsNum > 6){
		fprintf(stderr,"[EXHEADER ERROR] Too many UniqueId in \"AccessibleSaveDataIds\".\n");
		return false;
	}
	if (rsf->AccessControlInfo.UseExtSaveData) {
		fprintf(stderr, "[EXHEADER ERROR] UseExtSaveData must be false if AccessibleSaveDataIds is specified.\n");
		return false;
	}
	if (rsf->AccessControlInfo.ExtSaveDataId){
		fprintf(stderr,"[EXHEADER ERROR] ExtSaveDataId is unavailable if AccessibleSaveDataIds is specified.\n");
		return false;
	}
	if (rsf->AccessControlInfo.OtherUserSaveDataId1 && strtoul(rsf->AccessControlInfo.OtherUserSaveDataId1,NULL,0) > 0){
		fprintf(stderr,"[EXHEADER ERROR] OtherUserSaveDataId1 must be 0 if AccessibleSaveDataIds is specified.\n");
		return false;
	}
	if (rsf->AccessControlInfo.OtherUserSaveDataId2 && strtoul(rsf->AccessControlInfo.OtherUserSaveDataId2,NULL,0) > 0){
		fprintf(stderr,"[EXHEADER ERROR] OtherUserSaveDataId2 must be 0 if AccessibleSaveDataIds is specified.\n");
		return false;
	}
	if (rsf->AccessControlInfo.OtherUserSaveDataId3 && strtoul(rsf->AccessControlInfo.OtherUserSaveDataId3,NULL,0) > 0){
		fprintf(stderr,"[EXHEADER ERROR] OtherUserSaveDataId3 must be 0 if AccessibleSaveDataIds is specified.\n");
		return false;
	}
	return true;
}

void SetARM11StorageInfoAccessibleSaveDataIds(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	u64 region_ExtSaveDataId = 0;
	u64 region_OtherUseSaveData = 0;

	if(rsf->AccessControlInfo.AccessibleSaveDataIdsNum > 0){
		u32 max = rsf->AccessControlInfo.AccessibleSaveDataIdsNum < 3 ? rsf->AccessControlInfo.AccessibleSaveDataIdsNum : 3;
		for(int i = 0; i < max; i++){
			u32 uniqueID = 0xffffff & strtoul(rsf->AccessControlInfo.AccessibleSaveDataIds[i],NULL,0);
			region_OtherUseSaveData = region_OtherUseSaveData << 20;
			region_OtherUseSaveData |= uniqueID;
		}
	}
	if(rsf->AccessControlInfo.AccessibleSaveDataIdsNum > 3){
		for(int i = 3; i < rsf->AccessControlInfo.AccessibleSaveDataIdsNum; i++){
			u32 uniqueID = 0xffffff & strtoul(rsf->AccessControlInfo.AccessibleSaveDataIds[i],NULL,0);
			region_ExtSaveDataId = region_ExtSaveDataId << 20;
			region_ExtSaveDataId |= uniqueID;
		}
	}

	arm11->storageInfo.otherAttributes |= attribute_USE_EXTENDED_SAVEDATA_ACCESS_CONTROL;

	/* UseOtherVariationSaveData Flag */
	if(rsf->AccessControlInfo.UseOtherVariationSaveData)
		region_OtherUseSaveData |= 0x1000000000000000;

	u64_to_u8(arm11->storageInfo.extSavedataId,region_ExtSaveDataId,LE);
	u64_to_u8(arm11->storageInfo.storageAccessableUniqueIds,region_OtherUseSaveData,LE);
}

int SetARM11ServiceAccessControl(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	if(rsf->AccessControlInfo.ServiceAccessControl){
		if(rsf->AccessControlInfo.ServiceAccessControlNum > 34){
			fprintf(stderr,"[EXHEADER ERROR] Too Many Service Names, maximum is 34\n");
			return EXHDR_BAD_RSF_OPT;
		}
		for(int i = 0; i < rsf->AccessControlInfo.ServiceAccessControlNum; i++){
			if(strlen(rsf->AccessControlInfo.ServiceAccessControl[i]) > 8){
				fprintf(stderr,"[EXHEADER ERROR] Service Name: \"%s\" is too long\n",rsf->AccessControlInfo.ServiceAccessControl[i]);
				return EXHDR_BAD_RSF_OPT;
			}
			strncpy((char*)arm11->serviceAccessControl[i],rsf->AccessControlInfo.ServiceAccessControl[i],8);
		}
	}
	else{
		WarnParamNotFound("AccessControlInfo/ServiceAccessControl");
	}
	return 0;
}

int get_ExHeaderARM11KernelInfo(exhdr_ARM11KernelCapabilities *arm11, rsf_settings *rsf)
{
	int result = 0;
	u16 totalDesc, descIndex;
	ARM11KernelCapabilityDescriptor desc[6];
	clrmem(&desc,sizeof(ARM11KernelCapabilityDescriptor)*6);

	/* Get Descriptors */
	if((result = SetARM11KernelDescSysCallControl(&desc[0],rsf)))
		goto finish;
	if((result = SetARM11KernelDescInteruptNumList(&desc[1],rsf)))
		goto finish;
	if((result = SetARM11KernelDescAddressMapping(&desc[2],rsf)))
		goto finish;
	if((result = SetARM11KernelDescOtherCapabilities(&desc[3],rsf)))
		goto finish;
	if((result = SetARM11KernelDescHandleTableSize(&desc[4],rsf)))
		goto finish;
	if((result = SetARM11KernelDescReleaseKernelVersion(&desc[5],rsf)))
		goto finish;

	/* Write Descriptors To Exheader */
	totalDesc = 0;
	for(int i = 0; i < 6; i++)
		totalDesc += desc[i].num;

	if(totalDesc >= 28){
		fprintf(stderr,"[EXHEADER ERROR] Too many Kernel Capabilities.\n");
		result = EXHDR_BAD_RSF_OPT;
		goto finish;
	}

	descIndex = 0;
	for(int i = 0; i < 6; i++){
		for(int j = 0; j < desc[i].num; j++){
			u32_to_u8(arm11->descriptors[descIndex],desc[i].data[j],LE);
			descIndex++;
		}
	}

	/* Fill Remaining Descriptors with 0xffffffff */
	for(int i = descIndex; i < 28; i++)
		u32_to_u8(arm11->descriptors[i],0xffffffff,LE);

finish:
	for(int i = 0; i < 6; i++)
		free(desc[i].data);
	return result;
}

int SetARM11KernelDescSysCallControl(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	int ret = 0;
	u16 activeSysCallDesc, sysCallDescPos;

	// Create Temporary Descriptor
	ARM11KernelCapabilityDescriptor tmp;
	clrmem(&tmp,sizeof(ARM11KernelCapabilityDescriptor));

	AllocateARM11KernelDescMemory(&tmp,8);
	for(int i = 0; i < 8; i++)
		SetARM11KernelDescValue(&tmp,i,desc_SysCallControl | (i << 24));

	// Get SysCalls
	if((ret = GetARM11SysCalls(&tmp,rsf)))
		goto finish;

	// Count Active Syscall Descs
	activeSysCallDesc = 0;
	for(int i = 0; i < 8; i++)
		if((tmp.data[i] & 0x00ffffff) != 0)
			activeSysCallDesc++;

	// Transfer Active Syscall Descs to out Descriptor
	AllocateARM11KernelDescMemory(desc,activeSysCallDesc);
	sysCallDescPos = 0;
	for(int i = 0; i < 8; i++){
		if((tmp.data[i] & 0x00ffffff) != 0) {
			SetARM11KernelDescValue(desc,sysCallDescPos,tmp.data[i]);
			sysCallDescPos++;
		}
	}

finish:
	// Free data in Temporary Descriptor
	free(tmp.data);
	return ret;
}

int GetARM11SysCalls(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	if(!rsf->AccessControlInfo.SystemCallAccess){
		ErrorParamNotFound("AccessControlInfo/SystemCallAccess");
		return EXHDR_BAD_RSF_OPT;
	}
	for(int i = 0; i < rsf->AccessControlInfo.SystemCallAccessNum; i++){
		int sysCall = strtoul(rsf->AccessControlInfo.SystemCallAccess[i],NULL,0);
		if(sysCall > 184){
			fprintf(stderr,"[EXHEADER ERROR] Unexpected Syscall: 0x%02x. Expected Range: 0x00 - 0xB8\n",sysCall);
			return EXHDR_BAD_RSF_OPT;
		}
		EnableSystemCall(desc,sysCall);
	}

	return 0;
}

void EnableSystemCall(ARM11KernelCapabilityDescriptor *desc, int sysCall)
{
	int num = sysCall / 24;
	int num1 = sysCall % 24;
	desc->data[num] |= 1 << (num1 & 31);
}

void DisableSystemCall(ARM11KernelCapabilityDescriptor *desc, int sysCall)
{
	int num = sysCall / 24;
	int num1 = sysCall % 24;
	desc->data[num] = desc->data[num] & ~(1 << (num1 & 31));
}

int SetARM11KernelDescInteruptNumList(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	int ret = 0;
	u16 activeInteruptDesc, interuptDescPos;

	// Create Temporary Descriptor
	ARM11KernelCapabilityDescriptor tmp;
	memset(&tmp,0,sizeof(ARM11KernelCapabilityDescriptor));

	AllocateARM11KernelDescMemory(&tmp, 80/4);

	// Get Interupts
	ret = GetARM11Interupts(&tmp,rsf);
	if(ret) goto finish;

	// Count Active Interupt Descs
	activeInteruptDesc = 0;
	for(int i = 0; i < 80/4; i++)
		if(tmp.data[i])
			activeInteruptDesc++;

	// Transfer Active Interupt Descs to output Descriptor
	AllocateARM11KernelDescMemory(desc,activeInteruptDesc);
	interuptDescPos = 0;
	for(int i = 0; i < 80/4; i++){
		if(tmp.data[i]) {
			SetARM11KernelDescValue(desc,interuptDescPos,(tmp.data[i] & 0x0fffffff) | desc_InteruptNumList);
			interuptDescPos++;
		}
	}

finish:
	// Free data in Temporary Descriptor
	free(tmp.data);
	return ret;
}

int GetARM11Interupts(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	if(!rsf->AccessControlInfo.InterruptNumbers)
		return 0;

	if(rsf->AccessControlInfo.InterruptNumbersNum > 80){
		// There are between 80 and 88 valid PPIs on 3DS, and a dozen of them are reserved by kernel (CDMA)
		fprintf(stderr,"[EXHEADER ERROR] Too many Interupts. Maximum is 80\n");
		return EXHDR_BAD_RSF_OPT;
	}
	for(int i = 0; i < rsf->AccessControlInfo.InterruptNumbersNum; i++){
		int interrupt = strtoul(rsf->AccessControlInfo.InterruptNumbers[i],NULL,0);
		if(interrupt > 0x7f){
			fprintf(stderr,"[EXHEADER ERROR] Unexpected Interupt: 0x%02x. Expected Range: 0x00 - 0x7f\n",interrupt);
			return EXHDR_BAD_RSF_OPT;
		}
		EnableInterupt(desc,interrupt,i);
	}

	return 0;
}

void EnableInterupt(ARM11KernelCapabilityDescriptor *desc, int Interrupt, int i)
{
	int num = i / 4;
	if(num*4 == i) desc->data[num] |= 0xffffffff;
	desc->data[num] = desc->data[num] << 7;
	desc->data[num] |= Interrupt;
}

int SetARM11KernelDescAddressMapping(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	int ret = 0;
	u16 memMapDescPos;

	// Create Temporary Descriptors
	ARM11KernelCapabilityDescriptor io_tmp;
	clrmem(&io_tmp,sizeof(ARM11KernelCapabilityDescriptor));
	ARM11KernelCapabilityDescriptor static_tmp;
	clrmem(&static_tmp,sizeof(ARM11KernelCapabilityDescriptor));

	// Getting IO Mapping
	if((ret = GetARM11IOMappings(&io_tmp,rsf)))
		goto finish;

	// Getting Static Mapping
	if((ret = GetARM11StaticMappings(&static_tmp,rsf)))
		goto finish;


	// Creating Output Descriptor and Combining the two MemMap Descriptors
	AllocateARM11KernelDescMemory(desc,io_tmp.num+static_tmp.num);
	memMapDescPos = 0;
	for(int i = 0; i < io_tmp.num; i++){
		SetARM11KernelDescValue(desc,memMapDescPos,io_tmp.data[i]);
		memMapDescPos++;
	}
	for(int i = 0; i < static_tmp.num; i++){
		SetARM11KernelDescValue(desc,memMapDescPos,static_tmp.data[i]);
		memMapDescPos++;
	}

finish:
	free(io_tmp.data);
	free(static_tmp.data);
	return ret;
}

int GetARM11IOMappings(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	if(!rsf->AccessControlInfo.IORegisterMapping)
		return 0;

	AllocateARM11KernelDescMemory(desc,rsf->AccessControlInfo.IORegisterMappingNum*2);
	u16 descUsed = 0;

	for(int i = 0; i < rsf->AccessControlInfo.IORegisterMappingNum; i++){
		if(strlen(rsf->AccessControlInfo.IORegisterMapping[i])){
			// Parse Address String
			char *AddressStartStr = rsf->AccessControlInfo.IORegisterMapping[i];
			char *AddressEndStr = strstr(AddressStartStr,"-");
			if(AddressEndStr){
				if(strlen(AddressEndStr) > 1) // if not just '-'
					AddressEndStr = (AddressEndStr+1); // Setting the str to the expected start of address string
				else
					AddressEndStr = NULL;
			}


			u32 AddressStart = strtoul(AddressStartStr,NULL,16);
			if(!IsStartAddress(AddressStart)){
				fprintf(stderr,"[EXHEADER ERROR] Address 0x%x is not valid mapping start address.\n",AddressStart);
				return EXHDR_BAD_RSF_OPT;
			}
			if(!AddressEndStr){ // No End Addr Was Specified
				SetARM11KernelDescValue(desc,descUsed,GetIOMappingDesc(AddressStart));
				descUsed++;
				continue;
			}

			u32 AddressEnd = strtoul(AddressEndStr,NULL,16);
			if(!IsEndAddress(AddressEnd)){
				fprintf(stderr,"[EXHEADER ERROR] Address 0x%x is not valid mapping end address.\n",AddressEnd);
				return EXHDR_BAD_RSF_OPT;
			}

			u32 DescStartAddr = GetStaticMappingDesc(AddressStart,false);
			u32 DescEndAddr = GetStaticMappingDesc(AddressEnd+0x1000,false);
			if(DescStartAddr != DescEndAddr){
				SetARM11KernelDescValue(desc,descUsed,DescStartAddr);
				SetARM11KernelDescValue(desc,descUsed+1,DescEndAddr);
				descUsed += 2;
				continue;
			}
			else{
				SetARM11KernelDescValue(desc,descUsed,GetIOMappingDesc(AddressStart));
				descUsed++;
				continue;
			}
		}
	}
	desc->num = descUsed;
	return 0;
}

int GetARM11StaticMappings(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	if(!rsf->AccessControlInfo.MemoryMapping)
		return 0;

	AllocateARM11KernelDescMemory(desc,rsf->AccessControlInfo.MemoryMappingNum*2);
	u16 descUsed = 0;
	for(int i = 0; i < rsf->AccessControlInfo.MemoryMappingNum; i++){
		if(strlen(rsf->AccessControlInfo.MemoryMapping[i])){
			char *AddressStartStr = rsf->AccessControlInfo.MemoryMapping[i];
			char *AddressEndStr = strstr(AddressStartStr,"-");
			char *ROFlagStr = strstr(AddressStartStr,":");
			bool IsRO = false;
			if(ROFlagStr)
				IsRO = strcasecmp(ROFlagStr,":r") == 0 ? true : false;

			if(AddressEndStr){
				if(strlen(AddressEndStr) > 1) {
					AddressEndStr = (AddressEndStr+1);
					if(AddressEndStr == ROFlagStr)
						AddressEndStr = NULL;
				}
				else
					AddressEndStr = NULL;
			}
			u32 AddressStart = strtoul(AddressStartStr,NULL,16);
			if(!IsStartAddress(AddressStart)){
				fprintf(stderr,"[EXHEADER ERROR] Address 0x%x (%s) is not valid mapping start address.\n",AddressStart,AddressStartStr);
				return EXHDR_BAD_RSF_OPT;
			}
			if(!AddressEndStr){ // No End Addr Was Specified
				SetARM11KernelDescValue(desc,descUsed,GetStaticMappingDesc(AddressStart,IsRO));
				SetARM11KernelDescValue(desc,descUsed+1,GetStaticMappingDesc(AddressStart+0x1000, true));
				descUsed += 2;
				continue;
			}

			u32 AddressEnd = strtoul(AddressEndStr,NULL,16);
			if(!IsEndAddress(AddressEnd)){
				fprintf(stderr,"[EXHEADER ERROR] Address 0x%x (%s) is not valid mapping end address.\n",AddressEnd,AddressEndStr);
				return EXHDR_BAD_RSF_OPT;
			}

			u32 DescStartAddr = GetStaticMappingDesc(AddressStart,IsRO);
			u32 DescEndAddr = GetStaticMappingDesc(AddressEnd+0x1000,true);
			if(DescStartAddr != DescEndAddr){
				SetARM11KernelDescValue(desc,descUsed,DescStartAddr);
				SetARM11KernelDescValue(desc,descUsed+1,DescEndAddr);
				descUsed += 2;
				continue;
			}
			else{
				SetARM11KernelDescValue(desc,descUsed,GetStaticMappingDesc(AddressStart,IsRO));
				SetARM11KernelDescValue(desc,descUsed+1,GetStaticMappingDesc(AddressStart+0x1000, true));
				descUsed += 2;
				continue;
			}
		}
	}
	desc->num = descUsed;
	return 0;
}

bool IsEndAddress(u32 address)
{
	return (address & 0x0fff) == 0x0fff;
}

bool IsStartAddress(u32 address)
{
	return (address & 0x0fff) == 0;
}

u32 GetIOMappingDesc(u32 address)
{
	return GetMappingDesc(address,0xFFE,0xC,false);
}

u32 GetStaticMappingDesc(u32 address, bool IsReadOnly)
{
	return GetMappingDesc(address,0x7FC,0xB,IsReadOnly);
}

u32 GetMappingDesc(u32 address, u32 prefixVal, s32 numPrefixBits, bool IsRO)
{
	u32 prefixMask = GetDescPrefixMask(numPrefixBits);
	u32 prefixBits = GetDescPrefixBits(numPrefixBits,prefixVal);
	u32 desc = (address >> 12 & ~prefixMask) | prefixBits;
	if (IsRO)
		desc |= 0x100000;
	return desc;
}

int SetARM11KernelDescOtherCapabilities(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	u32 otherCapabilities = 0;
	u32 memType = 0;

	if(!rsf->AccessControlInfo.DisableDebug)
		otherCapabilities |= othcap_PERMIT_DEBUG;
	if(rsf->AccessControlInfo.EnableForceDebug)
		otherCapabilities |= othcap_FORCE_DEBUG;
	if(rsf->AccessControlInfo.CanUseNonAlphabetAndNumber)
		otherCapabilities |= othcap_CAN_USE_NON_ALPHABET_AND_NUMBER;
	if(rsf->AccessControlInfo.CanWriteSharedPage)
		otherCapabilities |= othcap_CAN_WRITE_SHARED_PAGE;
	if(rsf->AccessControlInfo.CanUsePrivilegedPriority)
		otherCapabilities |= othcap_CAN_USE_PRIVILEGE_PRIORITY;
	if(rsf->AccessControlInfo.PermitMainFunctionArgument)
		otherCapabilities |= othcap_PERMIT_MAIN_FUNCTION_ARGUMENT;
	if(rsf->AccessControlInfo.CanShareDeviceMemory)
		otherCapabilities |= othcap_CAN_SHARE_DEVICE_MEMORY;
	if(rsf->AccessControlInfo.RunnableOnSleep)
		otherCapabilities |= othcap_RUNNABLE_ON_SLEEP;
	if(rsf->AccessControlInfo.SpecialMemoryArrange)
		otherCapabilities |= othcap_SPECIAL_MEMORY_ARRANGE;
	if (rsf->AccessControlInfo.CanAccessCore2)
		otherCapabilities |= othcap_CAN_ACCESS_CORE2;

	if(rsf->AccessControlInfo.MemoryType){
		if(strcasecmp(rsf->AccessControlInfo.MemoryType,"application") == 0)
			memType = memtype_APPLICATION;
		else if(strcasecmp(rsf->AccessControlInfo.MemoryType,"system") == 0)
			memType = memtype_SYSTEM;
		else if(strcasecmp(rsf->AccessControlInfo.MemoryType,"base") == 0)
			memType = memtype_BASE;
		else{
			fprintf(stderr,"[EXHEADER ERROR] Invalid memory type: \"%s\"\n",rsf->AccessControlInfo.MemoryType);
			return EXHDR_BAD_RSF_OPT;
		}
		otherCapabilities = (otherCapabilities & 0xfffff0ff) | (memType & 0xf) << 8;
	}

	if(otherCapabilities){
		AllocateARM11KernelDescMemory(desc,1);
		SetARM11KernelDescBitmask(desc,desc_OtherCapabilities);
		SetARM11KernelDescValue(desc,0,otherCapabilities);
	}
	return 0;
}

int SetARM11KernelDescHandleTableSize(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	if(rsf->AccessControlInfo.HandleTableSize){
		u16 handleTableSize = strtoul(rsf->AccessControlInfo.HandleTableSize,NULL,0);
		if(handleTableSize > 1023){
			fprintf(stderr,"[EXHEADER ERROR] Too large handle table size\n");
			return EXHDR_BAD_RSF_OPT;
		}
		AllocateARM11KernelDescMemory(desc,1);
		SetARM11KernelDescBitmask(desc,desc_HandleTableSize);
		SetARM11KernelDescValue(desc,0,handleTableSize);
	}
	else{
		ErrorParamNotFound("AccessControlInfo/HandleTableSize");
		return EXHDR_BAD_RSF_OPT;
	}
	return 0;
}

int SetARM11KernelDescReleaseKernelVersion(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	if(rsf->AccessControlInfo.ReleaseKernelMajor && rsf->AccessControlInfo.ReleaseKernelMinor){
		u32 releaseKernelMajor = strtoul(rsf->AccessControlInfo.ReleaseKernelMajor,NULL,0);
		u32 releaseKernelMinor = strtoul(rsf->AccessControlInfo.ReleaseKernelMinor,NULL,0);
		if (releaseKernelMajor > 255 || releaseKernelMinor > 255){
			fprintf(stderr,"[EXHEADER ERROR] Invalid release kernel Version");
		}
		AllocateARM11KernelDescMemory(desc,1);
		SetARM11KernelDescBitmask(desc,desc_KernelReleaseVersion);
		SetARM11KernelDescValue(desc,0,(releaseKernelMajor << 8 | releaseKernelMinor));
	}
	return 0;
}

void SetARM11KernelDescValue(ARM11KernelCapabilityDescriptor *desc, u16 index, u32 value)
{
	if(index >= desc->num) return;
	desc->data[index] |= value;
}

void SetARM11KernelDescBitmask(ARM11KernelCapabilityDescriptor *desc, u32 bitmask)
{
	for(int i = 0; i < desc->num; i++)
		SetARM11KernelDescValue(desc,i,bitmask);
}

void AllocateARM11KernelDescMemory(ARM11KernelCapabilityDescriptor *desc, u16 num)
{
	if(num == 0) return;
	desc->num = num;
	desc->data = malloc(sizeof(u32)*num);
	clrmem(desc->data,sizeof(u32)*num);
	return;
}

u32 GetDescPrefixMask(int numPrefixBits)
{
	return (u32)(~((1 << (32 - (numPrefixBits & 31))) - 1));
}

u32 GetDescPrefixBits(int numPrefixBits, u32 prefixVal)
{
	return prefixVal << (32 - (numPrefixBits & 31));
}

int get_ExHeaderARM9AccessControlInfo(exhdr_ARM9AccessControlInfo *arm9, rsf_settings *rsf)
{
	u32 arm9AccessControl = 0;
	for(int i = 0; i < rsf->AccessControlInfo.IoAccessControlNum; i++){
		if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"FsMountNand") == 0)
			arm9AccessControl |= arm9cap_FS_MOUNT_NAND;
		else if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"FsMountNandRoWrite") == 0)
			arm9AccessControl |= arm9cap_FS_MOUNT_NAND_RO_WRITE;
		else if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"FsMountTwln") == 0)
			arm9AccessControl |= arm9cap_FS_MOUNT_TWLN;
		else if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"FsMountWnand") == 0)
			arm9AccessControl |= arm9cap_FS_MOUNT_WNAND;
		else if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"FsMountCardSpi") == 0)
			arm9AccessControl |= arm9cap_FS_MOUNT_CARD_SPI;
		else if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"UseSdif3") == 0)
			arm9AccessControl |= arm9cap_USE_SDIF3;
		else if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"CreateSeed") == 0)
			arm9AccessControl |= arm9cap_CREATE_SEED;
		else if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"UseCardSpi") == 0)
			arm9AccessControl |= arm9cap_USE_CARD_SPI;
		else{
			fprintf(stderr,"[EXHEADER ERROR] Invalid IoAccessControl Name: \"%s\"\n",rsf->AccessControlInfo.IoAccessControl[i]);
			return EXHDR_BAD_RSF_OPT;
		}
	}

	for(int i = 0; i < rsf->AccessControlInfo.FileSystemAccessNum; i++){
		if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"DirectSdmc") == 0)
			arm9AccessControl |= arm9cap_USE_DIRECT_SDMC;
	}

	if(rsf->Option.UseOnSD)
		arm9AccessControl |= arm9cap_SD_APPLICATION;

	u32_to_u8(arm9->descriptors,arm9AccessControl,LE);

	if(rsf->AccessControlInfo.DescVersion)
		arm9->descriptors[15] = strtol(rsf->AccessControlInfo.DescVersion,NULL,0);
	else{
		//ErrorParamNotFound("AccessControlInfo/DescVersion");
		//return EXHDR_BAD_RSF_OPT;
		arm9->descriptors[15] = 2; // Makerom generates a desc version 2 anyway, so if not specified, it will be set to 2
	}

	return 0;
}

/* Generic Exheader Errors */
void ErrorParamNotFound(char *string)
{
	fprintf(stderr,"[EXHEADER ERROR] Parameter Not Found: \"%s\"\n",string);
}

void WarnParamNotFound(char *string)
{
	fprintf(stderr, "[EXHEADER WARNING] Parameter Not Found: \"%s\"\n", string);
}

/* ExHeader Binary Print Functions */
void exhdr_Print_ServiceAccessControl(extended_hdr *hdr)
{
	printf("[+] Service Access Control\n");
	for(int i = 0; i < 32; i ++){
		char *SVC_Handle = (char*)hdr->arm11SystemLocalCapabilities.serviceAccessControl[i];
		if(SVC_Handle[0] == 0) break;
		printf("%.8s\n",hdr->arm11SystemLocalCapabilities.serviceAccessControl[i]);
	}
}

/* ExHeader Binary Read Functions */
u8* GetAcexRsaSig(access_descriptor *acexDesc)
{
	return acexDesc->signature ;
}

u8* GetAcexNcchPubKey(access_descriptor *acexDesc)
{
	return acexDesc->ncchRsaPubKey;
}

u16 GetRemasterVersion_frm_exhdr(extended_hdr *hdr)
{
	return u8_to_u16(hdr->codeSetInfo.remasterVersion,LE);
}

u64 GetSaveDataSize_frm_exhdr(extended_hdr *hdr)
{
	return u8_to_u64(hdr->systemInfo.savedataSize,LE);
}

void GetCoreVersion_frm_exhdr(u8 *Dest, extended_hdr *hdr)
{
	memcpy(Dest,hdr->arm11SystemLocalCapabilities.coreVersion,4);
}

int GetDependencyList_frm_exhdr(u8 *Dest, extended_hdr *hdr)
{
	if(!Dest) return -1;
	memcpy(Dest,hdr->dependencyList,0x30*8);

	return 0;
}

/* ExHeader Settings Read from RSF */
int GetSaveDataSizeFromString(u64 *out, char *string, char *moduleName)
{
	if(!string){
		*out = 0;
		return 0;
	}

	u64 SaveDataSize = strtoull(string,NULL,10);

	if(strstr(string,"K")){
		char *str = strstr(string,"K");
		if(strcmp(str,"K") == 0 || strcmp(str,"KB") == 0 ){
			SaveDataSize *= KB;
		}
	}
	else if(strstr(string,"M")){
		char *str = strstr(string,"M");
		if(strcmp(str,"M") == 0 || strcmp(str,"MB") == 0 ){
			SaveDataSize *= MB;
		}
	}
	else if(strstr(string,"G")){
		char *str = strstr(string,"G");
		if(strcmp(str,"G") == 0 || strcmp(str,"GB") == 0 ){
			SaveDataSize *= GB;
		}
	}
	else{
		if(moduleName)
			fprintf(stderr,"[%s ERROR] Invalid save data size format.\n",moduleName);
		else
			fprintf(stderr,"[ERROR] Invalid save data size format.\n");
		return EXHDR_BAD_RSF_OPT;
	}
	if((SaveDataSize % 65536) != 0){
		if(moduleName)
			fprintf(stderr,"[%s ERROR] Save data size must be aligned to 64K.\n",moduleName);
		else
			fprintf(stderr,"[ERROR] Save data size must be aligned to 64K.\n");
		return EXHDR_BAD_RSF_OPT;
	}
	*out = SaveDataSize;
	return 0;
}

int GetSaveDataSize_rsf(u64 *SaveDataSize, user_settings *usrset)
{

	if(usrset->common.rsfSet.SystemControlInfo.SaveDataSize){
		*SaveDataSize = strtoull(usrset->common.rsfSet.SystemControlInfo.SaveDataSize,NULL,10);
		if(strstr(usrset->common.rsfSet.SystemControlInfo.SaveDataSize,"K")){
			char *str = strstr(usrset->common.rsfSet.SystemControlInfo.SaveDataSize,"K");
			if(strcmp(str,"K") == 0 || strcmp(str,"KB") == 0 ){
				*SaveDataSize = *SaveDataSize*KB;
			}
		}
		else if(strstr(usrset->common.rsfSet.SystemControlInfo.SaveDataSize,"M")){
			char *str = strstr(usrset->common.rsfSet.SystemControlInfo.SaveDataSize,"M");
			if(strcmp(str,"M") == 0 || strcmp(str,"MB") == 0 ){
				*SaveDataSize = *SaveDataSize*MB;
			}
		}
		else if(strstr(usrset->common.rsfSet.SystemControlInfo.SaveDataSize,"G")){
			char *str = strstr(usrset->common.rsfSet.SystemControlInfo.SaveDataSize,"G");
			if(strcmp(str,"G") == 0 || strcmp(str,"GB") == 0 ){
				*SaveDataSize = *SaveDataSize*GB;
			}
		}
		else{
			fprintf(stderr,"[EXHEADER ERROR] Invalid save data size format.\n");
			return EXHDR_BAD_RSF_OPT;
		}
		if((*SaveDataSize % 65536) != 0){
			fprintf(stderr,"[EXHEADER ERROR] Save data size must be aligned to 64K.\n");
			return EXHDR_BAD_RSF_OPT;
		}
	}
	else{
		*SaveDataSize = 0;
	}
	return 0;
}

int GetRemasterVersion_rsf(u16 *RemasterVersion, user_settings *usrset)
{
	char *Str = usrset->common.rsfSet.SystemControlInfo.RemasterVersion;
	if(!Str){
		*RemasterVersion = 0;
		return 0;
	}
	*RemasterVersion = strtol(Str,NULL,0);
	return 0;
}
