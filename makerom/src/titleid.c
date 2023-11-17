#include "lib.h"
#include "ncch_read.h"
#include "titleid.h"

const u32 DEFAULT_CATEGORY = PROGRAM_ID_CATEGORY_APPLICATION;
const u32 DEFAULT_UNIQUE_ID = 0xff3ff;

void SetPIDType(u32 *type);
int SetPIDCategoryFromName(u32 *cat, char *CategoryStr);
int SetPIDCategoryFromFlags(u32 *cat, char **CategoryFlags, u32 FlagNum);
int SetPIDCategoryFromFlag(u32 *cat, u32 flag, char *flagName);
u32 SetPIDUniqueId(char *UniqueIdStr);
int SetTitleVariation(u8 *var, u32 cat, rsf_settings *rsf);

u64 ConvertTwlIdToCtrId(u64 pgid)
{
	return 0x0004800000000000 | (pgid & 0x00007FFFFFFFFFFF);
}

u32 GetTidCategory(u64 titleId)
{
	return (titleId>>32) & 0x3FFFF; 
}

u32 GetTidUniqueId(u64 titleId)
{
	return (titleId>>8) & 0xFFFFFF; 
}

int GetProgramID(u64 *dest, rsf_settings *rsf, bool IsForExheader)
{
	int ret = 0;
	u32 uniqueId;
	u32 type,category;
	u8 variation;

	if(rsf->TitleInfo.Category && rsf->TitleInfo.CategoryFlags){
		fprintf(stderr,"[ID ERROR] Can not set \"Category\" and \"CategoryFlags\" at the same time.\n");
		return PID_BAD_RSF_SET;
	}

	// Getting Type
	SetPIDType(&type);
	
	// Getting Category
	if(IsForExheader && rsf->TitleInfo.TargetCategory)
		ret = SetPIDCategoryFromName(&category,rsf->TitleInfo.TargetCategory);
	else if (rsf->TitleInfo.Category)
		ret = SetPIDCategoryFromName(&category, rsf->TitleInfo.Category);
	else if (rsf->TitleInfo.CategoryFlags)
		ret = SetPIDCategoryFromFlags(&category, rsf->TitleInfo.CategoryFlags, rsf->TitleInfo.CategoryFlagsNum);
	else
		category = DEFAULT_CATEGORY;

	if(ret == PID_INVALID_CATEGORY) // Error occured
		return PID_BAD_RSF_SET;

	// Getting UniqueId
	if(rsf->TitleInfo.UniqueId) 
		GetUniqueID(&uniqueId,rsf);
	else
		uniqueId = DEFAULT_UNIQUE_ID;

	if(uniqueId & 0xFFF00000u){
		fprintf(stderr,"[ID ERROR] Unique ID is out of range.\n");
		return PID_BAD_RSF_SET;
	}

	// Getting Variation
	if(SetTitleVariation(&variation,category,rsf) == PID_INVALID_VARIATION)
		return PID_BAD_RSF_SET;

	u64 programId = 0;
	programId |= (u64)variation<<0;
	programId |= (u64)uniqueId<<8;
	programId |= (u64)category<<32;
	programId |= (u64)type<<48;

	*dest = programId;

	return 0;
}

void SetPIDType(u32 *type)
{
	*type = 0x00004;
}

int GetUniqueID(u32 *uid, rsf_settings *rsf)
{
	if(rsf->TitleInfo.UniqueId) *uid = 0xffffff & SetPIDUniqueId(rsf->TitleInfo.UniqueId);
	else{
		fprintf(stderr,"[ID ERROR] ParameterNotFound: \"TitleInfo/UniqueId\"\n");
		return PID_BAD_RSF_SET;
	}
	return 0;
}

int SetPIDCategoryFromName(u32 *cat, char *CategoryStr)
{
	if(strcmp(CategoryStr,"Application") == 0) *cat = PROGRAM_ID_CATEGORY_APPLICATION;
	else if(strcmp(CategoryStr,"SystemApplication") == 0) *cat = PROGRAM_ID_CATEGORY_SYSTEM_APPLICATION;
	else if(strcmp(CategoryStr,"Applet") == 0) *cat = PROGRAM_ID_CATEGORY_APPLET;
	else if(strcmp(CategoryStr,"Firmware") == 0) *cat = PROGRAM_ID_CATEGORY_FIRMWARE;
	else if(strcmp(CategoryStr,"Base") == 0) *cat = PROGRAM_ID_CATEGORY_BASE;
	else if(strcmp(CategoryStr,"DlpChild") == 0) *cat = PROGRAM_ID_CATEGORY_DLP_CHILD;
	else if(strcmp(CategoryStr,"Demo") == 0) *cat = PROGRAM_ID_CATEGORY_DEMO;
	else if(strcmp(CategoryStr,"Contents") == 0) *cat = PROGRAM_ID_CATEGORY_CONTENTS;
	else if(strcmp(CategoryStr,"SystemContents") == 0) *cat = PROGRAM_ID_CATEGORY_SYSTEM_CONTENT;
	else if(strcmp(CategoryStr,"SharedContents") == 0) *cat = PROGRAM_ID_CATEGORY_SHARED_CONTENT;
	else if(strcmp(CategoryStr,"AddOnContents") == 0) *cat = PROGRAM_ID_CATEGORY_ADD_ON_CONTENTS;
	else if(strcmp(CategoryStr,"Patch") == 0) *cat = PROGRAM_ID_CATEGORY_PATCH;
	else if(strcmp(CategoryStr,"AutoUpdateContents") == 0) *cat = PROGRAM_ID_CATEGORY_AUTO_UPDATE_CONTENT;
	else if(strcmp(CategoryStr,"Manual") == 0) *cat = PROGRAM_ID_CATEGORY_MANUAL;
	else {
		fprintf(stderr,"[ID ERROR] Invalid Category: \"%s\"\n",CategoryStr);
		return PID_INVALID_CATEGORY;
	}
	
	return 0;
}

int SetPIDCategoryFromFlags(u32 *cat, char **CategoryFlags, u32 FlagNum)
{
	int ret = 0;
	for(u32 i = 0; i < FlagNum; i++){
		if(strcmp(CategoryFlags[i],"Normal") == 0)
			ret = SetPIDCategoryFromFlag(cat,PROGRAM_ID_CATEGORY_FLAG_NORMAL,"Normal");
		else if(strcmp(CategoryFlags[i],"DlpChild") == 0)
			ret = SetPIDCategoryFromFlag(cat,PROGRAM_ID_CATEGORY_FLAG_DLP_CHILD,"DlpChild");
		else if(strcmp(CategoryFlags[i],"Demo") == 0)
			ret = SetPIDCategoryFromFlag(cat,PROGRAM_ID_CATEGORY_FLAG_DEMO,"Demo");
		else if(strcmp(CategoryFlags[i],"Contents") == 0)
			ret = SetPIDCategoryFromFlag(cat,PROGRAM_ID_CATEGORY_FLAG_CONTENTS,"Contents");
		else if(strcmp(CategoryFlags[i],"AddOnContents") == 0)
			ret = SetPIDCategoryFromFlag(cat,PROGRAM_ID_CATEGORY_FLAG_ADD_ON_CONTENTS,"AddOnContents");
		else if(strcmp(CategoryFlags[i],"Patch") == 0)
			ret = SetPIDCategoryFromFlag(cat,PROGRAM_ID_CATEGORY_FLAG_PATCH,"Patch");
		else if(strcmp(CategoryFlags[i],"CannotExecution") == 0)
			ret = SetPIDCategoryFromFlag(cat,PROGRAM_ID_CATEGORY_FLAG_CANNOT_EXECUTION,"CannotExecution");
		else if(strcmp(CategoryFlags[i],"System") == 0)
			ret = SetPIDCategoryFromFlag(cat,PROGRAM_ID_CATEGORY_FLAG_SYSTEM,"System");
		else if(strcmp(CategoryFlags[i],"RequireBatchUpdate") == 0)
			ret = SetPIDCategoryFromFlag(cat,PROGRAM_ID_CATEGORY_FLAG_REQUIRE_BATCH_UPDATE,"RequireBatchUpdate");
		else if(strcmp(CategoryFlags[i],"NotRequireUserApproval") == 0)
			ret = SetPIDCategoryFromFlag(cat,PROGRAM_ID_CATEGORY_FLAG_NOT_REQUIRE_USER_APPROVAL,"NotRequireUserApproval");
		else if(strcmp(CategoryFlags[i],"NotRequireRightForMount") == 0)
			ret = SetPIDCategoryFromFlag(cat,PROGRAM_ID_CATEGORY_FLAG_NOT_REQUIRE_RIGHT_FOR_MOUNT,"NotRequireRightForMount");
		else if(strcmp(CategoryFlags[i],"CanSkipConvertJumpId") == 0)
			ret = SetPIDCategoryFromFlag(cat,PROGRAM_ID_CATEGORY_FLAG_CAN_SKIP_CONVERT_JUMP_ID,"CanSkipConvertJumpId");
		else if(strcmp(CategoryFlags[i],"Manual") == 0)
			ret = SetPIDCategoryFromFlag(cat,PROGRAM_ID_CATEGORY_FLAG_MANUAL,"Manual");
		else {
			fprintf(stderr,"[ID ERROR] Invalid CategoryFlag: \"%s\"\n",CategoryFlags[i]);
			return PID_INVALID_CATEGORY;
		}
	}
	return ret;
}

int SetPIDCategoryFromFlag(u32 *cat, u32 flag, char *flagName)
{
	if(!flag) return 0;
	if((*cat & flag) == flag){
		fprintf(stderr,"[ID ERROR] Failed to set \"%s\" for category. CategoryFlag was already set.\n",flagName);
		return PID_INVALID_CATEGORY;
	}
	*cat |= flag;
	
	return 0;
}

u32 SetPIDUniqueId(char *UniqueIdStr)
{
	return 0xffffff & strtoull(UniqueIdStr,NULL,0);
}

int SetTitleVariation(u8 *var, u32 cat, rsf_settings *rsf)
{
	if(IsDemo(cat)){
		if(rsf->TitleInfo.DemoIndex){
			u8 DemoIndex = 0xff & strtol(rsf->TitleInfo.DemoIndex,NULL,10);
			if(DemoIndex == 0){
				fprintf(stderr,"[ID ERROR] Invalid demo index \"%d\"\n",DemoIndex);
				return PID_INVALID_VARIATION;
			}
			*var = DemoIndex;
		}
		else{
			fprintf(stderr,"[ID ERROR] ParameterNotFound: \"TitleInfo/DemoIndex\"\n");
			return PID_INVALID_VARIATION;
		}
	}
	
	else if(IsDlpChild(cat)){
		if(rsf->TitleInfo.ChildIndex)
			*var = 0xff & strtol(rsf->TitleInfo.ChildIndex,NULL,10);
		else
			*var = 0;
	}
	else if(IsAddOnContent(cat)){
		if(rsf->TitleInfo.Variation) // Might Rename to DataTitleIndex
			*var = 0xff & strtol(rsf->TitleInfo.Variation,NULL,10);
		else
			*var = 0;
	}
	else if(IsContents(cat)){
		if(rsf->TitleInfo.ContentsIndex)
			*var = 0xff & strtol(rsf->TitleInfo.ContentsIndex,NULL,10);
		else
			*var = 0;
	}
	else{
		if(rsf->TitleInfo.Version)
			*var = 0xff & strtol(rsf->TitleInfo.Version,NULL,10);
		else
			*var = 0;
	}
	return 0;
}

bool IsDemo(u32 Category)
{
	return Category & PROGRAM_ID_CATEGORY_DEMO;
}

bool IsSystem(u32 Category)
{
	return Category & PROGRAM_ID_CATEGORY_FLAG_SYSTEM;
}

bool IsDlpChild(u32 Category)
{
	return Category & PROGRAM_ID_CATEGORY_DLP_CHILD;
}

bool IsPatch(u32 Category)
{
	return Category == PROGRAM_ID_CATEGORY_PATCH;
}

bool IsContents(u32 Category)
{
	return (Category & PROGRAM_ID_CATEGORY_FLAG_CONTENTS) == PROGRAM_ID_CATEGORY_FLAG_CONTENTS;
}

bool IsAddOnContent(u32 Category)
{
	return Category == PROGRAM_ID_CATEGORY_ADD_ON_CONTENTS;
}

bool IsManual(u32 Category)
{
	return Category & PROGRAM_ID_CATEGORY_MANUAL;
}
