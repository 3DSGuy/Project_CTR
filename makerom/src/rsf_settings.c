#include "lib.h"

void GET_Option(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_AccessControlInfo(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_SystemControlInfo(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_BasicInfo(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_RomFs(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_TitleInfo(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_CardInfo(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_CommonHeaderKey(ctr_yaml_context *ctx, rsf_settings *rsf);

void EvaluateRSF(rsf_settings *rsf, ctr_yaml_context *ctx)
{
	u32 start_level = ctx->Level-1;
	
	/* Check Group Key for Validity */
	CHECK_Group:
	//printf("RSF Found: %s\n",GetYamlString(ctx));
	if(cmpYamlValue("Option",ctx)) {FinishEvent(ctx); GET_Option(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("AccessControlInfo",ctx)) {FinishEvent(ctx); GET_AccessControlInfo(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("SystemControlInfo",ctx)) {FinishEvent(ctx); GET_SystemControlInfo(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("BasicInfo",ctx)) {FinishEvent(ctx); GET_BasicInfo(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("RomFs",ctx)) {FinishEvent(ctx); GET_RomFs(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("TitleInfo",ctx)) {FinishEvent(ctx); GET_TitleInfo(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("CardInfo",ctx)) {FinishEvent(ctx); GET_CardInfo(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("CommonHeaderKey",ctx)) {FinishEvent(ctx); GET_CommonHeaderKey(ctx,rsf); goto GET_NextGroup;}

	// If not recognised escape:
	fprintf(stderr,"[RSF ERROR] Unrecognised Key: '%s'\n",GetYamlString(ctx)); 
	FinishEvent(ctx); 
	ctx->error = YAML_BAD_GROUP_HEADER; 
	return;
		
	/* Get Next Group and call check */
	GET_NextGroup:
	// If done return
	if(ctx->done || ctx->error) return;
	
	// Recursively getting events until done or has value
	if(!ctx->event.type) GetEvent(ctx);
	if(ctx->Level <= start_level) return; // No longer in RSF Domain
	while(!EventIsScalar(ctx)){
		if(ctx->done || ctx->error) return;
		if(ctx->Level <= start_level) return; // No longer in RSF Domain
		FinishEvent(ctx);
		GetEvent(ctx);		
	}
	goto CHECK_Group;
}

void GET_Option(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		if(cmpYamlValue("AllowUnalignedSection",ctx)) SetBoolYAMLValue(&rsf->Option.AllowUnalignedSection,"AllowUnalignedSection",ctx);
		else if(cmpYamlValue("MediaFootPadding",ctx)) SetBoolYAMLValue(&rsf->Option.MediaFootPadding,"MediaFootPadding",ctx);
		else if(cmpYamlValue("EnableCrypt",ctx)) SetBoolYAMLValue(&rsf->Option.EnableCrypt,"EnableCrypt",ctx);
		else if(cmpYamlValue("EnableCompress",ctx)) SetBoolYAMLValue(&rsf->Option.EnableCompress,"EnableCompress",ctx);
		else if(cmpYamlValue("FreeProductCode",ctx)) SetBoolYAMLValue(&rsf->Option.FreeProductCode,"FreeProductCode",ctx);
		else if(cmpYamlValue("UseOnSD",ctx)) SetBoolYAMLValue(&rsf->Option.UseOnSD,"UseOnSD",ctx);
		else if(cmpYamlValue("UseKtrProgramId",ctx)) SetBoolYAMLValue(&rsf->Option.UseKtrProgramId,"UseKtrProgramId",ctx);
		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_AccessControlInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		if(cmpYamlValue("DisableDebug",ctx)) SetBoolYAMLValue(&rsf->AccessControlInfo.DisableDebug,"DisableDebug",ctx);
		else if(cmpYamlValue("EnableForceDebug",ctx)) SetBoolYAMLValue(&rsf->AccessControlInfo.EnableForceDebug,"EnableForceDebug",ctx);
		else if(cmpYamlValue("CanWriteSharedPage",ctx)) SetBoolYAMLValue(&rsf->AccessControlInfo.CanWriteSharedPage,"CanWriteSharedPage",ctx);
		else if(cmpYamlValue("CanUsePrivilegedPriority",ctx)) SetBoolYAMLValue(&rsf->AccessControlInfo.CanUsePrivilegedPriority,"CanUsePrivilegedPriority",ctx);
		else if(cmpYamlValue("CanUseNonAlphabetAndNumber",ctx)) SetBoolYAMLValue(&rsf->AccessControlInfo.CanUseNonAlphabetAndNumber,"CanUseNonAlphabetAndNumber",ctx);
		else if(cmpYamlValue("PermitMainFunctionArgument",ctx)) SetBoolYAMLValue(&rsf->AccessControlInfo.PermitMainFunctionArgument,"PermitMainFunctionArgument",ctx);
		else if(cmpYamlValue("CanShareDeviceMemory",ctx)) SetBoolYAMLValue(&rsf->AccessControlInfo.CanShareDeviceMemory,"CanShareDeviceMemory",ctx);
		else if(cmpYamlValue("UseOtherVariationSaveData",ctx)) SetBoolYAMLValue(&rsf->AccessControlInfo.UseOtherVariationSaveData,"UseOtherVariationSaveData",ctx);
		else if(cmpYamlValue("RunnableOnSleep",ctx)) SetBoolYAMLValue(&rsf->AccessControlInfo.RunnableOnSleep,"RunnableOnSleep",ctx);
		else if(cmpYamlValue("SpecialMemoryArrange",ctx)) SetBoolYAMLValue(&rsf->AccessControlInfo.SpecialMemoryArrange,"SpecialMemoryArrange",ctx);
		else if(cmpYamlValue("CanAccessCore2", ctx)) SetBoolYAMLValue(&rsf->AccessControlInfo.CanAccessCore2, "CanAccessCore2", ctx);
		else if(cmpYamlValue("UseExtSaveData", ctx)) SetBoolYAMLValue(&rsf->AccessControlInfo.UseExtSaveData, "UseExtSaveData", ctx);
		else if(cmpYamlValue("EnableL2Cache", ctx)) SetBoolYAMLValue(&rsf->AccessControlInfo.EnableL2Cache, "EnableL2Cache", ctx);

		
		else if(cmpYamlValue("IdealProcessor",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.IdealProcessor,"IdealProcessor",ctx,0); 
		else if(cmpYamlValue("Priority",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.Priority,"Priority",ctx,0); 
		else if(cmpYamlValue("MemoryType",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.MemoryType,"MemoryType",ctx,0); 
		else if(cmpYamlValue("SystemMode",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.SystemMode,"SystemMode",ctx,0); 
		else if(cmpYamlValue("SystemModeExt", ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.SystemModeExt, "SystemModeExt", ctx, 0);
		else if(cmpYamlValue("CpuSpeed", ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.CpuSpeed, "CpuSpeed", ctx, 0);
		else if(cmpYamlValue("CoreVersion",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.CoreVersion,"CoreVersion",ctx,0); 
		else if(cmpYamlValue("HandleTableSize",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.HandleTableSize,"HandleTableSize",ctx,0); 
		else if(cmpYamlValue("SystemSaveDataId1",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.SystemSaveDataId1,"SystemSaveDataId1",ctx,0); 
		else if(cmpYamlValue("SystemSaveDataId2",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.SystemSaveDataId2,"SystemSaveDataId2",ctx,0); 
		else if(cmpYamlValue("OtherUserSaveDataId1",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.OtherUserSaveDataId1,"OtherUserSaveDataId1",ctx,0); 
		else if(cmpYamlValue("OtherUserSaveDataId2",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.OtherUserSaveDataId2,"OtherUserSaveDataId2",ctx,0); 
		else if(cmpYamlValue("OtherUserSaveDataId3",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.OtherUserSaveDataId3,"OtherUserSaveDataId3",ctx,0); 
		else if(cmpYamlValue("ExtSaveDataId",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.ExtSaveDataId,"ExtSaveDataId",ctx,0); 
		else if(cmpYamlValue("AffinityMask",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.AffinityMask,"AffinityMask",ctx,0); 
		else if(cmpYamlValue("DescVersion",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.DescVersion,"DescVersion",ctx,0); 
		else if(cmpYamlValue("ResourceLimitCategory",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.ResourceLimitCategory,"ResourceLimitCategory",ctx,0); 		
		else if(cmpYamlValue("ReleaseKernelMajor",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.ReleaseKernelMajor,"ReleaseKernelMajor",ctx,0);
		else if(cmpYamlValue("ReleaseKernelMinor",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.ReleaseKernelMinor,"ReleaseKernelMinor",ctx,0); 
		else if(cmpYamlValue("MaxCpu",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.MaxCpu,"MaxCpu",ctx,0); 

		
		else if(cmpYamlValue("MemoryMapping",ctx)) rsf->AccessControlInfo.MemoryMappingNum = SetYAMLSequence(&rsf->AccessControlInfo.MemoryMapping,"MemoryMapping",ctx);
		else if(cmpYamlValue("IORegisterMapping",ctx)) rsf->AccessControlInfo.IORegisterMappingNum = SetYAMLSequence(&rsf->AccessControlInfo.IORegisterMapping,"IORegisterMapping",ctx);
		else if(cmpYamlValue("FileSystemAccess",ctx)) rsf->AccessControlInfo.FileSystemAccessNum = SetYAMLSequence(&rsf->AccessControlInfo.FileSystemAccess,"FileSystemAccess",ctx);
		else if(cmpYamlValue("IoAccessControl",ctx)) rsf->AccessControlInfo.IoAccessControlNum = SetYAMLSequence(&rsf->AccessControlInfo.IoAccessControl,"IoAccessControl",ctx);
		else if(cmpYamlValue("InterruptNumbers",ctx)) rsf->AccessControlInfo.InterruptNumbersNum = SetYAMLSequence(&rsf->AccessControlInfo.InterruptNumbers,"InterruptNumbers",ctx);
		else if(cmpYamlValue("SystemCallAccess",ctx)) rsf->AccessControlInfo.SystemCallAccessNum = SetYAMLSequenceFromMapping(&rsf->AccessControlInfo.SystemCallAccess,"SystemCallAccess",ctx,false);
		else if(cmpYamlValue("ServiceAccessControl",ctx)) rsf->AccessControlInfo.ServiceAccessControlNum = SetYAMLSequence(&rsf->AccessControlInfo.ServiceAccessControl,"ServiceAccessControl",ctx);
		else if(cmpYamlValue("AccessibleSaveDataIds",ctx)) rsf->AccessControlInfo.AccessibleSaveDataIdsNum = SetYAMLSequence(&rsf->AccessControlInfo.AccessibleSaveDataIds,"AccessibleSaveDataIds",ctx);

		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_SystemControlInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("AppType",ctx)) SetSimpleYAMLValue(&rsf->SystemControlInfo.AppType,"AppType",ctx,0);
		else if(cmpYamlValue("StackSize",ctx)) SetSimpleYAMLValue(&rsf->SystemControlInfo.StackSize,"StackSize",ctx,0);
		else if(cmpYamlValue("RemasterVersion",ctx)) SetSimpleYAMLValue(&rsf->SystemControlInfo.RemasterVersion,"RemasterVersion",ctx,0);
		else if(cmpYamlValue("JumpId",ctx)) SetSimpleYAMLValue(&rsf->SystemControlInfo.JumpId,"JumpId",ctx,0);
		else if(cmpYamlValue("SaveDataSize",ctx)) SetSimpleYAMLValue(&rsf->SystemControlInfo.SaveDataSize,"SaveDataSize",ctx,0);
		else if(cmpYamlValue("Dependency",ctx)) rsf->SystemControlInfo.DependencyNum = SetYAMLSequenceFromMapping(&rsf->SystemControlInfo.Dependency,"Dependency",ctx,false);
		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_BasicInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		if(cmpYamlValue("Title",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.Title,"Title",ctx,0);
		else if(cmpYamlValue("CompanyCode",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.CompanyCode,"CompanyCode",ctx,0);
		else if(cmpYamlValue("ProductCode",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.ProductCode,"ProductCode",ctx,0);
		else if(cmpYamlValue("ContentType",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.ContentType,"ContentType",ctx,0);
		else if(cmpYamlValue("Logo",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.Logo,"Logo",ctx,0);
		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_RomFs(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("RootPath",ctx)) SetSimpleYAMLValue(&rsf->RomFs.RootPath,"RootPath",ctx,0);
		
		else if(cmpYamlValue("DefaultReject",ctx)) rsf->RomFs.DefaultRejectNum = SetYAMLSequence(&rsf->RomFs.DefaultReject,"DefaultReject",ctx);
		else if(cmpYamlValue("Reject",ctx)) rsf->RomFs.RejectNum = SetYAMLSequence(&rsf->RomFs.Reject,"Reject",ctx);
		else if(cmpYamlValue("Include",ctx)) rsf->RomFs.IncludeNum = SetYAMLSequence(&rsf->RomFs.Include,"Include",ctx);
		else if(cmpYamlValue("File",ctx)) rsf->RomFs.FileNum = SetYAMLSequence(&rsf->RomFs.File,"File",ctx);
		
		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_TitleInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if (cmpYamlValue("Platform", ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.Platform, "Platform", ctx, 0);
		else if(cmpYamlValue("Category",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.Category,"Category",ctx,0);
		else if(cmpYamlValue("UniqueId",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.UniqueId,"UniqueId",ctx,0);
		else if(cmpYamlValue("Version",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.Version,"Version",ctx,0);
		else if(cmpYamlValue("ContentsIndex",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.ContentsIndex,"ContentsIndex",ctx,0);
		else if(cmpYamlValue("Variation",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.Variation,"Variation",ctx,0);
		else if(cmpYamlValue("ChildIndex",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.ChildIndex,"ChildIndex",ctx,0);
		else if(cmpYamlValue("DemoIndex",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.DemoIndex,"DemoIndex",ctx,0);
		else if(cmpYamlValue("TargetCategory",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.TargetCategory,"TargetCategory",ctx,0);
		
		else if(cmpYamlValue("CategoryFlags",ctx)) rsf->TitleInfo.CategoryFlagsNum = SetYAMLSequence(&rsf->TitleInfo.CategoryFlags,"CategoryFlags",ctx);
		
		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_CardInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("WritableAddress",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.WritableAddress,"WritableAddress",ctx,0);
		else if(cmpYamlValue("CardType",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.CardType,"CardType",ctx,0);
		else if(cmpYamlValue("CryptoType",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.CryptoType,"CryptoType",ctx,0);
		else if(cmpYamlValue("CardDevice",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.CardDevice,"CardDevice",ctx,0);
		else if(cmpYamlValue("MediaType",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.MediaType,"MediaType",ctx,0);
		else if(cmpYamlValue("MediaSize",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.MediaSize,"MediaSize",ctx,0);
		else if(cmpYamlValue("BackupWriteWaitTime",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.BackupWriteWaitTime,"BackupWriteWaitTime",ctx,0);
		else if(cmpYamlValue("SaveCrypto",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.SaveCrypto,"SaveCrypto",ctx,0);

		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_CommonHeaderKey(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	rsf->CommonHeaderKey.Found = true;
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("D",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.D,"D",ctx,0); 
		else if(cmpYamlValue("P",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.P,"P",ctx,0); 
		else if(cmpYamlValue("Q",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.Q,"Q",ctx,0); 
		else if(cmpYamlValue("DP",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.DP,"DP",ctx,0); 
		else if(cmpYamlValue("DQ",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.DQ,"DQ",ctx,0); 
		else if(cmpYamlValue("InverseQ",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.InverseQ,"InverseQ",ctx,0); 
		else if(cmpYamlValue("Modulus",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.Modulus,"Modulus",ctx,0); 
		else if(cmpYamlValue("Exponent",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.Exponent,"Exponent",ctx,0); 
		else if(cmpYamlValue("Signature",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.AccCtlDescSign,"Signature",ctx,0); 
		else if(cmpYamlValue("Descriptor",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.AccCtlDescBin,"Descriptor",ctx,0);

		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void free_RsfSettings(rsf_settings *set)
{
	//AccessControlInfo
	free(set->AccessControlInfo.IdealProcessor);
	free(set->AccessControlInfo.Priority);
	free(set->AccessControlInfo.MemoryType);
	free(set->AccessControlInfo.SystemMode);
	free(set->AccessControlInfo.SystemModeExt);
	free(set->AccessControlInfo.CpuSpeed);
	free(set->AccessControlInfo.CoreVersion);
	free(set->AccessControlInfo.HandleTableSize);
	free(set->AccessControlInfo.SystemSaveDataId1);
	free(set->AccessControlInfo.SystemSaveDataId2);
	free(set->AccessControlInfo.OtherUserSaveDataId1);
	free(set->AccessControlInfo.OtherUserSaveDataId2);
	free(set->AccessControlInfo.OtherUserSaveDataId3);
	free(set->AccessControlInfo.ExtSaveDataId);	
	free(set->AccessControlInfo.AffinityMask);
	free(set->AccessControlInfo.DescVersion);
	free(set->AccessControlInfo.ResourceLimitCategory);
	free(set->AccessControlInfo.ReleaseKernelMajor);
	free(set->AccessControlInfo.ReleaseKernelMinor);
	free(set->AccessControlInfo.MaxCpu);

	for(u32 i = 0; i < set->AccessControlInfo.MemoryMappingNum; i++){
		free(set->AccessControlInfo.MemoryMapping[i]);
	}
	free(set->AccessControlInfo.MemoryMapping);
	
	for(u32 i = 0; i < set->AccessControlInfo.IORegisterMappingNum; i++){
		free(set->AccessControlInfo.IORegisterMapping[i]);
	}
	free(set->AccessControlInfo.IORegisterMapping);
	
	for(u32 i = 0; i < set->AccessControlInfo.FileSystemAccessNum; i++){
		free(set->AccessControlInfo.FileSystemAccess[i]);
	}
	free(set->AccessControlInfo.FileSystemAccess);
	
	for(u32 i = 0; i < set->AccessControlInfo.IoAccessControlNum; i++){
		free(set->AccessControlInfo.IoAccessControl[i]);
	}
	free(set->AccessControlInfo.IoAccessControl);
	
	for(u32 i = 0; i < set->AccessControlInfo.InterruptNumbersNum; i++){
		free(set->AccessControlInfo.InterruptNumbers[i]);
	}
	free(set->AccessControlInfo.InterruptNumbers);
	
	for(u32 i = 0; i < set->AccessControlInfo.SystemCallAccessNum; i++){
		free(set->AccessControlInfo.SystemCallAccess[i]);
	}
	free(set->AccessControlInfo.SystemCallAccess);
	
	for(u32 i = 0; i < set->AccessControlInfo.ServiceAccessControlNum; i++){
		free(set->AccessControlInfo.ServiceAccessControl[i]);
	}
	free(set->AccessControlInfo.ServiceAccessControl);

	for(u32 i = 0; i < set->AccessControlInfo.AccessibleSaveDataIdsNum; i++){
		free(set->AccessControlInfo.AccessibleSaveDataIds[i]);
	}
	free(set->AccessControlInfo.AccessibleSaveDataIds);
	
	//SystemControlInfo
	free(set->SystemControlInfo.AppType);
	free(set->SystemControlInfo.StackSize);
	free(set->SystemControlInfo.RemasterVersion);
	free(set->SystemControlInfo.SaveDataSize);
	free(set->SystemControlInfo.JumpId);
	
	for(u32 i = 0; i < set->SystemControlInfo.DependencyNum; i++){
		free(set->SystemControlInfo.Dependency[i]);
	}
	free(set->SystemControlInfo.Dependency);
	
	//BasicInfo
	free(set->BasicInfo.Title);
	free(set->BasicInfo.CompanyCode);
	free(set->BasicInfo.ProductCode);
	free(set->BasicInfo.ContentType);
	free(set->BasicInfo.Logo);
	
	//Rom
	free(set->RomFs.RootPath);
	
	for(u32 i = 0; i < set->RomFs.DefaultRejectNum; i++){
		free(set->RomFs.DefaultReject[i]);
	}
	free(set->RomFs.DefaultReject);
	
	for(u32 i = 0; i < set->RomFs.RejectNum; i++){
		free(set->RomFs.Reject[i]);
	}
	free(set->RomFs.Reject);
	
	for(u32 i = 0; i < set->RomFs.IncludeNum; i++){
		free(set->RomFs.Include[i]);
	}
	free(set->RomFs.Include);
	
	for(u32 i = 0; i < set->RomFs.FileNum; i++){
		free(set->RomFs.File[i]);
	}
	free(set->RomFs.File);
	
	//TitleInfo
	free(set->TitleInfo.Platform);
	free(set->TitleInfo.Category);
	free(set->TitleInfo.UniqueId);
	free(set->TitleInfo.Version);
	free(set->TitleInfo.ContentsIndex);
	free(set->TitleInfo.Variation);
	free(set->TitleInfo.ChildIndex);
	free(set->TitleInfo.DemoIndex);
	free(set->TitleInfo.TargetCategory);
	
	for(u32 i = 0; i < set->TitleInfo.CategoryFlagsNum; i++){
		free(set->TitleInfo.CategoryFlags[i]);
	}
	free(set->TitleInfo.CategoryFlags);
	
	//CardInfo
	free(set->CardInfo.WritableAddress);
	free(set->CardInfo.CardType);
	free(set->CardInfo.CryptoType);
	free(set->CardInfo.CardDevice);
	free(set->CardInfo.MediaType);
	free(set->CardInfo.MediaSize);
	free(set->CardInfo.BackupWriteWaitTime);
	free(set->CardInfo.SaveCrypto);

	//CommonHeaderKey
	free(set->CommonHeaderKey.D);
	free(set->CommonHeaderKey.P);
	free(set->CommonHeaderKey.Q);
	free(set->CommonHeaderKey.DP);
	free(set->CommonHeaderKey.DQ);
	free(set->CommonHeaderKey.InverseQ);
	free(set->CommonHeaderKey.Modulus);
	free(set->CommonHeaderKey.Exponent);
	free(set->CommonHeaderKey.AccCtlDescSign);
	free(set->CommonHeaderKey.AccCtlDescBin);
}