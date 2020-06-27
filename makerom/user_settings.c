#include "lib.h"

// Private Prototypes
void DisplayHelp(char *app_name);
void DisplayExtendedHelp(char *app_name);
void SetDefaults(user_settings *set);
int SetArgument(int argc, int i, char *argv[], user_settings *set);
int CheckArgumentCombination(user_settings *set);
const char* GetOutputExtention(u8 file_type);
void PrintNeedsArg(char *arg);
void PrintArgInvalid(char *arg);
void PrintArgReqParam(char *arg, u32 paramNum);
void PrintNoNeedParam(char *arg);

int ParseArgs(int argc, char *argv[], user_settings *set)
{
	if (argv == NULL || set == NULL)
		return USR_PTR_PASS_FAIL;

	if (argc < 2) {
		DisplayHelp(argv[0]);
		return USR_HELP;
	}

	// Detecting Help Requried
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-help") == 0) {
			DisplayHelp(argv[0]);
			return USR_HELP;
		}
		else if (strcmp(argv[i], "-exthelp") == 0) {
			DisplayExtendedHelp(argv[0]);
			return USR_HELP;
		}
	}

	// Allocating Memory for Content Path Ptrs
	set->common.contentPath = calloc(CIA_MAX_CONTENT, sizeof(char*));
	if (set->common.contentPath == NULL) {
		fprintf(stderr, "[SETTING ERROR] Not Enough Memory\n");
		return USR_MEM_ERROR;
	}
	// Initialise Content Path Ptrs to NULL
	for (size_t i = 0; i < CIA_MAX_CONTENT; i++)
	{
		set->common.contentPath[i] = NULL;
	}

	// Initialise Keys
	InitKeys(&set->common.keys);

	// Setting Defaults
	SetDefaults(set);

	// Parsing Arguments
	int set_result;
	for (int i = 1; i < argc; i += set_result) {
		set_result = SetArgument(argc, i, argv, set);
		if (set_result < 1) {
			fprintf(stderr, "[RESULT] Invalid arguments, see '%s -help'\n", argv[0]);
			return set_result;
		}
	}

	// Checking arguments
	if ((set_result = CheckArgumentCombination(set)) != 0)
		return set_result;

	// Setting Keys
	if ((set_result = SetKeys(&set->common.keys)) != 0)
		return set_result;

	// Generating outpath if required
	if (!set->common.outFileName) {
		char *source_path = NULL;
		if (set->ncch.buildNcch0)
			source_path = set->common.rsfPath;
		else if (set->common.workingFileType == infile_ncsd || set->common.workingFileType == infile_cia || set->common.workingFileType == infile_srl)
			source_path = set->common.workingFilePath;
		else
			source_path = set->common.contentPath[0];
		set->common.outFileName_mallocd = true;
		set->common.outFileName = replace_filextention(source_path, GetOutputExtention(set->common.outFormat));
	}
	return 0;
}

void SetDefaults(user_settings *set)
{
	// Target Info
	set->common.keys.keyset = pki_TEST;
	set->common.keys.accessDescSign.presetType = desc_NotSpecified;
	set->common.keys.ignore_sign = false;

	// Build NCCH Info
	set->ncch.useSecCrypto = true;
	set->ncch.keyXID = 0;
	set->ncch.buildNcch0 = true;
	set->ncch.includeExefsLogo = false;
	set->common.outFormat = NCCH;
	set->ncch.ncchType = format_not_set;
	set->ncch.noCodePadding = false;

	// RSF Settings
	clrmem(&set->common.rsfSet, sizeof(rsf_settings));
	set->common.rsfSet.Option.EnableCompress = true;
	set->common.rsfSet.Option.EnableCrypt = false;
	set->common.rsfSet.Option.UseOnSD = false;
	set->common.rsfSet.Option.FreeProductCode = false;

	// Working File Info
	set->common.workingFileType = infile_ncch;

	// CCI Info
	set->cci.useSDKStockData = false;

	// CIA Info
	set->cia.includeUpdateNcch = false;
	set->cia.deviceId = 0;
	set->cia.eshopAccId = 0;
	set->cia.useDataTitleVer = false;
	set->cia.useFullTitleVer = false;
	set->cia.randomTitleKey = false;
	set->common.keys.aes.currentCommonKey = 0;
	for (int i = 0; i < CIA_MAX_CONTENT; i++)
		set->cia.contentId[i] = MAX_U32 + 1; // invalid so changes can be detected
}

int SetArgument(int argc, int i, char *argv[], user_settings *set)
{
	u16 ParamNum = 0;
	for (int j = i + 1; j < argc && argv[j][0] != '-'; j++)
		ParamNum++;

	// Global Settings
	if (strcmp(argv[i], "-rsf") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->common.rsfPath = argv[i + 1];
		return 2;
	}
	else if (strcmp(argv[i], "-f") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		if (strcasecmp(argv[i + 1], "ncch") == 0 || strcasecmp(argv[i + 1], "cxi") == 0 || strcasecmp(argv[i + 1], "cfa") == 0)
			set->common.outFormat = NCCH;
		else if (strcasecmp(argv[i + 1], "cci") == 0)
			set->common.outFormat = CCI;
		else if (strcasecmp(argv[i + 1], "cia") == 0)
			set->common.outFormat = CIA;
		else {
			fprintf(stderr, "[SETTING ERROR] Invalid output format '%s'\n", argv[i + 1]);
			return USR_BAD_ARG;
		}
		return 2;
	}
	else if (strcmp(argv[i], "-o") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->common.outFileName = argv[i + 1];
		set->common.outFileName_mallocd = false;
		return 2;
	}
	else if (strcmp(argv[i], "-v") == 0) {
		if (ParamNum) {
			PrintNoNeedParam(argv[i]);
			return USR_BAD_ARG;
		}
		set->common.verbose = true;
		return 1;
	}
	// Key Options
	else if (strcmp(argv[i], "-target") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		if (strcasecmp(argv[i + 1], "test") == 0 || strcasecmp(argv[i + 1], "t") == 0) {
			set->common.keys.keyset = pki_TEST;
		}
		//else if(strcasecmp(argv[i+1],"beta") == 0 || strcasecmp(argv[i+1],"b") == 0) {
		//	set->common.keys.keyset = pki_BETA;
		//}
		else if (strcasecmp(argv[i + 1], "debug") == 0 || strcasecmp(argv[i + 1], "development") == 0 || strcasecmp(argv[i + 1], "d") == 0) {
			set->common.keys.keyset = pki_DEVELOPMENT;
		}
		else if (strcasecmp(argv[i + 1], "retail") == 0 || strcasecmp(argv[i + 1], "production") == 0 || strcasecmp(argv[i + 1], "p") == 0) {
			set->common.keys.keyset = pki_PRODUCTION;
		}
		//else if(strcasecmp(argv[i+1],"custom") == 0 || strcasecmp(argv[i+1],"c") == 0) {
		//	set->common.keys.keyset = pki_CUSTOM;
		//}
		else {
			fprintf(stderr, "[SETTING ERROR] Unrecognised target '%s'\n", argv[i + 1]);
			return USR_BAD_ARG;
		}
		return 2;
	}
	else if (strcmp(argv[i], "-ckeyid") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->common.keys.aes.currentCommonKey = strtol(argv[i + 1], NULL, 0);
		if (set->common.keys.aes.currentCommonKey > MAX_CMN_KEY)
		{
			fprintf(stderr, "[SETTING ERROR] Invalid Common Key Index: 0x%x\n", set->common.keys.aes.currentCommonKey);
			return USR_BAD_ARG;
		}
		return 2;
	}
	else if (strcmp(argv[i], "-ncchseckey") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->ncch.useSecCrypto = true;
		set->ncch.keyXID = strtol(argv[i + 1], NULL, 0);
		if (set->ncch.keyXID > MAX_NCCH_KEYX)
		{
			fprintf(stderr, "[SETTING ERROR] Invalid NCCH KeyX Index: 0x%x\n", set->ncch.keyXID);
			return USR_BAD_ARG;
		}
		return 2;
	}
	else if (strcmp(argv[i], "-showkeys") == 0) {
		if (ParamNum) {
			PrintNoNeedParam(argv[i]);
			return USR_BAD_ARG;
		}
		set->common.keys.dumpkeys = true;
		return 1;
	}
	else if (strcmp(argv[i], "-ignoresign") == 0) {
		if (ParamNum) {
			PrintNoNeedParam(argv[i]);
			return USR_BAD_ARG;
		}
		set->common.keys.ignore_sign = true;
		return 1;
	}

	// Ncch Options
	else if (strcmp(argv[i], "-elf") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->ncch.elfPath = argv[i + 1];
		set->ncch.ncchType |= CXI;
		return 2;
	}

	else if (strcmp(argv[i], "-icon") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->ncch.iconPath = argv[i + 1];
		set->ncch.ncchType |= CFA;
		return 2;
	}
	else if (strcmp(argv[i], "-banner") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->ncch.bannerPath = argv[i + 1];
		set->ncch.ncchType |= CFA;
		return 2;
	}
	else if (strcmp(argv[i], "-logo") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->ncch.logoPath = argv[i + 1];
		set->ncch.ncchType |= CFA;
		return 2;
	}
	else if (strcmp(argv[i], "-desc") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		char *tmp = argv[i + 1];
		char *tmp2 = strstr(tmp, ":");
		if (!tmp2) {
			fprintf(stderr, "[SETTING ERROR] Bad argument '%s %s', correct format:\n", argv[i], argv[i + 1]);
			fprintf(stderr, "	-desc <APP TYPE>:<TARGET FIRMWARE>\n");
		}
		if (strlen(tmp2) < 2) {
			fprintf(stderr, "[SETTING ERROR] Bad argument '%s %s', correct format:\n", argv[i], argv[i + 1]);
			fprintf(stderr, "	-desc <APP TYPE>:<TARGET FIRMWARE>\n");
		}

		u32 app_type_len = (u32)(tmp2 - tmp);
		char *app_type = calloc(app_type_len + 1, sizeof(char));
		memcpy(app_type, tmp, app_type_len);

		if (strcasecmp(app_type, "App") == 0 || strcasecmp(app_type, "SDApp") == 0) set->common.keys.accessDescSign.presetType = desc_Application;
		else if (strcasecmp(app_type, "ECApp") == 0) set->common.keys.accessDescSign.presetType = desc_EcApplication;
		else if (strcasecmp(app_type, "Demo") == 0) set->common.keys.accessDescSign.presetType = desc_Demo;
		else if (strcasecmp(app_type, "DlpChild") == 0 || strcasecmp(app_type, "Dlp") == 0) set->common.keys.accessDescSign.presetType = desc_DlpChild;
		else if (strcasecmp(app_type, "ExtApp") == 0) set->common.keys.accessDescSign.presetType = desc_ExtApplication;
		else if (strcasecmp(app_type, "ExtDemo") == 0) set->common.keys.accessDescSign.presetType = desc_ExtDemo;
		else if (strcasecmp(app_type, "ExtDlpChild") == 0 || strcasecmp(app_type, "ExtDlp") == 0) set->common.keys.accessDescSign.presetType = desc_ExtDlpChild;
		else {
			fprintf(stderr, "[SETTING ERROR] Accessdesc AppType preset '%s' not valid, please manually configure RSF\n", app_type);
			return USR_BAD_ARG;
		}


		char *target_firmware = (tmp2 + 1);
		set->common.keys.accessDescSign.targetFirmware = strtoul(target_firmware, NULL, 0);
		switch (set->common.keys.accessDescSign.targetFirmware) {
		case 1:
			set->common.keys.accessDescSign.targetFirmware = 0x1B; // or 0x1C
			break;
		case 2:
			set->common.keys.accessDescSign.targetFirmware = 0x1D; // or 0x1E/0x1F
			break;
		case 3:
			set->common.keys.accessDescSign.targetFirmware = 0x20;
			break;
		case 4:
			set->common.keys.accessDescSign.targetFirmware = 0x21; // or 0x22
			break;
		case 5:
			set->common.keys.accessDescSign.targetFirmware = 0x23; // or 0x24
			break;
		case 6:
			set->common.keys.accessDescSign.targetFirmware = 0x25; // or 0x26
			break;
		case 7:
			set->common.keys.accessDescSign.targetFirmware = 0x27; // or 0x28
			break;
		case 8:
			set->common.keys.accessDescSign.targetFirmware = 0x2C;
			break;
		default:
			break;
		}

		set->ncch.ncchType |= CXI;
		return 2;
	}
	else if (strcmp(argv[i], "-exefslogo") == 0) {
		if (ParamNum) {
			PrintNoNeedParam(argv[i]);
			return USR_BAD_ARG;
		}
		set->ncch.includeExefsLogo = true;
		set->ncch.ncchType |= CFA;
		return 1;
	}
	else if (strcmp(argv[i], "-nocodepadding") == 0) {
		if (ParamNum) {
			PrintNoNeedParam(argv[i]);
			return USR_BAD_ARG;
		}
		set->ncch.noCodePadding = true;
		return 1;
	}

	// Ncch Rebuild Options
	else if (strcmp(argv[i], "-code") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->ncch.codePath = argv[i + 1];
		set->ncch.ncchType |= CXI;
		return 2;
	}
	else if (strcmp(argv[i], "-exheader") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->ncch.exheaderPath = argv[i + 1];
		set->ncch.ncchType |= CXI;
		return 2;
	}
	else if (strcmp(argv[i], "-plainrgn") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->ncch.plainRegionPath = argv[i + 1];
		set->ncch.ncchType |= CXI;
		return 2;
	}
	else if (strcmp(argv[i], "-romfs") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->ncch.romfsPath = argv[i + 1];
		set->ncch.ncchType |= CFA;
		return 2;
	}
	// Cci Options
	else if (strcmp(argv[i], "-devcci") == 0) {
		if (ParamNum) {
			PrintNoNeedParam(argv[i]);
			return USR_BAD_ARG;
		}
		set->cci.useSDKStockData = true;
		return 1;
	}
	else if (strcmp(argv[i], "-nomodtid") == 0) {
		if (ParamNum) {
			PrintNoNeedParam(argv[i]);
			return USR_BAD_ARG;
		}
		set->cci.dontModifyNcchTitleID = true;
		return 1;
	}
	else if (strcmp(argv[i], "-alignwr") == 0) {
		if (ParamNum) {
			PrintNoNeedParam(argv[i]);
			return USR_BAD_ARG;
		}
		set->cci.closeAlignWritableRegion = true;
		return 1;
	}
	else if (strcmp(argv[i], "-cverinfo") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_BAD_ARG;
		}
		char *pos = strstr(argv[i + 1], ":");
		if (!pos || strlen(pos) < 2) {
			fprintf(stderr, "[SETTING ERROR] Bad argument '%s %s', correct format:\n", argv[i], argv[i + 1]);
			fprintf(stderr, "	%s <DATA PATH>:<'cia'/'tmd'>\n", argv[i]);
			return USR_BAD_ARG;
		}

		char *dtype = pos + 1;
		if (strcasecmp(dtype, "tmd") == 0)
			set->cci.cverDataType = CVER_DTYPE_TMD;
		else if (strcasecmp(dtype, "cia") == 0)
			set->cci.cverDataType = CVER_DTYPE_CIA;
		else {
			fprintf(stderr, "[SETTING ERROR] Unrecognised cver data type:\"%s\"\n", dtype);
			return USR_BAD_ARG;
		}

		u32 path_len = (pos - argv[i + 1]) + 1;
		set->cci.cverDataPath = calloc(path_len, sizeof(char));
		strncpy(set->cci.cverDataPath, argv[i + 1], path_len - 1);

		if (!AssertFile(set->cci.cverDataPath)) {
			fprintf(stderr, "[SETTING ERROR] Failed to open '%s'\n", set->cci.cverDataPath);
			return USR_BAD_ARG;
		}

		return 2;
	}

	// Cia Options
	else if (strcmp(argv[i], "-ver") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->cia.useFullTitleVer = true;
		u32 ver = strtoul(argv[i + 1], NULL, 0);
		if (ver > VER_MAX) {
			fprintf(stderr, "[SETTING ERROR] Version: '%d' is too large, max: '%d'\n", ver, VER_MAX);
			return USR_BAD_ARG;
		}
		set->cia.titleVersion[VER_MAJOR] = (ver >> 10) & VER_MAJOR_MAX;
		set->cia.titleVersion[VER_MINOR] = (ver >> 4) & VER_MINOR_MAX;
		set->cia.titleVersion[VER_MICRO] = ver & VER_MICRO_MAX;
		return 2;
	}
	else if (strcmp(argv[i], "-major") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->cia.useNormTitleVer = true;
		u32 ver = strtoul(argv[i + 1], NULL, 0);
		if (ver > VER_MAJOR_MAX) {
			fprintf(stderr, "[SETTING ERROR] Major version: '%d' is too large, max: '%d'\n", ver, VER_MAJOR_MAX);
			return USR_BAD_ARG;
		}
		set->cia.titleVersion[VER_MAJOR] = ver;
		return 2;
	}
	else if (strcmp(argv[i], "-minor") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->cia.useNormTitleVer = true;
		u32 ver = strtoul(argv[i + 1], NULL, 0);
		if (ver > VER_MINOR_MAX) {
			fprintf(stderr, "[SETTING ERROR] Minor version: '%d' is too large, max: '%d'\n", ver, VER_MINOR_MAX);
			return USR_BAD_ARG;
		}
		set->cia.titleVersion[VER_MINOR] = ver;
		return 2;
	}
	else if (strcmp(argv[i], "-micro") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->cia.useFullTitleVer = true;
		set->cia.useNormTitleVer = false;
		u32 ver = strtoul(argv[i + 1], NULL, 0);
		if (ver > VER_MICRO_MAX) {
			fprintf(stderr, "[SETTING ERROR] Micro version: '%d' is too large, max: '%d'\n", ver, VER_MICRO_MAX);
			return USR_BAD_ARG;
		}
		set->cia.titleVersion[VER_MICRO] = ver;
		return 2;
	}
	else if (strcmp(argv[i], "-dver") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->cia.useDataTitleVer = true;
		u32 ver = strtoul(argv[i + 1], NULL, 0);
		if (ver > VER_DVER_MAX) {
			fprintf(stderr, "[SETTING ERROR] Data version: '%d' is too large, max: '%d'\n", ver, VER_DVER_MAX);
			return USR_BAD_ARG;
		}
		set->cia.titleVersion[VER_MAJOR] = (ver >> 6) & VER_MAJOR_MAX;
		set->cia.titleVersion[VER_MINOR] = ver & VER_MINOR_MAX;
		return 2;
	}
	else if (strcmp(argv[i], "-deviceid") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->cia.deviceId = strtoul(argv[i + 1], NULL, 16);
		return 2;
	}
	else if (strcmp(argv[i], "-esaccid") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->cia.eshopAccId = strtoul(argv[i + 1], NULL, 16);
		return 2;
	}
	else if (strcmp(argv[i], "-rand") == 0) {
		if (ParamNum) {
			PrintNoNeedParam(argv[i]);
			return USR_BAD_ARG;
		}
		set->cia.randomTitleKey = true;
		return 1;
	}
	else if (strcmp(argv[i], "-dlc") == 0) {
		if (ParamNum) {
			PrintNoNeedParam(argv[i]);
			return USR_BAD_ARG;
		}
		set->cia.DlcContent = true;
		return 1;
	}
	else if (strcmp(argv[i], "-srl") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->ncch.buildNcch0 = false;
		set->common.workingFileType = infile_srl;
		set->common.workingFilePath = argv[i + 1];
		set->common.outFormat = CIA;
		return 2;

	}

	// Ncch Container Conversion
	else if (strcmp(argv[i], "-ccitocia") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->ncch.buildNcch0 = false;
		set->common.workingFileType = infile_ncsd;
		set->common.workingFilePath = argv[i + 1];
		set->common.outFormat = CIA;
		return 2;
	}
	else if (strcmp(argv[i], "-ciatocci") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		set->ncch.buildNcch0 = false;
		set->common.workingFileType = infile_cia;
		set->common.workingFilePath = argv[i + 1];
		set->common.outFormat = CCI;
		return 2;
	}
	else if (strcmp(argv[i], "-inclupd") == 0) {
		if (ParamNum) {
			PrintNoNeedParam(argv[i]);
			return USR_BAD_ARG;
		}
		set->cia.includeUpdateNcch = true;
		return 1;
	}

	// Other Setting
	else if (strcmp(argv[i], "-content") == 0 || strcmp(argv[i], "-i") == 0) {
		if (ParamNum != 1) {
			PrintArgReqParam(argv[i], 1);
			return USR_ARG_REQ_PARAM;
		}
		int count = 0;
		char *pos = argv[i + 1];
		while ((pos = strstr(pos + 1, ":")))
			count++;

		pos = argv[i + 1];
		while (count-- > 1)
			pos = strstr(pos + 1, ":");

		if (!pos || strlen(pos) < 2) {
			fprintf(stderr, "[SETTING ERROR] Bad argument '%s %s', correct format:\n", argv[i], argv[i + 1]);
			fprintf(stderr, "	%s <CONTENT PATH>:<INDEX>\n", argv[i]);
			fprintf(stderr, "  If generating a CIA, then use the format:\n");
			fprintf(stderr, "	%s <CONTENT PATH>:<INDEX>:<ID>\n", argv[i]);
			return USR_BAD_ARG;
		}

		/* Getting Content Index */
		u16 content_index = strtol((char*)(pos + 1), NULL, 0);

		/* Storing Content Filepath */
		u32 path_len = (u32)(pos - argv[i + 1]) + 1;

		if (set->common.contentPath[content_index] != NULL) {
			fprintf(stderr, "[SETTING ERROR] Content %d is already specified\n", content_index);
			return USR_BAD_ARG;
		}
		set->common.contentPath[content_index] = calloc(path_len, sizeof(char));
		if (set->common.contentPath[content_index] == NULL) {
			fprintf(stderr, "[SETTING ERROR] Not enough memory\n");
			return USR_MEM_ERROR;
		}
		strncpy(set->common.contentPath[content_index], argv[i + 1], path_len - 1);
		if (!AssertFile(set->common.contentPath[content_index])) {
			fprintf(stderr, "[SETTING ERROR] '%s' could not be opened\n", set->common.contentPath[content_index]);
			return USR_BAD_ARG;
		}
		set->common.contentSize[content_index] = GetFileSize64(set->common.contentPath[content_index]);

		/* Get ContentID for CIA gen */
		char *pos2 = strstr(pos + 1, ":");
		if (pos2)
			set->cia.contentId[content_index] = strtoul((pos2 + 1), NULL, 0);

		/* Return Next Arg Pos*/
		return 2;
	}
	// RSF Value Substitution
	else if (strncmp(argv[i], "-D", 2) == 0) {
		if (ParamNum) {
			PrintNoNeedParam("-DNAME=VALUE");
			return USR_BAD_ARG;
		}
		if (set->dname.m_items == 0) {
			set->dname.m_items = 10;
			set->dname.u_items = 0;
			set->dname.items = calloc(set->dname.m_items, sizeof(dname_item));
			if (!set->dname.items) {
				fprintf(stderr, "[SETTING ERROR] Not enough memory\n");
				return MEM_ERROR;
			}
		}
		else if (set->dname.m_items == set->dname.u_items) {
			set->dname.m_items *= 2;
			set->dname.items = realloc(set->dname.items, sizeof(dname_item)*set->dname.m_items);
			if (!set->dname.items) {
				fprintf(stderr, "[SETTING ERROR] Not enough memory\n");
				return MEM_ERROR;
			}
		}

		char *name_pos = (char*)(argv[i] + 2);
		u32 name_len = 0;
		char *val_pos = strstr(name_pos, "=");
		u32 val_len = 0;
		if (!val_pos) {
			fprintf(stderr, "[SETTING ERROR] Format: '%s' is invalid\n", argv[i]);
			return USR_BAD_ARG;
		}
		if (strlen(val_pos) < 2) {
			fprintf(stderr, "[SETTING ERROR] Format: '%s' is invalid\n", argv[i]);
			return USR_BAD_ARG;
		}
		val_pos = (val_pos + 1);
		name_len = (val_pos - 1 - name_pos);
		set->dname.items[set->dname.u_items].name = calloc(name_len + 1, sizeof(char));
		memcpy(set->dname.items[set->dname.u_items].name, name_pos, name_len);

		val_len = strlen(val_pos);
		set->dname.items[set->dname.u_items].value = calloc(val_len + 1, sizeof(char));
		memcpy(set->dname.items[set->dname.u_items].value, val_pos, val_len);

		set->dname.u_items++;

		return 1;
	}


	// If not a valid argument
	fprintf(stderr, "[SETTING ERROR] Unrecognised argument '%s'\n", argv[i]);
	return USR_UNK_ARG;
}

int CheckArgumentCombination(user_settings *set)
{
	// If content 0 was not specified (and a special file aka SRL,CIA,CCI was not specified), we must build it (a NCCH file)
	if (set->common.contentPath[0] == NULL && set->common.workingFilePath == NULL) {
		set->ncch.buildNcch0 = true;
		// A CXI can contain elements of a CFA, but not the other way round.
		if (set->ncch.ncchType & CXI)
			set->ncch.ncchType = CXI;
		else
			set->ncch.ncchType = CFA;

		// If we are creating a NCCH file (as opposed to CIA/CCI), specify which NCCH type is the output format
		if (set->common.outFormat == NCCH) 
			set->common.outFormat = set->ncch.ncchType;
	}
	else {
		set->ncch.buildNcch0 = false;
		set->ncch.ncchType = 0;
	}

	for (int i = 0; i < CIA_MAX_CONTENT; i++) {
		if (i > CCI_MAX_CONTENT - 1 && set->common.contentPath[i] && set->common.outFormat == CCI) {
			fprintf(stderr, "[SETTING ERROR] Content indexes > %d are invalid for CCI\n", CCI_MAX_CONTENT - 1);
			return USR_BAD_ARG;
		}
		if (set->common.contentPath[i] && (set->common.outFormat == CXI || set->common.outFormat == CFA)) {
			fprintf(stderr, "[SETTING ERROR] You cannot specify content while outputting CXI/CFA files\n");
			return USR_BAD_ARG;
		}
	}

	if (set->common.outFormat == CIA && set->cci.cverDataPath) {
		fprintf(stderr, "[SETTING ERROR] You cannot use argument \"-cverinfo\" when generating a CIA\n");
		return USR_BAD_ARG;
	}

	if (set->cia.useDataTitleVer && set->cia.useNormTitleVer) {
		fprintf(stderr, "[SETTING ERROR] Arguments \"-dver\" and \"-major\"/\"-minor\" cannot be used together\n");
		return USR_BAD_ARG;
	}

	if (set->cia.useDataTitleVer && set->cia.useFullTitleVer) {
		fprintf(stderr, "[SETTING ERROR] Arguments \"-dver\" and \"-ver\" cannot be used together\n");
		return USR_BAD_ARG;
	}

	if (set->cia.useNormTitleVer && set->cia.useFullTitleVer) {
		fprintf(stderr, "[SETTING ERROR] Arguments \"-ver\" and \"-major\"/\"-minor\" cannot be used together\n");
		return USR_BAD_ARG;
	}

	if (set->ncch.elfPath && set->ncch.codePath) {
		fprintf(stderr, "[SETTING ERROR] Arguments \"-elf\" and \"-code\" cannot be used together\n");
		return USR_BAD_ARG;
	}

	bool buildCXI = set->ncch.ncchType == CXI;
	bool buildCFA = set->ncch.ncchType == CFA;
	// Detecting Required Arguments
	if (buildCXI && !set->ncch.elfPath && !set->ncch.codePath) {
		PrintNeedsArg("-elf");
		return USR_BAD_ARG;
	}
	if ((buildCXI || buildCFA) && !set->common.rsfPath) {
		PrintNeedsArg("-rsf");
		return USR_BAD_ARG;
	}
	if (buildCXI && set->ncch.codePath && !set->ncch.exheaderPath) {
		PrintNeedsArg("-exheader");
		return USR_BAD_ARG;
	}

	// Reporting bad arguments
	if (!buildCXI && set->ncch.elfPath) {
		PrintArgInvalid("-elf");
		return USR_BAD_ARG;
	}
	if (!buildCXI && set->ncch.codePath) {
		PrintArgInvalid("-code");
		return USR_BAD_ARG;
	}
	if (!buildCXI && set->ncch.exheaderPath) {
		PrintArgInvalid("-exheader");
		return USR_BAD_ARG;
	}
	if (!buildCXI && set->ncch.plainRegionPath) {
		PrintArgInvalid("-plainrgn");
		return USR_BAD_ARG;
	}
	if (!set->ncch.buildNcch0 && set->ncch.includeExefsLogo) {
		PrintArgInvalid("-exefslogo");
		return USR_BAD_ARG;
	}
	if (!set->ncch.buildNcch0 && set->ncch.romfsPath) {
		PrintArgInvalid("-romfs");
		return USR_BAD_ARG;
	}

	return 0;
}

const char* GetOutputExtention(u8 file_type)
{
	switch (file_type) {
	case(NCCH) : return ".app";
	case(CXI) : return ".cxi";
	case(CFA) : return ".cfa";
	case(CIA) : return ".cia";
	case(CCI) : return ".cci";
	default: return ".bin";
	}
}

void init_UserSettings(user_settings *set)
{
	memset(set, 0, sizeof(user_settings));
}

void free_UserSettings(user_settings *set)
{
	// Free Content Paths
	if (set->common.contentPath) {
		for (int i = 0; i < CIA_MAX_CONTENT; i++)
			free(set->common.contentPath[i]);
		free(set->common.contentPath);
	}

	// free -DNAME=VALUE
	for (u32 i = 0; i < set->dname.u_items; i++) {
		free(set->dname.items[i].name);
		free(set->dname.items[i].value);
	}
	free(set->dname.items);

	free(set->cci.cverDataPath);

	// Free Spec File Setting
	free_RsfSettings(&set->common.rsfSet);

	// Free Key Data
	FreeKeys(&set->common.keys);

	// Free Working File
	free(set->common.workingFile.buffer);

	// Free outfile path, if malloc'd
	if (set->common.outFileName_mallocd)
		free(set->common.outFileName);

	// Clear settings
	init_UserSettings(set);

	// Free
	free(set);
}

void PrintNeedsArg(char *arg)
{
	fprintf(stderr, "[SETTING ERROR] Argument \"%s\" is required\n", arg);
}

void PrintArgInvalid(char *arg)
{
	fprintf(stderr, "[SETTING ERROR] Argument \"%s\" is invalid\n", arg);
}

void PrintArgReqParam(char *arg, u32 paramNum)
{
	if (paramNum == 1)
		fprintf(stderr, "[SETTING ERROR] \"%s\" takes one parameter\n", arg);
	else
		fprintf(stderr, "[SETTING ERROR] \"%s\" requires %d parameters\n", arg, paramNum);
}

void PrintNoNeedParam(char *arg)
{
	fprintf(stderr, "[SETTING ERROR] \"%s\" does not take a parameter\n", arg);
}

void DisplayBanner(void)
{
	printf("CTR MAKEROM v0.17.1 (C) 3DSGuy 2020\n");
	printf("Built: %s %s\n\n", __TIME__, __DATE__);
}

void DisplayHelp(char *app_name)
{
	DisplayBanner();
	printf("Usage: %s [options... ]\n", app_name);
	printf("Option          Parameter           Explanation\n");
	printf("GLOBAL OPTIONS:\n");
	printf(" -help                              Display this text\n");
	printf(" -exthelp                           Display extended usage help\n");
	printf(" -rsf           <file>              ROM Spec File (*.rsf)\n");
	printf(" -f             <ncch|cci|cia>      Output format, defaults to 'ncch'\n");
	printf(" -o             <file>              Output file\n");
	printf(" -v                                 Verbose output\n");
	printf(" -DNAME=VALUE                       Substitute values in RSF file\n");
	printf("NCCH OPTIONS:\n");
	printf(" -elf           <file>              ELF file\n");
	printf(" -icon          <file>              Icon file\n");
	printf(" -banner        <file>              Banner file\n");
	printf(" -desc          <apptype>:<fw>      Specify Access Descriptor template\n");
	printf("NCCH REBUILD OPTIONS:\n");
	printf(" -code          <file>              Decompressed ExeFS \".code\"\n");
	printf(" -exheader      <file>              Exheader template\n");
	printf(" -romfs         <file>              RomFS binary\n");
	printf("CIA/CCI OPTIONS:\n");
	printf(" -content       <file>:<index>      Specify content files\n");
	printf(" -ver           <version>           Title Version\n");
}

void DisplayExtendedHelp(char *app_name)
{
	DisplayBanner();
	printf("Usage: %s [options... ]\n", app_name);
	printf("Option          Parameter           Explanation\n");
	printf("GLOBAL OPTIONS:\n");
	printf(" -help                              Display simple usage help\n");
	printf(" -exthelp                           Display this text\n");
	printf(" -rsf           <file>              ROM Spec File (*.rsf)\n");
	printf(" -f             <ncch|cci|cia>      Output format, defaults to 'ncch'\n");
	printf(" -o             <file>              Output file\n");
	printf(" -v                                 Verbose output\n");
	printf(" -DNAME=VALUE                       Substitute values in RSF file\n");
	printf("KEY OPTIONS:\n");
	printf(" -target        <t|d|p>             Target for crypto, defaults to 't'\n");
	printf("                                    't' Test(false) Keys & prod Certs\n");
	printf("                                    'd' Development Keys & Certs\n");
	printf("                                    'p' Production Keys & Certs\n");
	printf(" -ckeyid        <index>             Ticket Common Key Index, defaults to 0x00\n");
	printf("                                    0x00 : Applications / eShop\n");
	printf("                                    0x01 : System Titles\n");
	printf("                                    0x02-0x05 : Unused\n");
	printf(" -ncchseckey    <index>             NCCH KeyX index, defaults to 0x00\n");
	printf("                                    0x00 : FW 1.0.0+\n");
	printf("                                    0x01 : FW 7.0.0+\n");
	printf("                                    0x0a : FW 9.3.0+ (New3DS only)\n");
	printf("                                    0x0b : FW 9.6.0+ (New3DS only)\n");
	printf(" -showkeys                          Display the loaded key chain\n");
	printf(" -ignoresign                        Ignore invalid signatures\n");
	printf("NCCH OPTIONS:\n");
	printf(" -elf           <file>              ELF file\n");
	printf(" -icon          <file>              Icon file\n");
	printf(" -banner        <file>              Banner file\n");
	printf(" -logo          <file>              Logo file (Overrides \"BasicInfo/Logo\" in RSF)\n");
	printf(" -desc          <apptype>:<fw>      Specify Access Descriptor template\n");
	printf(" -exefslogo                         Include Logo in ExeFS (Required for usage on <5.0 systems)\n");
	printf(" -nocodepadding                     For building sysmodules, do not pad .code segments\n");
	printf("NCCH REBUILD OPTIONS:\n");
	printf(" -code          <file>              Decompressed ExeFS \".code\"\n");
	printf(" -exheader      <file>              Exheader template\n");
	printf(" -plainrgn      <file>              Plain Region binary\n");
	printf(" -romfs         <file>              RomFS binary\n");
	printf("CCI OPTIONS:\n");
	printf(" -content       <file>:<index>      Specify content files\n");
	printf(" -devcci                            Use external CTRSDK \"CardInfo\" method\n");
	printf(" -nomodtid                          Don't Modify Content TitleIDs\n");
	printf(" -alignwr                           Align writeable region to the end of last NCCH\n");
	printf(" -cverinfo      <file>:<cia|tmd>    Include cver title info\n");
	printf("CIA OPTIONS:\n");
	printf(" -content       <file>:<index>:<id> Specify content files\n");
	printf(" -ver           <version>           Title Version\n");
	printf(" -major         <version>           Major version\n");
	printf(" -minor         <version>           Minor version\n");
	printf(" -micro         <version>           Micro version\n");
	printf(" -dver          <version>           Data-title version\n");
	printf(" -deviceid      <hex id>            3DS unique device ID\n");
	printf(" -esaccid       <hex id>            e-Shop account ID\n");
	printf(" -rand                              Use a random title key\n");
	printf(" -dlc                               Create DLC CIA\n");
	printf(" -srl           <srl file>          Package a TWL SRL in a CIA\n");
	printf("NCCH CONTAINER CONVERSION:\n");
	printf(" -ccitocia      <cci file>          Convert CCI to CIA\n");
	printf(" -ciatocci      <cia file>          Convert CIA to CCI\n");
	printf(" -inclupd                           Include \"Update NCCH\" in CCI to CIA conversion\n");
}