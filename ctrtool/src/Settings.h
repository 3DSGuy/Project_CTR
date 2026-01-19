#pragma once
#include <string>
#include <vector>
#include <tc/Optional.h>
#include <tc/io.h>

#include "FirmProcess.h"
#include "KeyBag.h"

namespace ctrtool {

struct Settings
{
	enum FileType
	{
		FILE_TYPE_ERROR,
		FILE_TYPE_NCSD,
		FILE_TYPE_CIA,
		FILE_TYPE_NCCH,
		FILE_TYPE_EXHEADER,
		FILE_TYPE_EXEFS,
		FILE_TYPE_ROMFS,
		FILE_TYPE_FIRM,
		FILE_TYPE_CERT,
		FILE_TYPE_TIK,
		FILE_TYPE_TMD,
		FILE_TYPE_LZSS,
		FILE_TYPE_CRR,
		FILE_TYPE_CRO,
		FILE_TYPE_IVFC,
		FILE_TYPE_SMDH
	};

	struct InputFileOptions
	{
		FileType filetype;
		tc::Optional<tc::io::Path> path;
	} infile;

	struct Options
	{
		bool info;
		bool verbose;
		bool plain;
		bool raw;
		bool verify;
		bool show_keys;
		bool is_dev;
		KeyBag keybag;
	} opt;

	// LZSS options
	struct LzssOptions
	{
		tc::Optional<tc::io::Path> extract_path;
	} lzss;

	// NCCH options
	struct NcchOptions
	{
		tc::Optional<tc::io::Path> exheader_path;
		tc::Optional<tc::io::Path> logo_path;
		tc::Optional<tc::io::Path> plainregion_path;
		tc::Optional<tc::io::Path> exefs_path;
		tc::Optional<tc::io::Path> romfs_path;
	} ncch;

	// ExHeader options
	struct ExheaderOptions
	{
		bool show_syscalls_as_names;
	} exheader;

	// ExeFs options
	struct ExefsOptions
	{
		tc::Optional<tc::io::Path> extract_path;
		bool list_fs;
		bool decompress_code_partition;
	} exefs;

	// RomFs options
	struct RomfsOptions
	{
		tc::Optional<tc::io::Path> extract_path;
		bool list_fs;
	} romfs;

	// CCI/CIA options
	struct RomOptions
	{
		size_t content_process_index;
		tc::Optional<tc::io::Path> content_extract_path;
		bool decrypt_ncch;
	} rom;

	// CIA options
	struct CiaOptions
	{
		tc::Optional<tc::io::Path> certs_path;
		tc::Optional<tc::io::Path> tik_path;
		tc::Optional<tc::io::Path> tmd_path;
		tc::Optional<tc::io::Path> meta_path;
	} cia;
	
	// FIRM options
	struct FirmOptions
	{
		tc::Optional<tc::io::Path> extract_path;
		FirmProcess::FirmwareType firm_type;
	} firm;

	// CWAV options
	struct CwavOptions
	{
		tc::Optional<tc::io::Path> extract_path;
		size_t wav_loops;
	} cwav;
	

	Settings()
	{
		infile.filetype = FILE_TYPE_ERROR;
		infile.path = tc::Optional<tc::io::Path>();

		opt.info = true;
		opt.verbose = false;
		opt.plain = false;
		opt.raw = false;
		opt.verify = false;
		opt.show_keys = false;
		opt.is_dev = false;
		opt.keybag = KeyBag();

		exheader.show_syscalls_as_names = false;

		exefs.extract_path = tc::Optional<tc::io::Path>();
		exefs.list_fs = false;
		exefs.decompress_code_partition = false;

		romfs.extract_path = tc::Optional<tc::io::Path>();
		romfs.list_fs = false;

		rom.content_process_index = 0;
		rom.content_extract_path = tc::Optional<tc::io::Path>();
		rom.decrypt_ncch = false;

		cia.certs_path = tc::Optional<tc::io::Path>();
		cia.tik_path = tc::Optional<tc::io::Path>();
		cia.tmd_path = tc::Optional<tc::io::Path>();
		cia.meta_path = tc::Optional<tc::io::Path>();

		firm.extract_path = tc::Optional<tc::io::Path>();
		firm.firm_type = FirmProcess::FirmwareType_Nand;

		cwav.extract_path = tc::Optional<tc::io::Path>();
		cwav.wav_loops = 0;
	}
};

class SettingsInitializer : public Settings
{
public:
	SettingsInitializer(const std::vector<std::string>& args);
private:
	void parse_args(const std::vector<std::string>& args);
	void register_option_handlers();
	void determine_filetype();
	void usage_text();

	std::string mModuleLabel;

	bool mSuppressOutput;

	bool mShowKeys;
	tc::Optional<std::string> mFallBackTitleKey;
	tc::Optional<std::string> mFallBackSeed;
	tc::Optional<tc::io::Path> mSeedDbPath;
};

}