#pragma once
#include "types.h"
#include "KeyBag.h"
#include <tc/Optional.h>
#include <ntd/n3ds/ncch.h>

namespace ctrtool {

class NcchProcess
{
public:
	enum NcchRegion
	{
		NcchRegion_Header,
		NcchRegion_ExHeader,
		NcchRegion_PlainRegion,
		NcchRegion_Logo,
		NcchRegion_ExeFs,
		NcchRegion_RomFs,
		NcchRegionNum
	};

	NcchProcess();

	void setInputStream(const std::shared_ptr<tc::io::IStream>& input_stream);
	void setKeyBag(const ctrtool::KeyBag& key_bag);
	void setVerboseMode(bool verbose);
	void setVerifyMode(bool verify);
	void setRawMode(bool raw);
	void setPlainMode(bool plain);
	void setShowSyscallName(bool show_name);
	void setRegionProcessOutputMode(NcchRegion region, bool show_info, bool show_fs, const tc::Optional<tc::io::Path>& bin_extract_path, const tc::Optional<tc::io::Path>& fs_extract_path);

	void process();

	// decrypt NCCH stream
	void decryptNcchStream(std::shared_ptr<tc::io::IStream>& outStream);
private:
	std::string mModuleLabel;

	// Options
	std::shared_ptr<tc::io::IStream> mInputStream;
	ctrtool::KeyBag mKeyBag;
	bool mVerbose;
	bool mVerify;
	bool mRaw;
	bool mPlain;
	bool mShowSyscallNames;
	struct NcchRegionOpt
	{
		bool show_info;
		bool show_fs;
		tc::Optional<tc::io::Path> bin_extract_path;
		tc::Optional<tc::io::Path> fs_extract_path;
	};
	std::array<NcchRegionOpt, NcchRegionNum> mRegionOpt;


	// BEGIN Runtime NCCH info
	ntd::n3ds::NcchHeader mHeader;
	int64_t mContentSize; // determined in ncch header processing
	int64_t mBlockSize; // determined in ncch header processing
	bool mDecompressExeFsCode; // determined in ncch exheader processing
	struct NcchRegionInfo
	{
		byte_t valid;
		int64_t offset;
		int64_t size;
		int64_t hashed_offset;
		int64_t hashed_size;
		std::shared_ptr<tc::io::IStream> raw_stream;
		std::shared_ptr<tc::io::IStream> ready_stream;
	};
	std::array<NcchRegionInfo, NcchRegionNum> mRegionInfo;

	void importHeader();
	void determineRegionLayout();
	void determineRegionEncryption();
	void verifyRegions();
	void printHeader();
	void extractRegionBinaries();
	void processRegions();

	// string utils
	std::string getValidString(byte_t validstate);
	std::string getContentPlatformString(size_t bit);
	std::string getFormTypeString(byte_t var);
	std::string getContentTypeString(byte_t var);
	
	// utils
	bool isSystemTitle();
	void getAesCounter(byte_t* counter, byte_t ncch_region);
};

}