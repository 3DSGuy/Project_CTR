#pragma once
#include "types.h"
#include "KeyBag.h"
#include "NcchProcess.h"
#include <tc/Optional.h>
#include <tc/io/IFileSystem.h>
#include <ntd/n3ds/cci.h>

namespace ctrtool {

class CciProcess
{
public:
	CciProcess();

	void setInputStream(const std::shared_ptr<tc::io::IStream>& input_stream);
	void setKeyBag(const ctrtool::KeyBag& key_bag);
	void setCliOutputMode(bool show_header_info);
	void setVerboseMode(bool verbose);
	void setVerifyMode(bool verify);
	void setExtractPath(const tc::io::Path& extract_path);
	void setContentIndex(size_t index);
	
	// ncch settings passed on
	void setRawMode(bool raw);
	void setPlainMode(bool plain);
	void setShowSyscallName(bool show_name);
	void setNcchRegionProcessOutputMode(NcchProcess::NcchRegion region, bool show_info, bool show_fs, const tc::Optional<tc::io::Path>& bin_extract_path, const tc::Optional<tc::io::Path>& fs_extract_path);

	void process();
private:
	std::string mModuleLabel;

	std::shared_ptr<tc::io::IStream> mInputStream;
	ctrtool::KeyBag mKeyBag;
	bool mShowHeaderInfo;
	bool mVerbose;
	bool mVerify;
	tc::Optional<tc::io::Path> mExtractPath;
	size_t mContentIndex;

	int64_t mBlockSize;
	int64_t mUsedImageSize;
	byte_t mValidSignature;
	byte_t mValidInitialDataMac;
	byte_t mValidCryptoType;
	ntd::n3ds::CciHeader mHeader;
	tc::Optional<KeyBag::Aes128Key> mDecryptedTitleKey;
	ctrtool::NcchProcess mNcchProcess;
	std::shared_ptr<tc::io::IFileSystem> mFsReader;

	void importHeader();
	void verifyHeader();
	void printHeader();
	void extractFs();
	void processContent();

	// string utils
	std::string getValidString(byte_t validstate);
	std::string getRomSizeString(uint32_t rom_blk_size);
	std::string getMediaTypeString(byte_t media_type);
	std::string getCardDeviceString(byte_t card_device);
	std::string getPlatformString(size_t bit);
	std::string getCardTypeString(byte_t card_type);
	std::string getCryptoTypeString(byte_t crypto_type);
	std::string getTitleVersionString(uint16_t version);
};

}