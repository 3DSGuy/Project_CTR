#pragma once
#include "types.h"
#include "KeyBag.h"
#include "NcchProcess.h"
#include <tc/Optional.h>
#include <tc/io/IFileSystem.h>
#include <ntd/n3ds/cia.h>

#include <ntd/n3ds/es/RsaSigner.h>
#include <ntd/n3ds/es/Certificate.h>
#include <ntd/n3ds/es/Ticket.h>
#include <ntd/n3ds/es/TitleMetaData.h>

namespace ctrtool {

class CiaProcess
{
public:
	CiaProcess();

	void setInputStream(const std::shared_ptr<tc::io::IStream>& input_stream);
	void setKeyBag(const ctrtool::KeyBag& key_bag);
	void setCliOutputMode(bool show_header_info);
	void setVerboseMode(bool verbose);
	void setVerifyMode(bool verify);
	void setCertExtractPath(const tc::io::Path& extract_path);
	void setTikExtractPath(const tc::io::Path& extract_path);
	void setTmdExtractPath(const tc::io::Path& extract_path);
	void setContentExtractPath(const tc::io::Path& extract_path);
	void setFooterExtractPath(const tc::io::Path& extract_path);
	void setContentIndex(size_t index);
	
	// ncch settings passed on
	void setRawMode(bool raw);
	void setPlainMode(bool plain);
	void setShowSyscallName(bool show_name);
	void setNcchRegionProcessOutputMode(NcchProcess::NcchRegion region, bool show_info, bool show_fs, const tc::Optional<tc::io::Path>& bin_extract_path, const tc::Optional<tc::io::Path>& fs_extract_path);
	void setDecryptNcch(bool decryptNcch);

	void process();
private:
	std::string mModuleLabel;

	// input args
	std::shared_ptr<tc::io::IStream> mInputStream;
	ctrtool::KeyBag mKeyBag;
	bool mShowHeaderInfo;
	bool mVerbose;
	bool mVerify;
	bool mPlain;
	tc::Optional<tc::io::Path> mCertExtractPath;
	tc::Optional<tc::io::Path> mTikExtractPath;
	tc::Optional<tc::io::Path> mTmdExtractPath;
	tc::Optional<tc::io::Path> mContentExtractPath;
	tc::Optional<tc::io::Path> mFooterExtractPath;
	size_t mContentIndex;
	bool mDecryptNcch;

	// process variables
	ntd::n3ds::CiaHeader mHeader;
	std::map<std::string, std::shared_ptr<ntd::n3ds::es::ISigner>> mIssuerSigner;
	std::map<std::string, std::shared_ptr<ntd::n3ds::es::ISigner>> mCertImportedIssuerSigner;
	std::vector<ntd::n3ds::es::Certificate> mCertChain;
	std::vector<ValidState> mCertSigValid;
	ntd::n3ds::es::Ticket mTicket;
	ValidState mTicketSigValid;
	ntd::n3ds::es::TitleMetaData mTitleMetaData;
	ValidState mTitleMetaDataSigValid;
	tc::Optional<KeyBag::Aes128Key> mDecryptedTitleKey;
	bool mIsTwlTitle;
	ctrtool::NcchProcess mNcchProcess;
	std::shared_ptr<tc::io::IFileSystem> mFsReader;
	
	struct CiaSectionInfo
	{		
		int64_t offset;
		int64_t size;

		CiaSectionInfo() : offset(0), size(0) {} 
	} mCertSizeInfo, mTikSizeInfo, mTmdSizeInfo, mContentSizeInfo, mFooterSizeInfo;

	struct ContentInfo
	{
		int64_t offset;
		int64_t size;
		uint32_t cid;
		uint16_t cindex;
		bool is_encrypted;
		bool is_hashed;
		std::array<byte_t, 32> hash;
		int valid_state;

		ContentInfo() :
			offset(0),
			size(0),
			cid(0),
			cindex(0),
			is_encrypted(false),
			is_hashed(false),
			valid_state(ValidState::Unchecked)
		{
			memset(hash.data(), 0, hash.size());
		}
	};
	std::map<size_t, ContentInfo> mContentInfo;

	// helper methods
	void importIssuerProfiles();
	void importHeader();
	void verifyMetadata();
	void verifyContent();
	void printHeader();
	void extractCia();
	void processContent();

	void createContentIv(std::array<byte_t, 16>& content_iv, uint16_t index);

	bool isTwlTitle(uint64_t title_id);

	// string utils
	std::string getValidString(byte_t validstate);
	std::string getCiaTypeString(uint16_t type);
	std::string getFormatVersionString(uint16_t format_version);
	std::string getTruncatedBytesString(const byte_t* data, size_t len, bool do_not_truncate = false);
	std::string getSigTypeString(brd::es::ESSigType sig_type);
	std::string getCertificatePublicKeyTypeString(brd::es::ESCertPubKeyType public_key_type);
	std::string getTitleVersionString(uint16_t version);
};

}