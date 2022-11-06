#include "CciProcess.h"
#include <tc/io.h>
#include <tc/cli.h>
#include <tc/crypto.h>
#include <tc/ArgumentNullException.h>

#include <ntd/n3ds/CciFsSnapshotGenerator.h>
#include <ntd/n3ds/CtrKeyGenerator.h>

#include <mbedtls/ccm.h>

ctrtool::CciProcess::CciProcess() :
	mModuleLabel("ctrtool::CciProcess"),
	mInputStream(),
	mKeyBag(),
	mShowHeaderInfo(false),
	mVerbose(false),
	mVerify(false),
	mExtractPath(),
	mContentIndex(0),
	mBlockSize(0),
	mUsedImageSize(0),
	mValidSignature(ValidState::Unchecked),
	mValidInitialDataMac(ValidState::Unchecked),
	mValidCryptoType(ValidState::Unchecked),
	mDecryptedTitleKey(),
	mNcchProcess(),
	mFsReader()
{
	memset(&mHeader, 0, sizeof(mHeader));
}

void ctrtool::CciProcess::setInputStream(const std::shared_ptr<tc::io::IStream>& input_stream)
{
	mInputStream = input_stream;
}

void ctrtool::CciProcess::setKeyBag(const ctrtool::KeyBag& key_bag)
{
	mKeyBag = key_bag;
	mNcchProcess.setKeyBag(key_bag);
}

void ctrtool::CciProcess::setCliOutputMode(bool show_header_info)
{
	mShowHeaderInfo = show_header_info;
}

void ctrtool::CciProcess::setVerboseMode(bool verbose)
{
	mVerbose = verbose;
	mNcchProcess.setVerboseMode(verbose);
}

void ctrtool::CciProcess::setVerifyMode(bool verify)
{
	mVerify = verify;
	mNcchProcess.setVerifyMode(verify);
}

void ctrtool::CciProcess::setExtractPath(const tc::io::Path& extract_path)
{
	mExtractPath = extract_path;
}

void ctrtool::CciProcess::setContentIndex(size_t index)
{
	mContentIndex = index;
}

void ctrtool::CciProcess::setRawMode(bool raw)
{
	mNcchProcess.setRawMode(raw);
}

void ctrtool::CciProcess::setPlainMode(bool plain)
{
	mNcchProcess.setPlainMode(plain);
}

void ctrtool::CciProcess::setShowSyscallName(bool show_name)
{
	mNcchProcess.setShowSyscallName(show_name);
}

void ctrtool::CciProcess::setNcchRegionProcessOutputMode(NcchProcess::NcchRegion region, bool show_info, bool show_fs, const tc::Optional<tc::io::Path>& bin_extract_path, const tc::Optional<tc::io::Path>& fs_extract_path)
{
	mNcchProcess.setRegionProcessOutputMode(region, show_info, show_fs, bin_extract_path, fs_extract_path);
}

void ctrtool::CciProcess::process()
{
	importHeader();
	if (mVerify)
		verifyHeader();
	if (mShowHeaderInfo)
		printHeader();
	if (mExtractPath.isSet())
		extractFs();
	processContent();
}

void ctrtool::CciProcess::importHeader()
{
	// validate input stream
	if (mInputStream == nullptr)
	{
		throw tc::ArgumentNullException(mModuleLabel, "Input stream was null.");
	}
	if (mInputStream->canRead() == false || mInputStream->canSeek() == false)
	{
		throw tc::InvalidOperationException(mModuleLabel, "Input stream requires read/seek permissions.");
	}

	// import header
	if (mInputStream->length() < sizeof(ntd::n3ds::CciHeader))
	{
		throw tc::InvalidOperationException(mModuleLabel, "Input stream too small. (Too small to read header).");
	}
	mInputStream->seek(0, tc::io::SeekOrigin::Begin);
	mInputStream->read((byte_t*)&mHeader, sizeof(ntd::n3ds::CciHeader));

	// check the struct magic
	if (mHeader.ncsd_header.struct_magic.unwrap() != mHeader.ncsd_header.kStructMagic)
	{
		throw tc::InvalidOperationException(mModuleLabel, "NcsdCommonHeader is corrupted (Bad struct magic).");
	}

	// check supported media types
	if (mHeader.ncsd_header.flags.media_type != mHeader.ncsd_header.MediaType_Card1 && mHeader.ncsd_header.flags.media_type != mHeader.ncsd_header.MediaType_Card2)
	{
		throw tc::InvalidOperationException(mModuleLabel, "NcsdCommonHeader has an unsupported MediaType.");
	}

	// determine block size
	int64_t block_shift = (mHeader.ncsd_header.flags.block_size_log + 9);
	mBlockSize = static_cast<int64_t>(1) << block_shift;


	// determine used image size
	int64_t pos = 0;
	for (size_t i = 0; i < mHeader.ncsd_header.partition_offsetsize.size(); i++)
	{
		int64_t offset = mHeader.ncsd_header.partition_offsetsize[i].blk_offset.unwrap() * mBlockSize;
		int64_t size = mHeader.ncsd_header.partition_offsetsize[i].blk_size.unwrap() * mBlockSize;

		if (size != 0)
		{
				if (offset < pos)
			{
				throw tc::InvalidOperationException(mModuleLabel, "NcsdCommonHeader has an poorly aligned content offsets.");
			}

			pos = offset + size;
		}

	}
	mUsedImageSize = pos;

	if (mUsedImageSize > (mHeader.ncsd_header.image_blk_size.unwrap() * mBlockSize))
	{
		throw tc::InvalidOperationException(mModuleLabel, "NcsdCommonHeader content geometry exceeded media size.");
	}

	// check input stream is large enough
	if (mInputStream->length() < mUsedImageSize)
	{
		throw tc::InvalidOperationException(mModuleLabel, "Input stream too small. (Too small for total used image size).");
	}

	// decrypt title key
	ctrtool::KeyBag::Aes128Key initial_data_key;
	bool initial_data_key_available = false;

	// crypto_type 3 zeros initial_data key (used in developer ROMs only)
	if (mHeader.card_info.flag.crypto_type == ntd::n3ds::CciHeader::CryptoType_FixedKey)
	{
		memset(initial_data_key.data(), 0, initial_data_key.size());
		initial_data_key_available = true;
	}
	// crypto_type 0-2 is the normal "secure" initial data key 
	else
	{
		if (mKeyBag.brom_static_key_x.find(mKeyBag.KEYSLOT_INITIAL_DATA) != mKeyBag.brom_static_key_x.end())
		{	
			ntd::n3ds::CtrKeyGenerator::GenerateKey(mKeyBag.brom_static_key_x[mKeyBag.KEYSLOT_INITIAL_DATA].data(), mHeader.initial_data.key_source.data(), initial_data_key.data());
			initial_data_key_available = true;
		}
		else
		{
			initial_data_key_available = false;
		}
	}

	if (initial_data_key_available)
	{
		// initialise ccm context
		mbedtls_ccm_context ccm_ctx;
		mbedtls_ccm_init(&ccm_ctx);
		mbedtls_ccm_setkey(&ccm_ctx, MBEDTLS_CIPHER_ID_AES, initial_data_key.data(), 128);

		// decrypt titlekey
		ctrtool::KeyBag::Aes128Key decrypted_title_key;
		int dec_result = mbedtls_ccm_auth_decrypt(&ccm_ctx, decrypted_title_key.size(), mHeader.initial_data.nonce.data(), mHeader.initial_data.nonce.size(), nullptr, 0, mHeader.initial_data.encrypted_title_key.data(), decrypted_title_key.data(), mHeader.initial_data.mac.data(), mHeader.initial_data.mac.size());
		// dec_result will be non-zero if MAC was invalid
		if (dec_result == 0)
		{
			mDecryptedTitleKey = decrypted_title_key;
		}
		// Since CCM mode decrypts AND verifies, we should process the result here if required
		if (mVerify)
		{
			mValidInitialDataMac = dec_result == 0 ? ValidState::Good : ValidState::Fail;

			if (mValidInitialDataMac != ValidState::Good)
			{
				fmt::print(stderr, "[{} ERROR] InitialData MAC was invalid.\n", mModuleLabel);
			}
		}

		/*
		// test encrypt
		ctrtool::KeyBag::Aes128Key enc_title_key, mac;
		mbedtls_ccm_encrypt_and_tag(&ccm_ctx, enc_title_key.size(), mHeader.initial_data.nonce.data(), mHeader.initial_data.nonce.size(), nullptr, 0, decrypted_title_key.data(), enc_title_key.data(), mac.data(), mac.size());

		std::cout << "enc key: " << tc::cli::FormatUtil::formatBytesAsString(enc_title_key.data(), enc_title_key.size(), true, "") << std::endl;
		std::cout << "mac:     " << tc::cli::FormatUtil::formatBytesAsString(mac.data(), mac.size(), true, "") << std::endl;
		*/

		mbedtls_ccm_free(&ccm_ctx);
	}
	else
	{
		// no initial data key
		fmt::print(stderr, "[{} ERROR] Failed to determine key to decrypt InitialData.\n", mModuleLabel);
	}

	// verify crypto type
	if (mVerify)
	{
		// only verify if the enabled bit is set
		if (mHeader.ncsd_header.card_ext.crypto_type.enabled)
		{
			mValidCryptoType = mHeader.card_info.flag.crypto_type == mHeader.ncsd_header.card_ext.crypto_type.value ? ValidState::Good : ValidState::Fail;

			if (mValidCryptoType != ValidState::Good)
			{
				fmt::print(stderr, "[{} ERROR] CryptoType was invalid.\n", mModuleLabel);
			}
		}
	}

	// open fs reader
	mFsReader = std::shared_ptr<tc::io::VirtualFileSystem>(new tc::io::VirtualFileSystem(ntd::n3ds::CciFsShapshotGenerator(mInputStream)));
}

void ctrtool::CciProcess::verifyHeader()
{
	std::array<byte_t, tc::crypto::Sha256Generator::kHashSize> ncsd_header_hash;
	
	tc::crypto::GenerateSha256Hash(ncsd_header_hash.data(), (byte_t*)(&mHeader.ncsd_header), sizeof(mHeader.ncsd_header));

	if (mKeyBag.rsa_key.find(mKeyBag.RSAKEY_CFA_CCI) != mKeyBag.rsa_key.end())
	{
		tc::crypto::RsaKey pubkey = mKeyBag.rsa_key[mKeyBag.RSAKEY_CFA_CCI];

		mValidSignature = tc::crypto::VerifyRsa2048Pkcs1Sha256(mHeader.signature.data(), ncsd_header_hash.data(), pubkey) ? ValidState::Good : ValidState::Fail;
	}
	else
	{
		fmt::print(stderr, "[{} ERROR] Could not load CCI RSA2048 public key.\n", mModuleLabel);
		mValidSignature = ValidState::Fail;
	}

	if (mValidSignature != ValidState::Good)
	{
		fmt::print(stderr, "[{} ERROR] Signature for NcsdCommonHeader was invalid.\n", mModuleLabel);
	}
}

void ctrtool::CciProcess::printHeader()
{
	fmt::print("\n");
	fmt::print("[CCI]\n");

	// NCSD common header
	fmt::print("NcsdCommonHeader:\n");
	fmt::print(" Header:                 {}\n", "NCSD");
	fmt::print(" Signature: {:6}       {}", getValidString(mValidSignature), tc::cli::FormatUtil::formatBytesAsStringWithLineLimit(mHeader.signature.data(), mHeader.signature.size(), true, "", 0x20, 25, false));
	fmt::print(" RomSize:                {} (Used: 0x{:X})\n", getRomSizeString(mHeader.ncsd_header.image_blk_size.unwrap()), mUsedImageSize);
	fmt::print(" TitleId:                {:016x}\n", mHeader.ncsd_header.title_id.unwrap());
	fmt::print("\n");
	for (size_t i = 0; i < ntd::n3ds::NcsdCommonHeader::kPartitionNum; i++)
	{
		int64_t offset = mHeader.ncsd_header.partition_offsetsize[i].blk_offset.unwrap() * mBlockSize;
		int64_t size = mHeader.ncsd_header.partition_offsetsize[i].blk_size.unwrap() * mBlockSize;
		byte_t fs_type = mHeader.ncsd_header.partition_fs_type[i];
		byte_t crypto_type = mHeader.ncsd_header.partition_crypto_type[i];
		uint64_t id = mHeader.ncsd_header.card_ext.partition_id[i].unwrap();

		if (size != 0)
		{
			fmt::print(" Partition {}\n", i);
			fmt::print("  Id:                    {:016x}\n", id);
			fmt::print("  Area:                  0x{:08X}-0x{:08X}\n", offset, (offset + size));
			fmt::print("  FsType:                {:02X}\n", fs_type);
			fmt::print("  CryptoType:            {:02X}\n", crypto_type);
			fmt::print("\n");
		}
	}
	fmt::print(" Flags:                  {}\n", tc::cli::FormatUtil::formatBytesAsString(mHeader.ncsd_header.flags.data(), mHeader.ncsd_header.flags.size(), true, ""));
	fmt::print("  BackupWriteWaitTime:   {:02x}\n", (uint32_t)mHeader.ncsd_header.flags[mHeader.NcsdFlagIndex_BackupWriteWaitTime]);
	fmt::print("  BackupSecurityVersion: {:02x}\n", (uint32_t)mHeader.ncsd_header.flags[mHeader.NcsdFlagIndex_BackupSecurityVersion] + mHeader.ncsd_header.card_ext.backup_security_version);
	fmt::print("  CardInfo:              {:02x}\n", (uint32_t)mHeader.ncsd_header.flags[mHeader.NcsdFlagIndex_CardInfo]);
	byte_t card_device = (mHeader.ncsd_header.flags[mHeader.NcsdFlagIndex_CardDevice] | mHeader.ncsd_header.flags[mHeader.NcsdFlagIndex_CardDevice_Deprecated]);
	fmt::print("  CardDevice:            {:02x} ({})\n", (uint32_t)card_device, getCardDeviceString(card_device));
	fmt::print("  MediaPlatform:         {:02x}", (uint32_t)mHeader.ncsd_header.flags[mHeader.NcsdFlagIndex_MediaPlatform]);
	for (size_t bit = 0; bit < mHeader.ncsd_header.flags.media_platform.bit_size(); bit++)
	{
		if (mHeader.ncsd_header.flags.media_platform.test(bit))
		{
			fmt::print(" [{}]", getPlatformString(bit));
		}
	}
	fmt::print("\n");
	fmt::print("  MediaType:             {:02x} ({})\n", (uint32_t)mHeader.ncsd_header.flags[mHeader.NcsdFlagIndex_MediaType], getMediaTypeString(mHeader.ncsd_header.flags[mHeader.NcsdFlagIndex_MediaType]));
	fmt::print("  MediaBlockSize:        {:02x} (0x{:x})\n", (uint32_t)mHeader.ncsd_header.flags[mHeader.NcsdFlagIndex_MediaBlockSize], mBlockSize);

	// card info
	fmt::print("CardInfo:\n");
	fmt::print(" WriteableRegion:        0x{:08X}\n", mHeader.card_info.writable_region.unwrap());
	fmt::print(" CardType:               {} ({:X})\n", getCardTypeString(mHeader.card_info.flag.card_type), (uint32_t)mHeader.card_info.flag.card_type);
	fmt::print(" CryptoType: {:6}      {} ({:X})\n", getValidString(mValidCryptoType), getCryptoTypeString(mHeader.card_info.flag.crypto_type), (uint32_t)mHeader.card_info.flag.crypto_type);
	
	// mastering metadata
	fmt::print("MasteringMetadata:\n");
	fmt::print(" MediaSizeUsed:          0x{:08X}\n", mHeader.mastering_info.media_size_used.unwrap());
	fmt::print(" TitleVersion:           {} (v{:d})\n", getTitleVersionString(mHeader.mastering_info.title_version.unwrap()), mHeader.mastering_info.title_version.unwrap());
	fmt::print(" CardRevision:           {:d}\n", (uint32_t)mHeader.mastering_info.card_revision.unwrap());
	fmt::print(" CVer TitleId:           {:016x}\n", mHeader.mastering_info.cver_title_id.unwrap());
	fmt::print(" CVer Version:           {} (v{:d})\n", getTitleVersionString(mHeader.mastering_info.cver_title_version.unwrap()), mHeader.mastering_info.cver_title_version.unwrap());
	
	// initial data
	fmt::print("InitialData:\n");
	fmt::print(" KeySource:              {}\n", tc::cli::FormatUtil::formatBytesAsString(mHeader.initial_data.key_source.data(), mHeader.initial_data.key_source.size(), true, ""));
	fmt::print(" Enc TitleKey:           {}", tc::cli::FormatUtil::formatBytesAsString(mHeader.initial_data.encrypted_title_key.data(), mHeader.initial_data.encrypted_title_key.size(), true, ""));
	if (mDecryptedTitleKey.isSet())
	{
		fmt::print(" (decrypted: {})", tc::cli::FormatUtil::formatBytesAsString(mDecryptedTitleKey.get().data(), mDecryptedTitleKey.get().size(), true, ""));
	}
	fmt::print("\n");
	fmt::print(" MAC: {:6}""             {}\n", getValidString(mValidInitialDataMac), tc::cli::FormatUtil::formatBytesAsString(mHeader.initial_data.mac.data(), mHeader.initial_data.mac.size(), true, ""));

	// card device info
	fmt::print("CardDeviceInfo:\n");
	fmt::print(" TitleKey:               {}\n", tc::cli::FormatUtil::formatBytesAsString(mHeader.card_device_info.title_key.data(), mHeader.card_device_info.title_key.size(), true, ""));
}

void ctrtool::CciProcess::extractFs()
{
	tc::io::LocalFileSystem local_fs;

	tc::io::sDirectoryListing dir;

	mFsReader->getDirectoryListing(tc::io::Path("/"), dir);

	local_fs.createDirectory(mExtractPath.get());

	// iterate thru child files
	tc::ByteData cache = tc::ByteData(0x10000);
	size_t cache_read_len;
	tc::io::Path out_path;
	std::shared_ptr<tc::io::IStream> in_stream;
	std::shared_ptr<tc::io::IStream> out_stream;
	for (auto itr = dir.file_list.begin(); itr != dir.file_list.end(); itr++)
	{
		// build out path
		out_path = mExtractPath.get() + *itr;

		if (mVerbose)
		{
			fmt::print(stderr, "[{} LOG] Saving {}...\n", mModuleLabel, out_path.to_string());
		}

		// begin export
		mFsReader->openFile(*itr, tc::io::FileMode::Open, tc::io::FileAccess::Read, in_stream);
		local_fs.openFile(out_path, tc::io::FileMode::OpenOrCreate, tc::io::FileAccess::Write, out_stream);

		in_stream->seek(0, tc::io::SeekOrigin::Begin);
		out_stream->seek(0, tc::io::SeekOrigin::Begin);
		for (int64_t remaining_data = in_stream->length(); remaining_data > 0;)
		{
			cache_read_len = in_stream->read(cache.data(), cache.size());
			if (cache_read_len == 0)
			{
				throw tc::io::IOException(mModuleLabel, fmt::format("Failed to read from \"{}\".", (std::string)(dir.abs_path + *itr)));
			}

			out_stream->write(cache.data(), cache_read_len);

			remaining_data -= int64_t(cache_read_len);
		}
	}
}

void ctrtool::CciProcess::processContent()
{
	if (mContentIndex >= ntd::n3ds::NcsdCommonHeader::kPartitionNum)
	{
		fmt::print(stderr, "[{} ERROR] Content index {:d} isn't valid for CCI, use index 0-7, defaulting to 0 now.\n", mModuleLabel, mContentIndex);
		mContentIndex = 0;
	}
	if (mHeader.ncsd_header.partition_offsetsize[mContentIndex].blk_size.unwrap() != 0)
	{
		mNcchProcess.setInputStream(std::shared_ptr<tc::io::SubStream>(new tc::io::SubStream(mInputStream, mHeader.ncsd_header.partition_offsetsize[mContentIndex].blk_offset.unwrap() * mBlockSize, mHeader.ncsd_header.partition_offsetsize[mContentIndex].blk_size.unwrap() * mBlockSize)));
		mNcchProcess.process();
	}	
}

std::string ctrtool::CciProcess::getValidString(byte_t validstate)
{
	std::string ret_str;
	switch (validstate)
	{
		case ValidState::Unchecked:
			ret_str =  "";
			break;
		case ValidState::Good:
			ret_str =  "(GOOD)";
			break;
		case ValidState::Fail:
		default:
			ret_str =  "(FAIL)";
			break;
	}

	return ret_str;
}

std::string ctrtool::CciProcess::getRomSizeString(uint32_t rom_blk_size)
{
	std::string ret_str;

	switch (rom_blk_size)
	{
		case ntd::n3ds::CciHeader::RomSize_128MB :
			ret_str = "128MB";
			break;
		case ntd::n3ds::CciHeader::RomSize_256MB :
			ret_str = "256MB";
			break;
		case ntd::n3ds::CciHeader::RomSize_512MB :
			ret_str = "512MB";
			break;
		case ntd::n3ds::CciHeader::RomSize_1GB :
			ret_str = "1GB";
			break;
		case ntd::n3ds::CciHeader::RomSize_2GB :
			ret_str = "2GB";
			break;
		case ntd::n3ds::CciHeader::RomSize_4GB :
			ret_str = "4GB";
			break;
		default:
			ret_str = fmt::format("0x{:08X} blocks", rom_blk_size);
	}

	return ret_str;
}

std::string ctrtool::CciProcess::getMediaTypeString(byte_t media_type)
{
	std::string ret_str;

	switch (media_type)
	{
		case ntd::n3ds::NcsdCommonHeader::MediaType_InnerDevice :
			ret_str = "Inner Device";
			break;
		case ntd::n3ds::NcsdCommonHeader::MediaType_Card1 :
			ret_str = "CARD1";
			break;
		case ntd::n3ds::NcsdCommonHeader::MediaType_Card2 :
			ret_str = "CARD2";
			break;
		case ntd::n3ds::NcsdCommonHeader::MediaType_ExtendedDevice :
			ret_str = "Extended Device";
			break;
		default:
			ret_str = fmt::format("Unknown (0x{:02x})", media_type);
	}

	return ret_str;
}

std::string ctrtool::CciProcess::getCardDeviceString(byte_t card_device)
{
	std::string ret_str;

	switch (card_device)
	{
		case ntd::n3ds::CciHeader::CardDevice_Unspecified :
			ret_str = "Not Specified";
			break;
		case ntd::n3ds::CciHeader::CardDevice_NorFlash :
			ret_str = "NorFlash";
			break;
		case ntd::n3ds::CciHeader::CardDevice_None :
			ret_str = "None";
			break;
		case ntd::n3ds::CciHeader::CardDevice_BT :
			ret_str = "BT";
			break;
		default:
			ret_str = fmt::format("Unknown (0x{:02x})", card_device);
	}

	return ret_str;
}

std::string ctrtool::CciProcess::getPlatformString(size_t bit)
{
	std::string ret_str;

	switch(bit)
	{
		case ntd::n3ds::NcsdCommonHeader::MediaPlatform_CTR :
			ret_str = "CTR";
			break;
		case ntd::n3ds::NcsdCommonHeader::MediaPlatform_SNAKE :
			ret_str = "SNAKE";
			break;
		default:
			ret_str = fmt::format("Unknown (bit {:d})", bit);
	}

	return ret_str;
}

std::string ctrtool::CciProcess::getCardTypeString(byte_t card_type)
{
	std::string ret_str;

	switch(card_type)
	{
		case ntd::n3ds::CciHeader::CardType_S1 :
			ret_str = "S1";
			break;
		case ntd::n3ds::CciHeader::CardType_S2 :
			ret_str = "S2";
			break;
		default:
			ret_str = "Unknown";
			break;
	}
	
	return ret_str;
}

std::string ctrtool::CciProcess::getCryptoTypeString(byte_t crypto_type)
{
	std::string ret_str;

	switch(crypto_type)
	{
		case ntd::n3ds::CciHeader::CryptoType_Secure0 :
			ret_str = "Secure0";
			break;
		case ntd::n3ds::CciHeader::CryptoType_Secure1 :
			ret_str = "Secure1";
			break;
		case ntd::n3ds::CciHeader::CryptoType_Secure2 :
			ret_str = "Secure2";
			break;
		case ntd::n3ds::CciHeader::CryptoType_FixedKey :
			ret_str = "FixedKey";
			break;
		default:
			ret_str = "Unknown";
			break;
	}
	
	return ret_str;
}

std::string ctrtool::CciProcess::getTitleVersionString(uint16_t version)
{
	return fmt::format("{major:d}.{minor:d}.{build:d}", fmt::arg("major", (uint32_t)((version >> 10) & 0x3F)), fmt::arg("minor", (uint32_t)((version >> 4) & 0x3F)), fmt::arg("build", (uint32_t)(version & 0xF)));
}