#include "NcchProcess.h"
#include "lzss.h"
#include <tc/io.h>
#include <tc/cli.h>
#include <tc/crypto.h>
#include <tc/ArgumentNullException.h>

#include <ntd/n3ds/CtrKeyGenerator.h>
#include <ntd/n3ds/exheader.h>
#include "ExHeaderProcess.h"
#include "ExeFsProcess.h"
#include "IvfcProcess.h"

ctrtool::NcchProcess::NcchProcess() :
	mModuleLabel("ctrtool::NcchProcess"),
	mInputStream(),
	mVerbose(false),
	mVerify(false),
	mRaw(false),
	mPlain(false),
	mShowSyscallNames(false),
	mContentSize(0),
	mBlockSize(0),
	mDecompressExeFsCode(false)
{
	memset((byte_t*)&mHeader, 0, sizeof(ntd::n3ds::NcchHeader));
	for (size_t i = 0; i < NcchRegionNum; i++)
	{
		mRegionOpt[i].show_info = true;
		mRegionOpt[i].show_fs = false;
		mRegionOpt[i].bin_extract_path.makeNull();
		mRegionOpt[i].fs_extract_path.makeNull();

		mRegionInfo[i].valid = ValidState::Unchecked;
		mRegionInfo[i].offset = 0;
		mRegionInfo[i].size = 0;
		mRegionInfo[i].hashed_offset = 0;
		mRegionInfo[i].hashed_size = 0;
		mRegionInfo[i].raw_stream = nullptr;
		mRegionInfo[i].ready_stream = nullptr;
	}
}

void ctrtool::NcchProcess::setInputStream(const std::shared_ptr<tc::io::IStream>& input_stream)
{
	mInputStream = input_stream;
}

void ctrtool::NcchProcess::setKeyBag(const ctrtool::KeyBag& key_bag)
{
	mKeyBag = key_bag;
}

void ctrtool::NcchProcess::setVerboseMode(bool verbose)
{
	mVerbose = verbose;
}

void ctrtool::NcchProcess::setVerifyMode(bool verify)
{
	mVerify = verify;
}

void ctrtool::NcchProcess::setRawMode(bool raw)
{
	mRaw = raw;
}

void ctrtool::NcchProcess::setPlainMode(bool plain)
{
	mPlain = plain;
}

void ctrtool::NcchProcess::setShowSyscallName(bool show_name)
{
	mShowSyscallNames = show_name;
}


void ctrtool::NcchProcess::setRegionProcessOutputMode(NcchRegion region, bool show_info, bool show_fs, const tc::Optional<tc::io::Path>& bin_extract_path, const tc::Optional<tc::io::Path>& fs_extract_path)
{
	mRegionOpt[region].show_info = show_info;
	mRegionOpt[region].show_fs = show_fs;
	mRegionOpt[region].bin_extract_path = bin_extract_path;
	mRegionOpt[region].fs_extract_path = fs_extract_path;
}

void ctrtool::NcchProcess::process()
{
	importHeader();
	determineRegionLayout();
	determineRegionEncryption();
	if (mVerify)
		verifyRegions();
	if (mRegionOpt[NcchRegion_Header].show_info)
		printHeader();
	extractRegionBinaries();
	processRegions();
}

void ctrtool::NcchProcess::importHeader()
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
	if (mInputStream->length() < sizeof(ntd::n3ds::NcchHeader))
	{
		throw tc::InvalidOperationException(mModuleLabel, "Input stream too small.");
	}
	mInputStream->seek(0, tc::io::SeekOrigin::Begin);
	mInputStream->read((byte_t*)&mHeader, sizeof(ntd::n3ds::NcchHeader));

	// check the struct magic
	if (mHeader.header.struct_magic.unwrap() != ntd::n3ds::NcchCommonHeader::kStructMagic)
	{
		throw tc::InvalidOperationException(mModuleLabel, "NcchHeader is corrupted (Bad struct magic).");
	}


	// determine block size
	switch (mHeader.header.format_version.unwrap())
	{
		// CFA
		case ntd::n3ds::NcchCommonHeader::FormatVersion_CFA:
		// CXI
		case ntd::n3ds::NcchCommonHeader::FormatVersion_CXI:
			mBlockSize = static_cast<int64_t>(1) << (mHeader.header.flags.block_size_log + 9);
			break;
		// Prototype
		case ntd::n3ds::NcchCommonHeader::FormatVersion_CXI_PROTOTYPE:
			mBlockSize = static_cast<int64_t>(1);
			break;
		default:
			throw tc::InvalidOperationException(mModuleLabel, fmt::format("NcchHeader has unsupported format version. (0x{:02x})", mHeader.header.format_version.unwrap()));

	}


	if (mHeader.header.exhdr_size.unwrap() != 0 && mHeader.header.exhdr_size.unwrap() != sizeof(ntd::n3ds::ExtendedHeader))
	{
		throw tc::InvalidOperationException(mModuleLabel, fmt::format("NcchHeader has invalid ExHeader size. (0x{:02x})", mHeader.header.exhdr_size.unwrap()));
	}

	// get content size
	mContentSize = int64_t(mHeader.header.content_blk_size.unwrap()) * mBlockSize;

	if (mInputStream->length() < mContentSize)
	{
		throw tc::InvalidOperationException(mModuleLabel, "Input stream too small.");
	}
}

void ctrtool::NcchProcess::determineRegionLayout()
{
	// get region layout
	mRegionInfo[NcchRegion_Header].offset = 0;
	mRegionInfo[NcchRegion_Header].size = sizeof(ntd::n3ds::NcchHeader);
	mRegionInfo[NcchRegion_Header].hashed_offset = sizeof(ntd::n3ds::NcchHeader::signature);
	mRegionInfo[NcchRegion_Header].hashed_size = sizeof(ntd::n3ds::NcchCommonHeader);

	if (mHeader.header.exhdr_size.unwrap() > 0)
	{
		mRegionInfo[NcchRegion_ExHeader].offset = sizeof(ntd::n3ds::NcchHeader);
		mRegionInfo[NcchRegion_ExHeader].size = mHeader.header.exhdr_size.unwrap() + sizeof(ntd::n3ds::AccessDescriptor);
		mRegionInfo[NcchRegion_ExHeader].hashed_offset = 0;
		mRegionInfo[NcchRegion_ExHeader].hashed_size = mHeader.header.exhdr_size.unwrap();
	}
	if (mHeader.header.format_version.unwrap() == ntd::n3ds::NcchCommonHeader::FormatVersion_CXI_PROTOTYPE && mHeader.header.exhdr_hash[0] != 0)
	{
		mRegionInfo[NcchRegion_ExHeader].offset = sizeof(ntd::n3ds::NcchHeader);
		mRegionInfo[NcchRegion_ExHeader].size = sizeof(ntd::n3ds::ExtendedHeader) + sizeof(ntd::n3ds::AccessDescriptor);
		mRegionInfo[NcchRegion_ExHeader].hashed_offset = 0;
		mRegionInfo[NcchRegion_ExHeader].hashed_size = mHeader.header.exhdr_size.unwrap();
	}
	if (mHeader.header.plain_region_blk_size.unwrap() > 0)
	{
		mRegionInfo[NcchRegion_PlainRegion].offset = mHeader.header.plain_region_blk_offset.unwrap() * mBlockSize;
		mRegionInfo[NcchRegion_PlainRegion].size = mHeader.header.plain_region_blk_size.unwrap() * mBlockSize;
		mRegionInfo[NcchRegion_PlainRegion].hashed_offset = 0;
		mRegionInfo[NcchRegion_PlainRegion].hashed_size = 0;
	}
	if (mHeader.header.logo_blk_size.unwrap() > 0)
	{
		mRegionInfo[NcchRegion_Logo].offset = mHeader.header.logo_blk_offset.unwrap() * mBlockSize;
		mRegionInfo[NcchRegion_Logo].size = mHeader.header.logo_blk_size.unwrap() * mBlockSize;
		mRegionInfo[NcchRegion_Logo].hashed_offset = 0;
		mRegionInfo[NcchRegion_Logo].hashed_size = mRegionInfo[NcchRegion_Logo].size;
	}
	if (mHeader.header.exefs_blk_size.unwrap() > 0)
	{
		mRegionInfo[NcchRegion_ExeFs].offset = mHeader.header.exefs_blk_offset.unwrap() * mBlockSize;
		mRegionInfo[NcchRegion_ExeFs].size = mHeader.header.exefs_blk_size.unwrap() * mBlockSize;
		mRegionInfo[NcchRegion_ExeFs].hashed_offset = 0;
		mRegionInfo[NcchRegion_ExeFs].hashed_size = mHeader.header.exefs_prot_blk_size.unwrap() * mBlockSize;
	}
	if (mHeader.header.romfs_blk_size.unwrap() > 0)
	{
		mRegionInfo[NcchRegion_RomFs].offset = mHeader.header.romfs_blk_offset.unwrap() * mBlockSize;
		mRegionInfo[NcchRegion_RomFs].size = mHeader.header.romfs_blk_size.unwrap() * mBlockSize;
		mRegionInfo[NcchRegion_RomFs].hashed_offset = 0;
		mRegionInfo[NcchRegion_RomFs].hashed_size = mHeader.header.romfs_prot_blk_size.unwrap() * mBlockSize;
	}
	
	// create raw streams
	for (size_t i = 0; i < NcchRegionNum; i++)
	{
		if (mRegionInfo[i].size)
		{
			mRegionInfo[i].raw_stream = std::make_shared<tc::io::SubStream>(tc::io::SubStream(mInputStream, mRegionInfo[i].offset, mRegionInfo[i].size));
			// plain region & header are never encrypted
			if (i == NcchRegion_PlainRegion || i == NcchRegion_Header || i == NcchRegion_Logo)
			{
				mRegionInfo[i].ready_stream = mRegionInfo[i].raw_stream;
			}
		}
	}
}


void ctrtool::NcchProcess::determineRegionEncryption()
{
	// quick test to determine if the crypto layer has been stripped by tools like GodMode9, not strictly required, but this matches classic ctrtool behaviour
	bool crypto_is_stripped = false;
	if (mRegionInfo[NcchRegion_ExHeader].size >= sizeof(ntd::n3ds::ExtendedHeader) && mHeader.header.flags.other_flag.test(ntd::n3ds::NcchCommonHeader::OtherFlag_NoEncryption) == false)
	{
		std::array<byte_t, tc::crypto::Sha256Generator::kHashSize> exheader_hash;
		tc::ByteData exheader_data = tc::ByteData(sizeof(ntd::n3ds::ExtendedHeader));
		mRegionInfo[NcchRegion_ExHeader].raw_stream->seek(0, tc::io::SeekOrigin::Begin);
		mRegionInfo[NcchRegion_ExHeader].raw_stream->read(exheader_data.data(), exheader_data.size());
	
		tc::crypto::GenerateSha256Hash(exheader_hash.data(), exheader_data.data(), exheader_data.size());
		crypto_is_stripped = memcmp(exheader_hash.data(), mHeader.header.exhdr_hash.data(), exheader_hash.size()) == 0;
	}
	if (crypto_is_stripped)
	{
		fmt::print(stderr, "[{} ERROR] NCCH appears to be decrypted, contrary to header flags.\n", mModuleLabel);
	}

	// determine encryption mode
	if (mHeader.header.flags.other_flag.test(ntd::n3ds::NcchCommonHeader::OtherFlag_NoEncryption) || mPlain || crypto_is_stripped)
	{
		// set ready streams to be not encrypted
		for (size_t i = 0; i < NcchRegionNum; i++)
		{
			if (mRegionInfo[i].size && mRegionInfo[i].ready_stream == nullptr && mRegionInfo[i].raw_stream != nullptr)
			{
				mRegionInfo[i].ready_stream = mRegionInfo[i].raw_stream;
			}
		}
	}
	else
	{
		struct KeySlot
		{
			byte_t valid_x;
			KeyBag::Aes128Key x;
			byte_t valid_y;
			KeyBag::Aes128Key y;
			byte_t valid_key;
			KeyBag::Aes128Key key;
		} keyslot[2];

		keyslot[0].valid_x = ValidState::Unchecked;
		keyslot[0].valid_y = ValidState::Unchecked;
		keyslot[0].valid_key = ValidState::Unchecked;
		keyslot[1].valid_x = ValidState::Unchecked;
		keyslot[1].valid_y = ValidState::Unchecked;
		keyslot[1].valid_key = ValidState::Unchecked;

		// if fixed AES key
		if (mHeader.header.flags.other_flag.test(ntd::n3ds::NcchCommonHeader::OtherFlag_FixedAesKey))
		{
			// set AES keys to fixed key

			// load aes keys
			auto key_itr = mKeyBag.ncch_fixed_key.find(isSystemTitle() ? mKeyBag.NCCH_SYSTEM_FIXED_KEY : mKeyBag.NCCH_APPLICATION_FIXED_KEY);
			if (key_itr == mKeyBag.ncch_fixed_key.end())
			{
				keyslot[0].valid_key = ValidState::Fail;
				keyslot[1].valid_key = ValidState::Fail;

				fmt::print(stderr, "[{} ERROR] Could not load {} fixed key.\n", mModuleLabel, (isSystemTitle()? "system" : "application"));
			}

			// save keys
			keyslot[0].key = key_itr->second;
			keyslot[1].key = key_itr->second;

			keyslot[0].valid_key = ValidState::Good;
			keyslot[1].valid_key = ValidState::Good;

		}
		else
		{
			// keyslot[0]
			// load key_x
			auto keyx_itr = mKeyBag.ncch_secure_key_x.find(0);
			if (keyx_itr == mKeyBag.ncch_secure_key_x.end())
			{
				keyslot[0].valid_x = ValidState::Fail;

				fmt::print(stderr, "[{} ERROR] Could not load secure key_x[0x{:02x}].\n", mModuleLabel, 0);
			}
			else
			{
				keyslot[0].x = keyx_itr->second;

				keyslot[0].valid_x = ValidState::Good;
			}
			
			// load key_y
			memcpy(keyslot[0].y.data(), mHeader.signature.data(), keyslot[0].y.size());
			keyslot[0].valid_y = ValidState::Good;
			
			// keyslot[1]
			// load key_x
			byte_t security_version = mHeader.header.flags.security_version;
			keyx_itr = mKeyBag.ncch_secure_key_x.find(security_version);
			if (keyx_itr == mKeyBag.ncch_secure_key_x.end())
			{
				keyslot[1].valid_x = ValidState::Fail;

				fmt::print(stderr, "[{} ERROR] Could not load secure key_x[0x{:02x}].\n", mModuleLabel, security_version);
			}
			else
			{
				keyslot[1].x = keyx_itr->second;

				keyslot[1].valid_x = ValidState::Good;
			}
			
			memcpy(keyslot[1].x.data(), keyx_itr->second.data(), keyslot[1].x.size());

			// load key_y
			if (mHeader.header.flags.other_flag.test(ntd::n3ds::NcchCommonHeader::OtherFlag_SeededAesKeyY))
			{
				tc::crypto::Sha256Generator hashgen;
				std::array<byte_t, tc::crypto::Sha256Generator::kHashSize> hash;

				// import seed
				KeyBag::Aes128Key seed;
				auto seed_itr = mKeyBag.seed_db.find(mHeader.header.program_id.unwrap());
				if (seed_itr != mKeyBag.seed_db.end())
				{
					memcpy(seed.data(), seed_itr->second.data(), seed.size());
				}
				else if (mKeyBag.fallback_seed.isSet())
				{
					memcpy(seed.data(), mKeyBag.fallback_seed.get().data(), seed.size());
				}
				else
				{
					keyslot[1].valid_y = ValidState::Fail;

					fmt::print(stderr, "[{} ERROR] This title uses seed crypto, but no seed is set, unable to decrypt.\n", mModuleLabel);
					fmt::print(stderr, "         Use -p to avoid decryption or use --seeddb=dbfile or --seed=SEEDHERE.\n");
				}

				if (keyslot[1].valid_y != ValidState::Fail)
				{
					// validate seed
					hashgen.initialize();
					hashgen.update(seed.data(), seed.size());
					hashgen.update((byte_t*)&mHeader.header.program_id, sizeof(mHeader.header.program_id));
					hashgen.getHash(hash.data());
					if (memcmp(hash.data(), mHeader.header.seed_checksum.data(), mHeader.header.seed_checksum.size()) != 0)
					{
						keyslot[1].valid_y = ValidState::Fail;

						fmt::print(stderr, "[{} ERROR] Seed check mismatch. (Got {:08x}, expected: {:08x})\n",
							mModuleLabel,
							((tc::bn::be32<uint32_t>*)hash.data())->unwrap(),
							((tc::bn::be32<uint32_t>*)mHeader.header.seed_checksum.data())->unwrap());
					}
				}

				if (keyslot[1].valid_y != ValidState::Fail)
				{
					// generate seeded key_y
					hashgen.initialize();
					hashgen.update(keyslot[0].y.data(), keyslot[0].y.size());
					hashgen.update(seed.data(), seed.size());
					hashgen.getHash(hash.data());

					memcpy(keyslot[1].y.data(), hash.data(), keyslot[1].y.size());
					keyslot[1].valid_y = ValidState::Good;
				}
			}
			else
			{
				memcpy(keyslot[1].y.data(), mHeader.signature.data(), keyslot[1].y.size());
				keyslot[1].valid_y = ValidState::Good;
			}
			
			// generate secure keys
			if (keyslot[0].valid_x == ValidState::Good && keyslot[0].valid_y == ValidState::Good)
			{
				ntd::n3ds::CtrKeyGenerator::GenerateKey(keyslot[0].x.data(), keyslot[0].y.data(), keyslot[0].key.data());
				keyslot[0].valid_key = ValidState::Good;
			}
			else
			{
				keyslot[0].valid_key = ValidState::Fail;
			}

			if (keyslot[1].valid_x == ValidState::Good && keyslot[1].valid_y == ValidState::Good)
			{
				ntd::n3ds::CtrKeyGenerator::GenerateKey(keyslot[1].x.data(), keyslot[1].y.data(), keyslot[1].key.data());
				keyslot[1].valid_key = ValidState::Good;
			}
			else
			{
				keyslot[1].valid_key = ValidState::Fail;
			}	
		}

		// output keys if required
		if (mVerbose)
		{
			fmt::print(stderr, "[{} LOG] NCCH AES Key0 {}\n", mModuleLabel, (keyslot[0].valid_key ? tc::cli::FormatUtil::formatBytesAsString(keyslot[0].key.data(), keyslot[0].key.size(), true, "") : "could not be determined"));
			fmt::print(stderr, "[{} LOG] NCCH AES Key1 {}\n", mModuleLabel, (keyslot[1].valid_key ? tc::cli::FormatUtil::formatBytesAsString(keyslot[1].key.data(), keyslot[1].key.size(), true, "") : "could not be determined"));
		}

		// generate aes counter
		KeyBag::Aes128Key exheader_aesctr, exefs_aesctr, romfs_aesctr;
		if (mRegionInfo[NcchRegion_ExHeader].size)
		{
			getAesCounter(exheader_aesctr.data(), NcchRegion_ExHeader);

			if (mVerbose)
			{
				fmt::print(stderr, "[{} LOG] NCCH ExHeader AES Counter {}\n", mModuleLabel, tc::cli::FormatUtil::formatBytesAsString(exheader_aesctr.data(), exheader_aesctr.size(), true, ""));
			}
		}
		if (mRegionInfo[NcchRegion_ExeFs].size)
		{
			getAesCounter(exefs_aesctr.data(), NcchRegion_ExeFs);

			if (mVerbose)
			{
				fmt::print(stderr, "[{} LOG] NCCH ExeFS AES Counter {}\n", mModuleLabel, tc::cli::FormatUtil::formatBytesAsString(exefs_aesctr.data(), exefs_aesctr.size(), true, ""));
			}
		}
		if (mRegionInfo[NcchRegion_RomFs].size)
		{
			getAesCounter(romfs_aesctr.data(), NcchRegion_RomFs);

			if (mVerbose)
			{
				fmt::print(stderr, "[{} LOG] NCCH RomFS AES Counter {}\n", mModuleLabel, tc::cli::FormatUtil::formatBytesAsString(romfs_aesctr.data(), romfs_aesctr.size(), true, ""));
			}
		}

		// prepare ready_stream using encryption streams if keys are available
		if (mRegionInfo[NcchRegion_ExHeader].size && keyslot[0].valid_key == ValidState::Good)
		{
			mRegionInfo[NcchRegion_ExHeader].ready_stream = std::shared_ptr<tc::crypto::Aes128CtrEncryptedStream>(new tc::crypto::Aes128CtrEncryptedStream(mRegionInfo[NcchRegion_ExHeader].raw_stream, keyslot[0].key, exheader_aesctr));
		}
		if (mRegionInfo[NcchRegion_ExeFs].size && keyslot[0].valid_key == ValidState::Good)
		{
			// if key[1] is valid create the correct mixed key stream
			if (keyslot[1].valid_key == ValidState::Good)
			{
				// if the keys are the same, don't over complicate the encrypted stream
				if (false)//(memcmp(keyslot[0].key.data(), keyslot[1].key.data(), keyslot[0].key.size()) == 0)
				{
					mRegionInfo[NcchRegion_ExeFs].ready_stream = std::shared_ptr<tc::crypto::Aes128CtrEncryptedStream>(new tc::crypto::Aes128CtrEncryptedStream(mRegionInfo[NcchRegion_ExeFs].raw_stream, keyslot[0].key, exefs_aesctr));
				}
				else
				{
					// import ExeFs header
					if (mRegionInfo[NcchRegion_ExeFs].raw_stream->length() < sizeof(ntd::n3ds::ExeFsHeader))
					{
						throw tc::InvalidOperationException(mModuleLabel, "Stream is too small (cannot import ExeFsHeader).");
					}
					ntd::n3ds::ExeFsHeader exefs_hdr;
					mRegionInfo[NcchRegion_ExeFs].raw_stream->seek(0, tc::io::SeekOrigin::Begin);
					mRegionInfo[NcchRegion_ExeFs].raw_stream->read((byte_t*)&exefs_hdr, sizeof(exefs_hdr));

					tc::crypto::DecryptAes128Ctr((byte_t*)&exefs_hdr, (byte_t*)&exefs_hdr, sizeof(exefs_hdr), 0, keyslot[0].key.data(), keyslot[0].key.size(), exefs_aesctr.data(), exefs_aesctr.size());

					// quick header validation
					if (exefs_hdr.file_table[0].name[0] == 0 ||
					    exefs_hdr.file_table[0].offset.unwrap() != 0)
					{
						throw tc::ArgumentOutOfRangeException(mModuleLabel, "ExeFsHeader is corrupted (Bad first entry).");
					}

					// create key maps
					std::vector<std::shared_ptr<tc::io::IStream>> exefs_streams;
					exefs_streams.push_back(std::make_shared<tc::crypto::Aes128CtrEncryptedStream>(tc::crypto::Aes128CtrEncryptedStream(std::make_shared<tc::io::SubStream>(tc::io::SubStream(mRegionInfo[NcchRegion_ExeFs].raw_stream, 0x0, sizeof(ntd::n3ds::ExeFsHeader))), keyslot[0].key, exefs_aesctr)));
					byte_t keyslot_index;
					for (size_t i = 0; i < exefs_hdr.kFileNum; i++)
					{
						std::string file_name = exefs_hdr.file_table[i].name.decode();
						int64_t file_offset = sizeof(ntd::n3ds::ExeFsHeader) + int64_t(exefs_hdr.file_table[i].offset.unwrap());
						int64_t file_length = align<int64_t>(exefs_hdr.file_table[i].size.unwrap(), exefs_hdr.kExeFsSectionAlignSize);

						// skip empty sections
						if (exefs_hdr.file_table[i].size.unwrap() == 0)
							continue;

						// determine range based on name
						if (file_name == "icon" || file_name == "banner")
						{
							// old key
							keyslot_index = 0;
						}
						else
						{
							// new key
							keyslot_index = 1;
						}

						tc::crypto::Aes128CtrEncryptedStream::counter_t file_counter;
						memcpy(file_counter.data(), exefs_aesctr.data(), exefs_aesctr.size());
						tc::crypto::IncrementCounterAes128Ctr(file_counter.data(), file_offset >> 4);
						exefs_streams.push_back(std::make_shared<tc::crypto::Aes128CtrEncryptedStream>(tc::crypto::Aes128CtrEncryptedStream(std::make_shared<tc::io::SubStream>(tc::io::SubStream(mRegionInfo[NcchRegion_ExeFs].raw_stream, file_offset, file_length)), keyslot[keyslot_index].key, file_counter)));
					}
					mRegionInfo[NcchRegion_ExeFs].ready_stream = std::make_shared<tc::io::ConcatenatedStream>(tc::io::ConcatenatedStream(exefs_streams));
				}
			}
			// otherwise use the "best-effort" single key stream (only icon and banner will be decrypt properly)
			else
			{
				fmt::print(stderr, "[{} ERROR] Only NCCH key0 was determined, ExeFS may be partially decrypted\n", mModuleLabel);
				mRegionInfo[NcchRegion_ExeFs].ready_stream = std::shared_ptr<tc::crypto::Aes128CtrEncryptedStream>(new tc::crypto::Aes128CtrEncryptedStream(mRegionInfo[NcchRegion_ExeFs].raw_stream, keyslot[0].key, exefs_aesctr));
			}
		}
		if (mRegionInfo[NcchRegion_RomFs].size && keyslot[1].valid_key == ValidState::Good)
		{
			mRegionInfo[NcchRegion_RomFs].ready_stream = std::shared_ptr<tc::crypto::Aes128CtrEncryptedStream>(new tc::crypto::Aes128CtrEncryptedStream(mRegionInfo[NcchRegion_RomFs].raw_stream, keyslot[1].key, romfs_aesctr));
		}
	}
}


void ctrtool::NcchProcess::verifyRegions()
{
	tc::crypto::Sha256Generator hash_calc;
	using Sha256Hash = std::array<byte_t, hash_calc.kHashSize>;
	std::array<Sha256Hash, NcchRegionNum> region_hashes;
	tc::ByteData cache = tc::ByteData(0x10000);
	size_t cache_read_len = 0;

	// generate region sha2-256 hashes
	for (size_t i = 0; i < mRegionInfo.size(); i++)
	{
		if (mRegionInfo[i].hashed_size > 0 && mRegionInfo[i].ready_stream != nullptr)
		{
			// seek ready_stream to hashed_offset
			mRegionInfo[i].ready_stream->seek(mRegionInfo[i].hashed_offset, tc::io::SeekOrigin::Begin);

			// init hash calc
			hash_calc.initialize();

			// update hash with cache reads
			for (int64_t remaining_data = mRegionInfo[i].hashed_size; remaining_data > 0; remaining_data -= int64_t(cache_read_len))
			{
				cache_read_len = size_t(std::min<int64_t>(cache.size(), remaining_data));
				cache_read_len = mRegionInfo[i].ready_stream->read(cache.data(), cache_read_len);
				if (cache_read_len == 0)
				{
					throw tc::io::IOException(mModuleLabel, "Failed to read from NCCH region file.");
				}

				hash_calc.update(cache.data(), cache_read_len);
			}
			
			// save hash
			hash_calc.getHash(region_hashes[i].data());
		}
	}
	
	// header signature
	if (mRegionInfo[NcchRegion_Header].hashed_size > 0)
	{
		// verify hash using CFA key
		if (mHeader.header.flags.content_flag.form_type == mHeader.header.FormType_SimpleContent)
		{
			auto rsakey_itr = mKeyBag.rsa_key.find(mKeyBag.RSAKEY_CFA_CCI);
			if (rsakey_itr != mKeyBag.rsa_key.end())
			{
				tc::crypto::RsaKey pubkey = rsakey_itr->second;

				mRegionInfo[NcchRegion_Header].valid = tc::crypto::VerifyRsa2048Pkcs1Sha256(mHeader.signature.data(), region_hashes[NcchRegion_Header].data(), pubkey) ? ValidState::Good : ValidState::Fail;
			}
			else
			{
				// cannot locate rsa key to verify
				fmt::print(stderr, "[{} ERROR] Could not load CFA RSA2048 public key.\n", mModuleLabel);
				mRegionInfo[NcchRegion_Header].valid = ValidState::Fail;
			}
			
		}
		// verify hash using CXI key from exheader
		else
		{
			if (mRegionInfo[NcchRegion_ExHeader].size > 0 && mRegionInfo[NcchRegion_ExHeader].ready_stream != nullptr)
			{
				// import exheader
				tc::ByteData exheader_data = tc::ByteData(mRegionInfo[NcchRegion_ExHeader].size);
				mRegionInfo[NcchRegion_ExHeader].ready_stream->seek(0, tc::io::SeekOrigin::Begin);
				mRegionInfo[NcchRegion_ExHeader].ready_stream->read(exheader_data.data(), exheader_data.size());
				ntd::n3ds::AccessDescriptor* accessdesc = (ntd::n3ds::AccessDescriptor*)(exheader_data.data() + sizeof(ntd::n3ds::ExtendedHeader));

				// create public key from access desc
				tc::crypto::RsaKey pubkey = tc::crypto::RsaPublicKey(accessdesc->ncch_rsa_modulus.data(), accessdesc->ncch_rsa_modulus.size());

				// verify header signature
				mRegionInfo[NcchRegion_Header].valid = tc::crypto::VerifyRsa2048Pkcs1Sha256(mHeader.signature.data(), region_hashes[NcchRegion_Header].data(), pubkey) ? ValidState::Good : ValidState::Fail;
			}
			else
			{
				// cannot locate rsa key to verify
				fmt::print(stderr, "[{} ERROR] Could not load CXI RSA2048 public key from AccessDescriptor.\n", mModuleLabel);
				mRegionInfo[NcchRegion_Header].valid = ValidState::Fail;
			}
		}

		if (mRegionInfo[NcchRegion_Header].valid != ValidState::Good)
		{
			fmt::print(stderr, "[{} ERROR] Signature for NcchHeader was invalid.\n", mModuleLabel);
		}
	}

	// exheader hash
	if (mRegionInfo[NcchRegion_ExHeader].hashed_size > 0)
	{
		mRegionInfo[NcchRegion_ExHeader].valid = memcmp(region_hashes[NcchRegion_ExHeader].data(), mHeader.header.exhdr_hash.data(), region_hashes[NcchRegion_ExHeader].size()) == 0 ? ValidState::Good : ValidState::Fail;
	
		if (mRegionInfo[NcchRegion_ExHeader].valid != ValidState::Good)
		{
			fmt::print(stderr, "[{} ERROR] ExtendedHeader SHA2-256 hash was invalid.\n", mModuleLabel);
		}
	}

	// logo hash
	if (mRegionInfo[NcchRegion_Logo].hashed_size > 0)
	{
		mRegionInfo[NcchRegion_Logo].valid = memcmp(region_hashes[NcchRegion_Logo].data(), mHeader.header.logo_hash.data(), region_hashes[NcchRegion_Logo].size()) == 0 ? ValidState::Good : ValidState::Fail;
	
		if (mRegionInfo[NcchRegion_Logo].valid != ValidState::Good)
		{
			fmt::print(stderr, "[{} ERROR] Logo SHA2-256 hash was invalid.\n", mModuleLabel);
		}
	}

	// exefs hash
	if (mRegionInfo[NcchRegion_ExeFs].hashed_size > 0)
	{
		mRegionInfo[NcchRegion_ExeFs].valid = memcmp(region_hashes[NcchRegion_ExeFs].data(), mHeader.header.exefs_prot_hash.data(), region_hashes[NcchRegion_ExeFs].size()) == 0 ? ValidState::Good : ValidState::Fail;
	
		if (mRegionInfo[NcchRegion_ExeFs].valid != ValidState::Good)
		{
			fmt::print(stderr, "[{} ERROR] ExeFs SuperBlock SHA2-256 hash was invalid.\n", mModuleLabel);
		}
	}

	// romfs hash
	if (mRegionInfo[NcchRegion_RomFs].hashed_size > 0)
	{
		mRegionInfo[NcchRegion_RomFs].valid = memcmp(region_hashes[NcchRegion_RomFs].data(), mHeader.header.romfs_prot_hash.data(), region_hashes[NcchRegion_RomFs].size()) == 0 ? ValidState::Good : ValidState::Fail;
	
		if (mRegionInfo[NcchRegion_RomFs].valid != ValidState::Good)
		{
			fmt::print(stderr, "[{} ERROR] RomFs SuperBlock SHA2-256 hash was invalid.\n", mModuleLabel);
		}
	}
}

void ctrtool::NcchProcess::printHeader()
{
	fmt::print("\n");
	fmt::print("NCCH:\n");
	fmt::print("Header:                 {}\n", "NCCH");
	fmt::print("Signature: {:6}       {}", getValidString(mRegionInfo[NcchRegion_Header].valid), tc::cli::FormatUtil::formatBytesAsStringWithLineLimit(mHeader.signature.data(), mHeader.signature.size(), true, "", 0x20, 24, false));
	fmt::print("Content size:           0x{:08x}\n", mHeader.header.content_blk_size.unwrap() * mBlockSize);
	fmt::print("Title id:               {:016x}\n", mHeader.header.content_id.unwrap());
	fmt::print("Maker code:             {}\n", mHeader.header.maker_code.decode());
	fmt::print("FormatVersion:          {:d}\n", mHeader.header.format_version.unwrap());
	fmt::print("Title seed check:       {}\n", tc::cli::FormatUtil::formatBytesAsString(mHeader.header.seed_checksum.data(), mHeader.header.seed_checksum.size(), true, ""));
	fmt::print("Program id:             {:016x}\n", mHeader.header.program_id.unwrap());
	fmt::print("Logo hash: {:6}       {}\n", getValidString(mRegionInfo[NcchRegion_Logo].valid), tc::cli::FormatUtil::formatBytesAsString(mHeader.header.logo_hash.data(), mHeader.header.logo_hash.size(), true, ""));
	fmt::print("Product code:           {}\n",  mHeader.header.product_code.decode());
	fmt::print("Exheader size:          0x{:x}\n", mHeader.header.exhdr_size.unwrap());
	fmt::print("Exheader hash: {:6}   {}\n", getValidString(mRegionInfo[NcchRegion_ExHeader].valid), tc::cli::FormatUtil::formatBytesAsString(mHeader.header.exhdr_hash.data(), mHeader.header.exhdr_hash.size(), true, ""));
	fmt::print("Flags:                  {}\n", tc::cli::FormatUtil::formatBytesAsString(mHeader.header.flags.data(), mHeader.header.flags.size(), true, ""));

	// crypto key
	fmt::print(" > Crypto Key           ");
	if (mHeader.header.flags.other_flag.test(ntd::n3ds::NcchCommonHeader::OtherFlag_NoEncryption))
	{
		fmt::print("None");
	}
	else if (mHeader.header.flags.other_flag.test(ntd::n3ds::NcchCommonHeader::OtherFlag_FixedAesKey))
	{
		fmt::print("Fixed ({})", (isSystemTitle() ? "System" : "Application"));
	}
	else
	{
		fmt::print("Secure ({:d})", (uint32_t)mHeader.header.flags.security_version);
		if (mHeader.header.flags.other_flag.test(ntd::n3ds::NcchCommonHeader::OtherFlag_SeededAesKeyY))
		{
			fmt::print(" (KeyY seeded)");
		}
	}
	fmt::print("\n");

	std::vector<std::string> content_platforms;
	for (size_t bit = 0; bit < mHeader.header.flags.content_platform.bit_size(); bit++)
	{
		if (mHeader.header.flags.content_platform.test(bit))
		{
			content_platforms.push_back(getContentPlatformString(bit));
		}
	}
	fmt::print(" > ContentPlatorm:      {}", tc::cli::FormatUtil::formatListWithLineLimit(content_platforms, 4, 24, false));

	fmt::print(" > FormType:            {}\n", getFormTypeString(mHeader.header.flags.content_flag.form_type));
	fmt::print(" > ContentType:         {}\n", getContentTypeString(mHeader.header.flags.content_flag.content_type));
	fmt::print(" > BlockSize:           0x{:x}\n", mBlockSize);
	if (mHeader.header.flags.other_flag.test(ntd::n3ds::NcchCommonHeader::OtherFlag_NoMountRomFS))
		fmt::print(" > No RomFS mount\n");
	if (mHeader.header.flags.other_flag.test(ntd::n3ds::NcchCommonHeader::OtherFlag_ManualDisclosure))
		fmt::print(" > Disclose eManual\n");

	fmt::print("Plain region offset:    0x{:08x}\n", mHeader.header.plain_region_blk_offset.unwrap() * mBlockSize);
	fmt::print("Plain region size:      0x{:08x}\n", mHeader.header.plain_region_blk_size.unwrap() * mBlockSize);
	fmt::print("Logo offset:            0x{:08x}\n", mHeader.header.logo_blk_offset.unwrap() * mBlockSize);
	fmt::print("Logo size:              0x{:08x}\n", mHeader.header.logo_blk_size.unwrap() * mBlockSize);
	fmt::print("ExeFS offset:           0x{:08x}\n", mHeader.header.exefs_blk_offset.unwrap() * mBlockSize);
	fmt::print("ExeFS size:             0x{:08x}\n", mHeader.header.exefs_blk_size.unwrap() * mBlockSize);
	fmt::print("ExeFS hash region size: 0x{:08x}\n", mHeader.header.exefs_prot_blk_size.unwrap() * mBlockSize);
	fmt::print("RomFS offset:           0x{:08x}\n", mHeader.header.romfs_blk_offset.unwrap() * mBlockSize);
	fmt::print("RomFS size:             0x{:08x}\n", mHeader.header.romfs_blk_size.unwrap() * mBlockSize);
	fmt::print("RomFS hash region size: 0x{:08x}\n", mHeader.header.romfs_prot_blk_size.unwrap() * mBlockSize);
	fmt::print("ExeFS hash: {:6}      {}\n", getValidString(mRegionInfo[NcchRegion_ExeFs].valid), tc::cli::FormatUtil::formatBytesAsString(mHeader.header.exefs_prot_hash.data(), mHeader.header.exefs_prot_hash.size(), true, ""));
	fmt::print("RomFS hash: {:6}      {}\n", getValidString(mRegionInfo[NcchRegion_RomFs].valid), tc::cli::FormatUtil::formatBytesAsString(mHeader.header.romfs_prot_hash.data(), mHeader.header.romfs_prot_hash.size(), true, ""));
}

void ctrtool::NcchProcess::extractRegionBinaries()
{
	/*
	original order
		ncch_save(ctx, NCCHTYPE_EXEFS, actions);
		ncch_save(ctx, NCCHTYPE_ROMFS, actions);
		ncch_save(ctx, NCCHTYPE_EXHEADER, actions);
		ncch_save(ctx, NCCHTYPE_LOGO, actions);
		ncch_save(ctx, NCCHTYPE_PLAINRGN, actions);
	*/

	tc::io::LocalFileSystem local_fs;
	tc::ByteData cache = tc::ByteData(0x10000);
	size_t cache_read_len;
	std::shared_ptr<tc::io::IStream> in_stream;
	std::shared_ptr<tc::io::IStream> out_stream;
	for (size_t i = 0; i < NcchRegionNum; i++)
	{
		if (mRegionOpt[i].bin_extract_path.isSet() && mRegionInfo[i].ready_stream != nullptr)
		{
			if (mVerbose)
			{
				switch(i)
				{
					case NcchRegion_Header: fmt::print(stderr, "[{} LOG] Saving Header...\n", mModuleLabel); break;
					case NcchRegion_ExHeader: fmt::print(stderr, "[{} LOG] Saving Extended Header...\n", mModuleLabel); break;
					case NcchRegion_PlainRegion: fmt::print(stderr, "[{} LOG] Saving Plain Region...\n", mModuleLabel); break;
					case NcchRegion_Logo: fmt::print(stderr, "[{} LOG] Saving Logo...\n", mModuleLabel); break;
					case NcchRegion_ExeFs: fmt::print(stderr, "[{} LOG] Saving ExeFs...\n", mModuleLabel); break;
					case NcchRegion_RomFs: fmt::print(stderr, "[{} LOG] Saving RomFs...\n", mModuleLabel); break;
				}
			}
			

			in_stream = mRegionInfo[i].ready_stream;
			local_fs.openFile(mRegionOpt[i].bin_extract_path.get(), tc::io::FileMode::OpenOrCreate, tc::io::FileAccess::Write, out_stream);

			in_stream->seek(0, tc::io::SeekOrigin::Begin);
			out_stream->seek(0, tc::io::SeekOrigin::Begin);
			for (int64_t remaining_data = in_stream->length(); remaining_data > 0;)
			{
				cache_read_len = in_stream->read(cache.data(), cache.size());
				if (cache_read_len == 0)
				{
					throw tc::io::IOException(mModuleLabel, "Failed to read from NCCH Region.");
				}

				out_stream->write(cache.data(), cache_read_len);

				remaining_data -= int64_t(cache_read_len);
			}
		}
	}
}

void ctrtool::NcchProcess::processRegions()
{
	if (mRegionInfo[NcchRegion_ExHeader].size != 0 && mRegionInfo[NcchRegion_ExHeader].ready_stream != nullptr)
	{
		ctrtool::ExHeaderProcess proc;
		proc.setInputStream(mRegionInfo[NcchRegion_ExHeader].ready_stream);
		proc.setKeyBag(mKeyBag);
		proc.setCliOutputMode(mRegionOpt[NcchRegion_ExHeader].show_info);
		proc.setVerboseMode(mVerbose);
		proc.setVerifyMode(mVerify);
		proc.setShowSyscallName(mShowSyscallNames);
		
		proc.process();
	}
	if (mRegionInfo[NcchRegion_ExeFs].size != 0 && mRegionInfo[NcchRegion_ExeFs].ready_stream != nullptr)
	{
		// prior to reading exefs, check compressed flag in exheader
		if (mRegionInfo[NcchRegion_ExHeader].size > 0 && mRegionInfo[NcchRegion_ExHeader].ready_stream != nullptr)
		{
			// import exheader			
			ntd::n3ds::ExtendedHeader exheader;
			mRegionInfo[NcchRegion_ExHeader].ready_stream->seek(0, tc::io::SeekOrigin::Begin);
			mRegionInfo[NcchRegion_ExHeader].ready_stream->read((byte_t*)&exheader, sizeof(ntd::n3ds::ExtendedHeader));

			mDecompressExeFsCode = exheader.system_control_info.flags.bitarray.test(ntd::n3ds::SystemControlInfo::Flags_CompressExefsPartition0);
		}

		ctrtool::ExeFsProcess proc;
		proc.setInputStream(mRegionInfo[NcchRegion_ExeFs].ready_stream);
		proc.setCliOutputMode(mRegionOpt[NcchRegion_ExeFs].show_info, mRegionOpt[NcchRegion_ExeFs].show_fs);
		proc.setVerboseMode(mVerbose);
		proc.setVerifyMode(mVerify);
		proc.setRawMode(mRaw);
		proc.setDecompressCode(mDecompressExeFsCode);
		if (mRegionOpt[NcchRegion_ExeFs].fs_extract_path.isSet())
		{
			proc.setExtractPath(mRegionOpt[NcchRegion_ExeFs].fs_extract_path.get());
		}
		proc.process();
	}
	if (mRegionInfo[NcchRegion_RomFs].size != 0 && mRegionInfo[NcchRegion_RomFs].ready_stream != nullptr)
	{
		ctrtool::IvfcProcess proc;
		proc.setInputStream(mRegionInfo[NcchRegion_RomFs].ready_stream);
		proc.setKeyBag(mKeyBag);
		proc.setCliOutputMode(mRegionOpt[NcchRegion_RomFs].show_info, mRegionOpt[NcchRegion_RomFs].show_fs);
		proc.setVerboseMode(mVerbose);
		proc.setVerifyMode(mVerify);
		if (mRegionOpt[NcchRegion_RomFs].fs_extract_path.isSet())
		{
			proc.setExtractPath(mRegionOpt[NcchRegion_RomFs].fs_extract_path.get());
		}
		proc.process();
	}
}

std::string ctrtool::NcchProcess::getValidString(byte_t validstate)
{
	std::string ret_str;

	switch (validstate)
	{
		case Unchecked:
			ret_str =  "";
			break;
		case Good:
			ret_str =  "(GOOD)";
			break;
		case Fail:
		default:
			ret_str =  "(FAIL)";
			break;
	}

	return ret_str;
}

std::string ctrtool::NcchProcess::getContentPlatformString(size_t bit)
{
	std::string ret_str;

	switch(bit)
	{
		case ntd::n3ds::NcchCommonHeader::ContentPlatform_CTR :
			ret_str = "CTR";
			break;
		case ntd::n3ds::NcchCommonHeader::ContentPlatform_SNAKE :
			ret_str = "SNAKE";
			break;
		default:
			ret_str = fmt::format("Unknown (bit {:d}", bit);
	}

	return ret_str;
}

std::string ctrtool::NcchProcess::getFormTypeString(byte_t var)
{
	std::string ret_str;

	switch(var)
	{
		case ntd::n3ds::NcchCommonHeader::FormType_Unassigned :
			ret_str = "Not Assigned";
			break;
		case ntd::n3ds::NcchCommonHeader::FormType_SimpleContent :
			ret_str = "Simple Content";
			break;
		case ntd::n3ds::NcchCommonHeader::FormType_ExecutableWithoutRomFS :
			ret_str = "Executable (without RomFS)";
			break;
		case ntd::n3ds::NcchCommonHeader::FormType_Executable :
			ret_str = "Executable";
			break;
		default:
			ret_str = "Unknown";
			break;
	}

	return ret_str;
}

std::string ctrtool::NcchProcess::getContentTypeString(byte_t var)
{
	std::string ret_str;

	switch(var)
	{
		case ntd::n3ds::NcchCommonHeader::ContentType_Application :
			ret_str = "Application";
			break;
		case ntd::n3ds::NcchCommonHeader::ContentType_SystemUpdate :
			ret_str = "System Update (CTR)";
			break;
		case ntd::n3ds::NcchCommonHeader::ContentType_Manual :
			ret_str = "Manual";
			break;
		case ntd::n3ds::NcchCommonHeader::ContentType_Child :
			ret_str = "Child";
			break;
		case ntd::n3ds::NcchCommonHeader::ContentType_Trial :
			ret_str = "Trial";
			break;
		case ntd::n3ds::NcchCommonHeader::ContentType_ExtendedSystemUpdate :
			ret_str = "System Update (SNAKE)";
			break;
		default:
			ret_str = "Unknown";
			break;
	}

	return ret_str;
}


bool ctrtool::NcchProcess::isSystemTitle()
{
	return (mHeader.header.content_id.unwrap() & 0x0000001000000000) != 0;
}

void ctrtool::NcchProcess::getAesCounter(byte_t* counter, byte_t ncch_region)
{
	uint16_t version = mHeader.header.format_version.unwrap();

	struct AesCounter_v0_v2
	{
		enum NcchTypeForCtr
		{
			NcchTypeForCtr_ExHeader = 1,
			NcchTypeForCtr_ExeFs = 2,
			NcchTypeForCtr_RomFs = 3
		};

		tc::bn::be64<uint64_t> title_id;
		byte_t type;
		std::array<byte_t, 7> block_bytes;
	};

	struct AesCounter_v1
	{
		tc::bn::le64<uint64_t> title_id;
		tc::bn::be64<uint64_t> begin_offset;
	};

	if (version == ntd::n3ds::NcchCommonHeader::FormatVersion_CFA || version == ntd::n3ds::NcchCommonHeader::FormatVersion_CXI)
	{
		AesCounter_v0_v2* tmp = (AesCounter_v0_v2*)counter;
		tmp->title_id.wrap(mHeader.header.content_id.unwrap());
		if (ncch_region == NcchRegion_ExHeader)
			tmp->type = tmp->NcchTypeForCtr_ExHeader;
		else if (ncch_region == NcchRegion_ExeFs)
			tmp->type = tmp->NcchTypeForCtr_ExeFs;
		else if (ncch_region == NcchRegion_RomFs)
			tmp->type = tmp->NcchTypeForCtr_RomFs;
		memset(tmp->block_bytes.data(), 0, tmp->block_bytes.size());
	}
	else if (version == ntd::n3ds::NcchCommonHeader::FormatVersion_CXI_PROTOTYPE)
	{
		AesCounter_v1* tmp = (AesCounter_v1*)counter;
		tmp->title_id.wrap(mHeader.header.content_id.unwrap());
		tmp->begin_offset.wrap(mRegionInfo[ncch_region].offset);
	}
}
