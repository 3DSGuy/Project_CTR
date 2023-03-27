#include "ExeFsProcess.h"
#include "lzss.h"
#include <tc/io.h>
#include <tc/cli.h>
#include <tc/crypto.h>
#include <tc/ArgumentNullException.h>

#include <ntd/n3ds/ExeFsSnapshotGenerator.h>

ctrtool::ExeFsProcess::ExeFsProcess() :
	mModuleLabel("ctrtool::ExeFsProcess"),
	mInputStream(),
	mShowHeaderInfo(false),
	mShowFs(false),
	mVerbose(false),
	mVerify(false),
	mRaw(false),
	mDecompressCode(false),
	mExtractPath(),
	mFsReader()
{
	memset((byte_t*)&mHeader, 0, sizeof(ntd::n3ds::ExeFsHeader));
	memset(mSectionValidation.data(), ValidState::Unchecked, mSectionValidation.size());
}

void ctrtool::ExeFsProcess::setInputStream(const std::shared_ptr<tc::io::IStream>& input_stream)
{
	mInputStream = input_stream;
}

void ctrtool::ExeFsProcess::setCliOutputMode(bool show_header_info, bool show_fs)
{
	mShowHeaderInfo = show_header_info;
	mShowFs = show_fs;
}

void ctrtool::ExeFsProcess::setVerboseMode(bool verbose)
{
	mVerbose = verbose;
}

void ctrtool::ExeFsProcess::setVerifyMode(bool verify)
{
	mVerify = verify;
}

void ctrtool::ExeFsProcess::setRawMode(bool raw)
{
	mRaw = raw;
}

void ctrtool::ExeFsProcess::setDecompressCode(bool decompress)
{
	mDecompressCode = decompress;
}

void ctrtool::ExeFsProcess::setExtractPath(const tc::io::Path& extract_path)
{
	mExtractPath = extract_path;
}

void ctrtool::ExeFsProcess::process()
{
	// begin processing
	importHeader();
	if (mVerify)
		verifyFs();
	if (mShowHeaderInfo)
		printHeader();
	if (mShowFs)
		printFs();
	if (mExtractPath.isSet())
		extractFs();
}

void ctrtool::ExeFsProcess::importHeader()
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
	if (mInputStream->length() < sizeof(ntd::n3ds::ExeFsHeader))
	{
		throw tc::InvalidOperationException(mModuleLabel, "Input stream too small.");
	}
	mInputStream->seek(0, tc::io::SeekOrigin::Begin);
	mInputStream->read((byte_t*)&mHeader, sizeof(ntd::n3ds::ExeFsHeader));

	// do some simple checks to verify if this is an EXEFS header
	if (mHeader.file_table[0].name[0] == 0 || mHeader.file_table[0].offset.unwrap() != 0)
	{
		throw tc::ArgumentOutOfRangeException(mModuleLabel, "ExeFsHeader is corrupted (Bad first entry).");
	}

	// create FileSystem reader (but don't verify the hashes, we'll do this if necessary to match ctrtool behaviour)
	mFsReader = std::shared_ptr<tc::io::VirtualFileSystem>(new tc::io::VirtualFileSystem(ntd::n3ds::ExeFsSnapshotGenerator(mInputStream, false)));
}

void ctrtool::ExeFsProcess::verifyFs()
{
	tc::crypto::Sha256Generator hash_calc;
	std::array<byte_t, hash_calc.kHashSize> hash;
	tc::ByteData cache = tc::ByteData(0x10000);

	for (size_t i = 0; i < ntd::n3ds::ExeFsHeader::kFileNum; i++)
	{
		if (mHeader.file_table[i].size.unwrap() > 0)
		{
			auto offset = mHeader.file_table[i].offset.unwrap() + sizeof(ntd::n3ds::ExeFsHeader);
			auto size = mHeader.file_table[i].size.unwrap();
			auto& hdr_hash = mHeader.hash_table[ntd::n3ds::ExeFsHeader::kFileNum - 1 - i];

			mInputStream->seek(offset, tc::io::SeekOrigin::Begin);
			hash_calc.initialize();
			for (size_t i = size; i > 0;)
			{
				size_t read_len = std::min<size_t>(i, cache.size());
				read_len = mInputStream->read(cache.data(), read_len);

				hash_calc.update(cache.data(), read_len);

				i -= read_len;
			}
			hash_calc.getHash(hash.data());

			mSectionValidation[i] = memcmp(hash.data(), hdr_hash.data(), hash.size()) == 0? ValidState::Good : ValidState::Fail;

			if (mSectionValidation[i] != ValidState::Good)
			{
				fmt::print(stderr, "[{} ERROR] ExeFs file \"{}\" had an invalid SHA2-256 hash.\n", mModuleLabel, mHeader.file_table[i].name.decode());
			}
		}
	}
}

void ctrtool::ExeFsProcess::printHeader()
{
	fmt::print("\n");
	fmt::print("ExeFS:\n");
	for (size_t i = 0; i < ntd::n3ds::ExeFsHeader::kFileNum; i++)
	{
		if (mHeader.file_table[i].size.unwrap() > 0)
		{
			const auto& name = mHeader.file_table[i].name;
			const auto& offset = mHeader.file_table[i].offset;
			const auto& size = mHeader.file_table[i].size;
			const auto& hash = mHeader.hash_table[ntd::n3ds::ExeFsHeader::kFileNum - 1 - i];

			fmt::print("Section name:           {}\n", name.decode());
			fmt::print("Section offset:         0x{:08x}\n", offset.unwrap() + sizeof(ntd::n3ds::ExeFsHeader));
			fmt::print("Section size:           0x{:08x}\n", size.unwrap());
			fmt::print("Section hash: {:6}    {}\n", getValidString(mSectionValidation[i]), tc::cli::FormatUtil::formatBytesAsString(hash.data(), hash.size(), true, ""));
		}
	}
}

void ctrtool::ExeFsProcess::printFs()
{
	tc::io::sDirectoryListing dir;
	mFsReader->getDirectoryListing(tc::io::Path("/"), dir);

	fmt::print("[ExeFs Filesystem]\n");
	fmt::print("  ExeFs:/\n");
	for (auto itr = dir.file_list.begin(); itr != dir.file_list.end(); itr++)
	{
		fmt::print("    {}\n", *itr);
	}
}

void ctrtool::ExeFsProcess::extractFs()
{
	tc::io::sDirectoryListing dir;

	mFsReader->getDirectoryListing(tc::io::Path("/"), dir);

	tc::io::LocalFileSystem local_fs;
	std::shared_ptr<tc::io::IStream> in_stream;
	std::shared_ptr<tc::io::IStream> out_stream;
	for (auto itr = dir.file_list.begin(); itr != dir.file_list.end(); itr++)
	{
		
		// open input stream
		mFsReader->openFile(*itr, tc::io::FileMode::Open, tc::io::FileAccess::Read, in_stream);

		// create output file name
		std::string f_name;
		if (itr->at(0) == '.')
			f_name = itr->substr(1, std::string::npos) + ".bin";
		else
			f_name = *itr + ".bin";

		// create output file path
		tc::io::Path f_path = mExtractPath.get() + f_name;

		// open out stream
		local_fs.createDirectory(mExtractPath.get());
		local_fs.openFile(f_path, tc::io::FileMode::OpenOrCreate, tc::io::FileAccess::Write, out_stream);

		if (*itr == ".code" && mDecompressCode && !mRaw)
		{
			tc::ByteData compdata = tc::ByteData(in_stream->length());
			in_stream->seek(0, tc::io::SeekOrigin::Begin);
			in_stream->read(compdata.data(), compdata.size());

			// get code hash, only decompress if hash is valid
			std::array<byte_t, tc::crypto::Sha256Generator::kHashSize> hash;
			tc::crypto::GenerateSha256Hash(hash.data(), compdata.data(), compdata.size());
			const byte_t* test_hash = nullptr;
			for (size_t i = 0; i < ntd::n3ds::ExeFsHeader::kFileNum; i++)
			{
				if (mHeader.file_table[i].name.decode() == *itr)
				{
					test_hash = mHeader.getFileHash(i)->data();
					break;
				}
			}
			if (test_hash != nullptr && memcmp(test_hash, hash.data(), hash.size()) == 0)
			{
				if (mVerbose)
				{
					fmt::print(stderr, "[{} LOG] Decompressing {} to {}...\n", mModuleLabel, *itr, f_path.to_string());
				}
				
				tc::ByteData decompdata = tc::ByteData(lzss_get_decompressed_size(compdata.data(), compdata.size()));
				lzss_decompress(compdata.data(), compdata.size(), decompdata.data(), decompdata.size());

				out_stream->seek(0, tc::io::SeekOrigin::Begin);
				out_stream->write(decompdata.data(), decompdata.size());
			}
			else
			{
				if (mVerbose)
				{
					fmt::print(stderr, "[{} LOG] Saving {} to {}...\n", mModuleLabel, *itr, f_path.to_string());
				}

				out_stream->seek(0, tc::io::SeekOrigin::Begin);
				out_stream->write(compdata.data(), compdata.size());
			}
		}
		else
		{
			if (mVerbose)
			{
				fmt::print(stderr, "[{} LOG] Saving {} to {}...\n", mModuleLabel, *itr, f_path.to_string());
			}
			
			tc::ByteData filedata = tc::ByteData(in_stream->length());
			in_stream->seek(0, tc::io::SeekOrigin::Begin);
			in_stream->read(filedata.data(), filedata.size());

			out_stream->seek(0, tc::io::SeekOrigin::Begin);
			out_stream->write(filedata.data(), filedata.size());
		}
		
	}
}

std::string ctrtool::ExeFsProcess::getValidString(byte_t validstate)
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
