#include <ntd/n3ds/ExeFsSnapshotGenerator.h>
#include <tc/io/SubStream.h>
#include <tc/crypto/Sha256Generator.h>
#include <tc/crypto/CryptoException.h>
#include <tc/io/MemoryStream.h>

#include <ntd/n3ds/exefs.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <tc/cli/FormatUtil.h>

ntd::n3ds::ExeFsSnapshotGenerator::ExeFsSnapshotGenerator(const std::shared_ptr<tc::io::IStream>& stream, bool verify_hashes) :
	FileSystemSnapshot()
{
	// validate stream properties
	if (stream == nullptr)
	{
		throw tc::ObjectDisposedException("ntd::n3ds::ExeFsSnapshotGenerator", "Failed to open input stream.");
	}
	if (stream->canRead() == false || stream->canSeek() == false)
	{
		throw tc::NotSupportedException("ntd::n3ds::ExeFsSnapshotGenerator", "Input stream requires read/seek permissions.");
	}

	// validate and read EXEFS header
	ntd::n3ds::ExeFsHeader hdr;
	if (stream->length() < sizeof(ntd::n3ds::ExeFsHeader))
	{
		throw tc::ArgumentOutOfRangeException("ntd::n3ds::ExeFsSnapshotGenerator", "Input stream is too small.");
	}
	stream->seek(0, tc::io::SeekOrigin::Begin);
	stream->read((byte_t*)(&hdr), sizeof(ntd::n3ds::ExeFsHeader));

	if (hdr.file_table[0].name[0] == 0 || hdr.file_table[0].offset.unwrap() != 0)
	{
		throw tc::ArgumentOutOfRangeException("ntd::n3ds::ExeFsSnapshotGenerator", "ExeFsHeader is corrupted (Bad first entry).");
	}

	// parse header sections
	struct SectionInformation
	{
		std::string name;
		uint32_t offset;
		uint32_t size;
		std::array<byte_t, 32> hash;
	};
	
	std::vector<SectionInformation> section;

	int64_t pos = 0;
	for (size_t i = 0; i < ntd::n3ds::ExeFsHeader::kFileNum; i++)
	{
		// skip empty entry
		if (hdr.file_table[i].name.size() == 0 || hdr.file_table[i].size.unwrap() == 0) { continue; }

		if (hdr.file_table[i].offset.unwrap() != pos)
		{
			throw tc::ArgumentOutOfRangeException("ntd::n3ds::ExeFsSnapshotGenerator", "ExeFs section had unexpected offset.");
		}

		SectionInformation tmp;
		tmp.name = hdr.file_table[i].name.decode();
		tmp.offset = hdr.file_table[i].offset.unwrap();
		tmp.size = hdr.file_table[i].size.unwrap();
		tmp.hash = hdr.hash_table[ntd::n3ds::ExeFsHeader::kFileNum - 1 - i];

		pos = align<int64_t>((static_cast<int64_t>(tmp.offset) + static_cast<int64_t>(tmp.size)), ntd::n3ds::ExeFsHeader::kExeFsSectionAlignSize);

		section.push_back(std::move(tmp));
	}

	// Add root directory
	dir_entries.push_back(DirEntry());
	auto cur_dir = &dir_entries.front();
	cur_dir->dir_listing.abs_path = tc::io::Path("/");
	dir_entry_path_map[tc::io::Path("/")] = dir_entries.size()-1;

	// populate virtual filesystem
	std::array<byte_t, tc::crypto::Sha256Generator::kHashSize> hash_tmp;
	for (size_t i = 0; i < section.size(); i++)
	{
		if (section[i].size != 0)
		{			
			FileEntry tmp;
			
			// if we verify the hashes, we import and validate file, after validation creating a memorystream
			if (verify_hashes)
			{	
				auto tmp_data = tc::ByteData(section[i].size);
				stream->seek(section[i].offset + sizeof(ntd::n3ds::ExeFsHeader), tc::io::SeekOrigin::Begin);
				stream->read(tmp_data.data(), tmp_data.size());

				tc::crypto::GenerateSha256Hash(hash_tmp.data(), tmp_data.data(), tmp_data.size());
				if (memcmp(hash_tmp.data(), section[i].hash.data(), hash_tmp.size()) != 0)
				{
					throw tc::crypto::CryptoException("ntd::n3ds::ExeFsSnapshotGenerator", "File failed hash check.");
				}

				tmp.stream = std::make_shared<tc::io::MemoryStream>(tc::io::MemoryStream(std::move(tmp_data)));				
			}
			// otherwise we just create a substream
			else
			{
				tmp.stream = std::make_shared<tc::io::SubStream>(tc::io::SubStream(stream, static_cast<int64_t>(section[i].offset) + static_cast<int64_t>(sizeof(ntd::n3ds::ExeFsHeader)), static_cast<int64_t>(section[i].size)));
			}

			// create file path
			tc::io::Path file_path = cur_dir->dir_listing.abs_path + section[i].name;

			// add file entry to list
			file_entries.push_back(std::move(tmp));

			// add file entry to map
			file_entry_path_map[file_path] = file_entries.size()-1;

			// add name to parent directory listing
			cur_dir->dir_listing.file_list.push_back(section[i].name);
		}
	}
}
