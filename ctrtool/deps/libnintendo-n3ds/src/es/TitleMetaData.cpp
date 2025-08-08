#include <ntd/n3ds/es/TitleMetaData.h>
#include <fmt/core.h>

#include <brd/es/es_tmd.h>
#include <tc/ByteData.h>
#include <tc/crypto/Sha256Generator.h>

ntd::n3ds::es::TitleMetaDataDeserialiser::TitleMetaDataDeserialiser(const std::shared_ptr<tc::io::IStream>& tmd_stream) :
	TitleMetaData(),
	mModuleLabel("ntd::n3ds::es::TitleMetaDataDeserialiser")
{
	if (tmd_stream == nullptr)
	{
		throw tc::ArgumentNullException(mModuleLabel, "TMD stream was null.");
	}

	if (tmd_stream->length() < (sizeof(brd::es::ESV1TitleMeta) + sizeof(brd::es::ESV1ContentMeta)))
	{
		throw tc::ArgumentOutOfRangeException(mModuleLabel, "TMD was too small.");
	}

	// import TMD v1 data (less the ESV1ContentMeta data)
	tc::ByteData tmd_data = tc::ByteData(sizeof(brd::es::ESV1TitleMeta));
	tmd_stream->seek(0, tc::io::SeekOrigin::Begin);
	if (tmd_stream->read(tmd_data.data(), tmd_data.size()) < tmd_data.size())
	{
		throw tc::ArgumentOutOfRangeException(mModuleLabel, "TMD had unexpected size after reading.");
	}


	// get pointer
	brd::es::ESV1TitleMeta* tmd = (brd::es::ESV1TitleMeta*)tmd_data.data();
	if (tmd->sig.sigType.unwrap() != brd::es::ESSigType::RSA2048_SHA256)
	{
		throw tc::ArgumentOutOfRangeException(mModuleLabel, "TMD had unexpected signature type.");
	}
	if (tmd->head.version != 1)
	{
		throw tc::ArgumentOutOfRangeException(mModuleLabel, "TMD had unexpected format version.");
	}

	/*
	std::cout << "[Tmd]" << std::endl;
	std::cout << "  > Issuer:            " << tmd->sig.issuer.data() << std::endl;
	std::cout << "  > Version:           " << (int)tmd->head.version << std::endl;
	std::cout << "  > CACrl Version:     " << (int)tmd->head.caCrlVersion << std::endl;
	std::cout << "  > SignerCrl Version: " << (int)tmd->head.signerCrlVersion << std::endl;
	std::cout << "  > TitleId:           " << std::hex << std::setfill('0') << std::setw(16) << tmd->head.titleId.unwrap() << std::endl;
	*/

	// determine if the TMD is the correct size given expected number of ESV1ContentMeta entries
	size_t total_contents_num = 0;
	size_t num_cmd_groups = 0;
	for (const auto &cmd_group : tmd->v1Head.cmdGroups)
	{
		if (cmd_group.nCmds.unwrap())
		{
			++num_cmd_groups;
			total_contents_num += cmd_group.nCmds.unwrap();
		}
	}

	size_t tmd_full_size = sizeof(brd::es::ESV1TitleMeta) + (total_contents_num * sizeof(brd::es::ESV1ContentMeta));

	if (tmd_stream->length() < (tmd_full_size))
	{
		throw tc::ArgumentOutOfRangeException(mModuleLabel, "TMD was too small.");
	}

	// import full TMD v1 data
	tmd_data = tc::ByteData(tmd_full_size);
	tmd_stream->seek(0, tc::io::SeekOrigin::Begin);
	if (tmd_stream->read(tmd_data.data(), tmd_data.size()) < tmd_data.size())
	{
		throw tc::ArgumentOutOfRangeException(mModuleLabel, "TMD had unexpected size after reading.");
	}
	// update tmd pointer
	tmd = (brd::es::ESV1TitleMeta*)tmd_data.data();

	// hash for staged validiation
	std::array<byte_t, tc::crypto::Sha256Generator::kHashSize> hash;

	// calculate hash for optional signature validation later
	tc::crypto::GenerateSha256Hash(calculated_hash.data(), (byte_t*)&tmd->sig.issuer, (size_t)((byte_t*)&tmd->v1Head.cmdGroups - (byte_t*)&tmd->sig.issuer));

	// verify v1 ESV1ContentMetaGroup array using hash in v1 header
	tc::crypto::GenerateSha256Hash(hash.data(), (byte_t*)&tmd->v1Head.cmdGroups, sizeof(tmd->v1Head.cmdGroups));
	if (memcmp(hash.data(), tmd->v1Head.hash.data(), hash.size()) != 0)
	{
		throw tc::ArgumentOutOfRangeException(mModuleLabel, "TMD had invalid CMD group hash.");
	}

	// verify ESV1ContentMeta array
	for (size_t i = 0; i < num_cmd_groups; i++) {
		tc::crypto::GenerateSha256Hash(hash.data(), (byte_t*)&tmd->contents[tmd->v1Head.cmdGroups[i].offset], tmd->v1Head.cmdGroups[i].nCmds.unwrap() * sizeof(brd::es::ESV1ContentMeta));
		if (memcmp(hash.data(), tmd->v1Head.cmdGroups[i].groupHash.data(), hash.size()) != 0)
		{
			throw tc::ArgumentOutOfRangeException(mModuleLabel, "TMD had invalid CMD group hash.");
		}
	}

	// verify other fields
	if (tmd->head.sysVersion.unwrap() != 0)
	{
		throw tc::InvalidOperationException(mModuleLabel, "TMD sysVersion had unexpected value.");
	}
	if (tmd->head.type.unwrap() != brd::es::ESTitleType::CT_TITLE)
	{
		throw tc::InvalidOperationException(mModuleLabel, "TMD type had unexpected value.");
	}

	// process header now that it is verified
	this->signature.sig_type = tmd->sig.sigType.unwrap();
	this->signature.sig = tc::ByteData(tmd->sig.sig.data(), tmd->sig.sig.size());
	this->signature.issuer = tmd->sig.issuer.decode();
	this->title_id = tmd->head.titleId.unwrap();
	this->title_version = tmd->head.titleVersion.unwrap();
	struct TmdCustomDataForCtr
	{
		struct TwlCustomData
		{
			tc::bn::le32<uint32_t> public_save_data_size;
			tc::bn::le32<uint32_t> private_save_data_size;
			tc::bn::pad<4> padding;
			byte_t flag;
		};
		struct CtrCustomData
		{
			tc::bn::le32<uint32_t> save_data_size;
			tc::bn::bitarray<1> flag;
		};
		union {
			TwlCustomData twl;
			CtrCustomData ctr;
		};
	};
	auto custom_data = (TmdCustomDataForCtr*)tmd->head.customData.data();
	this->twl_custom_data.public_save_data_size = custom_data->twl.public_save_data_size;
	this->twl_custom_data.private_save_data_size = custom_data->twl.private_save_data_size;
	this->twl_custom_data.flag = custom_data->twl.flag;
	this->ctr_custom_data.save_data_size = custom_data->ctr.save_data_size;
	this->ctr_custom_data.is_snake_only = custom_data->ctr.flag.test(0);

	// process ESV1ContentMeta entries
	for (size_t i = 0; i < total_contents_num; i++)
	{
		this->content_info.push_back(ContentInfo(
			tmd->contents[i].cid.unwrap(),
			tmd->contents[i].index.unwrap(),
			(tmd->contents[i].type.unwrap() & (uint16_t)brd::es::ESContentType_ENCRYPTED) == (uint16_t)brd::es::ESContentType_ENCRYPTED,
			(tmd->contents[i].type.unwrap() & (uint16_t)brd::es::ESContentType_OPTIONAL) == (uint16_t)brd::es::ESContentType_OPTIONAL,
			(int64_t)tmd->contents[i].size.unwrap(),
			tmd->contents[i].hash));
	}
}