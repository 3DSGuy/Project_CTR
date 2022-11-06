#pragma once
#include <tc/types.h>
#include <array>

#include <ntd/n3ds/ncch.h>

namespace ntd { namespace n3ds {

#pragma pack(push,8)

	/**
	 * @struct NcsdCommonHeader
	 * @brief NCSD header is used in both NAND storage and Gamecard Images
	 */
struct NcsdCommonHeader
{
	static const uint32_t kStructMagic = tc::bn::make_struct_magic_uint32("NCSD");
	static const size_t kPartitionNum = 8;

	enum PartitionFsType
	{
		PartitionFsType_None = 0,
		PartitionFsType_Normal = 1,
		PartitionFsType_FIRM = 3,
		PartitionFsType_AGBSave = 4,
	};

	enum PartitionCryptoType
	{
		PartitionCryptoType_None = 0x00,
		PartitionCryptoType_TWL = 0x01,
		PartitionCryptoType_CTR = 0x02,
		PartitionCryptoType_SNAKE = 0x03,
	};

	enum MediaPlatform : byte_t
	{
		MediaPlatform_CTR = 0,
		MediaPlatform_SNAKE = 1,
	};

	enum MediaType : byte_t
	{
		MediaType_InnerDevice = 0,
		MediaType_Card1 = 1,
		MediaType_Card2 = 2,
		MediaType_ExtendedDevice = 3,
	};

	enum FlagIndex
	{
		FlagIndex_Platform = 4,
		FlagIndex_Type = 5,
		FlagIndex_BlockSizeLog = 6,
	};

	struct NcsdFlags
	{
		tc::bn::pad<4>        reserved;
		tc::bn::bitarray<1>   media_platform;
		byte_t                media_type;
		byte_t                block_size_log; // this flag determines the block_size = 1 << (block_size_log + 9), alternatively this is always 0, and the blocksize is always 0x200
		tc::bn::bitarray<1>   reserved_07;

		// raw byte access
		byte_t& operator[](size_t index) { return ((byte_t*)this)[index]; }
		const byte_t& operator[](size_t index) const { return ((const byte_t*)this)[index]; }
		const byte_t* data() const { return ((const byte_t*)this); }
		const size_t size() const { return sizeof(uint64_t); }
	};
	static_assert(sizeof(NcsdFlags) == 8, "NcsdFlags had incorrect size.");

	struct OffsetSize
	{
		tc::bn::le32<uint32_t> blk_offset;
		tc::bn::le32<uint32_t> blk_size;
	};
	static_assert(sizeof(OffsetSize) == 8, "OffsetSize had incorrect size.");

	struct GameCardExtendedHeader
	{
		struct CryptoType
		{
			byte_t enabled : 1;
			byte_t value : 2;
			byte_t reserved : 5;
		};

		// 0x90
		std::array<tc::bn::le64<uint64_t>, kPartitionNum> partition_id;
		// 0xD0
		tc::bn::pad<0x2E>                                 reserved;
		// 0xFE
		CryptoType                                        crypto_type;
		byte_t                                            backup_security_version;
	};

	struct NandExtendedHeader
	{
		// 0x90
		tc::bn::pad<0x70>                                 reserved;
	};

	// 0x00
	tc::bn::le32<uint32_t>                struct_magic; // NCSD
	tc::bn::le32<uint32_t>                image_blk_size;
	tc::bn::le64<uint64_t>                title_id;
	// 0x10
	std::array<byte_t, kPartitionNum>     partition_fs_type;
	std::array<byte_t, kPartitionNum>     partition_crypto_type;
	// 0x20
	std::array<OffsetSize, kPartitionNum> partition_offsetsize;
	// 0x60
	/*
	std::array<byte_t, 0x20>              extended_header_hash; // unused
	// 0x80
	tc::bn::le32<uint32_t>                additional_header_size; // unused
	tc::bn::le32<uint32_t>                sector0_offset; // unused
	*/
	tc::bn::pad<0x28>                     reserved_0x60;
	// 0x88
	NcsdFlags                             flags;
	// 0x90
	union {
		GameCardExtendedHeader card_ext;
		NandExtendedHeader     nand_ext;
	};
};	
static_assert(sizeof(NcsdCommonHeader) == 0x100, "NcsdCommonHeader had incorrect size.");

struct CciHeader
{
	enum CardDevice : byte_t
	{
		CardDevice_Unspecified = 0,
		CardDevice_NorFlash = 1,
		CardDevice_None = 2,
		CardDevice_BT = 3,
	};

	enum PartitionIndex : byte_t
	{
		PartitionIndex_Application = 0,
		PartitionIndex_Manual = 1,
		PartitionIndex_DlpChild = 2,
		PartitionIndex_SnakeCup = 6,
		PartitionIndex_CtrCup = 7,
	};

	enum RomSize : uint32_t
	{
		RomSize_128MB = 0x40000,
		RomSize_256MB = 0x80000,
		RomSize_512MB = 0x100000,
		RomSize_1GB = 0x200000,
		RomSize_2GB = 0x400000,
		RomSize_4GB = 0x800000,
	};

	enum NcsdFlagIndex
	{
		NcsdFlagIndex_BackupWriteWaitTime = 0,
		NcsdFlagIndex_BackupSecurityVersion = 1,
		NcsdFlagIndex_CardInfo = 2,
		NcsdFlagIndex_CardDevice = 3,
		NcsdFlagIndex_MediaPlatform = 4,
		NcsdFlagIndex_MediaType = 5,
		NcsdFlagIndex_MediaBlockSize = 6,
		NcsdFlagIndex_CardDevice_Deprecated = 7,
	};

	enum CardType
	{
		CardType_S1 = 0,
		CardType_S2 = 1,
	};

	enum CryptoType
	{
		CryptoType_Secure0 = 0, // Secure initial data key (keyX bootrom, keyY initial data seed) (used in production ROMs)
		CryptoType_Secure1 = 1, // Secure initial data key (keyX bootrom, keyY initial data seed) (used in production ROMs)
		CryptoType_Secure2 = 2, // Secure initial data key (keyX bootrom, keyY initial data seed) (used in production ROMs)
		CryptoType_FixedKey = 3, // Zeros initial data key (used in non-HSM enviroments like development)
	};

	struct CardInfo
	{
		struct Flag
		{
			byte_t reserved : 5;
			byte_t card_type : 1; // see CardType
			byte_t crypto_type : 2; // see CryptoType
		};
		
		tc::bn::le32<uint32_t> writable_region; // offset in blocks
		tc::bn::pad<3>         padding;
		Flag                   flag;
		tc::bn::pad<0xf8>      reserved;
	};
	static_assert(sizeof(CardInfo) == 0x100, "CardInfo had incorrect size.");

	struct MasteringMetadata
	{
		tc::bn::le64<uint64_t> media_size_used;
		tc::bn::pad<0x8>       padding0;
		
		tc::bn::le16<uint16_t> title_version;
		tc::bn::le16<uint16_t> card_revision;
		tc::bn::pad<0xc>       padding1;
		
		tc::bn::le64<uint64_t> cver_title_id;
		tc::bn::le16<uint16_t> cver_title_version;
		tc::bn::pad<0x6>       padding2;
		
		tc::bn::pad<0xd0>      reserved;
	};
	static_assert(sizeof(MasteringMetadata) == 0x100, "MasteringMetadata had incorrect size.");

	struct InitialData
	{
		std::array<byte_t, 16> key_source;
		std::array<byte_t, 16> encrypted_title_key;
		std::array<byte_t, 16> mac;
		std::array<byte_t, 12> nonce;
		tc::bn::pad<4>         padding;
		tc::bn::pad<0xc0>      reserved;
	};
	static_assert(sizeof(InitialData) == 0x100, "InitialData had incorrect size.");

	struct CardDeviceInfo
	{
		tc::bn::pad<0x200>              card_device_reserved_0;
		std::array<byte_t, 16>          title_key;
		tc::bn::pad<0xf0>               card_device_reserved_1;
	};
	static_assert(sizeof(InitialData) == 0x100, "InitialData had incorrect size.");

public:
	// 0x0000 - 0x00ff: RSA2048-PKCS1-SHA2-256 over 0x0100-0x01ff
	std::array<byte_t, 0x100> signature;
	
	// 0x0100 - 0x01ff: NcsdCommonHeader
	NcsdCommonHeader          ncsd_header;

	// 0x0200 - 0x02ff: CardInfo
	CardInfo                  card_info; 

	// 0x0300 - 0x03ff: Mastering metadata
	MasteringMetadata         mastering_info;

	// 0x0400 - 0x0fff: Reserved
	tc::bn::pad<0xc00>        reserved_00;

	// 0x1000 - 0x10ff: Initial Data
	InitialData               initial_data;

	// 0x1100 - 0x11ff: Partition0 NcchCommonHeader
	NcchCommonHeader                ncch_header;

	// 0x1200 - 0x14ff: Contains decrypted titlekey for programming cards
	CardDeviceInfo            card_device_info;

	// 0x1500 - 0x3fff: Reserved
	tc::bn::pad<0x2B00>       reserved_01;
};
static_assert(sizeof(CciHeader) == 0x4000, "CciHeader had incorrect size.");

#pragma pack(pop)

}} // namespace ntd::n3ds