#include <tc/cli.h>
#include <tc/ArgumentException.h>
#include <tc/io/StreamSource.h>
#include "types.h"
#include "version.h"
#include "Settings.h"

#include <ntd/n3ds/cci.h>
#include <ntd/n3ds/cia.h>
#include <ntd/n3ds/cro.h>
#include <ntd/n3ds/crr.h>
#include <ntd/n3ds/exefs.h>
#include <ntd/n3ds/firm.h>
#include <ntd/n3ds/ivfc.h>
#include <ntd/n3ds/ncch.h>
#include <ntd/n3ds/romfs.h>
#include <ntd/n3ds/smdh.h>
#include <brd/es/es_cert.h>
#include <brd/es/es_ticket.h>
#include <brd/es/es_tmd.h>

class UnkOptionHandler : public tc::cli::OptionParser::IOptionHandler
{
public:
	UnkOptionHandler(const std::string& module_label) : mModuleLabel(module_label)
	{}

	const std::vector<std::string>& getOptionStrings() const
	{
		throw tc::InvalidOperationException("getOptionStrings() not defined for UnkOptionHandler.");
	}

	const std::vector<std::string>& getOptionRegexPatterns() const
	{
		throw tc::InvalidOperationException("getOptionRegexPatterns() not defined for UnkOptionHandler.");
	}

	void processOption(const std::string& option, const std::vector<std::string>& params)
	{
		throw tc::Exception(mModuleLabel, "Unrecognized option: \"" + option + "\"");
	}
private:
	std::string mModuleLabel;
};

class DeprecatedOptionHandler : public tc::cli::OptionParser::IOptionHandler
{
public:
	DeprecatedOptionHandler(const std::string& warn_message, const std::vector<std::string>& opts) : 
		mWarnMessage(warn_message),
		mOptStrings(opts),
		mOptRegexPatterns()
	{}

	const std::vector<std::string>& getOptionStrings() const
	{
		return mOptStrings;
	}

	const std::vector<std::string>& getOptionRegexPatterns() const
	{
		return mOptRegexPatterns;
	}

	void processOption(const std::string& option, const std::vector<std::string>& params)
	{
		fmt::print("[WARNING] Option \"{}\" is deprecated.{}{}\n", option, (mWarnMessage.empty() ? "" : " "), mWarnMessage);
	}
private:
	std::string mWarnMessage;
	std::vector<std::string> mOptStrings;
	std::vector<std::string> mOptRegexPatterns;
};

class FlagOptionHandler : public tc::cli::OptionParser::IOptionHandler
{
public:
	FlagOptionHandler(bool& flag, const std::vector<std::string>& opts) : 
		mFlag(flag),
		mOptStrings(opts),
		mOptRegexPatterns()
	{}

	const std::vector<std::string>& getOptionStrings() const
	{
		return mOptStrings;
	}

	const std::vector<std::string>& getOptionRegexPatterns() const
	{
		return mOptRegexPatterns;
	}

	void processOption(const std::string& option, const std::vector<std::string>& params)
	{
		if (params.size() != 0)
		{
			throw tc::ArgumentOutOfRangeException(fmt::format("Option \"{:s}\" is a flag, that takes no parameters.", option));
		}

		mFlag = true;
	}
private:
	bool& mFlag;
	std::vector<std::string> mOptStrings;
	std::vector<std::string> mOptRegexPatterns;
};

class SingleParamStringOptionHandler : public tc::cli::OptionParser::IOptionHandler
{
public:
	SingleParamStringOptionHandler(tc::Optional<std::string>& param, const std::vector<std::string>& opts) : 
		mParam(param),
		mOptStrings(opts),
		mOptRegexPatterns()
	{}

	const std::vector<std::string>& getOptionStrings() const
	{
		return mOptStrings;
	}

	const std::vector<std::string>& getOptionRegexPatterns() const
	{
		return mOptRegexPatterns;
	}

	void processOption(const std::string& option, const std::vector<std::string>& params)
	{
		if (params.size() != 1)
		{
			throw tc::ArgumentOutOfRangeException(fmt::format("Option \"{:s}\" requires a parameter.", option));
		}

		mParam = params[0];
	}
private:
	tc::Optional<std::string>& mParam;
	std::vector<std::string> mOptStrings;
	std::vector<std::string> mOptRegexPatterns;
};

class SingleParamPathOptionHandler : public tc::cli::OptionParser::IOptionHandler
{
public:
	SingleParamPathOptionHandler(tc::Optional<tc::io::Path>& param, const std::vector<std::string>& opts) : 
		mParam(param),
		mOptStrings(opts),
		mOptRegexPatterns()
	{}

	const std::vector<std::string>& getOptionStrings() const
	{
		return mOptStrings;
	}

	const std::vector<std::string>& getOptionRegexPatterns() const
	{
		return mOptRegexPatterns;
	}

	void processOption(const std::string& option, const std::vector<std::string>& params)
	{
		if (params.size() != 1)
		{
			throw tc::ArgumentOutOfRangeException(fmt::format("Option \"{:s}\" requires a parameter.", option));
		}

		mParam = params[0];
	}
private:
	tc::Optional<tc::io::Path>& mParam;
	std::vector<std::string> mOptStrings;
	std::vector<std::string> mOptRegexPatterns;
};


class SingleParamSizetOptionHandler : public tc::cli::OptionParser::IOptionHandler
{
public:
	SingleParamSizetOptionHandler(size_t& param, const std::vector<std::string>& opts) : 
		mParam(param),
		mOptStrings(opts),
		mOptRegexPatterns()
	{}

	const std::vector<std::string>& getOptionStrings() const
	{
		return mOptStrings;
	}

	const std::vector<std::string>& getOptionRegexPatterns() const
	{
		return mOptRegexPatterns;
	}

	void processOption(const std::string& option, const std::vector<std::string>& params)
	{
		if (params.size() != 1)
		{
			throw tc::ArgumentOutOfRangeException(fmt::format("Option \"{:s}\" requires a parameter.", option));
		}

		mParam = strtoul(params[0].c_str(), nullptr, 0);
	}
private:
	size_t& mParam;
	std::vector<std::string> mOptStrings;
	std::vector<std::string> mOptRegexPatterns;
};

class FirmTypeOptionHandler : public tc::cli::OptionParser::IOptionHandler
{
public:
	FirmTypeOptionHandler(ctrtool::FirmProcess::FirmwareType& param, const std::vector<std::string>& opts) : 
		mParam(param),
		mOptStrings(opts),
		mOptRegexPatterns()
	{}

	const std::vector<std::string>& getOptionStrings() const
	{
		return mOptStrings;
	}

	const std::vector<std::string>& getOptionRegexPatterns() const
	{
		return mOptRegexPatterns;
	}

	void processOption(const std::string& option, const std::vector<std::string>& params)
	{
		if (params.size() != 1)
		{
			throw tc::ArgumentOutOfRangeException(fmt::format("Option \"{:s}\" requires a parameter.", option));
		}

		if (params[0] == "nand" \
		 || params[0] == "normal")
		{
			mParam = ctrtool::FirmProcess::FirmwareType_Nand;
		}
		else if (params[0] == "ngc" \
		      || params[0] == "ntr" \
		      || params[0] == "ntrboot")
		{
			mParam = ctrtool::FirmProcess::FirmwareType_Ngc;
		}
		else if (params[0] == "nor")
		{
			mParam = ctrtool::FirmProcess::FirmwareType_Nor;
		}
		else if (params[0] == "sdmc")
		{
			mParam = ctrtool::FirmProcess::FirmwareType_Sdmc;
		}
		else
		{
			throw tc::ArgumentException(fmt::format("Firmware type \"{}\" unrecognised.", params[0]));
		}
	}
private:
	ctrtool::FirmProcess::FirmwareType& mParam;
	std::vector<std::string> mOptStrings;
	std::vector<std::string> mOptRegexPatterns;
};

class FileTypeOptionHandler : public tc::cli::OptionParser::IOptionHandler
{
public:
	FileTypeOptionHandler(ctrtool::Settings::FileType& param, const std::vector<std::string>& opts) : 
		mParam(param),
		mOptStrings(opts),
		mOptRegexPatterns()
	{}

	const std::vector<std::string>& getOptionStrings() const
	{
		return mOptStrings;
	}

	const std::vector<std::string>& getOptionRegexPatterns() const
	{
		return mOptRegexPatterns;
	}

	void processOption(const std::string& option, const std::vector<std::string>& params)
	{
		if (params.size() != 1)
		{
			throw tc::ArgumentOutOfRangeException(fmt::format("Option \"{:s}\" requires a parameter.", option));
		}

		if (params[0] == "ncsd" \
		 || params[0] == "cci" \
		 || params[0] == "csu" \
		 || params[0] == "3ds" \
		 || params[0] == "3dx")
		{
			mParam = ctrtool::Settings::FILE_TYPE_NCSD;
		}
		else if (params[0] == "cia")
		{
			mParam = ctrtool::Settings::FILE_TYPE_CIA;
		}
		else if (params[0] == "ncch" \
		 || params[0] == "cxi" \
		 || params[0] == "cfa")
		{
			mParam = ctrtool::Settings::FILE_TYPE_NCCH;
		}
		else if (params[0] == "exheader" \
		 || params[0] == "exhdr")
		{
			mParam = ctrtool::Settings::FILE_TYPE_EXHEADER;
		}
		else if (params[0] == "exefs")
		{
			mParam = ctrtool::Settings::FILE_TYPE_EXEFS;
		}
		else if (params[0] == "romfs")
		{
			mParam = ctrtool::Settings::FILE_TYPE_ROMFS;
		}
		else if (params[0] == "firm")
		{
			mParam = ctrtool::Settings::FILE_TYPE_FIRM;
		}
		else if (params[0] == "cert")
		{
			mParam = ctrtool::Settings::FILE_TYPE_CERT;
		}
		else if (params[0] == "tik")
		{
			mParam = ctrtool::Settings::FILE_TYPE_TIK;
		}
		else if (params[0] == "tmd")
		{
			mParam = ctrtool::Settings::FILE_TYPE_TMD;
		}
		else if (params[0] == "lzss")
		{
			mParam = ctrtool::Settings::FILE_TYPE_LZSS;
		}
		else
		{
			throw tc::ArgumentException(fmt::format("File type \"{}\" unrecognised.", params[0]));
		}
	}
private:
	ctrtool::Settings::FileType& mParam;
	std::vector<std::string> mOptStrings;
	std::vector<std::string> mOptRegexPatterns;
};

ctrtool::SettingsInitializer::SettingsInitializer(const std::vector<std::string>& args) :
	Settings(),
	mModuleLabel("ctrtool::SettingsInitializer"),
	mSuppressOutput(false),
	mShowKeys(false),
	mFallBackTitleKey(),
	mFallBackSeed(),
	mSeedDbPath()
{
	// parse input arguments
	parse_args(args);
	if (infile.path.isNull())
		throw tc::ArgumentException(mModuleLabel, "No input file was specified.");

	// suppress output if requested
	if (mSuppressOutput)
	{
		opt.info = false;
		//opt.verbose = false;
		exefs.list_fs = false;
		romfs.list_fs = false;
	}

	opt.keybag = KeyBagInitializer(opt.is_dev, mFallBackTitleKey, mSeedDbPath, mFallBackSeed);

	// determine filetype if not manually specified
	if (infile.filetype == FILE_TYPE_ERROR)
	{
		determine_filetype();
		if (infile.filetype == FILE_TYPE_ERROR)
		{
			throw tc::ArgumentException(mModuleLabel, "Input file type was undetermined.");
		}
	}
}

void ctrtool::SettingsInitializer::parse_args(const std::vector<std::string>& args)
{
	// check for minimum arguments
	if (args.size() < 2)
	{
		usage_text();
		throw tc::ArgumentException(mModuleLabel, "Not enough arguments.");
	}
	
	// detect request for help
	for (auto itr = ++(args.begin()); itr != args.end(); itr++)
	{
		if (*itr == "-h" || *itr == "--help" || *itr == "-help")
		{
			usage_text();
			throw tc::ArgumentException(mModuleLabel, "Help required.");
		}
	}

	// save input file
	infile.path = tc::io::Path(args.back());

	// test new option parser
	tc::cli::OptionParser opts;

	// register unk option handler
	opts.registerUnrecognisedOptionHandler(std::shared_ptr<UnkOptionHandler>(new UnkOptionHandler(mModuleLabel)));

	// register handler for deprecated options DeprecatedOptionHandler
	opts.registerOptionHandler(std::shared_ptr<DeprecatedOptionHandler>(new DeprecatedOptionHandler("Extract flag is redundant.", {"-x", "--extract"})));
	opts.registerOptionHandler(std::shared_ptr<DeprecatedOptionHandler>(new DeprecatedOptionHandler("Generic AES/RSA keys are initialised internally.", {"-k", "--keyset"})));
	opts.registerOptionHandler(std::shared_ptr<DeprecatedOptionHandler>(new DeprecatedOptionHandler("", {"--unitsize"})));
	opts.registerOptionHandler(std::shared_ptr<DeprecatedOptionHandler>(new DeprecatedOptionHandler("All common keys are initialised internally.", {"--commonkey"})));
	opts.registerOptionHandler(std::shared_ptr<DeprecatedOptionHandler>(new DeprecatedOptionHandler("All secure NCCH keys are initialised internally.", {"--ncchkey"})));
	opts.registerOptionHandler(std::shared_ptr<DeprecatedOptionHandler>(new DeprecatedOptionHandler("The NCCH system key is initialised internally.", {"--ncchsyskey"})));


	// get option flags
	opts.registerOptionHandler(std::shared_ptr<FlagOptionHandler>(new FlagOptionHandler(opt.info, {"-i", "--info"})));
	opts.registerOptionHandler(std::shared_ptr<FlagOptionHandler>(new FlagOptionHandler(opt.verbose, {"-v", "--verbose"})));
	opts.registerOptionHandler(std::shared_ptr<FlagOptionHandler>(new FlagOptionHandler(mSuppressOutput, {"-q", "--quiet"})));
	opts.registerOptionHandler(std::shared_ptr<FlagOptionHandler>(new FlagOptionHandler(opt.plain, {"-p", "--plain"})));
	opts.registerOptionHandler(std::shared_ptr<FlagOptionHandler>(new FlagOptionHandler(opt.raw, {"-r", "--raw"})));
	opts.registerOptionHandler(std::shared_ptr<FlagOptionHandler>(new FlagOptionHandler(opt.verify, {"-y", "--verify"})));
	opts.registerOptionHandler(std::shared_ptr<FlagOptionHandler>(new FlagOptionHandler(opt.is_dev, {"-d", "--dev"})));
	opts.registerOptionHandler(std::shared_ptr<FlagOptionHandler>(new FlagOptionHandler(opt.show_keys, {"--showkeys"})));

	// get user-provided keydata
	opts.registerOptionHandler(std::shared_ptr<SingleParamStringOptionHandler>(new SingleParamStringOptionHandler(mFallBackTitleKey, {"--titlekey"})));
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(mSeedDbPath, {"--seeddb"})));
	opts.registerOptionHandler(std::shared_ptr<SingleParamStringOptionHandler>(new SingleParamStringOptionHandler(mFallBackSeed, {"--seed"})));

	// lzss options
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(lzss.extract_path, {"--lzssout"})));


	// rom options
	opts.registerOptionHandler(std::shared_ptr<SingleParamSizetOptionHandler>(new SingleParamSizetOptionHandler(rom.content_process_index, {"-n", "--ncch", "--cidx"})));
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(rom.content_extract_path, {"--contents"})));
	opts.registerOptionHandler(std::shared_ptr<FlagOptionHandler>(new FlagOptionHandler(rom.decrypt_ncch, { "--decrypt" })));


	// ncch options
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(ncch.exheader_path, {"--exheader"})));
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(ncch.logo_path, {"--logo"})));
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(ncch.plainregion_path, {"--plainrgn", "--plainregion"})));
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(ncch.exefs_path, {"--exefs"})));
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(ncch.romfs_path, {"--romfs"})));


	// exheader options
	opts.registerOptionHandler(std::shared_ptr<FlagOptionHandler>(new FlagOptionHandler(exheader.show_syscalls_as_names, {"--showsyscalls"})));


	// exefs options
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(exefs.extract_path, {"--exefsdir"})));
	opts.registerOptionHandler(std::shared_ptr<FlagOptionHandler>(new FlagOptionHandler(exefs.decompress_code_partition, {"--decompresscode"})));
	//opts.registerOptionHandler(std::shared_ptr<FlagOptionHandler>(new FlagOptionHandler(exefs.list_fs, {"--listexefs"})));
	exefs.list_fs = false;

	// romfs options
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(romfs.extract_path, {"--romfsdir"})));
	opts.registerOptionHandler(std::shared_ptr<FlagOptionHandler>(new FlagOptionHandler(romfs.list_fs, {"--listromfs"})));


	// cia specific options
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(cia.certs_path, {"--certs"})));
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(cia.tik_path, {"--tik"})));
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(cia.tmd_path, {"--tmd"})));
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(cia.meta_path, {"--meta"})));

	// firm options
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(firm.extract_path, {"--firmdir"})));
	opts.registerOptionHandler(std::shared_ptr<FirmTypeOptionHandler>(new FirmTypeOptionHandler(firm.firm_type, {"--firmtype"})));

	// wav options
	opts.registerOptionHandler(std::shared_ptr<SingleParamPathOptionHandler>(new SingleParamPathOptionHandler(cwav.extract_path, {"--wav"})));
	opts.registerOptionHandler(std::shared_ptr<SingleParamSizetOptionHandler>(new SingleParamSizetOptionHandler(cwav.wav_loops, {"--wavloops"})));
	
	// process input file type
	opts.registerOptionHandler(std::shared_ptr<FileTypeOptionHandler>(new FileTypeOptionHandler(infile.filetype, {"-t", "--intype"})));

	opts.processOptions(args, 1, args.size() - 2);
}

void ctrtool::SettingsInitializer::determine_filetype()
{
	auto file = tc::io::StreamSource(std::make_shared<tc::io::FileStream>(tc::io::FileStream(infile.path.get(), tc::io::FileMode::Open, tc::io::FileAccess::Read)));

	auto raw_data = file.pullData(0, 0x1000);

#define _TYPE_PTR(st) ((st*)(raw_data.data()))
#define _ASSERT_FILE_SIZE(sz) (file.length() >= (sz))

	// do tests
	if (_ASSERT_FILE_SIZE(sizeof(ntd::n3ds::CciHeader)) 
	 && _TYPE_PTR(ntd::n3ds::CciHeader)->ncsd_header.struct_magic.unwrap() == ntd::n3ds::NcsdCommonHeader::kStructMagic)
	{
		infile.filetype = FILE_TYPE_NCSD;
	}
	else if (_ASSERT_FILE_SIZE(sizeof(ntd::n3ds::CiaHeader))
	      && _TYPE_PTR(ntd::n3ds::CiaHeader)->header_size.unwrap() == sizeof(ntd::n3ds::CiaHeader))
	{
		infile.filetype = FILE_TYPE_CIA;
	}
	else if (_ASSERT_FILE_SIZE(sizeof(ntd::n3ds::CrrHeader)) 
	      && _TYPE_PTR(ntd::n3ds::CrrHeader)->struct_magic.unwrap() == ntd::n3ds::CrrHeader::kStructMagic)
	{
		infile.filetype = FILE_TYPE_CRR;
	}
	else if (_ASSERT_FILE_SIZE(sizeof(ntd::n3ds::CroHeader)) 
	      && _TYPE_PTR(ntd::n3ds::CroHeader)->struct_magic.unwrap() == ntd::n3ds::CroHeader::kStructMagic)
	{
		infile.filetype = FILE_TYPE_CRO;
	}
	else if (_ASSERT_FILE_SIZE(sizeof(ntd::n3ds::ExeFsHeader)) 
	      && _TYPE_PTR(ntd::n3ds::ExeFsHeader)->file_table[0].offset.unwrap() == 0 
	      && _TYPE_PTR(ntd::n3ds::ExeFsHeader)->file_table[0].size.unwrap() != 0 
	      && _TYPE_PTR(ntd::n3ds::ExeFsHeader)->file_table[0].name[0] == '.')
	{
		infile.filetype = FILE_TYPE_EXEFS;
	}
	else if (_ASSERT_FILE_SIZE(sizeof(ntd::n3ds::FirmwareHeader)) 
	      && _TYPE_PTR(ntd::n3ds::FirmwareHeader)->struct_magic.unwrap() == ntd::n3ds::FirmwareHeader::kStructMagic)
	{
		infile.filetype = FILE_TYPE_FIRM;
	}
	else if (_ASSERT_FILE_SIZE(sizeof(ntd::n3ds::IvfcHeader)) 
	      && _TYPE_PTR(ntd::n3ds::IvfcHeader)->struct_magic.unwrap() == ntd::n3ds::IvfcHeader::kStructMagic)
	{
		infile.filetype = FILE_TYPE_IVFC;
	}
	else if (_ASSERT_FILE_SIZE(sizeof(ntd::n3ds::NcchHeader)) 
	      && _TYPE_PTR(ntd::n3ds::NcchHeader)->header.struct_magic.unwrap() == ntd::n3ds::NcchCommonHeader::kStructMagic)
	{
		infile.filetype = FILE_TYPE_NCCH;
	}
	else if (_ASSERT_FILE_SIZE(sizeof(ntd::n3ds::RomFsHeader)) 
	      && _TYPE_PTR(ntd::n3ds::RomFsHeader)->header_size.unwrap() == sizeof(ntd::n3ds::RomFsHeader))
	{
		infile.filetype = FILE_TYPE_ROMFS;
	}
	else if (_ASSERT_FILE_SIZE(sizeof(ntd::n3ds::SystemMenuDataHeader)) 
	      && _TYPE_PTR(ntd::n3ds::SystemMenuDataHeader)->struct_magic.unwrap() == ntd::n3ds::SystemMenuDataHeader::kStructMagic)
	{
		infile.filetype = FILE_TYPE_SMDH;
	}

	// CTR CA cert
	else if (_ASSERT_FILE_SIZE(sizeof(brd::es::ESCACert)) 
	      && _TYPE_PTR(brd::es::ESCACert)->sig.sigType.unwrap() == brd::es::ESSigType::RSA4096_SHA256
	      && _TYPE_PTR(brd::es::ESCACert)->sig.issuer.decode() == "Root"
	      && _TYPE_PTR(brd::es::ESCACert)->head.pubKeyType.unwrap() == brd::es::ESCertPubKeyType::RSA2048
	      && _TYPE_PTR(brd::es::ESCACert)->head.name.serverId.decode().substr(0, 2) == "CA")
	{
		infile.filetype = FILE_TYPE_CERT;
	}

	// CTR CA-signed cert
	else if (_ASSERT_FILE_SIZE(sizeof(brd::es::ESCASignedCert)) 
	      && _TYPE_PTR(brd::es::ESCASignedCert)->sig.sigType.unwrap() == brd::es::ESSigType::RSA2048_SHA256
	      && _TYPE_PTR(brd::es::ESCASignedCert)->sig.issuer.decode().substr(0, 5) == "Root-CA"
	      && _TYPE_PTR(brd::es::ESCASignedCert)->head.pubKeyType.unwrap() == brd::es::ESCertPubKeyType::RSA2048)
	{
		infile.filetype = FILE_TYPE_CERT;
	}

	// detect ticket
	else if (_ASSERT_FILE_SIZE(sizeof(brd::es::ESV1Ticket)) 
	      && _TYPE_PTR(brd::es::ESV1Ticket)->head.sig.sigType.unwrap() == brd::es::ESSigType::RSA2048_SHA256
	      && _TYPE_PTR(brd::es::ESV1Ticket)->head.sig.issuer.decode().substr(0, 5) == "Root-"
	      && _TYPE_PTR(brd::es::ESV1Ticket)->head.sig.issuer.decode().substr(16, 2) == "XS")
	{
		infile.filetype = FILE_TYPE_TIK;
	}
	// detect tmd
	else if (_ASSERT_FILE_SIZE(sizeof(brd::es::ESV1TitleMeta)) 
	      && _TYPE_PTR(brd::es::ESV1TitleMeta)->sig.sigType.unwrap() == brd::es::ESSigType::RSA2048_SHA256
	      && _TYPE_PTR(brd::es::ESV1TitleMeta)->sig.issuer.decode().substr(0, 5) == "Root-"
	      && _TYPE_PTR(brd::es::ESV1TitleMeta)->sig.issuer.decode().substr(16, 2) == "CP")
	{
		infile.filetype = FILE_TYPE_TMD;
	}

#undef _TYPE_PTR
#undef _ASSERT_FILE_SIZE
}

void ctrtool::SettingsInitializer::usage_text()
{
	fmt::print(stderr, "{:s} v{:d}.{:d}.{:d} (C) {:s}\n", APP_NAME, VER_MAJOR, VER_MINOR, VER_PATCH, AUTHORS);
	fmt::print(stderr, "Built: {:s} {:s}\n\n", __TIME__, __DATE__);

	fmt::print(stderr, "Usage: {:s} [options... ] <file>\n", BIN_NAME);

	fmt::print(stderr,
		"Options:\n"
		//"  -i, --info         Show file info.\n"
		//"                          This is the default action.\n"
		//"  -x, --extract      Extract data from file.\n"
		//"                          This is also the default action.\n"
		"  -v, --verbose      Give verbose output.\n"
		"  -q, --quiet        Only output errors (regular output is silenced).\n"
		"  -p, --plain        Extract data without decrypting.\n"
		"  -r, --raw          Keep raw data, don't unpack.\n"
		//"  -k, --keyset=file  Specify keyset file.\n"

		"  -y, --verify       Verify hashes and signatures.\n"
		"  -d, --dev          Decrypt with development keys instead of retail.\n"
		//"  --unitsize=size    Set media unit size (default 0x200).\n"
		//"  --commonkey=key    Set common key.\n"
		"  --titlekey=key     Set tik title key.\n"
		//"  --ncchkey=key      Set ncch key.\n"
		//"  --ncchsyskey=key   Set ncch fixed system key.\n"
		"  --seeddb=file      Set seeddb for ncch seed crypto.\n"
		"  --seed=key         Set specific seed for ncch seed crypto.\n"
		//"  --showkeys         Show the keys being used.\n"
		"  --showsyscalls     Show system call names instead of numbers.\n"
		"  -t, --intype=type  Specify input file type. [cia, tik, tmd, ncsd, ncch, exheader, exefs, romfs, firm, lzss]\n"
		"                     (only needed when file type isn't detected automatically)\n"
		"CCI options:\n"
		"  -n, --ncch=index   Specify NCCH partition index.\n"
		"  --contents=dir     Specify Contents directory path.\n"
		"  --decrypt          Decrypt NCCH partition.\n"
		//"  --initdata=file    Specify Initial Data file path.\n"
		"CIA options:\n"
		"  -n, --ncch=index   Specify NCCH partition index.\n"
		"  --contents=dir     Specify Contents directory path.\n"
		"  --certs=file       Specify Certificate chain file path.\n"
		"  --tik=file         Specify Ticket file path.\n"
		"  --tmd=file         Specify TMD file path.\n"
		"  --footer=file      Specify Footer file path.\n"
		"  --decrypt          Decrypt NCCH partition.\n"
		"NCCH options:\n"
		"  --exheader=file    Specify Extended Header file path.\n"
		"  --logo=file        Specify Logo file path.\n"
		"  --plainrgn=file    Specify Plain region file path\n"
		"  --exefs=file       Specify ExeFS file path.\n"
		"  --romfs=file       Specify RomFS file path.\n"
		"EXEFS options:\n"
		"  --exefsdir=dir     Specify ExeFS directory path.\n"
		"  --listexefs        List files in ExeFS.\n" 
		"  --decompresscode   Decompress .code section\n"
		"                     (only needed when using raw ExeFS file)\n"
		"ROMFS options:\n"
		"  --romfsdir=dir     Specify RomFS directory path.\n"
		"  --listromfs        List files in RomFS.\n" 
		"FIRM options:\n"
		"  --firmdir=dir      Specify Firm directory path.\n"
		"  --firmtype=type    Specify Firm location type, this determines encryption/signing.\n"
		"                       - nand: (default) FIRM images installed to internal NAND,\n"
	    "                       - ngc: FIRM images loaded from NTR game card at boot,\n"
		"                       - nor: FIRM images loaded from WiFi board NOR at boot,\n"
		"                       - sdmc: FIRM images installed from SD card by FIRM installers (internal dev tool).\n"
		"LZSS options:\n"
		"  --lzssout=file     Specify lzss output file\n"
		//"CWAV options:\n"
		//"  --wav=file         Specify wav output file.\n"
		//"  --wavloops=count   Specify wav loop count, default 0.\n"
	);
}