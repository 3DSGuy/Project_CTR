#include <tc.h>
#include <tc/os/UnicodeMain.h>
#include "Settings.h"

#include "ExeFsProcess.h"
#include "RomFsProcess.h"
#include "IvfcProcess.h"
#include "NcchProcess.h"
#include "ExHeaderProcess.h"
#include "CciProcess.h"
#include "CiaProcess.h"
#include "LzssProcess.h"
#include "CrrProcess.h"
#include "FirmProcess.h"
#include "TikProcess.h"
#include "TmdProcess.h"

#include <tc/io/SubStream.h>
#include <ntd/n3ds/IvfcStream.h>

int umain(const std::vector<std::string>& args, const std::vector<std::string>& env)
{
	try 
	{
		ctrtool::Settings set = ctrtool::SettingsInitializer(args);
		
		std::shared_ptr<tc::io::IStream> infile_stream = std::make_shared<tc::io::FileStream>(tc::io::FileStream(set.infile.path.get(), tc::io::FileMode::Open, tc::io::FileAccess::Read));

		if (set.infile.filetype == ctrtool::Settings::FILE_TYPE_EXEFS)
		{
			ctrtool::ExeFsProcess proc;
			proc.setInputStream(infile_stream);
			proc.setCliOutputMode(set.opt.info, set.exefs.list_fs);
			proc.setVerboseMode(set.opt.verbose);
			proc.setVerifyMode(set.opt.verify);
			proc.setRawMode(set.opt.raw);
			proc.setDecompressCode(set.exefs.decompress_code_partition);
			if (set.exefs.extract_path.isSet())
			{
				proc.setExtractPath(set.exefs.extract_path.get());
			}
			proc.process();
		}
		else if (set.infile.filetype == ctrtool::Settings::FILE_TYPE_ROMFS)
		{
			ctrtool::RomFsProcess proc;
			proc.setInputStream(infile_stream);
			proc.setKeyBag(set.opt.keybag);
			proc.setCliOutputMode(set.opt.info, set.romfs.list_fs);
			proc.setVerboseMode(set.opt.verbose);
			proc.setVerifyMode(set.opt.verify);
			if (set.romfs.extract_path.isSet())
			{
				proc.setExtractPath(set.romfs.extract_path.get());
			}
			proc.process();
		}
		else if (set.infile.filetype == ctrtool::Settings::FILE_TYPE_IVFC)
		{
			ctrtool::IvfcProcess proc;
			proc.setInputStream(infile_stream);
			proc.setKeyBag(set.opt.keybag);
			proc.setCliOutputMode(set.opt.info, set.romfs.list_fs);
			proc.setVerboseMode(set.opt.verbose);
			proc.setVerifyMode(set.opt.verify);
			if (set.romfs.extract_path.isSet())
			{
				proc.setExtractPath(set.romfs.extract_path.get());
			}
			proc.process();
		}
		else if (set.infile.filetype == ctrtool::Settings::FILE_TYPE_NCCH)
		{
			ctrtool::NcchProcess proc;
			proc.setInputStream(infile_stream);
			proc.setKeyBag(set.opt.keybag);
			proc.setVerboseMode(set.opt.verbose);
			proc.setVerifyMode(set.opt.verify);
			proc.setRawMode(set.opt.raw);
			proc.setPlainMode(set.opt.plain);
			proc.setShowSyscallName(set.exheader.show_syscalls_as_names);
			proc.setRegionProcessOutputMode(proc.NcchRegion_Header, set.opt.info, false, tc::Optional<tc::io::Path>(), tc::Optional<tc::io::Path>());
			proc.setRegionProcessOutputMode(proc.NcchRegion_ExHeader, set.opt.info, false, set.ncch.exheader_path, tc::Optional<tc::io::Path>());
			proc.setRegionProcessOutputMode(proc.NcchRegion_PlainRegion, false, false, set.ncch.plainregion_path, tc::Optional<tc::io::Path>());
			proc.setRegionProcessOutputMode(proc.NcchRegion_Logo, false, false, set.ncch.logo_path, tc::Optional<tc::io::Path>());
			proc.setRegionProcessOutputMode(proc.NcchRegion_ExeFs, set.opt.info, set.exefs.list_fs, set.ncch.exefs_path, set.exefs.extract_path);
			proc.setRegionProcessOutputMode(proc.NcchRegion_RomFs, set.opt.info, set.romfs.list_fs, set.ncch.romfs_path, set.romfs.extract_path);
			proc.process();
		}
		else if (set.infile.filetype == ctrtool::Settings::FILE_TYPE_EXHEADER)
		{
			ctrtool::ExHeaderProcess proc;
			proc.setInputStream(infile_stream);
			proc.setKeyBag(set.opt.keybag);
			proc.setCliOutputMode(set.opt.info);
			proc.setVerboseMode(set.opt.verbose);
			proc.setVerifyMode(set.opt.verify);
			proc.setShowSyscallName(set.exheader.show_syscalls_as_names);
			
			proc.process();
		}
		else if (set.infile.filetype == ctrtool::Settings::FILE_TYPE_NCSD)
		{
			ctrtool::CciProcess proc;
			proc.setInputStream(infile_stream);
			proc.setKeyBag(set.opt.keybag);
			proc.setCliOutputMode(set.opt.info);
			proc.setVerboseMode(set.opt.verbose);
			proc.setVerifyMode(set.opt.verify);
			if (set.rom.content_extract_path.isSet())
				proc.setExtractPath(set.rom.content_extract_path.get());
			proc.setContentIndex(set.rom.content_process_index);
			proc.setRawMode(set.opt.raw);
			proc.setPlainMode(set.opt.plain);
			proc.setShowSyscallName(set.exheader.show_syscalls_as_names);
			proc.setDecryptNcch(set.rom.decrypt_ncch);
			proc.setNcchRegionProcessOutputMode(ctrtool::NcchProcess::NcchRegion_Header, set.opt.info, false, tc::Optional<tc::io::Path>(), tc::Optional<tc::io::Path>());
			proc.setNcchRegionProcessOutputMode(ctrtool::NcchProcess::NcchRegion_ExHeader, set.opt.info, false, set.ncch.exheader_path, tc::Optional<tc::io::Path>());
			proc.setNcchRegionProcessOutputMode(ctrtool::NcchProcess::NcchRegion_PlainRegion, false, false, set.ncch.plainregion_path, tc::Optional<tc::io::Path>());
			proc.setNcchRegionProcessOutputMode(ctrtool::NcchProcess::NcchRegion_Logo, false, false, set.ncch.logo_path, tc::Optional<tc::io::Path>());
			proc.setNcchRegionProcessOutputMode(ctrtool::NcchProcess::NcchRegion_ExeFs, set.opt.info, set.exefs.list_fs, set.ncch.exefs_path, set.exefs.extract_path);
			proc.setNcchRegionProcessOutputMode(ctrtool::NcchProcess::NcchRegion_RomFs, set.opt.info, set.romfs.list_fs, set.ncch.romfs_path, set.romfs.extract_path);
			proc.process();
		}
		else if (set.infile.filetype == ctrtool::Settings::FILE_TYPE_CIA)
		{
			ctrtool::CiaProcess proc;
			proc.setInputStream(infile_stream);
			proc.setKeyBag(set.opt.keybag);
			proc.setCliOutputMode(set.opt.info);
			proc.setVerboseMode(set.opt.verbose);
			proc.setVerifyMode(set.opt.verify);
			if (set.rom.content_extract_path.isSet())
				proc.setContentExtractPath(set.rom.content_extract_path.get());
			proc.setContentIndex(set.rom.content_process_index);
			if (set.cia.certs_path.isSet())
				proc.setCertExtractPath(set.cia.certs_path.get());
			if (set.cia.tik_path.isSet())
				proc.setTikExtractPath(set.cia.tik_path.get());
			if (set.cia.tmd_path.isSet())
				proc.setTmdExtractPath(set.cia.tmd_path.get());
			if (set.cia.meta_path.isSet())
				proc.setFooterExtractPath(set.cia.meta_path.get());
			proc.setRawMode(set.opt.raw);
			proc.setPlainMode(set.opt.plain);
			proc.setShowSyscallName(set.exheader.show_syscalls_as_names);
			proc.setNcchRegionProcessOutputMode(ctrtool::NcchProcess::NcchRegion_Header, set.opt.info, false, tc::Optional<tc::io::Path>(), tc::Optional<tc::io::Path>());
			proc.setNcchRegionProcessOutputMode(ctrtool::NcchProcess::NcchRegion_ExHeader, set.opt.info, false, set.ncch.exheader_path, tc::Optional<tc::io::Path>());
			proc.setNcchRegionProcessOutputMode(ctrtool::NcchProcess::NcchRegion_PlainRegion, false, false, set.ncch.plainregion_path, tc::Optional<tc::io::Path>());
			proc.setNcchRegionProcessOutputMode(ctrtool::NcchProcess::NcchRegion_Logo, false, false, set.ncch.logo_path, tc::Optional<tc::io::Path>());
			proc.setNcchRegionProcessOutputMode(ctrtool::NcchProcess::NcchRegion_ExeFs, set.opt.info, set.exefs.list_fs, set.ncch.exefs_path, set.exefs.extract_path);
			proc.setNcchRegionProcessOutputMode(ctrtool::NcchProcess::NcchRegion_RomFs, set.opt.info, set.romfs.list_fs, set.ncch.romfs_path, set.romfs.extract_path);
			proc.process();
		}
		else if (set.infile.filetype == ctrtool::Settings::FILE_TYPE_LZSS)
		{
			ctrtool::LzssProcess proc;
			proc.setInputStream(infile_stream);
			if (set.lzss.extract_path.isSet())
				proc.setExtractPath(set.lzss.extract_path.get());
			proc.process();
		}
		else if (set.infile.filetype == ctrtool::Settings::FILE_TYPE_CRR)
		{
			ctrtool::CrrProcess proc;
			proc.setInputStream(infile_stream);
			proc.setKeyBag(set.opt.keybag);
			proc.setCliOutputMode(set.opt.info);
			proc.setVerboseMode(set.opt.verbose);
			proc.setVerifyMode(set.opt.verify);
			proc.process();
		}
		else if (set.infile.filetype == ctrtool::Settings::FILE_TYPE_FIRM)
		{
			ctrtool::FirmProcess proc;
			proc.setInputStream(infile_stream);
			proc.setKeyBag(set.opt.keybag);
			proc.setCliOutputMode(set.opt.info);
			proc.setVerboseMode(set.opt.verbose);
			proc.setVerifyMode(set.opt.verify);
			if (set.firm.extract_path.isSet())
			{
				proc.setExtractPath(set.firm.extract_path.get());
			}
			proc.setFirmwareType(set.firm.firm_type);
			proc.process();
		}
		else if (set.infile.filetype == ctrtool::Settings::FILE_TYPE_TIK)
		{
			ctrtool::TikProcess proc;
			proc.setInputStream(infile_stream);
			proc.setKeyBag(set.opt.keybag);
			proc.setCliOutputMode(set.opt.info);
			proc.setVerboseMode(set.opt.verbose);
			proc.setVerifyMode(set.opt.verify);
			proc.process();
		}
		else if (set.infile.filetype == ctrtool::Settings::FILE_TYPE_TMD)
		{
			ctrtool::TmdProcess proc;
			proc.setInputStream(infile_stream);
			proc.setKeyBag(set.opt.keybag);
			proc.setCliOutputMode(set.opt.info);
			proc.setVerboseMode(set.opt.verbose);
			proc.setVerifyMode(set.opt.verify);
			proc.process();
		}
		
		/*
		switch (set.infile.filetype)
		{
			case ctrtool::Settings::FILE_TYPE_NCSD :
				fmt::print("## FILE_TYPE_NCSD ##\n");
				break;
			case ctrtool::Settings::FILE_TYPE_CIA :
				fmt::print("## FILE_TYPE_CIA ##\n");
				break;
			case ctrtool::Settings::FILE_TYPE_NCCH :
				fmt::print("## FILE_TYPE_NCCH ##\n");
				break;
			case ctrtool::Settings::FILE_TYPE_EXHEADER :
				fmt::print("## FILE_TYPE_EXHEADER ##\n");
				break;
			case ctrtool::Settings::FILE_TYPE_EXEFS :
				fmt::print("## FILE_TYPE_EXEFS ##\n");
				break;
			case ctrtool::Settings::FILE_TYPE_ROMFS :
				fmt::print("## FILE_TYPE_ROMFS ##\n");
				break;
			case ctrtool::Settings::FILE_TYPE_FIRM :
				fmt::print("## FILE_TYPE_FIRM ##\n");
				break;
			case ctrtool::Settings::FILE_TYPE_CERT :
				fmt::print("## FILE_TYPE_CERT ##\n");
				break;
			case ctrtool::Settings::FILE_TYPE_TIK :
				fmt::print("## FILE_TYPE_TIK ##\n");
				break;
			case ctrtool::Settings::FILE_TYPE_TMD :
				fmt::print("## FILE_TYPE_TMD ##\n");
				break;
			case ctrtool::Settings::FILE_TYPE_LZSS :
				fmt::print("## FILE_TYPE_LZSS ##\n");
				break;
			case ctrtool::Settings::FILE_TYPE_CRR :
				fmt::print("## FILE_TYPE_CRR ##\n");
				break;
			case ctrtool::Settings::FILE_TYPE_CRO :
				fmt::print("## FILE_TYPE_CRO ##\n");
				break;
			case ctrtool::Settings::FILE_TYPE_IVFC :
				fmt::print("## FILE_TYPE_IVFC ##\n");
				break;
			case ctrtool::Settings::FILE_TYPE_SMDH :
				fmt::print("## FILE_TYPE_SMDH ##\n");
				break;
			default:
				fmt::print("## unknown({}) ##\n", (int)set.infile.filetype);
				break;
		}
		*/
		
	}
	catch (tc::Exception& e)
	{
		fmt::print("[{0}{1}ERROR] {2}\n", e.module(), (strlen(e.module()) != 0 ? " ": ""), e.error());
		return 1;
	}
	return 0;
}