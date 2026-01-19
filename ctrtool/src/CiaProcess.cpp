#include "CiaProcess.h"
#include "util.h"
#include <tc/io.h>
#include <tc/cli.h>
#include <tc/crypto.h>
#include <tc/ArgumentNullException.h>
#include <tc/NotSupportedException.h>

#include <ntd/n3ds/CiaFsSnapshotGenerator.h>
#include <ntd/n3ds/CtrKeyGenerator.h>

ctrtool::CiaProcess::CiaProcess() :
	mModuleLabel("ctrtool::CiaProcess"),
	mInputStream(),
	mKeyBag(),
	mShowHeaderInfo(false),
	mVerbose(false),
	mVerify(false),
	mPlain(false),
	mCertExtractPath(),
	mTikExtractPath(),
	mTmdExtractPath(),
	mContentExtractPath(),
	mFooterExtractPath(),
	mContentIndex(0),
	mIssuerSigner(),
	mCertImportedIssuerSigner(),
	mCertChain(),
	mCertSigValid(),
	mTicket(),
	mTicketSigValid(ValidState::Unchecked),
	mTitleMetaData(),
	mTitleMetaDataSigValid(ValidState::Unchecked),
	mDecryptedTitleKey(),
	mIsTwlTitle(false),
	mNcchProcess(),
	mFsReader()
{
	memset(&mHeader, 0, sizeof(mHeader));
}

void ctrtool::CiaProcess::setInputStream(const std::shared_ptr<tc::io::IStream>& input_stream)
{
	mInputStream = input_stream;
}

void ctrtool::CiaProcess::setKeyBag(const ctrtool::KeyBag& key_bag)
{
	mKeyBag = key_bag;
	mNcchProcess.setKeyBag(key_bag);
}

void ctrtool::CiaProcess::setCliOutputMode(bool show_header_info)
{
	mShowHeaderInfo = show_header_info;
}

void ctrtool::CiaProcess::setVerboseMode(bool verbose)
{
	mVerbose = verbose;
	mNcchProcess.setVerboseMode(verbose);
}

void ctrtool::CiaProcess::setVerifyMode(bool verify)
{
	mVerify = verify;
	mNcchProcess.setVerifyMode(verify);
}

void ctrtool::CiaProcess::setCertExtractPath(const tc::io::Path& extract_path)
{
	mCertExtractPath = extract_path;
}

void ctrtool::CiaProcess::setTikExtractPath(const tc::io::Path& extract_path)
{
	mTikExtractPath = extract_path;
}

void ctrtool::CiaProcess::setTmdExtractPath(const tc::io::Path& extract_path)
{
	mTmdExtractPath = extract_path;
}

void ctrtool::CiaProcess::setContentExtractPath(const tc::io::Path& extract_path)
{
	mContentExtractPath = extract_path;
}

void ctrtool::CiaProcess::setFooterExtractPath(const tc::io::Path& extract_path)
{
	mFooterExtractPath = extract_path;
}


void ctrtool::CiaProcess::setContentIndex(size_t index)
{
	mContentIndex = index;
}

void ctrtool::CiaProcess::setRawMode(bool raw)
{
	mNcchProcess.setRawMode(raw);
}

void ctrtool::CiaProcess::setPlainMode(bool plain)
{
	mPlain = plain;
	mNcchProcess.setPlainMode(plain);
}

void ctrtool::CiaProcess::setShowSyscallName(bool show_name)
{
	mNcchProcess.setShowSyscallName(show_name);
}

void ctrtool::CiaProcess::setNcchRegionProcessOutputMode(NcchProcess::NcchRegion region, bool show_info, bool show_fs, const tc::Optional<tc::io::Path>& bin_extract_path, const tc::Optional<tc::io::Path>& fs_extract_path)
{
	mNcchProcess.setRegionProcessOutputMode(region, show_info, show_fs, bin_extract_path, fs_extract_path);
}

void ctrtool::CiaProcess::process()
{
	importIssuerProfiles();
	importHeader();

	if (mVerify)
	{
		verifyMetadata();
		verifyContent();
	}
	
	if (mShowHeaderInfo)
	{
		printHeader();
	}

	extractCia();
	processContent();
}

void ctrtool::CiaProcess::importIssuerProfiles()
{
	// import issuer profiles from keybag
	for (auto itr = mKeyBag.broadon_rsa_signer.begin(); itr != mKeyBag.broadon_rsa_signer.end(); itr++)
	{
		brd::es::ESSigType sigType = itr->first == "Root" ? brd::es::ESSigType::RSA4096_SHA256 : brd::es::ESSigType::RSA2048_SHA256;
		mIssuerSigner.insert(std::pair<std::string, std::shared_ptr<ntd::n3ds::es::ISigner>>(itr->first, std::make_shared<ntd::n3ds::es::RsaSigner>(ntd::n3ds::es::RsaSigner(sigType, itr->first, itr->second.key))));
	}
}

void ctrtool::CiaProcess::importHeader()
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
	if (mInputStream->length() < sizeof(ntd::n3ds::CiaHeader))
	{
		throw tc::InvalidOperationException(mModuleLabel, "Input stream too small. (Too small to read header).");
	}
	mInputStream->seek(0, tc::io::SeekOrigin::Begin);
	mInputStream->read((byte_t*)&mHeader, sizeof(ntd::n3ds::CiaHeader));

	// check the header size
	if (mHeader.header_size.unwrap() != sizeof(ntd::n3ds::CiaHeader))
	{
		throw tc::InvalidOperationException(mModuleLabel, "CiaHeader is corrupted (Bad header size).");
	}

	// check cia type
	if (mHeader.type.unwrap() != mHeader.Type_Normal)
	{
		throw tc::InvalidOperationException(mModuleLabel, fmt::format("CiaHeader has an unsupported Type (0x{:04x}).", mHeader.type.unwrap()));
	}

	// check format versions
	if (mHeader.format_version.unwrap() != mHeader.FormatVersion_Default && mHeader.format_version.unwrap() != mHeader.FormatVersion_SimpleCia)
	{
		throw tc::InvalidOperationException(mModuleLabel, fmt::format("CiaHeader has an unsupported FormatVersion (0x{:04x}).", mHeader.format_version.unwrap()));
	}

	// determine expected CIA size
	int64_t pos = 0;

	// add header size
	pos += mHeader.header_size.unwrap();

	// add cert size
	if (mHeader.certificate_size.unwrap())
	{
		pos = align<int64_t>(pos, ntd::n3ds::CiaHeader::kCiaSectionAlignment);
		
		mCertSizeInfo.offset = pos;
		mCertSizeInfo.size = mHeader.certificate_size.unwrap();

		pos += mCertSizeInfo.size;
	}

	// add ticket size
	if (mHeader.ticket_size.unwrap())
	{
		pos = align<int64_t>(pos, ntd::n3ds::CiaHeader::kCiaSectionAlignment);

		mTikSizeInfo.offset = pos;
		mTikSizeInfo.size = mHeader.ticket_size.unwrap();

		pos += mTikSizeInfo.size;
	}

	// add tmd size
	if (mHeader.tmd_size.unwrap())
	{
		pos = align<int64_t>(pos, ntd::n3ds::CiaHeader::kCiaSectionAlignment);

		mTmdSizeInfo.offset = pos;
		mTmdSizeInfo.size = mHeader.tmd_size.unwrap();

		pos += mTmdSizeInfo.size;
	}

	// add content size
	if (mHeader.content_size.unwrap())
	{
		pos = align<int64_t>(pos, ntd::n3ds::CiaHeader::kCiaSectionAlignment);

		mContentSizeInfo.offset = pos;
		mContentSizeInfo.size = mHeader.content_size.unwrap();

		pos += mContentSizeInfo.size;
	}

	// add footer size
	if (mHeader.footer_size.unwrap())
	{
		pos = align<int64_t>(pos, ntd::n3ds::CiaHeader::kCiaSectionAlignment);

		mFooterSizeInfo.offset = pos;
		mFooterSizeInfo.size = mHeader.footer_size.unwrap();

		pos += mFooterSizeInfo.size;
	}

	if (mInputStream->length() < pos)
	{
		throw tc::InvalidOperationException(mModuleLabel, "Input stream too small, given calculated CIA size.");
	}

	// process CIA
	if (mHeader.format_version.unwrap() == ntd::n3ds::CiaHeader::FormatVersion_Default)
	{
		if (mCertSizeInfo.size > 0)
		{
			std::shared_ptr<tc::io::IStream> certchain_stream = std::shared_ptr<tc::io::SubStream>(new tc::io::SubStream(mInputStream, mCertSizeInfo.offset, mCertSizeInfo.size));

			while (certchain_stream->position() < certchain_stream->length())
			{
				std::shared_ptr<tc::io::IStream> cert_stream = std::make_shared<tc::io::SubStream>(tc::io::SubStream(certchain_stream, certchain_stream->position(), certchain_stream->length() - certchain_stream->position()));
				mCertChain.push_back(ntd::n3ds::es::CertificateDeserialiser(cert_stream));
				mCertSigValid.push_back(ValidState::Unchecked);

				// update position of input stream
				//certchain_stream->seek(cert_stream->position(), tc::io::SeekOrigin::Current);

				// import issuer profile from certificate
				if (mCertChain.back().public_key_type == brd::es::ESCertPubKeyType::RSA2048)
				{
					std::string issuer = fmt::format("{}-{}", mCertChain.back().signature.issuer, mCertChain.back().subject);
					brd::es::ESSigType sig_type = brd::es::ESSigType::RSA2048_SHA256;
					auto& public_key = mCertChain.back().rsa2048_public_key;
					
					mCertImportedIssuerSigner.insert(std::pair<std::string, std::shared_ptr<ntd::n3ds::es::ISigner>>(issuer, std::make_shared<ntd::n3ds::es::RsaSigner>(ntd::n3ds::es::RsaSigner(sig_type, issuer, tc::crypto::RsaPublicKey(public_key.m.data(), public_key.m.size())))));
				}
				else if (mCertChain.back().public_key_type == brd::es::ESCertPubKeyType::RSA4096)
				{
					std::string issuer = fmt::format("{}-{}", mCertChain.back().signature.issuer + mCertChain.back().subject);
					brd::es::ESSigType sig_type = brd::es::ESSigType::RSA4096_SHA256;
					auto& public_key = mCertChain.back().rsa4096_public_key;
					
					mCertImportedIssuerSigner.insert(std::pair<std::string, std::shared_ptr<ntd::n3ds::es::ISigner>>(issuer, std::make_shared<ntd::n3ds::es::RsaSigner>(ntd::n3ds::es::RsaSigner(sig_type, issuer, tc::crypto::RsaPublicKey(public_key.m.data(), public_key.m.size())))));
				}
			}

		}

		if (mTikSizeInfo.size > 0)
		{
			mTicket = ntd::n3ds::es::TicketDeserialiser(std::shared_ptr<tc::io::SubStream>(new tc::io::SubStream(mInputStream, mTikSizeInfo.offset, mTikSizeInfo.size)));

			// determine title key
			if (mKeyBag.fallback_title_key.isSet())
			{
				if (mVerbose)
				{
					fmt::print(stderr, "[{} LOG] Using fallback titlekey.\n", mModuleLabel);
				}
				mDecryptedTitleKey = mKeyBag.fallback_title_key.get();
			}
			else if (mKeyBag.common_key.find(mTicket.key_id) != mKeyBag.common_key.end())
			{
				if (mVerbose)
				{
					fmt::print(stderr, "[{} LOG] Decrypting titlekey from ticket.\n", mModuleLabel);
				}
				
				// get common key
				auto common_key = mKeyBag.common_key[mTicket.key_id];
				
				// initialise iv
				std::array<byte_t, 16> title_key_iv;
				memset(title_key_iv.data(), 0, title_key_iv.size());
				((tc::bn::be64<uint64_t>*)(&(title_key_iv[0])))->wrap(mTicket.title_id);

				// decrypt title key
				std::array<byte_t, 16> title_key;
				tc::crypto::DecryptAes128Cbc(title_key.data(), mTicket.title_key.data(), title_key.size(), common_key.data(), common_key.size(), title_key_iv.data(), title_key_iv.size());
			
				mDecryptedTitleKey = title_key;
			}
			else
			{
				fmt::print(stderr, "[{} ERROR] Cannot determine titlekey.\n", mModuleLabel);
			}
		}
		else
		{
			throw tc::InvalidOperationException(mModuleLabel, "CIA has no Ticket.");
		}
		
		if (mTmdSizeInfo.size > 0)
		{
			mTitleMetaData = ntd::n3ds::es::TitleMetaDataDeserialiser(std::shared_ptr<tc::io::SubStream>(new tc::io::SubStream(mInputStream, mTmdSizeInfo.offset, mTmdSizeInfo.size)));

			mIsTwlTitle = isTwlTitle(mTitleMetaData.title_id);
		}
		else
		{
			throw tc::InvalidOperationException(mModuleLabel, "CIA has no TitleMetaData.");
		}
		if (mContentSizeInfo.size > 0)
		{
			int64_t content_pos = 0;
			for (auto itr = mTitleMetaData.content_info.begin(); itr != mTitleMetaData.content_info.end(); itr++)
			{
				// skip content not included
				if (mHeader.content_bitarray.test(itr->index) == false) continue;
				
				ContentInfo cnt;
				cnt.offset = mContentSizeInfo.offset + align<int64_t>(content_pos, (int64_t)ntd::n3ds::CiaHeader::kCiaContentAlignment);
				cnt.size = itr->size;
				cnt.cid = itr->id;
				cnt.cindex = itr->index;
				cnt.is_encrypted = itr->is_encrypted;
				cnt.is_hashed = true;
				cnt.hash = itr->hash;

				content_pos += cnt.size;

				mContentInfo[cnt.cindex] = std::move(cnt);
			}
		}
		else
		{
			throw tc::InvalidOperationException(mModuleLabel, "CIA has no Content.");
		}
	}
	else if (mHeader.format_version.unwrap() == ntd::n3ds::CiaHeader::FormatVersion_SimpleCia)
	{
		if (mContentSizeInfo.size > 0)
		{
			ContentInfo cnt;
			cnt.offset = mContentSizeInfo.offset;
			cnt.size = mContentSizeInfo.size;
			cnt.cid = 0;
			cnt.cindex = 0;
			cnt.is_encrypted = false;
			cnt.is_hashed = false;
			memset(cnt.hash.data(), 0, cnt.hash.size());

			mContentInfo[cnt.cindex] = std::move(cnt);

			mIsTwlTitle = false;
		}
		else
		{
			throw tc::InvalidOperationException(mModuleLabel, "CIA has no Content.");
		}
	}
	else
	{
		throw tc::NotSupportedException(mModuleLabel, fmt::format("Unsupported CIA format version: 0x{:04x}.", mHeader.format_version.unwrap()));
	}
}

void ctrtool::CiaProcess::verifyMetadata()
{
	// validate signatures
	if (mHeader.format_version.unwrap() == ntd::n3ds::CiaHeader::FormatVersion_Default && mCertSizeInfo.size > 0)
	{
		// verify cert
		for (size_t i = 0; i < mCertChain.size(); i++)
		{
			auto local_issuer_itr = mCertImportedIssuerSigner.find(mCertChain[i].signature.issuer);
			auto keybag_issuer_itr = mIssuerSigner.find(mCertChain[i].signature.issuer);
			
			// first try with the issuer profiles imported from the local certificates
			if (local_issuer_itr != mCertImportedIssuerSigner.end() && local_issuer_itr->second->getSigType() == mCertChain[i].signature.sig_type)
			{
				mCertSigValid[i] = local_issuer_itr->second->verifyHash(mCertChain[i].calculated_hash.data(), mCertChain[i].signature.sig.data()) ? ValidState::Good : ValidState::Fail;
			}
			// fallback try with the keybag imported issuer
			else if (keybag_issuer_itr != mIssuerSigner.end() && keybag_issuer_itr->second->getSigType() == mCertChain[i].signature.sig_type)
			{
				// only show this warning for non-root signed certificates
				if (mCertChain[i].signature.issuer != "Root")
				{
					fmt::print(stderr, "[{} ERROR] Public key \"{}\" (for certificate \"{}\") was not present in the CIA certificate chain. The public key included with CTRTool was used instead.\n", mModuleLabel, mCertChain[i].signature.issuer, mCertChain[i].subject);
				}
				mCertSigValid[i] = keybag_issuer_itr->second->verifyHash(mCertChain[i].calculated_hash.data(), mCertChain[i].signature.sig.data()) ? ValidState::Good : ValidState::Fail;
			}
			else
			{
				// cannot locate rsa key to verify
				fmt::print(stderr, "[{} ERROR] Could not locate public key for \"{}\" (certificate).\n", mModuleLabel, mCertChain[i].signature.issuer);
				mCertSigValid[i] = ValidState::Fail;
			}

			// log certificate signature validation error
			if (mCertSigValid[i] != ValidState::Good)
			{
				fmt::print(stderr, "[{} ERROR] Signature for Certificate \"{}\" was invalid.\n", mModuleLabel, mCertChain[i].signature.issuer);
			}
		}
	}
	if (mHeader.format_version.unwrap() == ntd::n3ds::CiaHeader::FormatVersion_Default && mTikSizeInfo.size > 0)
	{
		// verify ticket
		auto local_issuer_itr = mCertImportedIssuerSigner.find(mTicket.signature.issuer);
		auto keybag_issuer_itr = mIssuerSigner.find(mTicket.signature.issuer);

		// first try with the issuer profiles imported from the local certificates
		if (local_issuer_itr != mCertImportedIssuerSigner.end() && local_issuer_itr->second->getSigType() == mTicket.signature.sig_type)
		{
			mTicketSigValid = local_issuer_itr->second->verifyHash(mTicket.calculated_hash.data(), mTicket.signature.sig.data()) ? ValidState::Good : ValidState::Fail;
		}
		// fallback try with the keybag imported issuer
		else if (keybag_issuer_itr != mIssuerSigner.end() && keybag_issuer_itr->second->getSigType() == mTicket.signature.sig_type)
		{
			fmt::print(stderr, "[{} ERROR] Public key \"{}\" (for ticket) was not present in the CIA certificate chain. The public key included with CTRTool was used instead.\n", mModuleLabel, mTicket.signature.issuer);
			mTicketSigValid = keybag_issuer_itr->second->verifyHash(mTicket.calculated_hash.data(), mTicket.signature.sig.data()) ? ValidState::Good : ValidState::Fail;
		}
		else
		{
			// cannot locate rsa key to verify
			fmt::print(stderr, "[{} ERROR] Could not locate public key \"{}\" (for ticket).\n", mModuleLabel, mTicket.signature.issuer);
			mTicketSigValid = ValidState::Fail;
		}

		// log ticket signature validation error
		if (mTicketSigValid != ValidState::Good)
		{
			fmt::print(stderr, "[{} ERROR] Signature for Ticket was invalid.\n", mModuleLabel);
		}
	}
	if (mHeader.format_version.unwrap() == ntd::n3ds::CiaHeader::FormatVersion_Default && mTmdSizeInfo.size > 0)
	{
		// verify tmd
		auto local_issuer_itr = mCertImportedIssuerSigner.find(mTitleMetaData.signature.issuer);
		auto keybag_issuer_itr = mIssuerSigner.find(mTitleMetaData.signature.issuer);

		// first try with the issuer profiles imported from the local certificates
		if (local_issuer_itr != mCertImportedIssuerSigner.end() && local_issuer_itr->second->getSigType() == mTitleMetaData.signature.sig_type)
		{
			mTitleMetaDataSigValid = local_issuer_itr->second->verifyHash(mTitleMetaData.calculated_hash.data(), mTitleMetaData.signature.sig.data()) ? ValidState::Good : ValidState::Fail;
		}
		// fallback try with the keybag imported issuer
		else if (keybag_issuer_itr != mIssuerSigner.end() && keybag_issuer_itr->second->getSigType() == mTitleMetaData.signature.sig_type)
		{
			fmt::print(stderr, "[{} ERROR] Public key \"{}\" (for tmd) was not present in the CIA certificate chain. The public key included with CTRTool was used instead.\n", mModuleLabel, mTitleMetaData.signature.issuer);
			mTitleMetaDataSigValid = keybag_issuer_itr->second->verifyHash(mTitleMetaData.calculated_hash.data(), mTitleMetaData.signature.sig.data()) ? ValidState::Good : ValidState::Fail;
		}
		else
		{
			// cannot locate rsa key to verify
			fmt::print(stderr, "[{} ERROR] Could not locate public key \"{}\" (for tmd).\n", mModuleLabel, mTitleMetaData.signature.issuer);
			mTitleMetaDataSigValid = ValidState::Fail;
		}

		// log tmd signature validation error
		if (mTitleMetaDataSigValid != ValidState::Good)
		{
			fmt::print(stderr, "[{} ERROR] Signature for TitleMetaData was invalid.\n", mModuleLabel);
		}
	}
}

void ctrtool::CiaProcess::verifyContent()
{
	std::shared_ptr<tc::io::IStream> content_stream;
	tc::ByteData cache = tc::ByteData(0x10000);
	size_t cache_read_len;
	tc::crypto::Sha256Generator sha256_calc;
	std::array<byte_t, tc::crypto::Sha256Generator::kHashSize> sha256_hash;

	if (mContentInfo.size() > 0)
	{
		for (auto itr = mContentInfo.begin(); itr != mContentInfo.end(); itr++)
		{
			// skip unhashed content
			if (itr->second.is_hashed == false) continue;

			content_stream = std::shared_ptr<tc::io::SubStream>(new tc::io::SubStream(mInputStream, itr->second.offset, itr->second.size));

			if (!mPlain && itr->second.is_encrypted && mDecryptedTitleKey.isSet())
			{
				tc::crypto::Aes128CbcEncryptedStream::iv_t content_iv;
				createContentIv(content_iv, itr->second.cindex);

				content_stream = std::shared_ptr<tc::crypto::Aes128CbcEncryptedStream>(new tc::crypto::Aes128CbcEncryptedStream(content_stream, mDecryptedTitleKey.get(), content_iv));
			}
		
			sha256_calc.initialize();
			memset(sha256_hash.data(), 0, sha256_hash.size());

			content_stream->seek(0, tc::io::SeekOrigin::Begin);
			for (int64_t remaining_data = content_stream->length(); remaining_data > 0;)
			{
				cache_read_len = content_stream->read(cache.data(), cache.size());
				if (cache_read_len == 0)
				{
					throw tc::io::IOException(mModuleLabel, "Failed to read from source file.");
				}

				sha256_calc.update(cache.data(), cache_read_len);

				remaining_data -= int64_t(cache_read_len);
			}

			sha256_calc.getHash(sha256_hash.data());

			itr->second.valid_state = memcmp(sha256_hash.data(), itr->second.hash.data(), sha256_hash.size()) == 0 ? ValidState::Good : ValidState::Fail;

			if (itr->second.valid_state != ValidState::Good)
			{
				fmt::print(stderr, "[{} ERROR] Hash for content (index=0x{:04x}, id=0x{:08x}) was invalid.\n", mModuleLabel, itr->second.cindex, itr->second.cid);
			}
		}
	}
}

void ctrtool::CiaProcess::printHeader()
{
	{
		fmt::print("CiaHeader:\n");
		fmt::print("|- HeaderSize:      0x{:x}\n", mHeader.header_size.unwrap());
		fmt::print("|- Type:            {} (0x{:04x})\n", getCiaTypeString(mHeader.type.unwrap()), mHeader.type.unwrap());
		fmt::print("|- FormatVersion:   {} (0x{:04x})\n", getFormatVersionString(mHeader.format_version.unwrap()), mHeader.format_version.unwrap());
		fmt::print("|- CertificateSize: 0x{:x}\n", mHeader.certificate_size.unwrap());
		fmt::print("|- TicketSize:      0x{:x}\n", mHeader.ticket_size.unwrap());
		fmt::print("|- TitleMetaSize:   0x{:x}\n", mHeader.tmd_size.unwrap());
		fmt::print("|- FooterSize:      0x{:x}\n", mHeader.footer_size.unwrap());
		fmt::print("|- ContentSize:     0x{:x}\n", mHeader.content_size.unwrap());
		fmt::print("\\- EnabledContent:\n");
		std::vector<size_t> enabled_content;
		for (size_t i = 0; i < mHeader.content_bitarray.bit_size(); i++)
		{
			if (mHeader.content_bitarray.test(i))
			{
				enabled_content.push_back(i);
			}
		}
		for (size_t i = 0; i < enabled_content.size(); i++)
		{
			fmt::print("   {:1}- 0x{:04x}\n", (i+1 < enabled_content.size() ? "|" : "\\"), enabled_content[i]);
		}
	}
	if (mHeader.format_version.unwrap() == ntd::n3ds::CiaHeader::FormatVersion_Default && mCertSizeInfo.size > 0)
	{
		fmt::print("Certificate Chain:\n");
		for (size_t i = 0; i < mCertChain.size(); i++)
		{
			#define _CERT_FORMAT_MACRO(x,y) (i+1 < mCertChain.size() ? (x) : (y))

			fmt::print("{:1}- Certificate {:d}:\n", _CERT_FORMAT_MACRO("|","\\"), i);
			fmt::print("{:1}  |- DigitalSignature: {:s}\n", _CERT_FORMAT_MACRO("|"," "), getValidString(mCertSigValid[i]));
			fmt::print("{:1}  |  |- SigType:    {:s} (0x{:x})\n", _CERT_FORMAT_MACRO("|"," "), getSigTypeString(mCertChain[i].signature.sig_type), (uint32_t)mCertChain[i].signature.sig_type);
			fmt::print("{:1}  |  |- Issuer:     {:s}\n", _CERT_FORMAT_MACRO("|"," "), mCertChain[i].signature.issuer);
			fmt::print("{:1}  |  \\- Signature:  {:s}\n", _CERT_FORMAT_MACRO("|"," "), getTruncatedBytesString(mCertChain[i].signature.sig.data(), mCertChain[i].signature.sig.size(), mVerbose));
			fmt::print("{:1}  |- Subject:       {:s}\n", _CERT_FORMAT_MACRO("|"," "), mCertChain[i].subject);
			//fmt::print("{:1}  |- Date:          {:d}\n", _CERT_FORMAT_MACRO("|"," "), mCertChain[i].date);
			fmt::print("{:1}  \\- PublicKey:     {:s} (0x{:x})\n", _CERT_FORMAT_MACRO("|"," "), getCertificatePublicKeyTypeString(mCertChain[i].public_key_type), (uint32_t)mCertChain[i].public_key_type);
			switch (mCertChain[i].public_key_type)
			{
				case brd::es::ESCertPubKeyType::RSA4096:
					fmt::print("{:1}     |- m:          {:s}\n", _CERT_FORMAT_MACRO("|"," "), getTruncatedBytesString(mCertChain[i].rsa4096_public_key.m.data(), mCertChain[i].rsa4096_public_key.m.size(), mVerbose));
					fmt::print("{:1}     \\- e:          {:s}\n", _CERT_FORMAT_MACRO("|"," "), getTruncatedBytesString(mCertChain[i].rsa4096_public_key.e.data(), mCertChain[i].rsa4096_public_key.e.size(), mVerbose));
					break;
				case brd::es::ESCertPubKeyType::RSA2048:
					fmt::print("{:1}     |- m:          {:s}\n", _CERT_FORMAT_MACRO("|"," "), getTruncatedBytesString(mCertChain[i].rsa2048_public_key.m.data(), mCertChain[i].rsa2048_public_key.m.size(), mVerbose));
					fmt::print("{:1}     \\- e:          {:s}\n", _CERT_FORMAT_MACRO("|"," "), getTruncatedBytesString(mCertChain[i].rsa2048_public_key.e.data(), mCertChain[i].rsa2048_public_key.e.size(), mVerbose));
					break;
				case brd::es::ESCertPubKeyType::ECC:
					fmt::print("{:1}     |- x:          {:s}\n", _CERT_FORMAT_MACRO("|"," "), getTruncatedBytesString(mCertChain[i].ecc233_public_key.x.data(), mCertChain[i].ecc233_public_key.x.size(), mVerbose));
					fmt::print("{:1}     \\- y:          {:s}\n", _CERT_FORMAT_MACRO("|"," "), getTruncatedBytesString(mCertChain[i].ecc233_public_key.y.data(), mCertChain[i].ecc233_public_key.y.size(), mVerbose));
					break;
				default:
					break;
			}

			#undef _CERT_FORMAT_MACRO
		}
		
	}
	if (mHeader.format_version.unwrap() == ntd::n3ds::CiaHeader::FormatVersion_Default && mTikSizeInfo.size > 0)
	{
		fmt::print("Ticket:\n");
		fmt::print("|- DigitalSignature: {:s} \n", getValidString(mTicketSigValid));
		fmt::print("|  |- SigType:    {:s} (0x{:x})\n", getSigTypeString(mTicket.signature.sig_type), (uint32_t)mTicket.signature.sig_type);
		fmt::print("|  |- Issuer:     {:s}\n", mTicket.signature.issuer);
		fmt::print("|  \\- Signature:  {:s}\n", getTruncatedBytesString(mTicket.signature.sig.data(), mTicket.signature.sig.size(), mVerbose));
		fmt::print("|- TitleKey:      {}", tc::cli::FormatUtil::formatBytesAsString(mTicket.title_key.data(), mTicket.title_key.size(), true, ""));
		if (mDecryptedTitleKey.isSet())
		{
			fmt::print(" (decrypted: {})", tc::cli::FormatUtil::formatBytesAsString(mDecryptedTitleKey.get().data(), mDecryptedTitleKey.get().size(), true, ""));
		}
		fmt::print("\n");
		fmt::print("|- TicketId:      {:016x}\n", mTicket.ticket_id);
		fmt::print("|- DeviceId:      {:08x}\n", mTicket.device_id);
		fmt::print("|- TitleId:       {:016x}\n", mTicket.title_id);
		fmt::print("|- TicketVersion: {} ({:d})\n", getTitleVersionString(mTicket.ticket_version), mTicket.ticket_version);
		fmt::print("|- LicenseType:   {:02x}\n", mTicket.license_type);
		fmt::print("|- KeyId:         {:02x}\n", mTicket.key_id);
		fmt::print("|- ECAccountID:   {:08x}\n", mTicket.ec_account_id);
		fmt::print("|- DemoLaunchCnt: {:d}\n", mTicket.launch_count);
		fmt::print("\\- EnabledContent:\n");
		std::vector<size_t> enabled_content;
		for (size_t i = 0; i < mTicket.enabled_content.size(); i++)
		{
			if (mTicket.enabled_content.test(i))
			{
				enabled_content.push_back(i);
			}
		}
		for (size_t i = 0; i < enabled_content.size(); i++)
		{
			fmt::print("   {:1}- 0x{:04x}\n", (i+1 < enabled_content.size() ? "|" : "\\"), enabled_content[i]);
		}
	}
	if (mHeader.format_version.unwrap() == ntd::n3ds::CiaHeader::FormatVersion_Default && mTmdSizeInfo.size > 0)
	{
		fmt::print("TitleMetaData:\n");
		fmt::print("|- DigitalSignature: {:s}\n", getValidString(mTitleMetaDataSigValid));
		fmt::print("|  |- SigType:    {:s} (0x{:x})\n", getSigTypeString(mTitleMetaData.signature.sig_type), (uint32_t)mTitleMetaData.signature.sig_type);
		fmt::print("|  |- Issuer:     {:s}\n", mTitleMetaData.signature.issuer);
		fmt::print("|  \\- Signature:  {:s}\n", getTruncatedBytesString(mTitleMetaData.signature.sig.data(), mTitleMetaData.signature.sig.size(), mVerbose));
		fmt::print("|- TitleId:       {:016x}\n", mTitleMetaData.title_id);
		fmt::print("|- TitleVersion:  {} ({:d})\n", getTitleVersionString(mTitleMetaData.title_version), mTitleMetaData.title_version);
		fmt::print("|- CustomData:\n");
		// TWL Title
		if (isTwlTitle(mTitleMetaData.title_id))
		{
			fmt::print("|  |- PublicSaveDataSize:  0x{:x}\n", mTitleMetaData.twl_custom_data.public_save_data_size);
			fmt::print("|  |- PrivateSaveDataSize: 0x{:x}\n", mTitleMetaData.twl_custom_data.private_save_data_size);
			fmt::print("|  \\- Flag:                0x{:02x}\n", mTitleMetaData.twl_custom_data.flag);
		}
		// CTR
		else
		{
			fmt::print("|  |- SaveDataSize: 0x{:x}\n", mTitleMetaData.ctr_custom_data.save_data_size);
			fmt::print("|  \\- IsSnakeOnly: {}\n", mTitleMetaData.ctr_custom_data.is_snake_only);
		}
		fmt::print("\\- ContentInfo:\n");
		for (size_t i = 0; i < mTitleMetaData.content_info.size(); i++)
		{
			fmt::print("   {:1}- 0x{:04x}:\n", (i+1 < mTitleMetaData.content_info.size() ? "|" : "\\"), mTitleMetaData.content_info[i].index);
			fmt::print("   {:1}  |- ContentId:   0x{:08x}\n", (i+1 < mTitleMetaData.content_info.size() ? "|" : ""), mTitleMetaData.content_info[i].id);
			fmt::print("   {:1}  |- Encrypted:   {}\n", (i+1 < mTitleMetaData.content_info.size() ? "|" : ""), (mTitleMetaData.content_info[i].is_encrypted ? "YES" : "NO"));
			fmt::print("   {:1}  |- Optional:    {}\n", (i+1 < mTitleMetaData.content_info.size() ? "|" : ""), (mTitleMetaData.content_info[i].is_optional ? "YES" : "NO"));
			fmt::print("   {:1}  |- Size:        0x{:x}\n", (i+1 < mTitleMetaData.content_info.size() ? "|" : ""), mTitleMetaData.content_info[i].size);
			fmt::print("   {:1}  \\- Hash: {:6} {}\n", (i+1 < mTitleMetaData.content_info.size() ? "|" : ""),
				getValidString(mContentInfo.find(mTitleMetaData.content_info[i].index) != mContentInfo.end() ? mContentInfo[mTitleMetaData.content_info[i].index].valid_state : ValidState::Unchecked),
				tc::cli::FormatUtil::formatBytesAsString(mTitleMetaData.content_info[i].hash.data(), mTitleMetaData.content_info[i].hash.size(), true, ""));
		}
	}
	
}

void ctrtool::CiaProcess::extractCia()
{
	tc::ByteData cache = tc::ByteData(0x10000);
	tc::io::Path out_path;
	std::shared_ptr<tc::io::IStream> in_stream;

	if (mCertExtractPath.isSet() && mCertSizeInfo.size > 0)
	{
		out_path = mCertExtractPath.get();

		in_stream = std::shared_ptr<tc::io::SubStream>(new tc::io::SubStream(mInputStream, mCertSizeInfo.offset, mCertSizeInfo.size));

		if (mVerbose)
		{
			fmt::print(stderr, "[{} LOG] Saving certs to {}...\n", mModuleLabel, out_path.to_string());
		}
		
		writeStreamToFile(in_stream, out_path, cache);
	}

	if (mTikExtractPath.isSet() && mTikSizeInfo.size > 0)
	{
		out_path = mTikExtractPath.get();

		in_stream = std::shared_ptr<tc::io::SubStream>(new tc::io::SubStream(mInputStream, mTikSizeInfo.offset, mTikSizeInfo.size));

		if (mVerbose)
		{
			fmt::print(stderr, "[{} LOG] Saving tik to {}...\n", mModuleLabel, out_path.to_string());
		}

		writeStreamToFile(in_stream, out_path, cache);
	}

	if (mTmdExtractPath.isSet() && mTmdSizeInfo.size > 0)
	{
		out_path = mTmdExtractPath.get();

		in_stream = std::shared_ptr<tc::io::SubStream>(new tc::io::SubStream(mInputStream, mTmdSizeInfo.offset, mTmdSizeInfo.size));

		if (mVerbose)
		{
			fmt::print(stderr, "[{} LOG] Saving tmd to {}...\n", mModuleLabel, out_path.to_string());
		}

		writeStreamToFile(in_stream, out_path, cache);
	}

	if (mFooterExtractPath.isSet() && mFooterSizeInfo.size > 0)
	{
		out_path = mFooterExtractPath.get();

		in_stream = std::shared_ptr<tc::io::SubStream>(new tc::io::SubStream(mInputStream, mFooterSizeInfo.offset, mFooterSizeInfo.size));

		if (mVerbose)
		{
			fmt::print(stderr, "[{} LOG] Saving meta to {}...\n", mModuleLabel, out_path.to_string());
		}

		writeStreamToFile(in_stream, out_path, cache);
	}

	if (mContentExtractPath.isSet() && mContentInfo.size() > 0)
	{
		for (auto itr = mContentInfo.begin(); itr != mContentInfo.end(); itr++)
		{
			out_path = mContentExtractPath.get();
			out_path.back() = fmt::format("{}.{:04x}.{:08x}", out_path.back(), itr->second.cindex, itr->second.cid);

			in_stream = std::shared_ptr<tc::io::SubStream>(new tc::io::SubStream(mInputStream, itr->second.offset, itr->second.size));

			if (!mPlain && itr->second.is_encrypted && mDecryptedTitleKey.isSet())
			{
				tc::crypto::Aes128CbcEncryptedStream::iv_t content_iv;
				createContentIv(content_iv, itr->second.cindex);

				in_stream = std::shared_ptr<tc::crypto::Aes128CbcEncryptedStream>(new tc::crypto::Aes128CbcEncryptedStream(in_stream, mDecryptedTitleKey.get(), content_iv));
			}

			if (mVerbose)
			{
				fmt::print(stderr, "[{} LOG] Saving content {:04x} to {}...\n", mModuleLabel, itr->second.cindex, out_path.to_string());
			}

			if (mDecryptNcch)
			{
				if (mVerbose)
				{
					fmt::print(stderr, "[{} LOG] Decrypting NCCH partition before saving {}...\n", mModuleLabel, out_path.to_string());
				}

				NcchProcess ncchProcess;
				ncchProcess.setInputStream(in_stream);
				ncchProcess.setVerboseMode(mVerbose);
				ncchProcess.setKeyBag(mKeyBag);
				ncchProcess.decryptNcchStream(in_stream);
			}
			
			writeStreamToFile(in_stream, out_path, cache);
		}
	}
}

void ctrtool::CiaProcess::processContent()
{
	if (mContentIndex >= ntd::n3ds::CiaHeader::kCiaMaxContentNum)
	{
		fmt::print(stderr, "[{} ERROR] Content index {:d} isn't valid for CIA, use index 0-{:d}, defaulting to 0 now.\n", mModuleLabel, mContentIndex, ((size_t)ntd::n3ds::CiaHeader::kCiaMaxContentNum)-1);
		mContentIndex = 0;
	}
	if (mContentInfo.find(mContentIndex) != mContentInfo.end() && mContentInfo[mContentIndex].size != 0)
	{
		std::shared_ptr<tc::io::IStream> content_stream = std::shared_ptr<tc::io::SubStream>(new tc::io::SubStream(mInputStream, mContentInfo[mContentIndex].offset, mContentInfo[mContentIndex].size));
		
		if (!mPlain && mContentInfo[mContentIndex].is_encrypted && mDecryptedTitleKey.isSet())
		{
			tc::crypto::Aes128CbcEncryptedStream::iv_t content_iv;
			createContentIv(content_iv, mContentInfo[mContentIndex].cindex);

			content_stream = std::shared_ptr<tc::crypto::Aes128CbcEncryptedStream>(new tc::crypto::Aes128CbcEncryptedStream(content_stream, mDecryptedTitleKey.get(), content_iv));
		}
		
		if (mIsTwlTitle == false)
		{
			mNcchProcess.setInputStream(content_stream);
			mNcchProcess.process();
		}
		else
		{
			throw tc::NotImplementedException(mModuleLabel, "TWL title processing not supported.");
		}
	}
}

void ctrtool::CiaProcess::createContentIv(std::array<byte_t, 16>& content_iv, uint16_t index)
{
	memset(content_iv.data(), 0, content_iv.size());
	((tc::bn::be16<uint16_t>*)&content_iv[0])->wrap(index);
}

bool ctrtool::CiaProcess::isTwlTitle(uint64_t title_id)
{
	return ((title_id >> 47) & 1) == 1;
}

std::string ctrtool::CiaProcess::getValidString(byte_t validstate)
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

std::string ctrtool::CiaProcess::getCiaTypeString(uint16_t type)
{
	std::string ret_str;

	switch (type)
	{
		case ntd::n3ds::CiaHeader::Type_Normal:
			ret_str =  "Normal";
			break;
		default:
			ret_str =  "Unknown";
			break;
	}

	return ret_str;
}

std::string ctrtool::CiaProcess::getFormatVersionString(uint16_t format_version)
{
	std::string ret_str;

	switch (format_version)
	{
		case ntd::n3ds::CiaHeader::FormatVersion_Default:
			ret_str =  "Cia";
			break;
		case ntd::n3ds::CiaHeader::FormatVersion_SimpleCia:
			ret_str =  "SimpleCia";
			break;
		default:
			ret_str =  "Unknown";
			break;
	}

	return ret_str;
}

std::string ctrtool::CiaProcess::getTruncatedBytesString(const byte_t* data, size_t len, bool do_not_truncate)
{
	if (data == nullptr) { return fmt::format(""); }

	std::string str = "";

	if (len <= 8 || do_not_truncate)
	{
		str = tc::cli::FormatUtil::formatBytesAsString(data, len, true, "");
	}
	else
	{
		str = fmt::format("{:02X}{:02X}{:02X}{:02X}...{:02X}{:02X}{:02X}{:02X}", data[0], data[1], data[2], data[3], data[len-4], data[len-3], data[len-2], data[len-1]);
	}

	return str;
}

std::string ctrtool::CiaProcess::getSigTypeString(brd::es::ESSigType sig_type)
{
	std::string ret_str;

	switch (sig_type)
	{
		case brd::es::ESSigType::RSA4096_SHA1:
			ret_str =  "RSA-4096-SHA1";
			break;
		case brd::es::ESSigType::RSA2048_SHA1:
			ret_str =  "RSA-2048-SHA1";
			break;
		case brd::es::ESSigType::ECC_SHA1:
			ret_str =  "ECDSA-233-SHA1";
			break;
		case brd::es::ESSigType::RSA4096_SHA256:
			ret_str =  "RSA-4096-SHA256";
			break;
		case brd::es::ESSigType::RSA2048_SHA256:
			ret_str =  "RSA-2048-SHA256";
			break;
		case brd::es::ESSigType::ECC_SHA256:
			ret_str =  "ECDSA-233-SHA256";
			break;
		default:
			ret_str = fmt::format("0x{:x}", (uint32_t)sig_type);
	}

	return ret_str;
}

std::string ctrtool::CiaProcess::getCertificatePublicKeyTypeString(brd::es::ESCertPubKeyType public_key_type)
{
	std::string ret_str;

	switch (public_key_type)
	{
		case brd::es::ESCertPubKeyType::RSA4096:
			ret_str =  "RSA-4096";
			break;
		case brd::es::ESCertPubKeyType::RSA2048:
			ret_str =  "RSA-2048";
			break;
		case brd::es::ESCertPubKeyType::ECC:
			ret_str =  "ECC-233";
			break;
		default:
			ret_str = fmt::format("0x{:x}", (uint32_t)public_key_type);
	}

	return ret_str;
}

std::string ctrtool::CiaProcess::getTitleVersionString(uint16_t version)
{
	return fmt::format("{major:d}.{minor:d}.{build:d}", fmt::arg("major", (uint32_t)((version >> 10) & 0x3F)), fmt::arg("minor", (uint32_t)((version >> 4) & 0x3F)), fmt::arg("build", (uint32_t)(version & 0xF)));
}

void ctrtool::CiaProcess::setDecryptNcch(bool decryptNcch)
{
	mDecryptNcch = decryptNcch;
}