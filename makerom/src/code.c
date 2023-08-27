#include "lib.h"
#include "elf.h"
#include "ncch_build.h"
#include "exheader_read.h"
#include "code.h"

#include <blz.h>

const u32 CTR_PAGE_SIZE = 0x1000;
const u32 DEFAULT_STACK_SIZE = 0x4000; // 10KB

typedef struct code_segment
{
	u32 address;
	u32 memSize;
	u32 fileSize;
	u32 pageNum;
	const u8 *data;
} code_segment;

u32 SizeToPage(u32 memorySize)
{
	return align(memorySize, CTR_PAGE_SIZE) / CTR_PAGE_SIZE;
}

u32 PageToSize(u32 pageNum)
{
	return pageNum * CTR_PAGE_SIZE;
}

int ImportPlainRegionFromFile(ncch_settings *set)
{
	set->sections.plainRegion.size = align(set->componentFilePtrs.plainregionSize, set->options.blockSize);
	set->sections.plainRegion.buffer = calloc(set->sections.plainRegion.size, 1);
	if (!set->sections.plainRegion.buffer) { fprintf(stderr, "[ELF ERROR] Not enough memory\n"); return MEM_ERROR; }
	ReadFile64(set->sections.plainRegion.buffer, set->componentFilePtrs.plainregionSize, 0, set->componentFilePtrs.plainregion);
	return 0;
}

int ImportExeFsCodeBinaryFromFile(ncch_settings *set)
{
	u32 size = set->componentFilePtrs.codeSize;
	u8 *buffer = malloc(size);
	if (!buffer) {
		fprintf(stderr, "[CODE ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	ReadFile64(buffer, size, 0, set->componentFilePtrs.code);

	set->exefsSections.code.size = set->componentFilePtrs.codeSize;
	set->exefsSections.code.buffer = malloc(set->exefsSections.code.size);
	if (!set->exefsSections.code.buffer) { fprintf(stderr, "[ELF ERROR] Not enough memory\n"); return MEM_ERROR; }
	ReadFile64(set->exefsSections.code.buffer, set->exefsSections.code.size, 0, set->componentFilePtrs.code);
	if (set->options.CompressCode) {
		if (set->options.verbose)
			printf("[CODE] Compressing code... ");
		u32 new_len;
		set->exefsSections.code.buffer = BLZ_Code(buffer, size, &new_len, BLZ_NORMAL);
		set->exefsSections.code.size = new_len;
		free(buffer);
		if (set->options.verbose)
			printf("Done!\n");
	}
	else {
		set->exefsSections.code.size = size;
		set->exefsSections.code.buffer = buffer;
	}

	size = set->componentFilePtrs.exhdrSize;
	if (size < sizeof(extended_hdr)) {
		fprintf(stderr, "[CODE ERROR] Exheader code info template is too small\n");
		return FAILED_TO_IMPORT_FILE;
	}
	extended_hdr *exhdr = malloc(size);
	if (!exhdr) {
		fprintf(stderr, "[CODE ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	ReadFile64(exhdr, size, 0, set->componentFilePtrs.exhdr);

	/* Setting code_segment data */
	set->codeDetails.textAddress = u8_to_u32(exhdr->codeSetInfo.text.address, LE);
	set->codeDetails.textMaxPages = u8_to_u32(exhdr->codeSetInfo.text.numMaxPages, LE);
	set->codeDetails.textSize = u8_to_u32(exhdr->codeSetInfo.text.codeSize, LE);

	set->codeDetails.roAddress = u8_to_u32(exhdr->codeSetInfo.rodata.address, LE);
	set->codeDetails.roMaxPages = u8_to_u32(exhdr->codeSetInfo.rodata.numMaxPages, LE);
	set->codeDetails.roSize = u8_to_u32(exhdr->codeSetInfo.rodata.codeSize, LE);

	set->codeDetails.rwAddress = u8_to_u32(exhdr->codeSetInfo.data.address, LE);
	set->codeDetails.rwMaxPages = u8_to_u32(exhdr->codeSetInfo.data.numMaxPages, LE);
	set->codeDetails.rwSize = u8_to_u32(exhdr->codeSetInfo.data.codeSize, LE);

	set->codeDetails.bssSize = u8_to_u32(exhdr->codeSetInfo.bssSize, LE);

	set->codeDetails.stackSize = u8_to_u32(exhdr->codeSetInfo.stackSize, LE);

	free(exhdr);

	return 0;
}

int ImportPlainRegionFromElf(elf_context *elf, ncch_settings *set)
{
	elf_segment segment = elf_GetSegments(elf)[elf_SegmentNum(elf) - 1];

	/* Check last segment
	If the last segment is RO segment, this must be an SDK .module_id segment */
	if (segment.flags != PF_RODATA) {
		/* not a RO segment */
		return 0;
	}

	if (segment.fileSize > 0) {
		/* Creating Output Buffer */
		set->sections.plainRegion.size = align(segment.fileSize, set->options.blockSize);
		set->sections.plainRegion.buffer = calloc(set->sections.plainRegion.size, 1);
		if (!set->sections.plainRegion.buffer) { fprintf(stderr, "[CODE ERROR] Not enough memory\n"); return MEM_ERROR; }

		/* Copy Plain Region */
		memcpy(set->sections.plainRegion.buffer, segment.ptr, segment.fileSize);
	}
	return 0;
}

void CreateCodeSegmentFromElf(code_segment *out, elf_context *elf, u64 segment_flags, bool baremetal, u32 baremetalOrder)
{
	u32 segmentNum = elf_SegmentNum(elf);
	const elf_segment *segments = elf_GetSegments(elf);
	u16 foundSegmentId = segmentNum;

	/* Initialise struct data */
	out->address = 0;
	out->memSize = 0;
	out->pageNum = 0;
	out->fileSize = 0;
	out->data = NULL;

	if (baremetal) {
		/*	With Kernel9 and with LGY firm K11, everything is RWX with no memory management.
			While it is a bit hard to replicate what Nintendo do with their toolchain, we can
			abuse how these kernels work and remove meaning from "text segment" etc.

			The other option would be to add support for multiple phdr per "section" and allow
			for RWX phdrs (and perhaps parse phdr list from .rsf), plus read LMA instead of VMA below,
			but that's a lot more work compared to this dirty workaround.

			First segment defines entrypoint and LMA for the rest of the image.*/
		if (baremetalOrder < segmentNum && (segments[baremetalOrder].flags & segment_flags) == segment_flags && segments[baremetalOrder].type == PT_LOAD)
			foundSegmentId = baremetalOrder;
	} else {
		/* Find segment */
		for (u16 i = 0; i < segmentNum; i++) {
			/*	Skip SDK ELF .module_id segment
				The last segment should always be data in valid ELFs,
				unless this is an SDK ELF with .module_id segment */
			if (i == segmentNum-1 && segments[i].flags == PF_RODATA)
				continue;

			/* Found segment */
			if ((segments[i].flags & ~PF_CTRSDK) == segment_flags && segments[i].type == PT_LOAD) {
				foundSegmentId = i;
				break;
			}
		}
	}

	if (foundSegmentId < segmentNum) {
		out->address = segments[foundSegmentId].vAddr;
		out->memSize = segments[foundSegmentId].memSize;
		out->fileSize = segments[foundSegmentId].fileSize;
		out->pageNum = SizeToPage(out->fileSize);
		out->data = segments[foundSegmentId].ptr;
	}
}

int CreateExeFsCode(elf_context *elf, ncch_settings *set)
{
	/* Getting Code Segments */
	code_segment text;
	code_segment rodata;
	code_segment rwdata;

	bool baremetal = set->options.baremetal;
	CreateCodeSegmentFromElf(&text, elf, PF_TEXT, baremetal, 0);
	CreateCodeSegmentFromElf(&rodata, elf, PF_RODATA, baremetal, 1);
	CreateCodeSegmentFromElf(&rwdata, elf, PF_DATA, baremetal, 2);

	/* Checking the existence of essential ELF Segments */
	if (!text.fileSize) return NOT_FIND_TEXT_SEGMENT;

	/* Allocating Buffer for ExeFs Code */
	bool noCodePadding = set->options.noCodePadding || baremetal;
	u32 size;
	if (noCodePadding) {
		size = text.fileSize + rodata.fileSize + rwdata.fileSize;
	}
	else {
		size = PageToSize(text.pageNum + rodata.pageNum + rwdata.pageNum);
	}
	u8 *code = calloc(1, size);

	/* Writing Code into Buffer */
	u8 *textPos = code;
	u8 *rodataPos = (textPos + (noCodePadding ? text.fileSize : PageToSize(text.pageNum)));
	u8 *rwdataPos = (rodataPos + (noCodePadding ? rodata.fileSize : PageToSize(rodata.pageNum)));
	if (text.fileSize) memcpy(textPos, text.data, text.fileSize);
	if (rodata.fileSize) memcpy(rodataPos, rodata.data, rodata.fileSize);
	if (rwdata.fileSize) memcpy(rwdataPos, rwdata.data, rwdata.fileSize);


	/* Compressing if needed */
	if (set->options.CompressCode) {
		if (set->options.verbose)
			printf("[CODE] Compressing code... ");
		u32 new_len;
		set->exefsSections.code.buffer = BLZ_Code(code, size, &new_len, BLZ_NORMAL);
		set->exefsSections.code.size = new_len;
		free(code);
		if (set->options.verbose)
			printf("Done!\n");
	}
	else {
		set->exefsSections.code.size = size;
		set->exefsSections.code.buffer = code;
	}

	/* Setting code_segment data */
	set->codeDetails.textAddress = text.address;
	set->codeDetails.textMaxPages = text.pageNum;
	set->codeDetails.textSize = text.fileSize;

	set->codeDetails.roAddress = rodata.address;
	set->codeDetails.roMaxPages = rodata.pageNum;
	set->codeDetails.roSize = rodata.fileSize;

	set->codeDetails.rwAddress = rwdata.address;
	set->codeDetails.rwMaxPages = rwdata.pageNum;
	set->codeDetails.rwSize = rwdata.fileSize;

	/* Calculating BSS size */
	if (rwdata.fileSize && !baremetal) {
		set->codeDetails.bssSize = rwdata.memSize - rwdata.fileSize;
	}
	else {
		set->codeDetails.bssSize = 0;
	}

	if (set->rsfSet->SystemControlInfo.StackSize)
		set->codeDetails.stackSize = strtoul(set->rsfSet->SystemControlInfo.StackSize, NULL, 0);
	else {
		set->codeDetails.stackSize = DEFAULT_STACK_SIZE;
		fprintf(stderr, "[CODE WARNING] \"SystemControlInfo/StackSize\" not specified, defaulting to 0x%x bytes\n", DEFAULT_STACK_SIZE);
	}

	/* Return */
	return 0;
}

/*
void PrintElfContext(elf_context *elf)
{
	printf("[ELF] Program Table Data\n");
	printf(" Offset: 0x%x\n", elf->programTableOffset);
	printf(" Size:   0x%x\n", elf->programTableEntrySize);
	printf(" Count:  0x%x\n", elf->programTableEntryCount);
	printf("[ELF] Section Table Data\n");
	printf(" Offset: 0x%x\n", elf->sectionTableOffset);
	printf(" Size:   0x%x\n", elf->sectionTableEntrySize);
	printf(" Count:  0x%x\n", elf->sectionTableEntryCount);
	printf(" Label index: 0x%x\n", elf->sectionHeaderNameEntryIndex);
	for (int i = 0; i < elf->activeSegments; i++) {
		printf(" Segment [%d][%s]\n", i, elf->segments[i].name);
		printf(" > Size(Memory):   0x%x\n", elf->segments[i].header->sizeInMemory);
		printf(" > Size(File):     0x%x\n", elf->segments[i].header->sizeInFile);
		printf(" > Address:        0x%x\n", elf->segments[i].vAddr);
		printf(" > Flags:          0x%x\n", elf->segments[i].header->flags);
		printf(" > Type:           0x%x\n", elf->segments[i].header->type);
		printf(" > Sections: %d\n", elf->segments[i].sectionNum);
		for (int j = 0; j < elf->segments[i].sectionNum; j++)
			printf("    > Section [%d][%s][0x%x][0x%x]\n", j, elf->segments[i].sections[j].name, elf->segments[i].sections[j].flags, elf->segments[i].sections[j].type);
	}
}
*/

int BuildExeFsCode(ncch_settings *set)
{
	int result = 0;
	if (set->options.IsCfa)
		return result;

	if (!set->options.IsBuildingCodeSection) { // Import ExeFs Code from file and return
		if (set->componentFilePtrs.plainregion) // Import PlainRegion from file
			if ((result = ImportPlainRegionFromFile(set))) return result;
		return ImportExeFsCodeBinaryFromFile(set);
	}

	/* Import ELF */
	u8 *elfFile = malloc(set->componentFilePtrs.elfSize);
	if (!elfFile) {
		fprintf(stderr, "[CODE ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	ReadFile64(elfFile, set->componentFilePtrs.elfSize, 0, set->componentFilePtrs.elf);

	/* Create ELF Context */
	elf_context elf;

	if ((result = elf_Init(&elf, elfFile))) goto finish;

	if ((result = ImportPlainRegionFromElf(&elf, set))) goto finish;
	if ((result = CreateExeFsCode(&elf, set))) goto finish;

finish:
	switch (result) {
	case (0) :
		break;
	case (NOT_ELF_FILE) :
		fprintf(stderr, "[CODE ERROR] Not ELF File\n");
		break;
	case (NOT_CTR_ARM_ELF) :
		fprintf(stderr, "[CODE ERROR] Not CTR ARM ELF\n");
		break;
	case (NON_EXECUTABLE_ELF) :
		fprintf(stderr, "[CODE ERROR] Not Executeable ELF\n");
		break;
	case (NOT_FIND_TEXT_SEGMENT) :
		fprintf(stderr, "[CODE ERROR] Failed to retrieve text sections from ELF\n");
		break;
	case (NOT_FIND_DATA_SEGMENT) :
		fprintf(stderr, "[CODE ERROR] Failed to retrieve data sections from ELF\n");
		break;
	default:
		fprintf(stderr, "[CODE ERROR] Failed to process ELF file (%d)\n", result);
	}

	elf_Free(&elf);
	free(elfFile);
	return result;
}
