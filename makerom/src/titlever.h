#pragma once
#include "types.h"

typedef enum
{
	VER_MAX = 65535,
	VER_MAJOR_MAX = 63,
	VER_MINOR_MAX = 63,
	VER_MICRO_MAX = 15,
	VER_DVER_MAX = 4095,
} title_ver_max;


// construct version from inputs
u16 SetupVersion(u16 major, u16 minor, u16 micro);
u16 SetupFromDataVersion(u16 data_version, u16 micro);

// extract components from version
u16 ExtractVersionMajor(u16 version);
u16 ExtractVersionMinor(u16 version);
u16 ExtractVersionMicro(u16 version);

// extract components from data version
u16 ExtractDataVersionMajor(u16 data_version);
u16 ExtractDataVersionMinor(u16 data_version);
