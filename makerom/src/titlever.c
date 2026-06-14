#include "titlever.h"

u16 SetupVersion(u16 major, u16 minor, u16 micro)
{
    // limit input values
    if (major > VER_MAJOR_MAX)
    {
        major = VER_MAJOR_MAX;
    }
    if (minor > VER_MINOR_MAX)
    {
        minor = VER_MINOR_MAX;
    } 
    if (micro > VER_MICRO_MAX)
    {
        micro = VER_MICRO_MAX;
    }

    // construct version
	return (((major << 10) & 0xFC00) | ((minor << 4) & 0x3F0) | (micro & 0xf));
}

u16 SetupFromDataVersion(u16 data_version, u16 micro)
{
    // limit input values
    if (data_version > VER_DVER_MAX)
    {
        data_version = VER_DVER_MAX;
    }
    if (micro > VER_MICRO_MAX)
    {
        micro = VER_MICRO_MAX;
    }

    // construct version
	return (((data_version << 4) & 0xFFF0) | (micro & 0xf));
}

u16 ExtractVersionMajor(u16 version)
{
    return (version & 0xFC00) >> 10;
}

u16 ExtractVersionMinor(u16 version)
{
    return (version & 0x3F0) >> 4;
}

u16 ExtractVersionMicro(u16 version)
{
    return (version & 0xF);
}

u16 ExtractDataVersionMajor(u16 data_version)
{
    return (data_version & 0xFC0) >> 6;
}

u16 ExtractDataVersionMinor(u16 data_version)
{
    return (data_version & 0x3F);
}