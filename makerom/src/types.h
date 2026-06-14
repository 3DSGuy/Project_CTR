#pragma once

#include <stdlib.h>
#include <stdint.h>
//Bools
typedef enum
{
	Good,
	Fail
} return_basic;

typedef enum
{
	MEM_ERROR = -1,
	FAILED_TO_OPEN_FILE = -2,
	FAILED_TO_IMPORT_FILE = -3,
	FAILED_TO_CREATE_OUTFILE = -4,
} global_errors;

typedef enum
{
	BE = 0,
	LE = 1
} endianness_flag;

typedef enum
{
	KB = 1024,
	MB = 1048576,
	GB = 1073741824
} file_unit_size;

typedef enum
{
	MAX_U8 = 0xff,
	MAX_U16 = 0xffff,
	MAX_U32 = 0xffffffff,
	MAX_U64 = 0xffffffffffffffff,
} data_type_max;

typedef uint8_t                 u8;
typedef uint16_t                u16;
typedef uint32_t                u32;
typedef uint64_t                u64;

typedef int8_t                  s8;
typedef int16_t                 s16;
typedef int32_t                 s32;
typedef int64_t                 s64;