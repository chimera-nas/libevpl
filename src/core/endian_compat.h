// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

/*
 * Portable fixed-width byte-order helpers.
 *
 * Linux provides htobe64()/be64toh() etc. via <endian.h>.  macOS has no
 * <endian.h>; it exposes the equivalent swaps through <libkern/OSByteOrder.h>.
 * Map the BSD/glibc names onto those so callers can use htobe64()/be64toh()
 * unconditionally.
 */

#ifdef _WIN32
#include <stdlib.h>
#include <stdint.h>
#define htobe16(x) _byteswap_ushort((uint16_t) (x))
#define be16toh(x) htobe16(x)
#define htobe32(x) _byteswap_ulong((uint32_t) (x))
#define be32toh(x) htobe32(x)
#define htobe64(x) _byteswap_uint64((uint64_t) (x))
#define be64toh(x) htobe64(x)
#define htole16(x) ((uint16_t) (x))
#define le16toh(x) htole16(x)
#define htole32(x) ((uint32_t) (x))
#define le32toh(x) htole32(x)
#define htole64(x) ((uint64_t) (x))
#define le64toh(x) htole64(x)
#elif defined(__APPLE__)

#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#else /* ifdef __APPLE__ */

#include <endian.h>

#endif /* ifdef __APPLE__ */
