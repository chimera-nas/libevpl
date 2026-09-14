// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include <winioctl.h>
#include "core/test_log.h"
#include "evpl/evpl.h"
#include "tests/test_common.h"

static void
done(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    int *pending = private_data;

    (void) evpl;
    evpl_test_abort_if(status, "file operation failed: %d", status);
    *pending = 0;
} /* done */

int
main(void)
{
    const wchar_t            *path   = L"evpl-\u03bb-\u6587.img";
    const uint64_t            offset = (1ULL << 32) + 65536;
    char                      utf8[128];
    HANDLE                    file;
    LARGE_INTEGER             size;
    DWORD                     bytes;
    struct evpl              *evpl;
    struct evpl_block_device *device;
    struct evpl_block_queue  *queue;
    struct evpl_iovec         write_iov, read_iov;
    int                       pending;

    test_evpl_config();
    evpl_test_abort_if(!WideCharToMultiByte(CP_UTF8, 0, path, -1, utf8, sizeof(utf8), NULL, NULL),
                       "path conversion failed");
    file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    evpl_test_abort_if(file == INVALID_HANDLE_VALUE, "cannot create Unicode fixture");
    evpl_test_abort_if(!DeviceIoControl(file, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &bytes, NULL),
                       "cannot make sparse fixture");
    size.QuadPart = (LONGLONG) (offset + 4096);
    evpl_test_abort_if(!SetFilePointerEx(file, size, NULL, FILE_BEGIN) || !SetEndOfFile(file),
                       "cannot size sparse fixture");
    CloseHandle(file);

    evpl   = evpl_create(NULL);
    device = evpl_block_open_device(EVPL_BLOCK_PROTOCOL_PREAD, utf8);
    evpl_test_abort_if(!device || evpl_block_size(device) != offset + 4096,
                       "Unicode path or 64-bit file size failed");
    queue = evpl_block_open_queue(evpl, device);
    evpl_test_abort_if(evpl_iovec_alloc(evpl, 4096, 0, 1, 0, &write_iov) != 1 ||
                       evpl_iovec_alloc(evpl, 4096, 0, 1, 0, &read_iov) != 1, "allocation failed");
    memset(write_iov.data, 0xa5, 4096);
    memset(read_iov.data, 0, 4096);
    pending = 1;
    evpl_block_write(evpl, queue, &write_iov, 1, offset, 1, done, &pending);
    while (pending) {
        evpl_continue(evpl);
    }
    pending = 1;
    evpl_block_read(evpl, queue, &read_iov, 1, offset, done, &pending);
    while (pending) {
        evpl_continue(evpl);
    }
    evpl_test_abort_if(memcmp(write_iov.data, read_iov.data, 4096), "64-bit offset did not round trip");
    evpl_iovec_release(evpl, &write_iov);
    evpl_iovec_release(evpl, &read_iov);
    evpl_block_close_queue(evpl, queue);
    evpl_block_close_device(device);
    evpl_destroy(evpl);
    evpl_test_abort_if(!DeleteFileW(path), "file handle leaked");
    return 0;
} /* main */
