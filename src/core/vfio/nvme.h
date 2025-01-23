#pragma once

/* NVME definitions per 1.4 specification */

#include <stdint.h>

#define NVME_NSID_ALL     0xffffffff

#define NVME_COMMAND_SIZE 64

#define NVME_LBAF_TOTAL   16

#pragma pack(push, 1)

enum {
    NVME_CMD_FLUSH               = 0x00,
    NVME_CMD_WRITE               = 0x01,
    NVME_CMD_READ                = 0x02,
    NVME_CMD_WRITE_UNCORRECTABLE = 0x04,
    NVME_CMD_COMPARE             = 0x05,
    NVME_CMD_WRITE_ZEROES        = 0x08,
    NVME_CMD_DATASET_MANAGEMENT  = 0x09,
    NVME_CMD_VERIFY              = 0x0C,
    NVME_CMD_RESERVE_REGISTER    = 0x0D,
    NVME_CMD_RESERVE_REPORT      = 0x0E,
    NVME_CMD_RESERVE_ACQUIRE     = 0x11,
    NVME_CMD_RESERVE_RELEASE     = 0x15,
};

enum {
    NVME_ADMIN_DELETE_IO_SQ      = 0x00,
    NVME_ADMIN_CREATE_IO_SQ      = 0x01,
    NVME_ADMIN_GET_LOG_PAGE      = 0x02,
    NVME_ADMIN_DELETE_IO_CQ      = 0x04,
    NVME_ADMIN_CREATE_IO_CQ      = 0x05,
    NVME_ADMIN_IDENTIFY          = 0x06,
    NVME_ADMIN_ABORT             = 0x08,
    NVME_ADMIN_SET_FEATURES      = 0x09,
    NVME_ADMIN_GET_FEATURES      = 0x0A,
    NVME_ADMIN_ASYNC_EVENT_REA   = 0x0C,
    NVME_ADMIN_FW_ACTIVATE       = 0x10,
    NVME_ADMIN_FW_DOWNLOAD       = 0x11,
    NVME_ADMIN_SELF_TEST         = 0x14,
    NVME_ADMIN_ATTACH_NS         = 0x15,
    NVME_ADMIN_KEEP_ALIVE        = 0x18,
    NVME_ADMIN_DIRECTIVE_SEND    = 0x19,
    NVME_ADMIN_DIRECTIVE_RECEIVE = 0x1A,
    NVME_ADMIN_VIRT_MGMT         = 0x1C,
    NVME_ADMIN_MI_SEND           = 0x1D,
    NVME_ADMIN_MI_RECEIVE        = 0x1E,
    NVME_ADMIN_DOORBELL_CONFIG   = 0x7C,
    NVME_ADMIN_NVM_FORMAT        = 0x80,
};

enum {
    NVME_FEATURE_ARBITRATION       = 0x01,
    NVME_FEATURE_POWER_MGMT        = 0x02,
    NVME_FEATURE_LBA_RANGE         = 0x03,
    NVME_FEATURE_TEMP_THRESHOLD    = 0x04,
    NVME_FEATURE_ERROR_RECOVERY    = 0x05,
    NVME_FEATURE_WRITE_CACHE       = 0x06,
    NVME_FEATURE_NUM_QUEUES        = 0x07,
    NVME_FEATURE_INT_COALESCING    = 0x08,
    NVME_FEATURE_INT_VECTOR        = 0x09,
    NVME_FEATURE_WRITE_ATOMICITY   = 0x0A,
    NVME_FEATURE_ASYNC_EVENT       = 0x0B,
    NVME_FEATURE_AUTO_POWER        = 0x0C,
    NVME_FEATURE_HOST_MEM_BUFFER   = 0x0D,
    NVME_FEATURE_TIMESTAMP         = 0x0E,
    NVME_FEATURE_KEEP_ALIVE        = 0x0F,
    NVME_FEATURE_THERMAL           = 0x10,
    NVME_FEATURE_POWER_STATE       = 0x11,
    NVME_FEATURE_RECOVERY_LEVEL    = 0x12,
    NVME_FEATURE_PREDICT_LAT_CFG   = 0x13,
    NVME_FEATURE_PREDICT_LAT_WDW   = 0x14,
    NVME_FEATURE_LBA_STAT_INTERVAL = 0x15,
    NVME_FEATURE_HOST_BEHAVIOR     = 0x16,
    NVME_FEATURE_SANITIZE_CONFIG   = 0x17,
    NVME_FEATURE_ENDURANCE         = 0x18,
};

enum {
    NVME_ONCS_SUPPORTS_COMPARE      = 0x01,
    NVME_ONCS_SUPPORTS_WRITE_UNCOR  = 0x02,
    NVME_ONCS_SUPPORTS_DSM          = 0x04,
    NVME_ONCS_SUPPORTS_WRITE_ZEROES = 0x08,
    NVME_ONCS_SUPPORTS_SAVE_FIELD   = 0x10,
    NVME_ONCS_SUPPORTS_RESERVATIONS = 0x20,
    NVME_ONCS_SUPPORTS_TIMESTAMP    = 0x40,
    NVME_ONCS_SUPPORTS_VERIFY       = 0x80,
};

enum {
    NVME_LOGPAGE_SUPPORTEDLOGPAGES       = 0x00,    /* not part of nvme 1.e specification */
    NVME_LOGPAGE_ERRORINFORMATION        = 0x01,
    NVME_LOGPAGE_SMARTINFORMATION        = 0x02,
    NVME_LOGPAGE_FIRMWARESLOTINFORMATION = 0x03,
    NVME_LOGPAGE_MAX                     = 0x100
};

enum {
    NVME_CNS_ID_NS       = 0x00,
    NVME_CNS_ID_CTRLR    = 0x01,
    NVME_CNS_ACTIVE_NSID = 0x02,
    NVME_CNS_NSID_DESC   = 0x03,
};

enum {
    NVME_FORMAT_SECURE_ERASE_NONE   = 0x00,
    NVME_FORMAT_SECURE_ERASE_USER   = 0x01,
    NVME_FORMAT_SECURE_ERASE_CRYPTO = 0x02,
};

enum {
    NVME_STATUS_CODE_TYPE_GENERIC         = 0x00,
    NVME_STATUS_CODE_TYPE_CMD_SPECIFIC    = 0x01,
    NVME_STATUS_CODE_TYPE_MEDIA_ERROR     = 0x02,
    NVME_STATUS_CODE_TYPE_PATH_RELATED    = 0x03,
    NVME_STATUS_CODE_TYPE_VENDOR_SPECIFIC = 0x07,
};

enum {
    NVME_VENDOR_ID_SAMSUNG = 0x144D,
    NVME_VENDOR_ID_INTEL   = 0x8086,
    NVME_VENDOR_ID_MICRON  = 0x1344,
    NVME_VENDOR_ID_TOSHIBA = 0x1179,
    NVME_VENDOR_ID_WDC     = 0x1B96,
    NVME_VENDOR_ID_SEAGATE = 0x1BB1,
    NVME_VENDOR_ID_SANDISK = 0x15B7,
    NVME_VENDOR_ID_DELL    = 0x1028,
    NVME_VENDOR_ID_VMWARE  = 0x15AD,
    NVME_VENDOR_ID_REDHAT  = 0x1B36, /* As seen from things like QEMU NVM Express Controllers */
};

#define NVME_WORD_SIZE_BYTES                4
#define NVME_ERROR_LOGPAGE_REPORTED_ENTRIES 64
#define NVME_ERROR_ENTRY_WORDS              16
#define NVME_ERROR_LOGPAGE_REPORTED_ENTRIES_WORDS \
        NVME_ERROR_LOGPAGE_REPORTED_ENTRIES \
        *NVME_ERROR_ENTRY_WORDS

#define NVME_IDENTIFIER_TYPE_EUI64          0x01
#define NVME_IDENTIFIER_TYPE_NGUID          0x02
#define NVME_IDENTIFIER_TYPE_UUID           0x03

#define NVME_IDENTIFIER_PAYLOAD_SIZE        4096

union nvme_version {
    uint32_t value;
    struct {
        uint8_t  ter;
        uint8_t  mnr;
        uint16_t mjr;
    };
};

struct nvme_smart_log {
    uint8_t     critical_warning;
    uint8_t     temperature[2];
    uint8_t     avail_spare;
    uint8_t     spare_thresh;
    uint8_t     percent_used;
    uint8_t     rsvd6[26];
    /* All __uint128_t fields below are objects
     * to be converted into ascii string on demand
     * for the sake of saving precision */
    __uint128_t data_units_read;
    __uint128_t data_units_written;
    __uint128_t host_reads;
    __uint128_t host_writes;
    __uint128_t ctrl_busy_time;
    __uint128_t power_cycles;
    __uint128_t power_on_hours;
    __uint128_t unsafe_shutdowns;
    __uint128_t media_errors;
    __uint128_t num_err_log_entries;
    uint32_t    warning_temp_time;
    uint32_t    critical_comp_time;
    uint16_t    temp_sensor[8];
    uint8_t     rsvd216[296];
};

/* Specification <-> Encoding format  */
/* Example from Create I/O Completion Queue */

struct nvme_identify_ctlr {
    uint16_t           vid;
    uint16_t           ssvid;
    char               sn[20];
    char               mn[40];
    char               fr[8];
    uint8_t            rab;
    uint8_t            ieee[3];
    uint8_t            mic;
    uint8_t            mdts;
    uint16_t           cntlid;
    union nvme_version ver;
    uint8_t            rsvd12[12]; // 84
    uint32_t           ctratt; // 96
    uint8_t            rsvd156[156]; // 100
    uint16_t           oacs;   // 256
    uint8_t            acl;
    uint8_t            aerl;
    uint8_t            frmw;
    uint8_t            lpa;
    uint8_t            elpe;
    uint8_t            npss;
    uint8_t            avscc;
    uint8_t            rsvd265[247];
    uint8_t            sqes;
    uint8_t            cqes;
    uint8_t            rsvd514[2];
    uint32_t           nn;
    uint16_t           oncs;
    uint16_t           fuses;
    uint8_t            fna;
    uint8_t            vwc;
    uint16_t           awun;
    uint16_t           awupf;
    uint8_t            nvscc;
    uint8_t            rsvd531[173];
    uint8_t            rsvd704[1344];
    uint8_t            psd[1024];
    uint8_t            vs[1024];
};

union nvme_controller_cap {
    uint64_t value;
    struct {
        uint16_t mqes;
        uint8_t  cqr     : 1;
        uint8_t  ams     : 2;
        uint8_t  rsvd    : 5;
        uint8_t  to;

        uint32_t dstrd   : 4;
        uint32_t nssrs   : 1;
        uint32_t css     : 8;
        uint32_t rsvd2   : 3;
        uint32_t mpsmin  : 4;
        uint32_t mpsmax  : 4;
        uint32_t rsvd3   : 8;
    };
};

union nvme_controller_config {
    uint32_t value;
    struct {
        uint32_t en      : 1;
        uint32_t rsvd    : 3;
        uint32_t css     : 3;
        uint32_t mps     : 4;
        uint32_t ams     : 3;
        uint32_t shn     : 2;
        uint32_t iosqes  : 4;
        uint32_t iocqes  : 4;
        uint32_t rsvd2   : 8;
    };
};

union nvme_controller_status {
    uint32_t value;
    struct {
        uint32_t rdy     : 1;
        uint32_t cfs     : 1;
        uint32_t shst    : 2;
        uint32_t rsvd    : 28;
    };
};

union nvme_adminq_attr {
    uint32_t value;
    struct {
        uint16_t asqs;
        uint16_t acqs;
    };
};

union nvme_cmbloc {
    uint32_t value;
    struct {
        uint32_t bir     : 3;
        uint32_t rsvd    : 9;
        uint32_t ofst    : 20;
    };
};

union nvme_cmbsz {
    uint32_t value;
    struct {
        uint32_t sqs     : 1;
        uint32_t cqs     : 1;
        uint32_t lists   : 1;
        uint32_t rds     : 1;
        uint32_t wds     : 1;
        uint32_t rsvd    : 3;
        uint32_t szu     : 4;
        uint32_t sz      : 20;
    };
};


struct nvme_controller_reg {
    union nvme_controller_cap    cap;
    union nvme_version           vs;
    uint32_t                     intms;
    uint32_t                     intmc;
    union nvme_controller_config cc;
    uint32_t                     rsvd;
    union nvme_controller_status csts;
    uint32_t                     nssr;
    union nvme_adminq_attr       aqa;
    uint64_t                     asq;
    uint64_t                     acq;
    union nvme_cmbloc            cmbloc;
    union nvme_cmbsz             cmbsz;
    uint32_t                     rcss[1008];
    uint32_t                     sq0tdbl[1024];
};

/* Common Command Format */
struct nvme_command_common {
    /* Command DWord 0 */
    uint8_t  opc;
    uint8_t  fuse : 2; /* fuse bit will be set if command is desired be atomic with another */
    uint8_t  rsvd : 4;
    uint8_t  psdt : 2;
    uint16_t cid;

    uint32_t nsid;
    uint64_t cdw2_3;
    uint64_t mptr;
    uint64_t prp1; /* we always use prp, so exclude sg, which could be a union. */
    uint64_t prp2;

    /* Command-Specific Dword 10-15 follows */
    /* per specific command */
};

struct nvme_command_rw {
    struct nvme_command_common common;
    /* Command Dword 10 and 11 */
    uint64_t                   slba;

    /* Command Dword 12 */
    uint16_t                   nlb;
    uint16_t                   rsvd12 : 10;
    uint16_t                   prinfo : 4;
    uint16_t                   fua : 1;
    uint16_t                   lr  : 1;

    /* Command Dword 13 */
    uint8_t                    dsm;
    uint8_t                    rsvd13[3];

    /* Command Dword 14 */
    uint32_t                   eilbrt;

    /* Command Dword 15 */
    uint16_t                   elbat;
    uint16_t                   elbatm;
};

struct nvme_command_dsm {
    struct nvme_command_common common;
    /* Command Dword 10 */
    uint32_t                   nr;
    /* Command Dword 11 */
    uint32_t                   idr : 1;
    uint32_t                   idw : 1;
    uint32_t                   ad : 1;
    uint32_t                   rsrvd11 : 29;

    /* Command Dword 12 - 15 */
    uint32_t                   rsrvd12[4];
};

struct nvme_dsm_range {
    uint32_t attrs;
    uint32_t length;
    uint64_t lba;
};

struct nvme_command_wz {
    struct nvme_command_common common;
    uint64_t                   slba;
    uint16_t                   nlb;
    uint16_t                   rsvd12 : 9;
    uint16_t                   deac : 1;
    uint16_t                   prinfo : 4;
    uint16_t                   fua : 1;
    uint16_t                   lr  : 1;
    /* Command Dword 13 */
    uint32_t                   rsvd13;
    /* Command Dword 14 - 15 */
    uint32_t                   eilbrt;
    uint16_t                   elbat;
    uint16_t                   elbatm;
};

struct nvme_command_vs {
    struct nvme_command_common common;
    union {
        struct {
            uint32_t ndt;
            uint32_t ndm;
            uint32_t cdw12_15[4];
        };
        uint32_t cdw10_15[6];
    };
};

struct nvme_admin_delete_ioq {
    struct nvme_command_common common;
    uint16_t                   qid;
    uint16_t                   rsvd10;
    uint32_t                   cdw11_15[5];
};

struct nvme_admin_create_sq {
    struct nvme_command_common common;
    uint16_t                   qid;
    uint16_t                   qsize;
    uint16_t                   pc : 1;
    uint16_t                   qprio : 2;
    uint16_t                   rsvd11 : 13;
    uint16_t                   cqid;
    uint32_t                   cdw12_15[4];
};

struct nvme_admin_create_cq {
    struct nvme_command_common common;
    uint16_t                   qid;
    uint16_t                   qsize;
    uint16_t                   pc : 1;
    uint16_t                   ien : 1;
    uint16_t                   rsvd11 : 14;
    uint16_t                   iv;
    uint32_t                   cdw12_15[4];
};

struct nvme_admin_identify {
    struct nvme_command_common common;
    uint32_t                   cns;
    uint32_t                   cdw11_15[5];
};

struct nvme_admin_abort {
    struct nvme_command_common common;
    uint16_t                   sqid;
    uint16_t                   cid;
    uint32_t                   cdw11_15[5];
};

struct nvme_admin_get_log_page {
    struct nvme_command_common common;

    /* Command Dword 10 */
    uint8_t                    lid;
    uint8_t                    lsp : 7; // Log Specific Field, may be set for specific logs, otherwise reserved
    uint8_t                    rae : 1;
    uint16_t                   numdl;
//    uint16_t                   rsvd10b : 4;

    /* Command Dword 11 - 15 */
    uint32_t                   rsvd11[5];
};

struct nvme_admin_get_features {
    struct nvme_command_common common;
    uint8_t                    fid;
    uint8_t                    sel : 3;
    uint32_t                   reserved10 : 21;

    /* Command Dword 11 - 13 */
    uint32_t                   rsvd11[3];
    /* Command Dword 14 */
    uint32_t                   uuid_idx : 7;
    uint32_t                   rsvd14 : 25;
    /* Command Dword 15 */
    uint32_t                   rsvd15;

};

struct nvme_admin_set_features {
    struct nvme_command_common common;
    uint8_t                    fid;
    uint32_t                   reserved10 : 23;
    uint16_t                   save : 1;
    uint32_t                   val;

    /* Command Dword 12 - 15 */
    uint32_t                   rsvd12[4];
};

struct nvme_admin_nvm_format {
    struct nvme_command_common common;

    /* Command Dword 10 */
    uint16_t                   lbaf : 4;
    uint16_t                   mset : 1;
    uint16_t                   pi : 3;
    uint16_t                   pil : 1;
    uint16_t                   ses : 3;
    uint32_t                   reserved10 : 20;

    /* Command Dword 11 - 15 */
    uint32_t                   rsvd11[5];

};


union nvme_sq_entry {
    struct nvme_command_rw         rw;
    struct nvme_command_dsm        dsm;
    struct nvme_command_wz         wz;
    struct nvme_command_vs         vs;
    struct nvme_admin_abort        abort;
    struct nvme_admin_create_cq    create_cq;
    struct nvme_admin_create_sq    create_sq;
    struct nvme_admin_delete_ioq   delete_ioq;
    struct nvme_admin_identify     identify;
    struct nvme_admin_get_log_page get_log_page;
    struct nvme_admin_get_features get_features;
    struct nvme_admin_set_features set_features;
    struct nvme_admin_nvm_format   nvm_format;
};

struct nvme_cq_entry {
    /* DW 0 */
    uint32_t cs;
    /* DW 1 */
    uint32_t rsvd;
    /* DW 2*/
    uint16_t sqhd;
    uint16_t sqid;
    /* DW 3 */
    uint16_t cid;
    union {
        uint16_t psf;
        struct {
            uint16_t p : 1;
            uint16_t sc : 8;
            uint16_t sct : 3;
            uint16_t rsvd3 : 2;
            uint16_t m : 1;
            uint16_t dnr : 1;
        };
    };
};

struct nvme_feature_num_queues {
    union {
        uint32_t val;
        struct {
            uint16_t nsq;
            uint16_t ncq;
        };
    };
};

struct nvme_lba_format {
    uint16_t ms;
    uint8_t  lbads;
    uint8_t  rp : 2;
    uint8_t  rsvd : 6;
};

/* Identify Namespace Data Structure - CNS 00h) */
struct nvme_identify_ns {
    uint64_t               nsze;                  // 0
    uint64_t               ncap;                  // 8
    uint64_t               nuse;                  // 16
    uint8_t                nsfeat;                // 24
    uint8_t                nlbaf;                 // 25
    uint8_t                flbas;                 // 26
    uint8_t                mc;                    // 27
    uint8_t                dpc;                   // 28
    uint8_t                dps;                   // 29
    uint8_t                nmic;                  // 30
    uint8_t                rescap;                // 31
    uint8_t                fpi;                   // 32
    uint8_t                dlfeat;                // 33
    uint16_t               nawun;                 // 34
    uint16_t               nawupf;                // 36
    uint16_t               nacwu;                 // 38
    uint16_t               nabsn;                 // 40
    uint16_t               nabo;                  // 42
    uint16_t               nabspf;                // 44
    uint16_t               noiob;                 // 46
    uint8_t                nvmcap[16];      // 48
    uint8_t                rsvd40[40];      // 64
    uint8_t                nguid[16];       // 104
    uint8_t                eui64[8];              // 120
    struct nvme_lba_format lbaf[NVME_LBAF_TOTAL]; // 128
    uint8_t                rsvd192[192];    // 192
    uint8_t                vs[3712];              // 384
};

struct nvme_identify_ns_desc {
    uint8_t  nidt;                                // 0
    uint8_t  nidl;                                // 1
    uint16_t rsvd2;                               // 2
    uint8_t  nid[];                               // 4
};

struct nvme_lid_supported_effects {
    uint8_t  lid_supported : 1;
    uint8_t  index_offset_supported : 1;
    uint16_t reserved : 14;
    uint16_t lid_specific;
};


struct nvme_supported_log_pages {
    struct nvme_lid_supported_effects lp_id[NVME_LOGPAGE_MAX];
};

/* Error Information (Log Id 01h) */

/* Error Information Log Entry */
struct nvme_error_log_page_entry {
    uint64_t error_count;

    uint16_t cmdid;
    uint16_t sqid;

    uint16_t parm_error_location;
    uint16_t status_field;

    uint64_t lba;

    uint32_t nsid;

    uint8_t  rsvd[2];
    uint8_t  trtype;
    uint8_t  vs;

    uint64_t cs;

    uint8_t  rsvd2[2];
    uint16_t trtype_spec_info;

    uint8_t  rsvd3[20];
};
#pragma pack(pop)