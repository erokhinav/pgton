#include "string.h"
#include "postgres.h"
#include "common/base64.h"
#include "utils/builtins.h"
#include "libpq/pqformat.h"
#include "fmgr.h"

PG_MODULE_MAGIC;

// TonHash type. It stores td::Bits256 for the fair 32 bytes.
typedef struct TonHash {
    char data[32];
} TonHash;

PG_FUNCTION_INFO_V1(tonhash_in);
PG_FUNCTION_INFO_V1(tonhash_out);
PG_FUNCTION_INFO_V1(tonhash_send);
PG_FUNCTION_INFO_V1(tonhash_recv);

PG_FUNCTION_INFO_V1(tonhash_lt);
PG_FUNCTION_INFO_V1(tonhash_le);
PG_FUNCTION_INFO_V1(tonhash_eq);
PG_FUNCTION_INFO_V1(tonhash_gt);
PG_FUNCTION_INFO_V1(tonhash_ge);
PG_FUNCTION_INFO_V1(tonhash_cmp);


Datum tonhash_in(PG_FUNCTION_ARGS) {
    char *str = PG_GETARG_CSTRING(0);
    TonHash *result = (TonHash*) palloc(sizeof(TonHash));
    int len = strlen(str);
    if (len == 0) {
        PG_RETURN_NULL();
    }
    if (len != 44) {
        pfree(result);
        ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
            errmsg("invalid length of input for type %s: \"%ld\" != 44", "tonhash", strlen(str))));
    }
    if (pg_b64_decode(str, 44, result->data, 32) < 0) {
        pfree(result);
        ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
            errmsg("failed to decode base64 value for type %s", "tonhash")));
    }
    PG_RETURN_POINTER(result);
}

Datum tonhash_out(PG_FUNCTION_ARGS) {
    TonHash *hash = (TonHash*) PG_GETARG_POINTER(0);
    char *result = (char*) palloc(45);
    result[44] = '\0';
    if (pg_b64_encode(hash->data, 32, result, 44) < 0) {
        pfree(result);
        ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
            errmsg("failed to base64-encode value of type %s", "tonhash")));
    }
    PG_RETURN_CSTRING(result);
}

Datum tonhash_send(PG_FUNCTION_ARGS) {
    StringInfo buf = (StringInfo) PG_GETARG_POINTER(0);
	TonHash *result = (TonHash*) palloc(sizeof(TonHash));
    
    memcpy(result->data, pq_getmsgbytes(buf, 32), 32);
    PG_RETURN_POINTER(result);
}

Datum tonhash_recv(PG_FUNCTION_ARGS) {
    TonHash *result = (TonHash*) PG_GETARG_POINTER(0);
    StringInfoData buf;

    pq_begintypsend(&buf);
    pq_sendbytes(&buf, result->data, 32);
    PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}

static int tonhash_cmp_internal(TonHash *a, TonHash *b) {
    return memcmp(a->data, b->data, 32);
}

Datum tonhash_lt(PG_FUNCTION_ARGS) {
    TonHash *a = (TonHash*) PG_GETARG_POINTER(0);
    TonHash *b = (TonHash*) PG_GETARG_POINTER(1);

    PG_RETURN_BOOL(tonhash_cmp_internal(a, b) < 0);
}

Datum tonhash_le(PG_FUNCTION_ARGS) {
    TonHash *a = (TonHash*) PG_GETARG_POINTER(0);
    TonHash *b = (TonHash*) PG_GETARG_POINTER(1);

    PG_RETURN_BOOL(tonhash_cmp_internal(a, b) <= 0);
}

Datum tonhash_eq(PG_FUNCTION_ARGS) {
    TonHash *a = (TonHash*) PG_GETARG_POINTER(0);
    TonHash *b = (TonHash*) PG_GETARG_POINTER(1);

    PG_RETURN_BOOL(tonhash_cmp_internal(a, b) == 0);
}

Datum tonhash_gt(PG_FUNCTION_ARGS) {
    TonHash *a = (TonHash*) PG_GETARG_POINTER(0);
    TonHash *b = (TonHash*) PG_GETARG_POINTER(1);

    PG_RETURN_BOOL(tonhash_cmp_internal(a, b) > 0);
}

Datum tonhash_ge(PG_FUNCTION_ARGS) {
    TonHash *a = (TonHash*) PG_GETARG_POINTER(0);
    TonHash *b = (TonHash*) PG_GETARG_POINTER(1);

    PG_RETURN_BOOL(tonhash_cmp_internal(a, b) >= 0);
}

Datum tonhash_cmp(PG_FUNCTION_ARGS) {
    TonHash *a = (TonHash*) PG_GETARG_POINTER(0);
    TonHash *b = (TonHash*) PG_GETARG_POINTER(1);

    PG_RETURN_INT32(tonhash_cmp_internal(a, b));
}

// TonAddr type. It stores TON address in raw format as a struct of 36 bytes.
typedef struct TonAddr {
    int32 workchain;
    char addr[32];
} TonAddr;

PG_FUNCTION_INFO_V1(tonaddr_in);
PG_FUNCTION_INFO_V1(tonaddr_out);
PG_FUNCTION_INFO_V1(tonaddr_to_base64);
PG_FUNCTION_INFO_V1(raw_to_base64);
PG_FUNCTION_INFO_V1(base64_to_raw);
PG_FUNCTION_INFO_V1(tonaddr_send);
PG_FUNCTION_INFO_V1(tonaddr_recv);

PG_FUNCTION_INFO_V1(tonaddr_lt);
PG_FUNCTION_INFO_V1(tonaddr_le);
PG_FUNCTION_INFO_V1(tonaddr_eq);
PG_FUNCTION_INFO_V1(tonaddr_gt);
PG_FUNCTION_INFO_V1(tonaddr_ge);
PG_FUNCTION_INFO_V1(tonaddr_cmp);


Datum tonaddr_in(PG_FUNCTION_ARGS) {
    char *str = PG_GETARG_CSTRING(0);
    TonAddr *result = (TonAddr*) palloc(sizeof(TonAddr));

    int pos, len = strlen(str);
    if (len == 0) {
        PG_RETURN_NULL();
    }
    if (strncmp(str, "addr_none", 9) == 0) {
        result->workchain = 123456;
        PG_RETURN_POINTER(result);
    }
    if (strncmp(str, "addr_extern", 11) == 0) {
        result->workchain = 123457;
        PG_RETURN_POINTER(result);
    }

    if (strchr(str, ':') == NULL) {
        size_t b64_len = strlen(str);
        char *std_base64 = palloc(b64_len + 4);
        int std_len = 0;
        for (size_t i = 0; i < b64_len; i++) {
            if (str[i] == '-') {
                std_base64[std_len++] = '+';
            } else if (str[i] == '_') {
                std_base64[std_len++] = '/';
            } else {
                std_base64[std_len++] = str[i];
            }
        }
        while (std_len % 4 != 0) {
            std_base64[std_len++] = '=';
        }
        std_base64[std_len] = '\0';

        char decoded[36];
        if (pg_b64_decode(std_base64, std_len, decoded, 36) != 36) {
            pfree(std_base64);
            pfree(result);
            ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                errmsg("invalid base64 input for type %s", "tonaddr")));
        }
        pfree(std_base64);

        unsigned short received_crc;
        memcpy(&received_crc, decoded + 34, 2);
        received_crc = ntohs(received_crc);
        unsigned short calculated_crc = crc16_xmodem((unsigned char *)decoded, 34);
        if (received_crc != calculated_crc) {
            pfree(result);
            ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                errmsg("invalid checksum in base64 address")));
        }
        if (decoded[0] != 17 && decoded[0] != 81) {
            pfree(result);
            ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                errmsg("invalid address tag %d", decoded[0])));
        }
        result->workchain = (int8)decoded[1];
        memcpy(result->addr, decoded + 2, 32);
        PG_RETURN_POINTER(result);
    }
    
    if (sscanf(str, "%d:%n", &result->workchain, &pos) != 1) {
        pfree(result);
        ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
            errmsg("invalid workchain for type %s: \"%s\"", "tonaddr", str)));
    }

    if (len - pos != 64) {
        pfree(result);
        ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
            errmsg("wrong address length for type %s: \"%d\" != 64", "tonaddr", len - pos)));
    }
    if (hex_decode(str + pos, 64, result->addr) < 0) {
        pfree(result);
        ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
            errmsg("failed to decode hex value for type %s", "tonaddr")));
    }
    PG_RETURN_POINTER(result);
}

Datum tonaddr_out(PG_FUNCTION_ARGS) {
    TonAddr *addr = (TonAddr*) PG_GETARG_POINTER(0);

    if (addr->workchain == 123456) {
        char *result = psprintf("addr_none");
        PG_RETURN_CSTRING(result);
    }
    if (addr->workchain == 123457) {
        char *result = psprintf("addr_extern");
        PG_RETURN_CSTRING(result);
    }

    char workchain[20];
    memset(workchain, '\0', 20);
    sprintf(workchain, "%d:", addr->workchain);

    int len = strlen(workchain);
    int full_len = len + 64;

    char *result = (char*) palloc(full_len + 1);
    result[full_len] = '\0';
    memcpy(result, workchain, len);
    if(hex_encode(addr->addr, 32, result + len) < 0) {
        pfree(result);
        ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
            errmsg("failed to hex-encode value of type %s", "tonaddr")));
    }
    for(int i = 0; i < full_len; ++i) {
        if (result[i] >= 'a' && result[i] <= 'z') {
            result[i] += 'A' - 'a';
        }
    }
    PG_RETURN_CSTRING(result);
}

static const unsigned short crc16_ccitt_table[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
	0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
	0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
	0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
	0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
	0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
	0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
	0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
	0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
	0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
	0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
	0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
	0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
	0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
	0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
	0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
	0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
	0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
	0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
	0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
	0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
	0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
	0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
	0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
	0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
	0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
	0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
	0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
	0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
	0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
	0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
	0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
};

unsigned short crc16_xmodem(const unsigned char* data_p, unsigned int length);
unsigned short crc16_xmodem(const unsigned char* data_p, unsigned int length) {
    unsigned short crc = 0x0000;
    unsigned short temp;

    while (length--) {
        temp = (crc >> 8) ^ *data_p++;
        crc = (crc << 8) ^ crc16_ccitt_table[temp];
    }

    return crc;
}

static char* tonaddr_to_base64_internal(TonAddr *addr) {
    return tonaddr_to_base64_with_tag(addr, 17);
}

static char* tonaddr_to_base64_with_tag(TonAddr *addr, unsigned char tag) {
    if (addr->workchain == 123456) {
        return pstrdup("addr_none");
    }
    if (addr->workchain == 123457) {
        return pstrdup("addr_extern");
    }

    char *checksumData = (char *) palloc(34);
    checksumData[0] = (char)tag;
    checksumData[1] = (char)(addr->workchain);
    memcpy(checksumData + 2, addr->addr, 32);

    char *address = (char *) palloc(36);
    memcpy(address, checksumData, 34);
    
    unsigned short crc = crc16_xmodem((unsigned char *)checksumData, 34);
    unsigned short crc_be = htons(crc);
    memcpy(address + 34, &crc_be, 2);

    size_t base64_buffer_size = pg_b64_enc_len(36) + 1;
    char *base64_result = palloc(base64_buffer_size);
    int base64_len = pg_b64_encode((const char *)address, 36, base64_result, base64_buffer_size - 1);

    // Convert to URL-safe base64 and remove padding
    int url_safe_len = 0;
    for (int i = 0; i < base64_len; i++) {
        if (base64_result[i] == '+') {
            base64_result[url_safe_len++] = '-';
        } else if (base64_result[i] == '/') {
            base64_result[url_safe_len++] = '_';
        } else if (base64_result[i] != '=') {
            base64_result[url_safe_len++] = base64_result[i];
        }
    }
    base64_result[url_safe_len] = '\0';

    pfree(checksumData);
    pfree(address);

    return base64_result;
}

Datum tonaddr_to_base64(PG_FUNCTION_ARGS) {
    TonAddr *addr = (TonAddr*) PG_GETARG_POINTER(0);
    char *result = tonaddr_to_base64_internal(addr);
    PG_RETURN_CSTRING(result);
}

Datum raw_to_base64(PG_FUNCTION_ARGS) {
    char *str = PG_GETARG_CSTRING(0);
    TonAddr addr;

    if (strcmp(str, "addr_none") == 0) {
        addr.workchain = 123456;
    } else if (strcmp(str, "addr_extern") == 0) {
        addr.workchain = 123457;
    } else {
        int pos;
        if (sscanf(str, "%d:%n", &addr.workchain, &pos) != 1) {
            ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                errmsg("invalid workchain for type %s: \"%s\"", "tonaddr", str)));
        }
        if (strlen(str) - pos != 64) {
            ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                errmsg("wrong address length for type %s: \"%d\" != 64", "tonaddr", (int)(strlen(str) - pos))));
        }
        if (hex_decode(str + pos, 64, addr.addr) < 0) {
            ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                errmsg("failed to decode hex value for type %s", "tonaddr")));
        }
    }

    bool return_bounceable = true;
    if (PG_NARGS() >= 2 && !PG_ARGISNULL(1)) {
        return_bounceable = PG_GETARG_BOOL(1);
    }
    unsigned char tag = return_bounceable ? 17 : 81;

    char *result = tonaddr_to_base64_with_tag(&addr, tag);
    PG_RETURN_CSTRING(result);
}

Datum base64_to_raw(PG_FUNCTION_ARGS) {
    char *base64_str = PG_GETARG_CSTRING(0);
    
    if (strcmp(base64_str, "addr_none") == 0) {
        char *result = pstrdup("addr_none");
        PG_RETURN_CSTRING(result);
    }
    if (strcmp(base64_str, "addr_extern") == 0) {
        char *result = pstrdup("addr_extern");
        PG_RETURN_CSTRING(result);
    }

    size_t len = strlen(base64_str);
    char *std_base64 = palloc(len + 4);
    int std_len = 0;
    
    for (size_t i = 0; i < len; i++) {
        if (base64_str[i] == '-') {
            std_base64[std_len++] = '+';
        } else if (base64_str[i] == '_') {
            std_base64[std_len++] = '/';
        } else {
            std_base64[std_len++] = base64_str[i];
        }
    }
    
    while (std_len % 4 != 0) {
        std_base64[std_len++] = '=';
    }
    std_base64[std_len] = '\0';

    char decoded[36];
    if (pg_b64_decode(std_base64, std_len, decoded, 36) != 36) {
        pfree(std_base64);
        ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
            errmsg("invalid base64 input for type %s", "tonaddr")));
    }
    pfree(std_base64);

    unsigned short received_crc;
    memcpy(&received_crc, decoded + 34, 2);
    received_crc = ntohs(received_crc);
    
    unsigned short calculated_crc = crc16_xmodem((unsigned char *)decoded, 34);
    
    if (received_crc != calculated_crc) {
        ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
            errmsg("invalid checksum in base64 address")));
    }

    if (decoded[0] != 17 && decoded[0] != 81) {
        ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
            errmsg("invalid address tag %d", decoded[0])));
    }

    int32 workchain = (int8)decoded[1];
    char addr_hex[65];
    addr_hex[64] = '\0';
    
    if (hex_encode(decoded + 2, 32, addr_hex) < 0) {
        ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
            errmsg("failed to encode address as hex")));
    }

    char *result = psprintf("%d:%s", workchain, addr_hex);

    PG_RETURN_CSTRING(result);
}

Datum tonaddr_send(PG_FUNCTION_ARGS) {
    StringInfo buf = (StringInfo) PG_GETARG_POINTER(0);
	TonAddr *result = (TonAddr*) palloc(sizeof(TonAddr));
    
    result->workchain = (int32) pq_getmsgint(buf, 4);
    memcpy(result->addr, pq_getmsgbytes(buf, 32), 32);
    PG_RETURN_POINTER(result);
}

Datum tonaddr_recv(PG_FUNCTION_ARGS) {
    TonAddr *result = (TonAddr*) PG_GETARG_POINTER(0);
    StringInfoData buf;

    pq_begintypsend(&buf);
    pq_sendint32(&buf, (uint32) result->workchain);
    pq_sendbytes(&buf, result->addr, 32);
    PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}

static int tonaddr_cmp_internal(TonAddr *a, TonAddr *b) {
    if (a->workchain < b->workchain) {
        return -1;
    }
    if (a->workchain > b->workchain) {
        return 1;
    }
    if (a->workchain == 123456 || a->workchain == 123457) {
        return 0;
    }
    return memcmp(a->addr, b->addr, 32);
}

Datum tonaddr_lt(PG_FUNCTION_ARGS) {
    TonAddr *a = (TonAddr*) PG_GETARG_POINTER(0);
    TonAddr *b = (TonAddr*) PG_GETARG_POINTER(1);

    PG_RETURN_BOOL(tonaddr_cmp_internal(a, b) < 0);
}

Datum tonaddr_le(PG_FUNCTION_ARGS) {
    TonAddr *a = (TonAddr*) PG_GETARG_POINTER(0);
    TonAddr *b = (TonAddr*) PG_GETARG_POINTER(1);

    PG_RETURN_BOOL(tonaddr_cmp_internal(a, b) <= 0);
}

Datum tonaddr_eq(PG_FUNCTION_ARGS) {
    TonAddr *a = (TonAddr*) PG_GETARG_POINTER(0);
    TonAddr *b = (TonAddr*) PG_GETARG_POINTER(1);

    PG_RETURN_BOOL(tonaddr_cmp_internal(a, b) == 0);
}

Datum tonaddr_gt(PG_FUNCTION_ARGS) {
    TonAddr *a = (TonAddr*) PG_GETARG_POINTER(0);
    TonAddr *b = (TonAddr*) PG_GETARG_POINTER(1);

    PG_RETURN_BOOL(tonaddr_cmp_internal(a, b) > 0);
}

Datum tonaddr_ge(PG_FUNCTION_ARGS) {
    TonAddr *a = (TonAddr*) PG_GETARG_POINTER(0);
    TonAddr *b = (TonAddr*) PG_GETARG_POINTER(1);

    PG_RETURN_BOOL(tonaddr_cmp_internal(a, b) >= 0);
}

Datum tonaddr_cmp(PG_FUNCTION_ARGS) {
    TonAddr *a = (TonAddr*) PG_GETARG_POINTER(0);
    TonAddr *b = (TonAddr*) PG_GETARG_POINTER(1);

    PG_RETURN_INT32(tonaddr_cmp_internal(a, b));
}
