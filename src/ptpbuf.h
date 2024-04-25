#ifndef _ptpbuf_h_
#define _ptpbuf_h_

/* Cacheable/uncacheable RAM pointers */
// SJE FIXME: why does ptpbuf.h define these as well as mem.h?
// The definitions must be kept in sync for 7D builds, which
// link against ptpbuf.o, or gcc complains about redefinition
// of the define (sensibly).
#ifdef CONFIG_VXWORKS
#define UNCACHEABLE(x) ((void*)(((uint32_t)(x)) |  0x10000000))
#define CACHEABLE(x)   ((void*)(((uint32_t)(x)) & ~0x10000000))
#else
#define UNCACHEABLE(x) ((void*)(((uint32_t)(x)) | (((uint32_t)(x)) < 0x40000000 ?  0x40000000 : 0)))
#define CACHEABLE(x)   ((void*)(((uint32_t)(x)) & ~0x40000000))
#endif

#define PTPBUF_BUFS      16
#define PTPBUF_BUFSIZE   256
#define PTPBUF_MAGIC     0xEAEA3388

typedef struct
{
    uint32_t bytes_used;
    uint8_t data[PTPBUF_BUFSIZE];
} ptpbuf_buffer_t;

typedef struct
{
    uint32_t type;
    uint32_t length;
} ptpbuf_packet_t;

typedef struct
{
    uint32_t magic;
    uint32_t commit;
    uint32_t buffer_count;
    uint32_t buffer_size;
    uint32_t current_buffer;
    uint32_t overflow;
    ptpbuf_buffer_t *buffers;
    uint32_t *fetchable;
} ptpbuf_t;

#endif // _ptpbuf_h_
