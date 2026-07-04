#ifndef BASE_CORE_H_
#define BASE_CORE_H_

#include <stdint.h>

//
// TYPEDEF
//

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef uint8_t  b8;
typedef uint16_t b16;
typedef uint32_t b32;
typedef uint64_t b64;

typedef float  f32;
typedef double f64;

typedef uintptr_t uptr;
typedef intptr_t  sptr;

//
// ALIGNMENT
//

#ifndef __cplusplus
#   if 1
#       define alignof(type) (s64)offsetof(struct { u8 c; type member; }, member)
#   else
#       define alignof(type) (s64)(sizeof(struct{ u8 c; type member; }) - sizeof(type))
#   endif
#endif

//
// UNITS
//

#define Bytes(n)     ((s64)(n))
#define Kilobytes(n) (1024*Bytes((n)))
#define Megabytes(n) (1024*Kilobytes((n)))
#define Gigabytes(n) (1024*Megabytes((n)))
#define Terabytes(n) (1024*Gigabytes((n)))

//
// LOOP HELPERS
//

// iterate over each `type` in the memory range [`ptr` + `offset` .. `ptr` + `offset` + `count`)
// `item.data` points to the current item, `item.index` is the current iteration number,
// starting from 0
//
// usage example:
// ```
// s64 offset = 3;
// s64 count = array_count(string_array) - offset; // NOTE: `count` must account for `offset` to avoid out of bounds access
// for each_count(String8, string, string_array, count, offset) {
//     printf("string %ld is: " str8format "\n",
//            string.index, str8spread(*string.data));
// }
// ```
#define each_count(type, item, ptr, count, offset) \
    (struct { type *data; s64 index; } item = { (ptr) + (offset), 0 }; \
     item.index < (count); \
     item.data += 1, item.index += 1)

// iterate over each `type` in the memory range [`ptr` + `offset` .. `ptr` + `size_in_bytes`)
//
// usage example:
// ```
// s64 array_size = sizeof(string_array); // NOTE: no need to manually account for `offset` like in `each_count`
// for each_size(String8, string, string_array, array_size, 3) {
//     printf("string %ld is: " str8format "\n",
//            string.index, str8spread(*string.data));
// }
// ```
#define each_size(type, item, ptr, size_in_bytes, offset) \
    each_count(type, item, ptr, (size_in_bytes)/sizeof(type) - (offset), offset)

// usage example:
// ```
// f32 thread_local_array[100] = {0};
// s64 stride_offset = 15;
// s64 count = array_count(thread_local_array) - stride_offset; // NOTE: `count` must account for `stride_offset` to avoid out of bounds access
// for each_strided_count(f32, value, values, count, thread_id, total_threads, stride_offset) {
//     thread_local_array[stride_offset + value.index] = *value.data;
// }
// ```
#define each_strided_count(type, item, ptr, count, offset, stride, stride_offset) \
    (struct { type *data; s64 index; } item = { (ptr) + (offset) + (stride)*(stride_offset), 0 }; \
     item.index < (count); \
     item.data += (stride), item.index += 1)

// usage example:
// ```
// f32 thread_local_array[100] = {0};
// s64 stride_offset = 15;
// s64 array_size = sizeof(thread_local_array); // NOTE: no need to manually account for `stride_offset` like in `each_strided_count`
// for each_strided_size(f32, value, values, sizeof(thread_local_array), thread_id, total_threads, stride_offset) {
//     thread_local_array[stride_offset + value.index] = *value.data;
// }
// ```
#define each_strided_size(type, item, ptr, size_in_bytes, offset, stride, stride_offset) \
    each_strided_count(type, item, ptr, (size_in_bytes)/sizeof(type) - (stride_offset), offset, stride, stride_offset)

//
// ENDIANNESS
//

u16 bswap_u16(u16 x);
u32 bswap_u32(u32 x);
u64 bswap_u64(u64 x);

//
//
//

void memory_set(void *memory, s64 size, u8 value);
void memory_copy(void *dst, void *src, s64 size);

#endif // BASE_CORE_H_
