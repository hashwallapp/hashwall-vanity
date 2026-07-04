//
// ENDIANNESS
//

u16 bswap_u16(u16 x) {
    u16 result = (((x & 0xFF00) >> 8) |
                  ((x & 0x00FF) << 8));
    return result;
}

u32 bswap_u32(u32 x) {
    u32 result = (((x & 0xFF000000) >> 24) |
                  ((x & 0x00FF0000) >> 8)  |
                  ((x & 0x0000FF00) << 8)  |
                  ((x & 0x000000FF) << 24));
    return result;
}

u64 bswap_u64(u64 x) {
    u64 result = (((x & 0xFF00000000000000ULL) >> 56) |
                  ((x & 0x00FF000000000000ULL) >> 40) |
                  ((x & 0x0000FF0000000000ULL) >> 24) |
                  ((x & 0x000000FF00000000ULL) >> 8)  |
                  ((x & 0x00000000FF000000ULL) << 8)  |
                  ((x & 0x0000000000FF0000ULL) << 24) |
                  ((x & 0x000000000000FF00ULL) << 40) |
                  ((x & 0x00000000000000FFULL) << 56));
    return result;
}

//
//
//

void memory_set(void *memory, s64 size, u8 value) {
    for (s64 i = 0; i < size; i += 1) {
        ((u8 *)memory)[i] = value;
    }
}

void memory_copy(void *dst, void *src, s64 size) {
    for (s64 i = 0; i < size; i += 1) {
        ((u8 *)dst)[i] = ((u8 *)src)[i];
    }
}
