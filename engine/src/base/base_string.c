#include <stdarg.h>
#include <assert.h>

#define STB_SPRINTF_IMPLEMENTATION
#include "third_party/stb_sprintf.h"
#undef STB_SPRINTF_IMPLEMENTATION

String8 make_string8(u8 *bytes, s64 length) {
    String8 result = {0};
    result.bytes = bytes;
    result.length = length;
    return result;
}

String8 push_string8(Arena *arena, s64 length) {
    String8 result = {0};
    result.bytes = arena_push_array(arena, length, u8);
    result.length = length;
    return result;
}

String8 push_string8_nt(Arena *arena, s64 length) {
    String8 result = {0};
    result.bytes = arena_push_array(arena, length + 1, u8);
    result.length = length;
    result.bytes[result.length] = '\0';
    return result;
}

String8 push_string8fv(Arena *arena, char *fmt, va_list va1) {
    va_list va2;
    va_copy(va2, va1);
    int length = stbsp_vsnprintf(0, 0, fmt, va1) + 1;
    String8 result = push_string8_nt(arena, length - 1);
    stbsp_vsnprintf((char *)result.bytes, length, fmt, va2);
    va_end(va2);
    return result;
}

String8 push_string8f(Arena *arena, char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    String8 result = push_string8fv(arena, fmt, va);
    va_end(va);
    return result;
}

String8 string8_from_cstr(char *cstr) {
    String8 result = {0};
    if (cstr) {
        result.bytes = (u8 *)cstr;
        s64 length = 0;
        while (*cstr != '\0') {
            length += 1;
            cstr += 1;
        }
        result.length = length;
    }
    return result;
}

char *cstr_from_string8(Arena *arena, String8 string) {
    char *result = arena_push_array(arena, string.length+1, char);
    memory_copy(result, string.bytes, string.length);
    result[string.length] = '\0';
    return result;
}

String8 string8_trim_left(String8 string, s64 amount) {
    if (string.length < 1) {
        return string;
    }
    String8 result = {0};
    result.bytes = string.bytes + 1;
    result.length = string.length - 1;
    return result;
}

String8 string8_trim_right(String8 string, s64 amount) {
    if (string.length < 1) {
        return string;
    }
    String8 result = {0};
    result.bytes = string.bytes;
    result.length = string.length - 1;
    return result;
}

b32 string8_match(String8 a, String8 b) {
    if (a.length != b.length) {
        return 0;
    }
    b32 still_matches = 1;
    for (int i = 0; i < a.length; i += 1) {
        if (a.bytes[i] != b.bytes[i]) {
            still_matches = 0;
            break;
        }
    }
    return still_matches;
}

b32 string8_match_cstr(String8 string, char *cstr) {
    b32 still_matches = 1;
    int i = 0;
    while (cstr[i] != '\0') {
        if (cstr[i] != string.bytes[i]) {
            still_matches = 0;
            break;
        }
        i += 1;
    }
    if (i != string.length) {
        still_matches = 0;
    }
    return still_matches;
}

u64 u64_from_string8(String8 string) {
    u64 result = 0;
    b32 is_negative = string.bytes[0] == '-';
    for (int i = is_negative ? 1 : 0; i < string.length; i += 1) {
        u8 ch = string.bytes[i];
        s8 num = ch - '0';
        assert(num >= 0 && num <= 9);
        u64 max_result = (UINT64_MAX - num)/10;
        assert(max_result >= result);
        result *= 10;
        result += num;
    }
    result *= is_negative ? -1 : 1;
    return result;
}

void print_string8(String8 string) {
    printf(str8format, str8spread(string));
}

void print_string8f(Arena *arena, char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    print_string8(push_string8fv(arena, fmt, va));
    va_end(va);
}

String8 string8_from_list(Arena *arena, List *list, String8 delimiter) {
    String8 result = {0};
    result.bytes = arena_push_array(arena, 0, u8);
    s64 cursor = 0;
    for (ListNode *node = list->first; node != 0; node = node->next) {
        String8 *string = (String8 *)node->data;
        arena_push_array(arena, string->length, u8);
        for (s64 i = 0; i < string->length; i += 1) {
            result.bytes[cursor] = string->bytes[i];
            cursor += 1;
        }
        if (delimiter.length > 0 && node->next != 0) {
            arena_push_array(arena, delimiter.length, u8);
            for (s64 i = 0; i < delimiter.length; i += 1) {
                result.bytes[cursor] = delimiter.bytes[i];
                cursor += 1;
            }
        }
    }
    result.length = cursor;
    return result;
}

String8 utf8_encode(Arena *arena, List unicode_codepoints) {
    String8 result = {0};

    for (ListNode *codepoint_node = unicode_codepoints.first; codepoint_node != 0; codepoint_node = codepoint_node->next) {
        s32 codepoint = *(s32 *)codepoint_node->data;
        assert(codepoint >= 0);

        // TODO: there are 66 codepoints that can never be assigned to characters

        u8 *bytes = 0;

        if (codepoint <= 0x7F) {
            bytes = arena_push_array(arena, 1, u8);
            bytes[0] = codepoint;
            result.length += 1;
        } else if (codepoint <= 0x7FF) {
            bytes = arena_push_array(arena, 2, u8);
            bytes[0] = 0b11000000 | (codepoint >> 6);
            bytes[1] = 0b10000000 | (codepoint & 0b00111111);
            result.length += 2;
        } else if (codepoint <= 0xFFFF) {
            bytes = arena_push_array(arena, 3, u8);
            bytes[0] = 0b11100000 |  (codepoint >> 12);
            bytes[1] = 0b10000000 | ((codepoint >> 6) & 0b00111111);
            bytes[2] = 0b10000000 |  (codepoint & 0b00111111);
            result.length += 3;
        } else if (codepoint <= 0x10FFFF) {
            bytes = arena_push_array(arena, 4, u8);
            bytes[0] = 0b11110000 |  (codepoint >> 18);
            bytes[1] = 0b10000000 | ((codepoint >> 12) & 0b00111111);
            bytes[2] = 0b10000000 | ((codepoint >> 6) & 0b00111111);
            bytes[3] = 0b10000000 |  (codepoint & 0b00111111);
            result.length += 4;
        } else {
            assert(0);
        }

        if (!result.bytes) {
            result.bytes = bytes;
        }
    }

    u8 *null_terminator = arena_push_type(arena, u8);
    *null_terminator = 0;

    return result;
}

List utf8_decode(Arena *arena, String8 string) {
    List result = {0};

    s64 i = 0;
    while (i < string.length) {
        u8 c1 = string.bytes[i];
        if ((c1 >> 7) == 0) {
            list_push(arena, &result, s32, (s32)c1);
            i += 1;
        } else if ((c1 >> 5) == 0b00000110) {
            assert(i + 1 < string.length);
            u8 c2 = string.bytes[i + 1];
            assert((c2 >> 6) == 0b00000010);
            s32 codepoint = ((s32)(c1 & 0b00011111) << 6) |
                                  (c2 & 0b00111111);
            list_push(arena, &result, s32, codepoint);
            i += 2;
        } else if ((c1 >> 4) == 0b00001110) {
            assert(i + 2 < string.length);
            u8 c2 = string.bytes[i + 1];
            u8 c3 = string.bytes[i + 2];
            assert((c2 >> 6) == 0b00000010);
            assert((c3 >> 6) == 0b00000010);
            s32 codepoint = ((s32)(c1 & 0b00001111) << 12) |
                            ((s32)(c2 & 0b00111111) << 6) |
                                  (c3 & 0b00111111);
            list_push(arena, &result, s32, codepoint);
            i += 3;
        } else if ((c1 >> 3) == 0b00011110) {
            assert(i + 3 < string.length);
            u8 c2 = string.bytes[i + 1];
            u8 c3 = string.bytes[i + 2];
            u8 c4 = string.bytes[i + 3];
            assert((c2 >> 6) == 0b00000010);
            assert((c3 >> 6) == 0b00000010);
            assert((c4 >> 6) == 0b00000010);
            s32 codepoint = ((s32)(c1 & 0b00000111) << 18) |
                            ((s32)(c2 & 0b00111111) << 12) |
                            ((s32)(c3 & 0b00111111) << 6) |
                                  (c4 & 0b00111111);
            list_push(arena, &result, s32, codepoint);
            i += 4;
        } else {
            assert(0);
        }
    }

    return result;
}

String16 utf16_encode(Arena *arena, List unicode_codepoints) {
    String16 result = {0};

    for (ListNode *codepoint_node = unicode_codepoints.first; codepoint_node != 0; codepoint_node = codepoint_node->next) {
        s32 codepoint = *(s32 *)codepoint_node->data;
        assert(codepoint >= 0);

        u16 *high = 0;
        u16 *low = 0;

        if (codepoint <= 0xFFFF) {
            high = arena_push_type_aligned(arena, u16, 0);
            *high = codepoint;
            result.length += 1;
        } else if (codepoint <= 0x10FFFF) {
            high = arena_push_type_aligned(arena, u16, 0);
            low = arena_push_type_aligned(arena, u16, 0);
            u32 codepoint_prime = codepoint - 0x10000;
            *high = 0b1101100000000000 | (codepoint_prime >> 10);
            *low  = 0b1101110000000000 | (codepoint_prime & 0b00000000001111111111);
            result.length += 2;
        } else {
            assert(0);
        }

        if (!result.bytes) {
            result.bytes = high;
        }
    }

    u16 *null_terminator = arena_push_type_aligned(arena, u16, 0);
    *null_terminator = 0;

    return result;
}

List utf16_decode(Arena *arena, String16 string) {
    List result = {0};

    s64 i = 0;
    while (i < string.length) {
        u16 high = string.bytes[i];
        if (high < 0xD800 || high > 0xDFFF) {
            list_push(arena, &result, s32, (s32)high);
            i += 1;
        } else if (0xD800 < high && high < 0xDBFF) {
            assert(i + 1 < string.length);
            u16 low = string.bytes[i + 1];
            u32 codepoint_prime = ((u32)high << 10) | (low & 0b00000000001111111111);
            s32 codepoint = codepoint_prime + 0x10000;
            list_push(arena, &result, s32, codepoint);
            i += 2;
        } else {
            assert(0);
        }
    }

    return result;
}

String8 string8_from_string16(Arena *arena, String16 string) {
    List unicode_codepoints = utf16_decode(arena, string);
    String8 result = utf8_encode(arena, unicode_codepoints);
    return result;
}

String16 string16_from_string8(Arena *arena, String8 string) {
    List unicode_codepoints = utf8_decode(arena, string);
    String16 result = utf16_encode(arena, unicode_codepoints);
    return result;
}
