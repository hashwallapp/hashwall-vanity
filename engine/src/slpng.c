#ifndef SLPNG_C_
#define SLPNG_C_

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>

//
// TYPEDEF
//

// unsigned int
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// signed int
typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

// boolean
typedef uint8_t  b8;
typedef uint16_t b16;
typedef uint32_t b32;
typedef uint64_t b64;

// real
typedef float  r32;
typedef double r64;

// memory index
typedef intptr_t  sptr;
typedef uintptr_t uptr;

//
// LOOP HELPERS
//

#define each(type, item, ptr, size, offset) \
    (struct { type *data; uptr index; } item = { (ptr) + (offset), 0 }; \
     item.index < (size); \
     item.data += 1, item.index += 1)

#define each_strided(type, item, ptr, size, offset, stride, stride_offset) \
    (struct { type *data; uptr index; } item = { (ptr) + (offset) + (stride)*(stride_offset), 0 }; \
     item.data < (ptr) + (offset) + (stride)*((stride_offset)+1)*(size)/sizeof(type); \
     item.data += (stride), item.index += 1)

//
// ARENA
//

typedef struct {
    uptr capacity;
    uptr used;
    void *memory;
} Arena;

void arena_init(Arena *arena, void *memory, uptr capacity) {
    // TODO: align memory in case an arbitrary pointer is passed
    // TODO: zero out memory by default
    arena->memory = memory;
    arena->capacity = capacity;
    arena->used = 0;
}

#define arena_push_type(arena, type, alignment)         (type *)arena_push_type_(arena, sizeof(type),         alignment)
#define arena_push_array(arena, count, type, alignment) (type *)arena_push_type_(arena, (count)*sizeof(type), alignment)

void *arena_push_type_(Arena *arena, uptr size, uptr alignment) {
    uptr padding = alignment ? alignment - ((arena->used + size) % alignment) : 0;
    assert((arena->used + size + padding) <= arena->capacity && "ERROR: not enough memory to push to arena");
    void *result = (void *) ((uptr)arena->memory + arena->used + padding);
    arena->used += size + padding;
    return result;
}

void arena_make_subarena(Arena *result, Arena *base_arena, uptr capacity, uptr alignment) {
    result->memory = (void *)arena_push_array(base_arena, capacity, u8, alignment);
    result->capacity = capacity;
    result->used = 0;
}

uptr arena_get_offset(Arena *arena, uptr ptr) {
    uptr result = ptr - (uptr)(arena->memory);
    return result;
}

#define ARENA_UNION_TYPE(type) type##ArenaUnion

#define TYPEDEF_ARENA_UNION(type) \
    static_assert(sizeof(type) % sizeof(uptr) == 0, "TYPEDEF_ARENA_UNION input type ("#type") must contain pointers only"); \
    typedef struct { \
        union { \
            type original_struct; \
            uptr pointers[sizeof(type)/sizeof(uptr)]; \
        }; \
    } ARENA_UNION_TYPE(type)

#define arena_copy_offsets(dst, dst_arena, src, src_arena, type) \
    do { \
        ARENA_UNION_TYPE(type) *dst_union = (ARENA_UNION_TYPE(type) *)dst; \
        ARENA_UNION_TYPE(type) *src_union = (ARENA_UNION_TYPE(type) *)src; \
        uptr size = sizeof(type)/sizeof(uptr); \
        for (uptr i = 0; i < size; i += 1) { \
            uptr arena_offset = arena_get_offset(src_arena, src_union->pointers[i]); \
            dst_union->pointers[i] = (uptr)(dst_arena->memory) + arena_offset; \
        } \
    } while (0)

void arena_free(Arena *arena) {
    arena->used = 0;
}

//
// STRINGS
//

typedef struct {
    u8 *bytes;
    uptr length;
} String_View;

String_View string_view_from_cstr(char *cstr) {
    String_View result = {0};
    if (cstr) {
        result.bytes = (u8 *)cstr;
        uptr length = 0;
        while (*cstr != '\0') {
            length += 1;
            cstr += 1;
        }
        result.length = length;
    }
    return result;
}

char *string_view_to_cstr(String_View sv, Arena *arena) {
    char *result = arena_push_array(arena, sv.length+1, char, alignof(char));
    for (int i = 0; i < sv.length; i += 1) {
        result[i] = sv.bytes[i];
    }
    result[sv.length] = '\0';
    return result;
}

String_View string_view_trim_left(String_View sv, uptr amount) {
    if (sv.length < 1) {
        return sv;
    }
    String_View result = {0};
    result.bytes = sv.bytes + 1;
    result.length = sv.length - 1;
    return result;
}

String_View string_view_trim_right(String_View sv, uptr amount) {
    if (sv.length < 1) {
        return sv;
    }
    String_View result = {0};
    result.bytes = sv.bytes;
    result.length = sv.length - 1;
    return result;
}

b32 string_view_compare(String_View a, String_View b) {
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

b32 string_view_compare_cstr(String_View sv, char *cstr) {
    b32 still_matches = 1;
    int i = 0;
    while (cstr[i] != '\0') {
        if (cstr[i] != sv.bytes[i]) {
            still_matches = 0;
            break;
        }
        i += 1;
    }
    if (i != sv.length) {
        still_matches = 0;
    }
    return still_matches;
}

u64 string_view_to_u64(String_View sv) {
    u64 result = 0;
    b32 is_negative = sv.bytes[0] == '-';
    for (int i = is_negative ? 1 : 0; i < sv.length; i += 1) {
        u8 ch = sv.bytes[i];
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

//
// FLAG PARSER
//

typedef enum {
    FLAG_TYPE_U64 = 0,
    FLAG_TYPE_B32,
    FLAG_TYPE_STRING_VIEW,
    FLAG_TYPE_COUNT
} Flag_Type;

typedef struct {
    String_View flag_name;
    String_View usage;
    Flag_Type type;
    uptr flag_address;
    b32 is_required;
    b32 was_found;
} Bound_Flag;

typedef struct {
    String_View program_name;
    uptr max_flags;
    Arena *backing_arena;
} Flag_Parser_Options;

typedef struct {
    Flag_Parser_Options options;
    Bound_Flag *bound_flags;
    uptr bound_flags_num;
} Flag_Parser;

Flag_Parser flag_parser_init(Flag_Parser_Options options) {
    Flag_Parser result = {0};
    result.options = options;
    result.bound_flags = arena_push_array(options.backing_arena, options.max_flags, Bound_Flag, 0);
    result.bound_flags_num = 0;
    return result;
}

void flag_parser_print_usage(Flag_Parser *parser) {
    printf("USAGE: %.*s [OPTIONS]\n", (int)parser->options.program_name.length, parser->options.program_name.bytes);
    for each(Bound_Flag, bound_flag, parser->bound_flags, parser->bound_flags_num, 0) {
        Bound_Flag flag = *bound_flag.data;
        printf("  -%.*s %*c %.*s\n",
               (int)flag.flag_name.length, flag.flag_name.bytes,
               20 - (int)flag.flag_name.length, ' ',
               (int)flag.usage.length, flag.usage.bytes);
    }
}

void flag_parser_bind(Flag_Parser *parser, Flag_Type type, void *flag_address, b32 is_required, char *flag_name, char *usage) {
    assert(type < FLAG_TYPE_COUNT);
    assert(parser->bound_flags);

    Bound_Flag bound_flag = {0};
    bound_flag.flag_name    = string_view_from_cstr(flag_name);
    bound_flag.usage        = string_view_from_cstr(usage);
    bound_flag.type         = type;
    bound_flag.flag_address = (uptr)flag_address;
    bound_flag.is_required  = is_required;
    bound_flag.was_found    = 0;

    parser->bound_flags[parser->bound_flags_num] = bound_flag;
    parser->bound_flags_num += 1;
}

b32 is_flag(String_View sv) {
    b32 result = sv.length >= 2 && sv.bytes[0] == '-';
    return result;
}


void flag_parser_parse(Flag_Parser *parser, int argc, char **argv) {
    int i = 1;

    while (i < argc) {
        String_View arg = string_view_from_cstr(argv[i]);
        if (!is_flag(arg)) {
            fprintf(stderr, "ERROR: unexpected argument '%.*s'\n", (int)arg.length, arg.bytes);
            flag_parser_print_usage(parser);
            exit(1);
        }

        String_View next_arg = string_view_from_cstr(argv[i + 1]);
        String_View trimmed_flag = string_view_trim_left(arg, 1);
        b32 flag_is_bound = 0;

#define read_next_arg() \
        do { \
            if (!(i + 1 < argc) || is_flag(next_arg)) { \
                fprintf(stderr, "ERROR: no value for flag '%.*s'\n", (int)flag->flag_name.length, flag->flag_name.bytes); \
                flag_parser_print_usage(parser); \
                exit(1); \
            } \
            i += 2; \
        } while (0)

        for each(Bound_Flag, bound_flag, parser->bound_flags, parser->bound_flags_num, 0) {
            Bound_Flag *flag = bound_flag.data;

            if (string_view_compare(trimmed_flag, flag->flag_name)) {
                flag_is_bound = 1;
                flag->was_found = 1;
                switch (flag->type) {
                    case FLAG_TYPE_U64:
                    {
                        read_next_arg();
                        u64 value = string_view_to_u64(next_arg);
                        *(u64 *)flag->flag_address = value;
                    }
                    break;

                    case FLAG_TYPE_B32:
                    {
                        *(b32 *)flag->flag_address = 1;
                        i += 1;
                    }
                    break;

                    case FLAG_TYPE_STRING_VIEW:
                    {
                        read_next_arg();
                        *(String_View *)flag->flag_address = next_arg;
                    }
                    break;

                    default:
                    {
                        assert(0);
                    }
                    break;
                }
                assert(FLAG_TYPE_COUNT <= 3);

                break;
            }
        }

#undef read_next_arg

        if (!flag_is_bound) {
            fprintf(stderr, "ERROR: unknown flag '%.*s'\n", (int)trimmed_flag.length, trimmed_flag.bytes);
            flag_parser_print_usage(parser);
            exit(1);
        }
    }

    b32 all_required_flags_found = 1;
    for each(Bound_Flag, bound_flag, parser->bound_flags, parser->bound_flags_num, 0) {
        if (bound_flag.data->is_required && !bound_flag.data->was_found) {
            all_required_flags_found = 0;
            fprintf(stderr, "ERROR: flag '%.*s' is required\n", (int)bound_flag.data->flag_name.length, bound_flag.data->flag_name.bytes);
        }
    }
    if (!all_required_flags_found) {
        flag_parser_print_usage(parser);
        exit(1);
    }
}

#endif // SLPNG_C_
