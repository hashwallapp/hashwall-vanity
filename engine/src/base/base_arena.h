#ifndef BASE_ARENA_H_
#define BASE_ARENA_H_

typedef struct {
    s64 capacity;
    s64 used;
    void *memory;
} Arena;

void arena_init(Arena *arena, void *memory, s64 capacity);
void arena_free(Arena *arena);

void *arena_push_type_no_zero_(Arena *arena, s64 size, s64 alignment);
#define arena_push_type_no_zero(arena, type)                            (type *)arena_push_type_no_zero_(arena, sizeof(type),         alignof(type))
#define arena_push_type_no_zero_aligned(arena, type, alignment)         (type *)arena_push_type_no_zero_(arena, sizeof(type),         alignment)
#define arena_push_array_no_zero(arena, count, type)                    (type *)arena_push_type_no_zero_(arena, (count)*sizeof(type), alignof(type))
#define arena_push_array_no_zero_aligned(arena, count, type, alignment) (type *)arena_push_type_no_zero_(arena, (count)*sizeof(type), alignment)

void *arena_push_type_(Arena *arena, s64 size, s64 alignment);
#define arena_push_type(arena, type)                            (type *)arena_push_type_(arena, sizeof(type),         alignof(type))
#define arena_push_type_aligned(arena, type, alignment)         (type *)arena_push_type_(arena, sizeof(type),         alignment)
#define arena_push_array(arena, count, type)                    (type *)arena_push_type_(arena, (count)*sizeof(type), alignof(type))
#define arena_push_array_aligned(arena, count, type, alignment) (type *)arena_push_type_(arena, (count)*sizeof(type), alignment)

Arena arena_make_subarena(Arena *base_arena, s64 capacity, s64 alignment);
s64 arena_get_offset(Arena *arena, sptr ptr);

#define ARENA_UNION_TYPE(type) type##ArenaUnion

#define TYPEDEF_ARENA_UNION(type) \
    static_assert(sizeof(type) % sizeof(sptr) == 0, "TYPEDEF_ARENA_UNION input type ("#type") must contain pointers only"); \
    typedef struct { \
        union { \
            type original_struct; \
            sptr pointers[sizeof(type)/sizeof(sptr)]; \
        }; \
    } ARENA_UNION_TYPE(type)

#define arena_copy_offsets(dst, dst_arena, src, src_arena, type) \
    do { \
        ARENA_UNION_TYPE(type) *dst_union = (ARENA_UNION_TYPE(type) *)dst; \
        ARENA_UNION_TYPE(type) *src_union = (ARENA_UNION_TYPE(type) *)src; \
        sptr size = sizeof(type)/sizeof(sptr); \
        for (sptr i = 0; i < size; i += 1) { \
            sptr arena_offset = arena_get_offset(src_arena, src_union->pointers[i]); \
            dst_union->pointers[i] = (sptr)(dst_arena->memory) + arena_offset; \
        } \
    } while (0)

#endif // BASE_ARENA_H_
