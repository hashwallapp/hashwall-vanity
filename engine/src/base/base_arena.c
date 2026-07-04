#include <assert.h>

void arena_init(Arena *arena, void *memory, s64 capacity) {
    // TODO: align memory in case an arbitrary pointer is passed
    arena->memory = memory;
    arena->capacity = capacity;
    arena->used = 0;
}

void arena_free(Arena *arena) {
    arena->used = 0;
}

void *arena_push_type_no_zero_(Arena *arena, s64 size, s64 alignment) {
    s64 padding = 0;

    b32 should_pad = alignment > 1 && alignment != arena->used;
    if (should_pad) {
        padding = alignment - ((arena->used + size) % alignment);
    }

    assert(arena->used + size + padding <= arena->capacity);

    void *result = (void *) ((sptr)arena->memory + arena->used + padding);
    arena->used += size + padding;
    return result;
}

void *arena_push_type_(Arena *arena, s64 size, s64 alignment) {
    void *result = arena_push_type_no_zero_(arena, size, alignment);
    memory_set(result, size, 0);
    return result;
}

Arena arena_make_subarena(Arena *base_arena, s64 capacity, s64 alignment) {
    Arena result = {0};

    result.memory = (void *)arena_push_array_aligned(base_arena, capacity, u8, alignment);
    result.capacity = capacity;
    result.used = 0;

    return result;
}

s64 arena_get_offset(Arena *arena, sptr ptr) {
    s64 result = ptr - (sptr)(arena->memory);
    return result;
}
