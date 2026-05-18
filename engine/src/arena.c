typedef struct {
    size_t capacity;
    size_t used;
    void *memory;
} Arena;

void arena_init(Arena *arena, void *memory, size_t capacity) {
    arena->memory = memory;
    arena->capacity = capacity;
    arena->used = 0;
}

#define arena_push_type(arena, type, alignment) (type *)arena_push_type_(arena, sizeof(type), alignment)
#define arena_push_array(arena, count, type, alignment) (type *)arena_push_type_(arena, (count) * sizeof(type), alignment)

void *arena_push_type_(Arena *arena, size_t size, size_t alignment) {
    size_t padding = alignment - ((arena->used + size) % alignment);

    assert((arena->used + size + padding) <= arena->capacity && "ERROR: not enough memory to push to arena");

    void *result = (uint8_t *)arena->memory + arena->used + padding;

    arena->used += size + padding;

    return result;
}
