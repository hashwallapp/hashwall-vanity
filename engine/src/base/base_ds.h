#ifndef BASE_DS_H_
#define BASE_DS_H_

//
// DOUBLY LINKED LIST
//

// TODO: list_insert_after(&arena, &list, list.first->next, String8, string);

typedef struct ListNode ListNode;
struct ListNode {
    void *data;
    ListNode *next;
    ListNode *prev;
};

typedef struct {
    ListNode *first;
    ListNode *last;
    s64 count;
} List;

#define list_push(arena, list, type, value) \
    do { \
        type *data = arena_push_type((arena), type); \
        *data = (value); \
        list_push_((arena), (list), (void *)data); \
    } while (0)

void list_push_(Arena *arena, List *list, void *data);

#endif // BASE_DS_H_
