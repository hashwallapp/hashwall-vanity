//
// DOUBLY LINKED LIST
//

void list_push_(Arena *arena, List *list, void *data) {
    ListNode *node = arena_push_type(arena, ListNode);
    node->data = data;
    node->next = 0;
    if (list->first == 0) {
        assert(list->last == 0);
        assert(list->count == 0);
        node->prev = 0;
        list->first = node;
        list->last = node;
    } else {
        assert(list->last != 0);
        assert(list->count > 0);
        node->prev = list->last;
        list->last->next = node;
        list->last = node;
    }
    list->count += 1;
}
