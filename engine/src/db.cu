#include "third_party/sqlite3.h"

#define SQLITE_CHECK(call)                                          \
    do {                                                            \
        int rc = call;                                              \
        if (rc != SQLITE_OK) {                                      \
            fprintf(stderr, "sqlite error in %s at %s:%d: %s\n",    \
                    #call, __FILE__, __LINE__, sqlite3_errmsg(db)); \
            exit(1);                                                \
        }                                                           \
    } while (0)

#define MAX_WORD_LENGTH 8
#define WORDLIST_SIZE (16*1024) // 16kB can fit about 2k 8-letter words

// 4:total_length + 4:word_length + 4:word_count + word_count:words + ...
__constant__ static u8 d_wordlist_memory[WORDLIST_SIZE];
__constant__ static Arena d_wordlists[MAX_WORD_LENGTH];

// WARN: vibe coded query
// TODO: generate MAX_WORD_LENGTH `union select N` lines
static char select_n_sql[] = " \
    select count(o.suffix) \
    from ( \
        select 1 as length \
        union select 2 \
        union select 3 \
        union select 4 \
        union select 5 \
        union select 6 \
        union select 7 \
        union select 8 \
    ) as n \
    left join orders o on length(o.suffix) = n.length \
                          and o.status = 'processing' \
    group by n.length \
    order by n.length; \
";

static char select_words_sql[] = " \
    select suffix, length(suffix) \
    from orders \
    where status = 'processing' \
    order by length(suffix) desc, timestamp asc; \
";

const char insert_found_vault_sql[] = " \
    insert into found_seed(seed, address, contract) \
    values (@seed, @address, @contract); \
";

static sqlite3_stmt *select_n_stmt;
static sqlite3_stmt *select_words_stmt;
static sqlite3_stmt *insert_found_vault_stmt;

void prepare_sql_statements(sqlite3 *db) {
    SQLITE_CHECK(sqlite3_prepare_v2(
        db,
        select_n_sql,
        sizeof(select_n_sql),
        &select_n_stmt,
        NULL
    ));

    SQLITE_CHECK(sqlite3_prepare_v2(
        db,
        select_words_sql,
        sizeof(select_words_sql),
        &select_words_stmt,
        NULL
    ));

    SQLITE_CHECK(sqlite3_prepare_v2(
        db,
        insert_found_vault_sql,
        sizeof(insert_found_vault_sql),
        &insert_found_vault_stmt,
        NULL
    ));

    SQLITE_CHECK(sqlite3_bind_text(
        insert_found_vault_stmt,
        sqlite3_bind_parameter_index(
            insert_found_vault_stmt,
            "@contract"
        ),
        "0",
        -1,
        SQLITE_STATIC
    ));
}

void reload_wordlist(Arena *arena) {
    arena_free(arena);

    //
    // read number of words for each word length
    //

    Arena wordlists[MAX_WORD_LENGTH] = {0};

    int row = 0;
    while (sqlite3_step(select_n_stmt) == SQLITE_ROW) {
        const u8 *n_str = sqlite3_column_text(select_n_stmt, 0);

        int word_count = atoi((const char *)n_str);
        int word_length = row + 1;

        Arena wordlist = {0};
        arena_make_subarena(&wordlist, arena, word_count*word_length, 0);
        wordlists[row] = wordlist;

        row += 1;
    }
    assert(row == MAX_WORD_LENGTH);
    sqlite3_reset(select_n_stmt);

    //
    // read words
    //

    while (sqlite3_step(select_words_stmt) == SQLITE_ROW) {
        const u8 *word     = sqlite3_column_text(select_words_stmt, 0);
        const u8 *size_str = sqlite3_column_text(select_words_stmt, 1);
        int size = atoi((const char *)size_str);

        Arena *wordlist = wordlists + size - 1;
        for (int i = 0; i < size; i++) {
            u8 *byte = arena_push_type(wordlist, u8, 0);
            *byte = word[i];
        }
    }
    sqlite3_reset(select_words_stmt);

    //
    // copy to device
    //

    for (int i = 0; i < MAX_WORD_LENGTH; i += 1) {
        Arena *wordlist = wordlists + i;
        assert(wordlist->used == wordlist->capacity);

        void *wordlist_memory;
        CUDA_CHECK(cudaGetSymbolAddress(&wordlist_memory, d_wordlist_memory));

        uintptr_t new_ptr = (uintptr_t)wordlist_memory + arena_get_offset(arena, (uintptr_t)wordlist->memory);
        wordlist->memory = (void *)new_ptr;
    }
    CUDA_CHECK(cudaMemcpyToSymbol(
        d_wordlist_memory,
        arena->memory,
        arena->used
    ));
    CUDA_CHECK(cudaMemcpyToSymbol(
        d_wordlists,
        wordlists,
        MAX_WORD_LENGTH*sizeof(Arena)
    ));
}

void save_found_vault(sqlite3 *db, char *keypair, char pda[SHA256_DIGEST_LENGTH]) {
    // NOTE: crashing if binding went wrong is ok

    SQLITE_CHECK(sqlite3_bind_text(
        insert_found_vault_stmt,
        sqlite3_bind_parameter_index(
            insert_found_vault_stmt,
            "@seed"
        ),
        keypair,
        -1,
        SQLITE_STATIC
    ));

    SQLITE_CHECK(sqlite3_bind_blob(
        insert_found_vault_stmt,
        sqlite3_bind_parameter_index(
            insert_found_vault_stmt,
            "@address"
        ),
        pda,
        SHA256_DIGEST_LENGTH,
        SQLITE_STATIC
    ));

    int rc = sqlite3_step(insert_found_vault_stmt);
    // TODO: handle SQLITE_BUSY, SQLITE_LOCKED etc.
    //       should probably retry a few times before crashing
    if (rc != SQLITE_DONE) {
        printf("sqlite error: rc for sqlite3_step(insert_found_seed_stmt) is %d\n", rc);
        exit(1);
    }

    sqlite3_reset(insert_found_vault_stmt);
}
