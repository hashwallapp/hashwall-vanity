#ifndef BASE_FLAGS_H_
#define BASE_FLAGS_H_

typedef enum {
    FLAG_TYPE_U64 = 0,
    FLAG_TYPE_B32,
    FLAG_TYPE_STRING_VIEW,
    FLAG_TYPE_COUNT
} Flag_Type;

typedef struct {
    String8 flag_name;
    String8 usage;
    Flag_Type type;
    void *flag_address;
    b32 is_required;
    b32 was_found;
} Bound_Flag;

typedef struct {
    String8 program_name;
    s64 max_flags;
    Arena *backing_arena;
} Flag_Parser_Options;

typedef struct {
    Flag_Parser_Options options;
    Bound_Flag *bound_flags;
    s64 bound_flags_num;
} Flag_Parser;

Flag_Parser make_flag_parser(Flag_Parser_Options options);
void flag_parser_print_usage(Flag_Parser *parser);
void flag_parser_bind(Flag_Parser *parser, Flag_Type type, void *flag_address, b32 is_required, char *flag_name, char *usage);
b32 is_flag(String8 string);
void flag_parser_parse(Flag_Parser *parser, int argc, char **argv);

#endif // BASE_FLAGS_H_
