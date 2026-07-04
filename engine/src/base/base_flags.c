Flag_Parser make_flag_parser(Flag_Parser_Options options) {
    Flag_Parser result = {0};
    result.options = options;
    result.bound_flags = arena_push_array(options.backing_arena, options.max_flags, Bound_Flag);
    result.bound_flags_num = 0;
    return result;
}

void flag_parser_print_usage(Flag_Parser *parser) {
    printf("USAGE: " str8format " [OPTIONS]\n", str8spread(parser->options.program_name));
    for each_count(Bound_Flag, bound_flag, parser->bound_flags, parser->bound_flags_num, 0) {
        Bound_Flag flag = *bound_flag.data;
        // TODO: wrap `usage` to next line if it's longer than `max_usage_length`
        int max_usage_length = 20;
        int padding = max_usage_length - (int)flag.flag_name.length;
        printf("  -" str8format " %*c " str8format "\n",
               str8spread(flag.flag_name),
               padding, ' ',
               str8spread(flag.usage));
    }
}

void flag_parser_bind(Flag_Parser *parser, Flag_Type type, void *flag_address, b32 is_required, char *flag_name, char *usage) {
    assert(type < FLAG_TYPE_COUNT);
    assert(parser->bound_flags);

    Bound_Flag bound_flag = {0};
    bound_flag.flag_name    = string8_from_cstr(flag_name);
    bound_flag.usage        = string8_from_cstr(usage);
    bound_flag.type         = type;
    bound_flag.flag_address = flag_address;
    bound_flag.is_required  = is_required;
    bound_flag.was_found    = 0;

    parser->bound_flags[parser->bound_flags_num] = bound_flag;
    parser->bound_flags_num += 1;
}

b32 is_flag(String8 string) {
    b32 result = string.length >= 2 && string.bytes[0] == '-';
    return result;
}

void flag_parser_parse(Flag_Parser *parser, int argc, char **argv) {
    int i = 1;

    while (i < argc) {
        String8 arg = string8_from_cstr(argv[i]);
        if (!is_flag(arg)) {
            fprintf(stderr, "ERROR: unexpected argument '%.*s'\n", (int)arg.length, arg.bytes);
            flag_parser_print_usage(parser);
            exit(1);
        }

        String8 next_arg = string8_from_cstr(argv[i + 1]);
        String8 trimmed_flag = string8_trim_left(arg, 1);
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

        for each_count(Bound_Flag, bound_flag, parser->bound_flags, parser->bound_flags_num, 0) {
            Bound_Flag *flag = bound_flag.data;

            if (string8_match(trimmed_flag, flag->flag_name)) {
                flag_is_bound = 1;
                flag->was_found = 1;
                switch (flag->type) {
                    case FLAG_TYPE_U64:
                    {
                        read_next_arg();
                        u64 value = u64_from_string8(next_arg);
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
                        *(String8 *)flag->flag_address = next_arg;
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
    for each_count(Bound_Flag, bound_flag, parser->bound_flags, parser->bound_flags_num, 0) {
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
