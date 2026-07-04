#ifndef BASE_STRING_H_
#define BASE_STRING_H_

typedef struct {
    u8 *bytes;
    s64 length;
} String8;

typedef struct {
    u16 *bytes;
    s64 length;
} String16;

#define str8format "%.*s"
#define str8spread(string) (int)(string).length, (string).bytes

String8 make_string8(u8 *bytes, s64 length);
String8 push_string8(Arena *arena, s64 length);
String8 push_string8_nt(Arena *arena, s64 length);
String8 push_string8fv(Arena *arena, char *fmt, va_list va1);
String8 push_string8f(Arena *arena, char *fmt, ...);

String8 string8_from_cstr(char *cstr);
#define string8_from_cstr_lit(lit) make_string8((u8 *)(lit), sizeof(lit) - 1)
#define str8lit(lit) string8_from_cstr_lit(lit)
char *cstr_from_string8(Arena *arena, String8 string);

String8 string8_trim_left(String8 string, s64 amount);
String8 string8_trim_right(String8 string, s64 amount);

b32 string8_match(String8 a, String8 b);
b32 string8_match_cstr(String8 string, char *cstr);

u64 u64_from_string8(String8 string);

void print_string8(String8 string);
void print_string8f(Arena *arena, char *fmt, ...);

String8 string8_from_list(Arena *arena, List *list, String8 delimiter);

String8 utf8_encode(Arena *arena, List unicode_codepoints);
List utf8_decode(Arena *arena, String8 string);
String16 utf16_encode(Arena *arena, List unicode_codepoints);
List utf16_decode(Arena *arena, String16 string);

String8 string8_from_string16(Arena *, String16 string);
String16 string16_from_string8(Arena *arena, String8 string);

#endif // BASE_STRING_H_
