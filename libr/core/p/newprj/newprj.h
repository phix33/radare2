/* radare - MIT - Copyright 2024-2026 - pancake */

#ifndef R2_CORE_NEWPRJ_H
#define R2_CORE_NEWPRJ_H

#include <r_core.h>

enum {
	RPRJ_MAPS,
	RPRJ_INFO,
	RPRJ_FLAG,
	RPRJ_CMNT,
	RPRJ_CMDS,
	RPRJ_BLOB,
	RPRJ_MODS,
	RPRJ_STRS,
	RPRJ_THEM,
	RPRJ_HINT,
	RPRJ_EVAL,
	RPRJ_XREF,
	RPRJ_FUNC,
	RPRJ_MAGIC = 0x4a525052,
};

#define RPRJ_VERSION 4
#define RPRJ_ADDR_SIZE 12
#define RPRJ_XREF_SIZE (RPRJ_ADDR_SIZE * 2 + 4)
#define RPRJ_FLAG_SIZE (4 + 4 + 8 + 4 + 1)
#define RPRJ_FUNCTION_SIZE (4 + RPRJ_ADDR_SIZE + 4 + 4 + 4)
#define RPRJ_FUNCTION_ATTR_SIZE (4 + 4 + 4 + 4 + 8)
#define RPRJ_COLOR_SIZE 9
#define RPRJ_BLOCK_SIZE (RPRJ_ADDR_SIZE + 8 + RPRJ_ADDR_SIZE + RPRJ_ADDR_SIZE + 4)
#define RPRJ_VAR_SIZE 16

enum {
	RPRJ_FUNC_ATTR_NORETURN = 1 << 0,
};

enum {
	RPRJ_FLAG_SPACE     = 1 << 0,
	RPRJ_FLAG_REALNAME  = 1 << 1,
	RPRJ_FLAG_RAWNAME   = 1 << 2,
	RPRJ_FLAG_TYPE      = 1 << 3,
	RPRJ_FLAG_COLOR     = 1 << 4,
	RPRJ_FLAG_COMMENT   = 1 << 5,
	RPRJ_FLAG_ALIAS     = 1 << 6,
	RPRJ_FLAG_DEMANGLED = 1 << 7,
};

enum {
	R_CORE_NEWPRJ_MODE_LOAD = 1,
	R_CORE_NEWPRJ_MODE_LOG = 2,
	R_CORE_NEWPRJ_MODE_CMD = 4,
	R_CORE_NEWPRJ_MODE_SCRIPT = 8,
	R_CORE_NEWPRJ_MODE_DIFF = 16
};

typedef struct {
	ut32 magic;
	ut32 version;
} R2ProjectHeader;

typedef struct {
	ut8 *data;
	ut32 size;
	ut32 capacity;
} R2ProjectStringTable;

typedef struct {
	ut32 size;
	ut32 type;
} R2ProjectEntry;

typedef struct {
	ut32 name;
	ut32 user;
	ut64 time;
} R2ProjectInfo;

typedef struct {
	ut32 name;
	ut32 file;
	ut64 pmin;
	ut64 pmax;
	ut64 vmin;
	ut64 vmax;
	ut32 csum;
} R2ProjectMod;

typedef struct {
	ut32 name;
	ut32 mod;
	ut64 delta;
	ut64 size;
	ut8 extras;
} R2ProjectFlag;

typedef struct {
	ut32 text;
	ut32 mod;
	ut64 delta;
	ut64 size;
} R2ProjectComment;

typedef struct {
	ut32 kind;
	ut32 mod;
	ut64 delta;
	ut64 value;
} R2ProjectHint;

typedef struct {
	ut32 mod;
	ut64 delta;
} R2ProjectAddr;

typedef struct {
	R2ProjectAddr from;
	R2ProjectAddr to;
	ut32 type;
} R2ProjectXref;

typedef struct {
	ut32 name;
	R2ProjectAddr addr;
	ut32 attr;
	ut32 nbbs;
	ut32 nvars;
} R2ProjectFunction;

typedef struct {
	ut32 cc;
	ut32 type;
	ut32 bits;
	ut32 flags;
	ut64 stack;
} R2ProjectFunctionAttr;

typedef struct {
	R2ProjectAddr addr;
	ut64 size;
	R2ProjectAddr jump;
	R2ProjectAddr fail;
	ut32 color;
} R2ProjectBlock;

typedef struct {
	ut32 name;
	ut32 type;
	st32 delta;
	ut8 kind;
	ut8 isarg;
} R2ProjectVar;

typedef struct {
	RCore *core;
	R2ProjectStringTable *st;
	RBuffer *b;
	RList *mods;
} RPrjCursor;

typedef struct {
	const char *space;
	const char *realname;
	const char *rawname;
	const char *type;
	const char *color;
	const char *comment;
	const char *alias;
} RPrjFlagExtras;

typedef struct {
	char *name;
	char *type;
	st32 delta;
	ut8 kind;
	ut8 isarg;
	bool seen;
} R2ProjectDiffVar;

typedef struct {
	ut64 addr;
	ut64 size;
	ut64 jump;
	ut64 fail;
	RColor color;
	bool has_color;
	bool seen;
} R2ProjectDiffBlock;

typedef struct {
	ut64 addr;
} R2ProjectDiffFunction;

typedef struct {
	ut64 addr;
} R2ProjectDiffAddr;

typedef struct {
	ut64 from;
	ut64 to;
	ut32 type;
	bool seen;
} R2ProjectDiffXref;

typedef struct {
	RPrjCursor *cur;
	RList *seen;
} R2ProjectDiffCtx;

static const char *rprj_entry_type_tostring(int type);
static const char *rprj_st_get(R2ProjectStringTable *st, ut32 idx);
static bool rprj_st_is_valid(R2ProjectStringTable *st);
static void rprj_st_write(RBuffer *b, R2ProjectStringTable *st);
static ut32 rprj_st_append(R2ProjectStringTable *st, const char *s);
static R2ProjectMod *rprj_find_mod(RPrjCursor *cur, ut64 addr, ut32 *mid);
static R2ProjectMod *rprj_mod_by_id(RPrjCursor *cur, ut32 id);
static R2ProjectAddr rprj_addr_to_project(RPrjCursor *cur, ut64 addr);
static bool rprj_project_addr_to_va(RPrjCursor *cur, R2ProjectAddr *addr, ut64 *va);
static void rprj_write_le32(RBuffer *b, ut32 v);
static void rprj_write_le64(RBuffer *b, ut64 v);
static void rprj_write_u8(RBuffer *b, ut8 v);
static void rprj_write_project_addr(RBuffer *b, R2ProjectAddr addr);
static bool rprj_color_is_set(const RColor *color);
static bool rprj_color_eq(const RColor *a, const RColor *b);
static void rprj_write_color(RBuffer *b, const RColor *color);
static bool rprj_read_color(RBuffer *b, RColor *color);
static bool rprj_read_le32(RBuffer *b, ut32 *out);
static bool rprj_cmnt_read(RBuffer *b, R2ProjectComment *cmnt);
static bool rprj_flag_read(RBuffer *b, R2ProjectFlag *flag);
static bool rprj_hint_read(RBuffer *b, R2ProjectHint *hint);
static bool rprj_xref_read(RBuffer *b, R2ProjectXref *xref);
static bool rprj_function_read(RBuffer *b, R2ProjectFunction *fcn);
static bool rprj_function_attr_read(RBuffer *b, R2ProjectFunctionAttr *attr);
static bool rprj_block_read(RBuffer *b, R2ProjectBlock *bb);
static bool rprj_var_read(RBuffer *b, R2ProjectVar *var);
static void rprj_header_write(RBuffer *b);
static bool rprj_header_read(RBuffer *b, R2ProjectHeader *hdr);
static bool rprj_entry_read(RBuffer *b, R2ProjectEntry *entry);
static bool rprj_entry_begin(RBuffer *b, ut64 *at, ut32 type, ut32 version);
static void rprj_entry_end(RBuffer *b, ut64 at);
static bool rprj_string_read(RBuffer *b, ut64 next_entry, char **s);
static bool rprj_mods_read(RBuffer *b, R2ProjectMod *mod);
static void rprj_mods_write_one(RBuffer *b, R2ProjectMod *mod);
static void rprj_mods_write(RPrjCursor *cur);
static RIOMap *rprj_coremod(RPrjCursor *cur, R2ProjectMod *mod);
static bool rprj_info_read(RBuffer *b, R2ProjectInfo *info);

static void r_core_newprj_save(RCore *core, const char *file);
static void r_core_newprj_load(RCore *core, const char *file, int mode);
static void r_core_newprj_open(RCore *core, const char *file);

#endif
