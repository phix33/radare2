/* radare - MIT - Copyright 2024-2026 - pancake */

#define R_LOG_ORIGIN "prj"

#include "newprj.h"

static ut8 emit_str(RPrjCursor *cur, ut8 bit, const char *s) {
	if (R_STR_ISNOTEMPTY (s)) {
		rprj_write_le32 (cur->b, rprj_st_append (cur->st, s));
		return bit;
	}
	return 0;
}

static void rprj_flag_write_one(RPrjCursor *cur, RFlagItem *fi) {
	R2ProjectAddr addr = rprj_addr_to_project (cur, fi->addr);
	const ut32 space_idx = fi->space? fi->space->privtag: UT32_MAX;
	RFlagItemMeta *fim = r_flag_get_meta (cur->core->flags, fi->id);
	const char *rn = (fi->realname && fi->realname != fi->name
			&& strcmp (fi->realname, fi->name))? fi->realname: NULL;
	const char *rw = (R_STR_ISNOTEMPTY (fi->rawname)
			&& strcmp (fi->rawname, fi->name)
			&& (!rn || strcmp (fi->rawname, rn)))? fi->rawname: NULL;
	// Reserve head, emit tail (accumulating extras), patch head.
	ut64 head_at = r_buf_at (cur->b);
	ut8 head[21] = {0};
	r_buf_write (cur->b, head, sizeof (head));
	ut8 extras = fi->demangled? RPRJ_FLAG_DEMANGLED: 0;
	if (space_idx != UT32_MAX) {
		extras |= RPRJ_FLAG_SPACE;
		rprj_write_le32 (cur->b, space_idx);
	}
	extras |= emit_str (cur, RPRJ_FLAG_REALNAME, rn);
	extras |= emit_str (cur, RPRJ_FLAG_RAWNAME, rw);
	extras |= emit_str (cur, RPRJ_FLAG_TYPE, fim? fim->type: NULL);
	extras |= emit_str (cur, RPRJ_FLAG_COLOR, fim? fim->color: NULL);
	extras |= emit_str (cur, RPRJ_FLAG_COMMENT, fim? fim->comment: NULL);
	extras |= emit_str (cur, RPRJ_FLAG_ALIAS, fim? fim->alias: NULL);
	r_write_le32 (head + 0, rprj_st_append (cur->st, fi->name));
	r_write_le32 (head + 4, addr.mod);
	r_write_le64 (head + 8, addr.delta);
	r_write_le32 (head + 16, fi->size);
	head[20] = extras;
	r_buf_write_at (cur->b, head_at, head, sizeof (head));
}

static bool flag_foreach_cb(RFlagItem *fi, void *user) {
	rprj_flag_write_one (user, fi);
	return true;
}

static void rprj_flag_write(RPrjCursor *cur) {
	// Seed the privtags first
	RSpaceIter *sit;
	RSpace *sp;
	r_flag_space_foreach (cur->core->flags, sit, sp) {
		if (sp) {
			sp->privtag = R_STR_ISNOTEMPTY (sp->name)
				? rprj_st_append (cur->st, sp->name)
				: UT32_MAX;
		}
	}
	rprj_write_le32 (cur->b, (ut32)r_flag_count (cur->core->flags, NULL));
	r_flag_foreach (cur->core->flags, flag_foreach_cb, cur);
}

static void rprj_cmnt_write_one(RPrjCursor *cur, RIntervalNode *node, RAnalMetaItem *mi) {
	R2ProjectComment cmnt = {0};
	ut64 va = node->start;
	ut32 text = rprj_st_append (cur->st, mi->str);
	R2ProjectAddr addr = rprj_addr_to_project (cur, va);
	r_write_le32 (&cmnt.text, text);
	r_write_le32 (&cmnt.mod, addr.mod);
	r_write_le64 (&cmnt.delta, addr.delta);
	const ut64 size = r_meta_node_size (node);
	r_write_le64 (&cmnt.size, size);
	r_buf_write (cur->b, (ut8*)&cmnt, sizeof (cmnt));
}

static void rprj_cmnt_write(RPrjCursor *cur) {
	RIntervalTreeIter it;
	RAnalMetaItem *item;
	r_interval_tree_foreach (&cur->core->anal->meta, it, item) {
		RIntervalNode *node = r_interval_tree_iter_get (&it);
		if (item->type == R_META_TYPE_COMMENT) {
			rprj_cmnt_write_one (cur, node, item);
		}
	}
}

static void rprj_xref_write_one(RPrjCursor *cur, RAnalRef *ref) {
	R2ProjectAddr from = rprj_addr_to_project (cur, ref->at);
	R2ProjectAddr to = rprj_addr_to_project (cur, ref->addr);
	rprj_write_project_addr (cur->b, from);
	rprj_write_project_addr (cur->b, to);
	rprj_write_le32 (cur->b, ref->type);
}

static void rprj_xref_write(RPrjCursor *cur) {
	RVecAnalRef *refs = r_anal_refs_get (cur->core->anal, UT64_MAX);
	const ut64 count_at = r_buf_at (cur->b);
	rprj_write_le32 (cur->b, 0);
	ut32 count = 0;
	if (refs) {
		RAnalRef *ref;
		R_VEC_FOREACH (refs, ref) {
			rprj_xref_write_one (cur, ref);
			count++;
		}
		RVecAnalRef_free (refs);
	}
	ut8 buf[4];
	r_write_le32 (buf, count);
	r_buf_write_at (cur->b, count_at, buf, sizeof (buf));
}

static ut32 rprj_color_index(RList *colors, RColor *color) {
	if (!rprj_color_is_set (color)) {
		return UT32_MAX;
	}
	ut32 idx = 0;
	RListIter *iter;
	RColor *it;
	r_list_foreach (colors, iter, it) {
		if (rprj_color_eq (it, color)) {
			return idx;
		}
		idx++;
	}
	RColor *copy = r_mem_dup (color, sizeof (*color));
	if (!copy) {
		return UT32_MAX;
	}
	r_list_append (colors, copy);
	return idx;
}

static bool fcn_attr_eq(R2ProjectFunctionAttr *a, R2ProjectFunctionAttr *b) {
	return a && b && a->cc == b->cc && a->type == b->type && a->bits == b->bits
		&& a->flags == b->flags && a->stack == b->stack;
}

static ut32 rprj_fcn_attr_index(RList *attrs, R2ProjectFunctionAttr *attr) {
	ut32 idx = 0;
	RListIter *iter;
	R2ProjectFunctionAttr *it;
	r_list_foreach (attrs, iter, it) {
		if (fcn_attr_eq (it, attr)) {
			return idx;
		}
		idx++;
	}
	R2ProjectFunctionAttr *copy = r_mem_dup (attr, sizeof (*attr));
	if (!copy) {
		return UT32_MAX;
	}
	r_list_append (attrs, copy);
	return idx;
}

static R2ProjectFunctionAttr rprj_function_attr(RPrjCursor *cur, RAnalFunction *fcn) {
	R2ProjectFunctionAttr attr = {
		.cc = R_STR_ISNOTEMPTY (fcn->callconv)? rprj_st_append (cur->st, fcn->callconv): UT32_MAX,
		.type = (ut32)fcn->type,
		.bits = (ut32)fcn->bits,
		.flags = fcn->is_noreturn? RPRJ_FUNC_ATTR_NORETURN: 0,
		.stack = (ut64)fcn->maxstack,
	};
	return attr;
}

static void rprj_function_collect_attrs(RPrjCursor *cur, RList *attrs, RAnalFunction *fcn) {
	R2ProjectFunctionAttr attr = rprj_function_attr (cur, fcn);
	rprj_fcn_attr_index (attrs, &attr);
}

static ut32 rprj_fcn_attr_index_for_fcn(RPrjCursor *cur, RList *attrs, RAnalFunction *fcn) {
	const ut32 flags = fcn->is_noreturn? RPRJ_FUNC_ATTR_NORETURN: 0;
	const st64 stack = fcn->maxstack;
	ut32 idx = 0;
	RListIter *iter;
	R2ProjectFunctionAttr *attr;
	r_list_foreach (attrs, iter, attr) {
		const char *cc = attr->cc != UT32_MAX? rprj_st_get (cur->st, attr->cc): NULL;
		if ((ut32)fcn->type == attr->type && (ut32)fcn->bits == attr->bits
				&& flags == attr->flags && stack == (st64)attr->stack
				&& !strcmp (r_str_get (cc), r_str_get (fcn->callconv))) {
			return idx;
		}
		idx++;
	}
	return UT32_MAX;
}

static void rprj_function_collect_colors(RList *colors, RAnalFunction *fcn) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		rprj_color_index (colors, &bb->color);
	}
}

static void rprj_var_write_one(RPrjCursor *cur, RAnalVar *var) {
	rprj_write_le32 (cur->b, rprj_st_append (cur->st, var->name));
	rprj_write_le32 (cur->b, rprj_st_append (cur->st, var->type));
	rprj_write_le32 (cur->b, (ut32)var->delta);
	rprj_write_u8 (cur->b, (ut8)var->kind);
	rprj_write_u8 (cur->b, var->isarg? 1: 0);
	rprj_write_u8 (cur->b, 0);
	rprj_write_u8 (cur->b, 0);
}

static void rprj_function_write_one(RPrjCursor *cur, RAnalFunction *fcn, RList *colors, RList *attrs) {
	RListIter *iter;
	RAnalBlock *bb;
	ut32 nbbs = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		nbbs++;
	}
	const ut32 nvars = (ut32)RVecAnalVarPtr_length (&fcn->vars);
	rprj_write_le32 (cur->b, rprj_st_append (cur->st, fcn->name));
	rprj_write_project_addr (cur->b, rprj_addr_to_project (cur, fcn->addr));
	rprj_write_le32 (cur->b, rprj_fcn_attr_index_for_fcn (cur, attrs, fcn));
	rprj_write_le32 (cur->b, nbbs);
	rprj_write_le32 (cur->b, nvars);
	r_list_foreach (fcn->bbs, iter, bb) {
		rprj_write_project_addr (cur->b, rprj_addr_to_project (cur, bb->addr));
		rprj_write_le64 (cur->b, bb->size);
		rprj_write_project_addr (cur->b, rprj_addr_to_project (cur, bb->jump));
		rprj_write_project_addr (cur->b, rprj_addr_to_project (cur, bb->fail));
		rprj_write_le32 (cur->b, rprj_color_index (colors, &bb->color));
	}
	RAnalVar **var;
	R_VEC_FOREACH (&fcn->vars, var) {
		rprj_var_write_one (cur, *var);
	}
}

static void rprj_function_write(RPrjCursor *cur) {
	RList *colors = r_list_newf (free);
	RList *attrs = r_list_newf (free);
	if (!colors || !attrs) {
		r_list_free (colors);
		r_list_free (attrs);
		return;
	}
	RListIter *iter;
	RAnalFunction *fcn;
	RList *fcns = r_anal_get_fcns (cur->core->anal);
	r_list_foreach (fcns, iter, fcn) {
		if (!fcn || R_STR_ISEMPTY (fcn->name)) {
			continue;
		}
		rprj_function_collect_attrs (cur, attrs, fcn);
		rprj_function_collect_colors (colors, fcn);
	}
	rprj_write_le32 (cur->b, (ut32)r_list_length (colors));
	RColor *color;
	r_list_foreach (colors, iter, color) {
		rprj_write_color (cur->b, color);
	}
	rprj_write_le32 (cur->b, (ut32)r_list_length (attrs));
	R2ProjectFunctionAttr *attr;
	r_list_foreach (attrs, iter, attr) {
		rprj_write_le32 (cur->b, attr->cc);
		rprj_write_le32 (cur->b, attr->type);
		rprj_write_le32 (cur->b, attr->bits);
		rprj_write_le32 (cur->b, attr->flags);
		rprj_write_le64 (cur->b, attr->stack);
	}
	const ut64 count_at = r_buf_at (cur->b);
	rprj_write_le32 (cur->b, 0);
	ut32 count = 0;
	r_list_foreach (fcns, iter, fcn) {
		if (!fcn || R_STR_ISEMPTY (fcn->name)) {
			continue;
		}
		rprj_function_write_one (cur, fcn, colors, attrs);
		count++;
	}
	ut8 buf[4];
	r_write_le32 (buf, count);
	r_buf_write_at (cur->b, count_at, buf, sizeof (buf));
	r_list_free (attrs);
	r_list_free (colors);
}

typedef struct {
	RPrjCursor *cur;
} HintsCtx;

static bool rprj_hints_collect_cb(ut64 addr, const RVecAnalAddrHintRecord *records, void *user) {
	HintsCtx *ctx = (HintsCtx*)user;
	RPrjCursor *cur = ctx->cur;
	const RAnalAddrHintRecord *record;
	R_VEC_FOREACH (records, record) {
		ut32 kind = 0;
		ut64 val = 0;
		switch (record->type) {
		case R_ANAL_ADDR_HINT_TYPE_IMMBASE:
			kind = 1;
			val = (ut64)record->immbase;
			break;
		case R_ANAL_ADDR_HINT_TYPE_NEW_BITS:
			kind = 2;
			val = (ut64)record->newbits;
			break;
		default:
			break;
		}
		if (!kind) {
			continue;
		}
		R2ProjectHint hint = {0};
		ut32 mid = UT32_MAX;
		R2ProjectMod *mod = rprj_find_mod (cur, addr, &mid);
		r_write_le32 (&hint.kind, kind);
		if (mod) {
			r_write_le32 (&hint.mod, mid);
			r_write_le64 (&hint.delta, addr - mod->vmin);
		} else {
			r_write_le32 (&hint.mod, UT32_MAX);
			r_write_le64 (&hint.delta, addr);
		}
		r_write_le64 (&hint.value, val);
		r_buf_write (cur->b, (const ut8*)&hint, sizeof (hint));
	}
	return true;
}

static void rprj_hints_write(RPrjCursor *cur) {
	HintsCtx ctx = { cur };
	r_anal_addr_hints_foreach (cur->core->anal, rprj_hints_collect_cb, &ctx);
}

static bool evalkey_is_saveable(RConfigNode *node) {
	if (r_config_node_is_ro (node)) {
		return false;
	}
	if (R_STR_ISEMPTY (node->name)) {
		return false;
	}
	// TODO this information nust be tied to the config vars and this function must go away soon or late
	static const char *skip_prefixes[] = {
		"dir.",
		"bin.limit", //triggers binreload wtf
		"file.",
		"prj.",
		"scr.",
		"env.",
		"stdin",
		"pdb.",
		"cfg.user",
		"cfg.log.",
		"cfg.debug",
		"cfg.prefixdump",
		"cmd.log",
		"dbg.backend",
		"dbg.btalgo",
		"http.",
		"key.",
		NULL,
	};
	const char *n = node->name;
	int i;
	for (i = 0; skip_prefixes[i]; i++) {
		if (r_str_startswith (n, skip_prefixes[i])) {
			return false;
		}
	}
	return true;
}

static void rprj_eval_write(RPrjCursor *cur) {
	RBuffer *b = cur->b;
	const ut64 count_at = r_buf_at (b);
	rprj_write_le32 (b, 0);
	ut32 count = 0;
	RListIter *iter;
	RConfigNode *node;
	r_list_foreach (cur->core->config->nodes, iter, node) {
		if (!evalkey_is_saveable (node)) {
			continue;
		}
		const char *val = r_config_get (cur->core->config, node->name);
		ut32 k = rprj_st_append (cur->st, node->name);
		ut32 v = rprj_st_append (cur->st, val);
		if (k == UT32_MAX || v == UT32_MAX) {
			continue;
		}
		rprj_write_le32 (b, k);
		rprj_write_le32 (b, v);
		count++;
	}
	ut8 buf[4];
	r_write_le32 (buf, count);
	r_buf_write_at (b, count_at, buf, sizeof (buf));
}

static void r_core_newprj_save(RCore *core, const char *file) {
	RBuffer *b = r_buf_new ();
	rprj_header_write (b);
	R2ProjectStringTable st = {0};
	RPrjCursor cur = {
		.core = core,
		.st = &st,
		.b = b,
		.mods = r_list_newf (free),
	};
	ut64 at;
	if (rprj_entry_begin (b, &at, RPRJ_INFO, 1)) {
		const char *prj_name = r_config_get (core->config, "prj.name");
		const char *prj_user = r_config_get (core->config, "cfg.user");
		R2ProjectInfo info = {
			.name = rprj_st_append (&st, r_str_get (prj_name)),
			.user = rprj_st_append (&st, r_str_get (prj_user)),
			.time = r_time_now ()
		};
		r_buf_write (b, (const ut8*)&info, sizeof (info));
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_MODS, 1)) {
		rprj_mods_write (&cur);
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_EVAL, 1)) {
		rprj_eval_write (&cur);
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_FLAG, 1)) {
		rprj_flag_write (&cur);
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_CMNT, 1)) {
		rprj_cmnt_write (&cur);
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_HINT, 1)) {
		rprj_hints_write (&cur);
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_FUNC, 1)) {
		rprj_function_write (&cur);
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_XREF, 1)) {
		rprj_xref_write (&cur);
		rprj_entry_end (b, at);
	}
	if (rprj_entry_begin (b, &at, RPRJ_STRS, 1)) {
		rprj_st_write (b, &st);
		rprj_entry_end (b, at);
	}
	// -------------
	bool can_write = true;
	if (r_file_exists (file)) {
		const bool isint = r_config_get_b (core->config, "scr.interactive");
		if (isint && !r_cons_yesno (core->cons, 'y', "Overwrite project file (Y/n)")) {
			R_LOG_ERROR ("File exists");
			can_write = false;
		} else {
			r_file_rm (file);
		}
	}
	if (can_write) {
		ut64 size;
		const ut8 *data = r_buf_data (b, &size);
		if (!r_file_dump (file, data, size, false)) {
			R_LOG_ERROR ("Cannot write file");
		}
	}
	r_unref (b);
	r_list_free (cur.mods);
	free (st.data);
}
