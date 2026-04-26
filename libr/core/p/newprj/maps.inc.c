/* radare - MIT - Copyright 2024-2026 - pancake */

#define R_LOG_ORIGIN "prj"

#include "newprj.h"
#include <r_util/r_json.h>

#define RPRJ_MOD_MATCH_MIN_SCORE 60

typedef struct {
	char *name;
	char *file;
	ut64 pmin;
	ut64 pmax;
	ut64 vmin;
	ut64 vmax;
	ut32 csum;
	int perm;
	int order;
	bool used;
} RPrjMap;

typedef struct {
	R2ProjectMod *mod;
	int id;
	int order;
	bool matched;
} RPrjModSlot;

typedef struct {
	int mod_order;
	int map_order;
	int score;
	int distance;
} RPrjModMatch;

static ut64 rprj_range_size(ut64 min, ut64 max) {
	return max >= min? max - min + 1: 0;
}

static ut64 rprj_range_end(ut64 start, ut64 size) {
	if (!size) {
		return start;
	}
	if (UT64_MAX - start < size - 1) {
		return UT64_MAX;
	}
	return start + size - 1;
}

static void rprj_map_free(RPrjMap *map) {
	if (map) {
		free (map->name);
		free (map->file);
		free (map);
	}
}

static ut32 rprj_checksum_update(ut32 csum, const ut8 *buf, int len) {
	int i;
	for (i = 0; i < len; i++) {
		csum = (csum << 1) ^ buf[i] ^ (csum & 1);
	}
	return csum;
}

static ut32 rprj_checksum(RCore *core, ut64 va, ut64 size) {
	if (!core || !core->io || !size) {
		return 0;
	}
	ut32 csum = 0;
	ut8 buf[1024];
	ut64 samples[3] = { va, va, va };
	const int sample_size = (int)R_MIN ((ut64)sizeof (buf), size);
	if (size > (ut64)sample_size) {
		const ut64 end = rprj_range_end (va, size);
		const ut64 last = end - (ut64)sample_size + 1;
		samples[1] = va + (size / 2);
		if (samples[1] > last) {
			samples[1] = last;
		}
		samples[2] = last;
	}
	int i;
	for (i = 0; i < 3; i++) {
		if (i && samples[i] == samples[i - 1]) {
			continue;
		}
		const int n = r_io_read_at (core->io, samples[i], buf, sample_size);
		if (n > 0) {
			csum = rprj_checksum_update (csum ^ (ut32)(samples[i] - va), buf, n);
		}
	}
	return csum;
}

static bool rprj_map_add(RPrjCursor *cur, RList *maps, const char *name, const char *file,
		ut64 pmin, ut64 pmax, ut64 vmin, ut64 vmax, int perm) {
	if (!cur || !maps || vmax < vmin) {
		return false;
	}
	RPrjMap *map = R_NEW0 (RPrjMap);
	map->name = R_STR_ISNOTEMPTY (name)? strdup (name): NULL;
	map->file = R_STR_ISNOTEMPTY (file)? strdup (file): NULL;
	map->pmin = pmin;
	map->pmax = pmax;
	map->vmin = vmin;
	map->vmax = vmax;
	map->perm = perm;
	map->order = r_list_length (maps);
	map->csum = rprj_checksum (cur->core, vmin, rprj_range_size (vmin, vmax));
	r_list_append (maps, map);
	return true;
}

static int rprj_map_cmp(const void *a, const void *b) {
	const RPrjMap *ma = (const RPrjMap *)a;
	const RPrjMap *mb = (const RPrjMap *)b;
	if (ma->vmin < mb->vmin) {
		return -1;
	}
	if (ma->vmin > mb->vmin) {
		return 1;
	}
	return ma->vmax < mb->vmax? -1: ma->vmax > mb->vmax;
}

static void rprj_maps_assign_order(RList *maps) {
	RListIter *iter;
	RPrjMap *map;
	int order = 0;
	r_list_foreach (maps, iter, map) {
		map->order = order++;
	}
}

static bool rprj_maps_from_debug_list(RPrjCursor *cur, RList *maps, RList *src) {
	RListIter *iter;
	RDebugMap *dm;
	r_list_foreach (src, iter, dm) {
		if (!dm || dm->addr_end <= dm->addr) {
			continue;
		}
		const ut64 size = dm->addr_end - dm->addr;
		const ut64 pmax = rprj_range_end (dm->offset, size);
		rprj_map_add (cur, maps, dm->name, dm->file, dm->offset, pmax,
			dm->addr, dm->addr_end - 1, dm->perm);
	}
	return !r_list_empty (maps);
}

static RList *rprj_maps_from_debug(RPrjCursor *cur) {
	RCore *core = cur? cur->core: NULL;
	if (!core || !core->dbg || !r_config_get_b (core->config, "cfg.debug")) {
		return NULL;
	}
	RList *maps = r_list_newf ((RListFree)rprj_map_free);
	if (!maps) {
		return NULL;
	}
	r_debug_map_sync (core->dbg);
	rprj_maps_from_debug_list (cur, maps, core->dbg->maps);
	rprj_maps_from_debug_list (cur, maps, core->dbg->maps_user);
	if (r_list_empty (maps)) {
		r_list_free (maps);
		return NULL;
	}
	r_list_sort (maps, rprj_map_cmp);
	rprj_maps_assign_order (maps);
	return maps;
}

static bool rprj_json_get_ut64(const RJson *json, const char *key, ut64 *out) {
	const RJson *field = r_json_get (json, key);
	if (!field) {
		return false;
	}
	switch (field->type) {
	case R_JSON_STRING:
		*out = r_num_get (NULL, field->str_value);
		return true;
	case R_JSON_INTEGER:
	case R_JSON_BOOLEAN:
		*out = field->num.u_value;
		return true;
	case R_JSON_DOUBLE:
		*out = (ut64)field->num.dbl_value;
		return true;
	default:
		return false;
	}
}

static bool rprj_json_map_bounds(const RJson *item, ut64 *vmin, ut64 *vmax) {
	if (!rprj_json_get_ut64 (item, "addr", vmin)
			&& !rprj_json_get_ut64 (item, "base", vmin)
			&& !rprj_json_get_ut64 (item, "from", vmin)
			&& !rprj_json_get_ut64 (item, "start", vmin)) {
		return false;
	}
	ut64 size = 0;
	if (rprj_json_get_ut64 (item, "size", &size) && size > 0) {
		*vmax = rprj_range_end (*vmin, size);
		return true;
	}
	ut64 end = 0;
	if (!rprj_json_get_ut64 (item, "addr_end", &end)
			&& !rprj_json_get_ut64 (item, "end", &end)
			&& !rprj_json_get_ut64 (item, "to", &end)) {
		return false;
	}
	if (end <= *vmin) {
		return false;
	}
	*vmax = end - 1;
	return true;
}

static const char *rprj_json_map_file(const RJson *item) {
	const char *file = r_json_get_str (item, "file");
	if (R_STR_ISNOTEMPTY (file)) {
		return file;
	}
	const RJson *file_obj = r_json_get (item, "file");
	if (file_obj && file_obj->type == R_JSON_OBJECT) {
		file = r_json_get_str (file_obj, "path");
		if (R_STR_ISNOTEMPTY (file)) {
			return file;
		}
	}
	return r_json_get_str (item, "path");
}

static void rprj_json_map_offset(const RJson *item, ut64 *pmin) {
	if (rprj_json_get_ut64 (item, "offset", pmin)) {
		return;
	}
	const RJson *file_obj = r_json_get (item, "file");
	if (file_obj && file_obj->type == R_JSON_OBJECT) {
		rprj_json_get_ut64 (file_obj, "offset", pmin);
	}
}

static RList *rprj_maps_from_iosystem(RPrjCursor *cur) {
	RCore *core = cur? cur->core: NULL;
	if (!core || !core->io || !core->io->desc) {
		return NULL;
	}
	char *json_text = r_io_system (core->io, "dmj");
	if (R_STR_ISEMPTY (json_text)) {
		free (json_text);
		return NULL;
	}
	RJson *json = r_json_parsedup (json_text);
	free (json_text);
	if (!json || json->type != R_JSON_ARRAY) {
		r_json_free (json);
		return NULL;
	}
	RList *maps = r_list_newf ((RListFree)rprj_map_free);
	if (!maps) {
		r_json_free (json);
		return NULL;
	}
	size_t i;
	for (i = 0; i < json->children.count; i++) {
		const RJson *item = r_json_item (json, i);
		if (!item || item->type != R_JSON_OBJECT) {
			continue;
		}
		ut64 vmin = 0;
		ut64 vmax = 0;
		if (!rprj_json_map_bounds (item, &vmin, &vmax)) {
			continue;
		}
		ut64 pmin = 0;
		rprj_json_map_offset (item, &pmin);
		ut64 pmax = rprj_range_end (pmin, rprj_range_size (vmin, vmax));
		const char *name = r_json_get_str (item, "name");
		const char *file = rprj_json_map_file (item);
		const char *perm = r_json_get_str (item, "perm");
		if (R_STR_ISEMPTY (perm)) {
			perm = r_json_get_str (item, "protection");
		}
		rprj_map_add (cur, maps, name, file, pmin, pmax, vmin, vmax,
			R_STR_ISNOTEMPTY (perm)? r_str_rwx (perm): -1);
	}
	r_json_free (json);
	if (r_list_empty (maps)) {
		r_list_free (maps);
		return NULL;
	}
	r_list_sort (maps, rprj_map_cmp);
	rprj_maps_assign_order (maps);
	return maps;
}

static RList *rprj_maps_from_io(RPrjCursor *cur) {
	RCore *core = cur? cur->core: NULL;
	if (!core || !core->io) {
		return NULL;
	}
	RList *maps = r_list_newf ((RListFree)rprj_map_free);
	if (!maps) {
		return NULL;
	}
	RIDStorage *storage = &core->io->maps;
	ut32 mapid;
	if (!r_id_storage_get_lowest (storage, &mapid)) {
		r_list_free (maps);
		return NULL;
	}
	do {
		RIOMap *m = r_id_storage_get (storage, mapid);
		if (!m) {
			continue;
		}
		const ut64 va = r_io_map_from (m);
		const ut64 va_end = r_io_map_to (m);
		const ut64 pa = m->delta;
		const ut64 pa_size = r_itv_size (m->itv);
		const ut64 pa_end = rprj_range_end (pa, pa_size);
		const char *file = r_io_fd_get_name (core->io, m->fd);
		rprj_map_add (cur, maps, r_str_get (m->name), file, pa, pa_end, va, va_end, m->perm);
	} while (r_id_storage_get_next (storage, &mapid));
	if (r_list_empty (maps)) {
		r_list_free (maps);
		return NULL;
	}
	r_list_sort (maps, rprj_map_cmp);
	rprj_maps_assign_order (maps);
	return maps;
}

static RList *rprj_maps_current(RPrjCursor *cur) {
	RList *maps = rprj_maps_from_debug (cur);
	if (maps) {
		return maps;
	}
	maps = rprj_maps_from_iosystem (cur);
	if (maps) {
		return maps;
	}
	return rprj_maps_from_io (cur);
}

static R2ProjectMod *rprj_find_mod(RPrjCursor *cur, ut64 addr, ut32 *mid) {
	RListIter *iter;
	ut32 id = 0;
	R2ProjectMod *mod;
	r_list_foreach (cur->mods, iter, mod) {
		if (addr >= mod->vmin && addr <= mod->vmax) {
			*mid = id;
			return mod;
		}
		id ++;
	}
	return NULL;
}

static R2ProjectMod *rprj_mod_by_id(RPrjCursor *cur, ut32 id) {
	if (id == UT32_MAX) {
		return NULL;
	}
	return (R2ProjectMod *)r_list_get_n (cur->mods, id);
}

static R2ProjectAddr rprj_addr_to_project(RPrjCursor *cur, ut64 addr) {
	R2ProjectAddr res = {
		.mod = UT32_MAX,
		.delta = addr,
	};
	ut32 mid = UT32_MAX;
	R2ProjectMod *mod = rprj_find_mod (cur, addr, &mid);
	if (mod) {
		res.mod = mid;
		res.delta = addr - mod->vmin;
	}
	return res;
}

static bool rprj_project_addr_to_va(RPrjCursor *cur, R2ProjectAddr *addr, ut64 *va) {
	if (addr->mod == UT32_MAX && addr->delta == UT64_MAX) {
		*va = UT64_MAX;
		return true;
	}
	if (addr->mod == UT32_MAX) {
		*va = addr->delta;
		return true;
	}
	R2ProjectMod *mod = rprj_mod_by_id (cur, addr->mod);
	if (!mod) {
		return false;
	}
	if (mod->vmax < mod->vmin || addr->delta > mod->vmax - mod->vmin) {
		return false;
	}
	*va = mod->vmin + addr->delta;
	return true;
}

static bool rprj_mods_read(RBuffer *b, R2ProjectMod *mod) {
	ut8 buf[sizeof (R2ProjectMod)];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	mod->name = r_read_le32 (buf + r_offsetof (R2ProjectMod, name));
	mod->file = r_read_le32 (buf + r_offsetof (R2ProjectMod, file));
	mod->csum = r_read_le32 (buf + r_offsetof (R2ProjectMod, csum));
	mod->pmin = r_read_le64 (buf + r_offsetof (R2ProjectMod, pmin));
	mod->pmax = r_read_le64 (buf + r_offsetof (R2ProjectMod, pmax));
	mod->vmin = r_read_le64 (buf + r_offsetof (R2ProjectMod, vmin));
	mod->vmax = r_read_le64 (buf + r_offsetof (R2ProjectMod, vmax));
	return true;
}

static void rprj_mods_write_one(RBuffer *b, R2ProjectMod *mod) {
	ut8 buf[sizeof (R2ProjectMod)] = {0};
	r_write_le32 (buf + r_offsetof (R2ProjectMod, name), mod->name);
	r_write_le32 (buf + r_offsetof (R2ProjectMod, file), mod->file);
	r_write_le64 (buf + r_offsetof (R2ProjectMod, pmin), mod->pmin);
	r_write_le64 (buf + r_offsetof (R2ProjectMod, pmax), mod->pmax);
	r_write_le64 (buf + r_offsetof (R2ProjectMod, vmin), mod->vmin);
	r_write_le64 (buf + r_offsetof (R2ProjectMod, vmax), mod->vmax);
	r_write_le32 (buf + r_offsetof (R2ProjectMod, csum), mod->csum);
	r_buf_write (b, buf, sizeof (buf));
}

static void rprj_mods_write(RPrjCursor *cur) {
	RList *maps = rprj_maps_current (cur);
	if (!maps) {
		return;
	}
	RListIter *iter;
	RPrjMap *map;
	r_list_foreach (maps, iter, map) {
		R2ProjectMod mod = {
			.name = rprj_st_append (cur->st, r_str_get (map->name)),
			.file = R_STR_ISNOTEMPTY (map->file)? rprj_st_append (cur->st, map->file): UT32_MAX,
			.pmin = map->pmin,
			.pmax = map->pmax,
			.vmin = map->vmin,
			.vmax = map->vmax,
			.csum = map->csum,
		};
		rprj_mods_write_one (cur->b, &mod);
		r_list_append (cur->mods, r_mem_dup (&mod, sizeof (mod)));
	}
	r_list_free (maps);
}

static int rprj_mod_slot_cmp(const void *a, const void *b) {
	const RPrjModSlot *ma = (const RPrjModSlot *)a;
	const RPrjModSlot *mb = (const RPrjModSlot *)b;
	if (ma->mod->vmin < mb->mod->vmin) {
		return -1;
	}
	if (ma->mod->vmin > mb->mod->vmin) {
		return 1;
	}
	return ma->id - mb->id;
}

static int rprj_match_cmp(const void *a, const void *b) {
	const RPrjModMatch *ma = (const RPrjModMatch *)a;
	const RPrjModMatch *mb = (const RPrjModMatch *)b;
	if (ma->score != mb->score) {
		return mb->score - ma->score;
	}
	if (ma->distance != mb->distance) {
		return ma->distance - mb->distance;
	}
	if (ma->mod_order != mb->mod_order) {
		return ma->mod_order - mb->mod_order;
	}
	return ma->map_order - mb->map_order;
}

static int rprj_mod_size_score(ut64 saved_size, ut64 map_size) {
	if (!saved_size || !map_size) {
		return 0;
	}
	if (saved_size == map_size) {
		return 30;
	}
	const ut64 min = R_MIN (saved_size, map_size);
	const ut64 max = R_MAX (saved_size, map_size);
	return min >= max - (max / 10)? 10: 0;
}

static int rprj_mod_name_score(const char *a, const char *b, int exact, int base) {
	if (R_STR_ISEMPTY (a) || R_STR_ISEMPTY (b)) {
		return 0;
	}
	if (!strcmp (a, b)) {
		return exact;
	}
	return !strcmp (r_file_basename (a), r_file_basename (b))? base: 0;
}

static int rprj_mod_neighbor_score(RPrjCursor *cur, RPrjModSlot *mods, int nmods, RPrjMap **maps, int nmaps, int mi, int ci, int dir) {
	const int smi = mi + dir;
	const int cmi = ci + dir;
	if (smi < 0 || smi >= nmods || cmi < 0 || cmi >= nmaps) {
		return smi == cmi? 5: 0;
	}
	R2ProjectMod *mod = mods[smi].mod;
	RPrjMap *map = maps[cmi];
	int score = 0;
	if (mod->csum && mod->csum == map->csum) {
		score += 35;
	}
	score += rprj_mod_size_score (rprj_range_size (mod->vmin, mod->vmax),
		rprj_range_size (map->vmin, map->vmax)) / 2;
	score += rprj_mod_name_score (rprj_st_get (cur->st, mod->file), map->file, 15, 5);
	score += rprj_mod_name_score (rprj_st_get (cur->st, mod->name), map->name, 10, 0);
	return score;
}

static int rprj_mod_match_score(RPrjCursor *cur, RPrjModSlot *mods, int nmods, RPrjMap **maps, int nmaps, int mi, int ci) {
	R2ProjectMod *mod = mods[mi].mod;
	RPrjMap *map = maps[ci];
	int score = 0;
	if (mod->csum && mod->csum == map->csum) {
		score += 100;
	}
	score += rprj_mod_name_score (rprj_st_get (cur->st, mod->file), map->file, 40, 15);
	score += rprj_mod_name_score (rprj_st_get (cur->st, mod->name), map->name, 30, 0);
	score += rprj_mod_size_score (rprj_range_size (mod->vmin, mod->vmax),
		rprj_range_size (map->vmin, map->vmax));
	if (mod->pmin == map->pmin) {
		score += 20;
	}
	if (map->perm >= 0) {
		score += 5;
	}
	score += rprj_mod_neighbor_score (cur, mods, nmods, maps, nmaps, mi, ci, -1);
	score += rprj_mod_neighbor_score (cur, mods, nmods, maps, nmaps, mi, ci, 1);
	return score;
}

static RPrjModSlot *rprj_mod_slots(RPrjCursor *cur, int *count) {
	const int nmods = r_list_length (cur->mods);
	*count = nmods;
	if (nmods < 1) {
		return NULL;
	}
	RPrjModSlot *mods = R_NEWS0 (RPrjModSlot, nmods);
	if (!mods) {
		return NULL;
	}
	RListIter *iter;
	R2ProjectMod *mod;
	int i = 0;
	r_list_foreach (cur->mods, iter, mod) {
		mods[i].mod = mod;
		mods[i].id = i;
		i++;
	}
	qsort (mods, nmods, sizeof (*mods), rprj_mod_slot_cmp);
	for (i = 0; i < nmods; i++) {
		mods[i].order = i;
	}
	return mods;
}

static RPrjMap **rprj_map_array(RList *maps, int *count) {
	const int nmaps = r_list_length (maps);
	*count = nmaps;
	if (nmaps < 1) {
		return NULL;
	}
	RPrjMap **array = R_NEWS0 (RPrjMap *, nmaps);
	if (!array) {
		return NULL;
	}
	RListIter *iter;
	RPrjMap *map;
	int i = 0;
	r_list_foreach (maps, iter, map) {
		array[i++] = map;
	}
	return array;
}

static RPrjModMatch *rprj_mod_matches(RPrjCursor *cur, RPrjModSlot *mods, int nmods, RPrjMap **maps, int nmaps, int *count) {
	*count = 0;
	if (nmods < 1 || nmaps < 1) {
		return NULL;
	}
	size_t total = 0;
	if (r_mul_overflow ((size_t)nmods, (size_t)nmaps, &total) || total > ST32_MAX) {
		return NULL;
	}
	RPrjModMatch *matches = R_NEWS0 (RPrjModMatch, total);
	if (!matches) {
		return NULL;
	}
	int i;
	for (i = 0; i < nmods; i++) {
		int j;
		for (j = 0; j < nmaps; j++) {
			const int score = rprj_mod_match_score (cur, mods, nmods, maps, nmaps, i, j);
			if (score < RPRJ_MOD_MATCH_MIN_SCORE) {
				continue;
			}
			RPrjModMatch *match = matches + *count;
			match->mod_order = i;
			match->map_order = j;
			match->score = score;
			match->distance = R_ABS (i - j);
			(*count)++;
		}
	}
	qsort (matches, *count, sizeof (*matches), rprj_match_cmp);
	return matches;
}

static void rprj_mod_apply_map(R2ProjectMod *mod, RPrjMap *map) {
	mod->pmin = map->pmin;
	mod->pmax = map->pmax;
	mod->vmin = map->vmin;
	mod->vmax = map->vmax;
}

static void rprj_mods_rebase(RPrjCursor *cur) {
	RList *maps = rprj_maps_current (cur);
	if (!maps) {
		return;
	}
	int nmods = 0;
	RPrjModSlot *mods = rprj_mod_slots (cur, &nmods);
	int nmaps = 0;
	RPrjMap **map_array = rprj_map_array (maps, &nmaps);
	if (!mods || !map_array) {
		free (mods);
		free (map_array);
		r_list_free (maps);
		return;
	}
	int nmatches = 0;
	RPrjModMatch *matches = rprj_mod_matches (cur, mods, nmods, map_array, nmaps, &nmatches);
	int i;
	for (i = 0; i < nmatches; i++) {
		RPrjModMatch *match = matches + i;
		RPrjModSlot *mod = mods + match->mod_order;
		RPrjMap *map = map_array[match->map_order];
		if (mod->matched || map->used) {
			continue;
		}
		mod->matched = true;
		map->used = true;
		rprj_mod_apply_map (mod->mod, map);
	}
	free (matches);
	free (mods);
	free (map_array);
	r_list_free (maps);
}
