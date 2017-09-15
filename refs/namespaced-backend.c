
#include "../cache.h"
#include "../config.h"
#include "../refs.h"
#include "refs-internal.h"
#include "../repository.h"
#include "../iterator.h"

/* Namespace backend intended to stack on top of existing ref store */

extern struct ref_storage_be refs_be_namespaced;

struct namespaced_ref_store {
	struct ref_store base;
	struct ref_store *lower;
	char *prefix;
};

static struct namespaced_ref_store *namespaced_downcast(
		struct ref_store *ref_store, const char *caller)
{
	struct namespaced_ref_store *refs;

	if (ref_store->be != &refs_be_namespaced)
		die("BUG: ref_store is type \"%s\" not \"namespaced\" in %s",
		    ref_store->be->name, caller);

	refs = (struct namespaced_ref_store *)ref_store;

	return refs;
}

int namespaced_ref_store_create(const char *gitdir,
                                struct ref_store **lower)
{
	struct namespaced_ref_store *refs = NULL;
	struct ref_store *ref_store;
	char *config = NULL, *prefix = NULL;
	int ret;
	struct config_options opts;
	struct config_set cs;
	struct strbuf sb = STRBUF_INIT;

	ret = get_common_dir(&sb, gitdir);
	if (ret < 0) {
		goto cleanup;
	}

	opts.respect_includes = 1;
	opts.commondir =  sb.buf;
	opts.git_dir = gitdir;
	memset(&cs, 0, sizeof(cs));
	git_configset_init(&cs);

	ret = git_configset_add_standard(&cs, &opts);
	if (ret < 0) {
		goto cleanup;
	}

#if 0
	ret = git_configset_get_string(&cs, "core.namespace", &config);
	if (ret != 0) {
		goto cleanup;
	}

	prefix = expand_namespace(config);
#else
	prefix = expand_namespace("foo");
#endif
	assert(prefix);

	refs = xcalloc(1, sizeof(*refs));
	ref_store = &refs->base;
	refs->prefix = prefix;
	prefix = NULL;

	base_ref_store_init(ref_store, &refs_be_namespaced);

	refs->lower = *lower;
	refs->lower->parent = ref_store;
	*lower = ref_store;
	refs = NULL;

cleanup:
	free(refs);
	git_configset_clear(&cs);
	free(prefix);
	free(config);
	strbuf_release(&sb);

	return ret;
}

static void prepend_prefix(struct ref_transaction *transaction,
                           const char *prefix)
{
	struct strbuf sb = STRBUF_INIT;
	size_t prefixlen;
	int i;

	strbuf_addstr(&sb, prefix);
	prefixlen = sb.len;

	for (i = 0; i < transaction->nr; i++) {
		struct ref_update *oldupdate, *newupdate;

		oldupdate = transaction->updates[i];

		if (ref_type(oldupdate->refname) == REF_TYPE_PSEUDOREF)
			continue;

		strbuf_addstr(&sb, oldupdate->refname);
		FLEX_ALLOC_STR(newupdate, refname, sb.buf);
		memcpy(newupdate, oldupdate,
		       ((char*)&newupdate->refname) - (char*)newupdate);
		transaction->updates[i] = newupdate;
		free(oldupdate);
		strbuf_setlen(&sb, prefixlen);
	}
	strbuf_release(&sb);
}

static char *add_namespace(
		struct strbuf *sb, struct namespaced_ref_store *refs,
		const char *refname)
{
	if (ref_type(refname) != REF_TYPE_PSEUDOREF)
		strbuf_addstr(sb, refs->prefix);
	if (refname)
		strbuf_addstr(sb, refname);
	return sb->buf;
}

static int namespaced_init_db(struct ref_store *ref_store, struct strbuf *err)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "init_db");
	int ret;
	
	ret = refs->lower->be->init_db(refs->lower, err);
	if (ret != 0)
		return ret;

	/* TODO: Needs to add an un-namespaced HEAD symlink,
	         is_git_directory assumes it's not a repo without it.
	         Can't change is_git_directory to resolve ref via backend
	         since it would need to make the backend and can't free it. */
	ret = refs->lower->be->create_symref(
			refs->lower, "HEAD", "refs/heads/master", NULL);
	if (ret != 0)
		return ret;

#if 0
	ret = refs_create_symref(ref_store, "HEAD", "refs/heads/master", NULL);
#endif

	return ret;
}

static int namespaced_transaction_prepare(struct ref_store *ref_store,
                                          struct ref_transaction *transaction,
                                          struct strbuf *err)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "transaction_prepare");
	int ret;

	prepend_prefix(transaction, refs->prefix);

	ret = refs->lower->be->transaction_prepare(refs->lower, transaction,
	                                           err);

	/* TODO: Fix missing ref update for namespaced HEAD */

	return ret;
}
static int namespaced_transaction_finish(struct ref_store *ref_store,
                                         struct ref_transaction *transaction,
                                         struct strbuf *err)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "transaction_finish");
	return refs->lower->be->transaction_finish(refs->lower, transaction,
	                                           err);
}
static int namespaced_transaction_abort(struct ref_store *ref_store,
                                        struct ref_transaction *transaction,
                                        struct strbuf *err)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "transaction_abort");
	return refs->lower->be->transaction_abort(refs->lower, transaction,
	                                          err);
}
static int namespaced_initial_transaction_commit(
		struct ref_store *ref_store,
		struct ref_transaction *transaction, struct strbuf *err)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "initial_transaction_commit");
	int ret;

	prepend_prefix(transaction, refs->prefix);

	ret = refs->lower->be->initial_transaction_commit(
			refs->lower, transaction, err);

	/* TODO: Fix missing ref update for namespaced HEAD */

	return ret;
}
static int namespaced_pack_refs(struct ref_store *ref_store, unsigned int flags)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "pack_refs");
	return refs->lower->be->pack_refs(refs->lower, flags);
}
static int namespaced_create_symref(struct ref_store *ref_store,
                                    const char *refname,
                                    const char *target,
                                    const char *logmsg)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "create_symref");
	struct strbuf rsb = STRBUF_INIT, tsb = STRBUF_INIT;
	int ret;

	ret = refs->lower->be->create_symref(
			refs->lower, add_namespace(&rsb, refs, refname),
			add_namespace(&tsb, refs, target), logmsg);
	
	strbuf_release(&rsb);
	strbuf_release(&tsb);

	return ret;
}
static int namespaced_delete_refs(struct ref_store *ref_store, const char *msg,
                                  struct string_list *refnames,
                                  unsigned int flags)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "delete_refs");
	struct string_list prefixed = STRING_LIST_INIT_DUP;
	struct string_list_item *it;
	int ret;

	for_each_string_list_item(it, refnames) {
		struct strbuf sb = STRBUF_INIT;

		/* TODO: Pseudorefs aren't namespaced,
		         so add_namespace may do nothing but strdup */
		add_namespace(&sb, refs, it->string);
		string_list_append_nodup(&prefixed, strbuf_detach(&sb, NULL));

		strbuf_release(&sb);
	}
	
	ret = refs->lower->be->delete_refs(refs->lower, msg, &prefixed, flags);

	string_list_clear(&prefixed, 1);

	return ret;
}
static int namespaced_rename_ref(struct ref_store *ref_store,
                                 const char *oldref, const char *newref,
                                 const char *logmsg)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "rename_ref");
	struct strbuf osb = STRBUF_INIT, nsb = STRBUF_INIT;
	int ret;

	ret = refs->lower->be->rename_ref(
			refs->lower, add_namespace(&osb, refs, oldref),
			add_namespace(&nsb, refs, newref), logmsg);
	
	strbuf_release(&osb);
	strbuf_release(&nsb);

	return ret;
}

extern struct ref_iterator_vtable namespaced_ref_iterator_vtable;

struct namespaced_ref_iterator {
	struct ref_iterator base;
	struct ref_iterator *lower;
	const char *prefix;
};

static struct namespaced_ref_iterator *nsiter_downcast(
		struct ref_iterator *ref_iterator, const char *caller)
{
	struct namespaced_ref_iterator *iter;

	if (ref_iterator->vtable != &namespaced_ref_iterator_vtable)
		die("BUG: ref_iterator is not \"namespaced\" in %s",
		    caller);

	iter = (struct namespaced_ref_iterator *)ref_iterator;

	return iter;
}
static int namespaced_ref_iterator_advance(struct ref_iterator *ref_iterator)
{
	struct namespaced_ref_iterator *iter = nsiter_downcast(ref_iterator,
	                                                       "advance");
	int ret;

	while ((ret = iter->lower->vtable->advance(iter->lower)) == ITER_OK) {
		/* Pseudorefs are not namespaced */
		if (ref_type(iter->lower->refname) == REF_TYPE_PSEUDOREF) {
			iter->base.oid = iter->lower->oid;
			iter->base.flags = iter->lower->flags;
			iter->base.refname = iter->lower->refname;
			return ITER_OK;
		}
		    
		/* Standard ref iterator is pre-filtered,
		   but the same function is used for reflogs
		   which has no pre-filtering. */
		if (!starts_with(iter->lower->refname, iter->prefix))
			continue;

		iter->base.oid = iter->lower->oid;
		iter->base.flags = iter->lower->flags;
		assert(skip_prefix(iter->lower->refname, iter->prefix,
		                   &iter->base.refname));

		/* Pseudorefs should not be returned via iteration.
		   files backend usually handles this by iterating from refs/,
		   but as namespaced head is in refs we must skip it. */
		/* TODO: Would be better to call is_pseudoref_syntax */
		/* TODO: Perhaps prefix for iter should include the refs/ at the end! */
		if (!starts_with(iter->base.refname, "refs/"))
			continue;

		return ITER_OK;
	}

	iter->lower = NULL;
	if (ref_iterator_abort(ref_iterator) != ITER_DONE)
		ret = ITER_ERROR;

	return ret;
}
static int namespaced_ref_iterator_peel(struct ref_iterator *ref_iterator,
                                        struct object_id *peeled)
{
	struct namespaced_ref_iterator *iter = nsiter_downcast(ref_iterator,
	                                                       "peel");
	return iter->lower->vtable->peel(iter->lower, peeled);
}
static int namespaced_ref_iterator_abort(struct ref_iterator *ref_iterator)
{
	struct namespaced_ref_iterator *iter = nsiter_downcast(ref_iterator,
	                                                       "abort");
	int ret = ITER_DONE;
	if (iter->lower)
		ret = iter->lower->vtable->abort(iter->lower);

	base_ref_iterator_free(ref_iterator);
	return ret;
}
struct ref_iterator_vtable namespaced_ref_iterator_vtable = {
	namespaced_ref_iterator_advance,
	namespaced_ref_iterator_peel,
	namespaced_ref_iterator_abort,
};

static struct ref_iterator *make_namespaced_iterator(
		struct ref_iterator *lower,
		const char *prefix)
{
	struct ref_iterator *ref_iterator;
	struct namespaced_ref_iterator *iter;

	iter = xcalloc(1, sizeof(*iter));
	ref_iterator = &iter->base;
	base_ref_iterator_init(ref_iterator, &namespaced_ref_iterator_vtable,
	                       lower->ordered);

	iter->lower = lower;
	iter->prefix = prefix;

	return ref_iterator;
}
static struct ref_iterator *namespaced_iterator_begin(
		struct ref_store *ref_store, const char *prefix,
		unsigned int flags)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "iterator_begin");
	struct ref_iterator *lower, *ret;
	struct strbuf sb = STRBUF_INIT;

	/* TODO: Pseudorefs aren't namespaced, but appear in the namespace.
	         Pseudorefs can only appear if there's no prefix or it's ""
	         at which point stripping the namespace off and filtering works,
	         so if we've got a prefix we prepend the namespace,
	         and if we don't we filter post-hoc.
	*/
	if (prefix && *prefix)
		prefix = add_namespace(&sb, refs, prefix);

	lower = refs->lower->be->iterator_begin(
			refs->lower, prefix, flags);

	ret = make_namespaced_iterator(lower, refs->prefix);

	strbuf_release(&sb);

	return ret;
}
static int namespaced_read_raw_ref(struct ref_store *ref_store,
                                   const char *refname, unsigned char *sha1,
                                   struct strbuf *referent, unsigned int *type)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "read_raw_ref");
	struct strbuf sb = STRBUF_INIT;
	int ret;

	ret = refs->lower->be->read_raw_ref(
			refs->lower, add_namespace(&sb, refs, refname), sha1,
			referent, type);

	if (ret == 0 && (*type & REF_ISSYMREF) == REF_ISSYMREF) {
		const char *stripped_ref;
		if (skip_prefix(referent->buf, refs->prefix, &stripped_ref)) {
			struct strbuf stripped = STRBUF_INIT;
			strbuf_addstr(&stripped, stripped_ref);
			strbuf_swap(referent, &stripped);
			strbuf_release(&stripped);
		}
	}

	strbuf_release(&sb);

	return ret;
}
static struct ref_iterator *namespaced_reflog_iterator_begin(
		struct ref_store *ref_store)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "reflog_iterator_begin");
	struct ref_iterator *lower;

	lower = refs->lower->be->reflog_iterator_begin(
			refs->lower);

	return make_namespaced_iterator(lower, refs->prefix);
}

static int namespaced_for_each_reflog_ent(struct ref_store *ref_store,
                                          const char *refname,
                                          each_reflog_ent_fn fn,
                                          void *cb_data)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "for_each_reflog_ent");
	struct strbuf sb = STRBUF_INIT;
	int ret;

	ret = refs->lower->be->for_each_reflog_ent(
			refs->lower, add_namespace(&sb, refs, refname),
			fn, cb_data);

	strbuf_release(&sb);

	return ret;
}
static int namespaced_for_each_reflog_ent_reverse(struct ref_store *ref_store,
                                                  const char *refname,
                                                  each_reflog_ent_fn fn,
                                                  void *cb_data)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "for_each_reflog_ent_reverse");
	struct strbuf sb = STRBUF_INIT;
	int ret;

	ret = refs->lower->be->for_each_reflog_ent_reverse(
			refs->lower, add_namespace(&sb, refs, refname),
			fn, cb_data);

	strbuf_release(&sb);

	return ret;
}
static int namespaced_reflog_exists(struct ref_store *ref_store,
                                    const char *refname)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "reflog_exists");
	struct strbuf sb = STRBUF_INIT;
	int ret;

	ret = refs->lower->be->reflog_exists(
			refs->lower, add_namespace(&sb, refs, refname));

	strbuf_release(&sb);

	return ret;
}
static int namespaced_create_reflog(struct ref_store *ref_store,
                                    const char *refname, int force_create,
                                    struct strbuf *err)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "create_reflog");
	struct strbuf sb = STRBUF_INIT;
	int ret;

	ret = refs->lower->be->create_reflog(
			refs->lower, add_namespace(&sb, refs, refname),
			force_create, err);

	strbuf_release(&sb);

	return ret;
}
static int namespaced_delete_reflog(struct ref_store *ref_store,
                                    const char *refname)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "delete_reflog");
	struct strbuf sb = STRBUF_INIT;
	int ret;

	ret = refs->lower->be->delete_reflog(
			refs->lower, add_namespace(&sb, refs, refname));

	strbuf_release(&sb);

	return ret;
}

struct wrap_expiry_cb_data {
	char *prefix;
	reflog_expiry_prepare_fn *prepare_fn;
	reflog_expiry_should_prune_fn *should_prune_fn;
	reflog_expiry_cleanup_fn *cleanup_fn;
	void *cb_data;
};
void wrap_expiry_prepare(const char *refname, const struct object_id *oid,
                         void *cb_data)
{
	struct wrap_expiry_cb_data *cbd = cb_data;
	skip_prefix(refname, cbd->prefix, &refname);
	cbd->prepare_fn(refname, oid, cbd->cb_data);
}
int wrap_expiry_should_prune(struct object_id *ooid, struct object_id *noid,
                             const char *email, timestamp_t timestamp, int tz,
                             const char *message, void *cb_data)
{
	struct wrap_expiry_cb_data *cbd = cb_data;
	return cbd->should_prune_fn(ooid, noid, email, timestamp, tz,
	                            message, cbd->cb_data);
}
void wrap_expiry_cleanup(void *cb_data)
{
	struct wrap_expiry_cb_data *cbd = cb_data;
	cbd->cleanup_fn(cbd->cb_data);
}
static int namespaced_reflog_expire(
		struct ref_store *ref_store, const char *refname,
		const unsigned char *sha1, unsigned int flags,
		reflog_expiry_prepare_fn prepare_fn,
		reflog_expiry_should_prune_fn should_prune_fn,
		reflog_expiry_cleanup_fn cleanup_fn,
		void *policy_cb_data)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "reflog_expire");
	struct strbuf sb = STRBUF_INIT;
	struct wrap_expiry_cb_data cbd = {
		refs->prefix,
		prepare_fn,
		should_prune_fn,
		cleanup_fn,
		policy_cb_data,
	};
	int ret;

	ret = refs->lower->be->reflog_expire(
			refs->lower, add_namespace(&sb, refs, refname), sha1,
			flags, wrap_expiry_prepare, wrap_expiry_should_prune,
			wrap_expiry_cleanup, &cbd);

	strbuf_release(&sb);

	return ret;
}
static const char *namespaced_render_ref(struct ref_store *ref_store,
                                         const char *refname,
                                         struct strbuf *result)
{
	struct namespaced_ref_store *refs = namespaced_downcast(
			ref_store, "render_ref");
	
	if (skip_prefix(refname, refs->prefix, &refname) == 0)
		return NULL;
	
	return render_ref(ref_store->parent, refname, result)
}

struct ref_storage_be refs_be_namespaced = {
	NULL,
	"namespaced",
	NULL, /* Initialised by namespaced_ref_store_create with different API */
	namespaced_init_db,
	namespaced_transaction_prepare,
	namespaced_transaction_finish,
	namespaced_transaction_abort,
	namespaced_initial_transaction_commit,
	namespaced_pack_refs,
	namespaced_create_symref,
	namespaced_delete_refs,
	namespaced_rename_ref,
	namespaced_iterator_begin,
	namespaced_read_raw_ref,
	namespaced_reflog_iterator_begin,
	namespaced_for_each_reflog_ent,
	namespaced_for_each_reflog_ent_reverse,
	namespaced_reflog_exists,
	namespaced_create_reflog,
	namespaced_delete_reflog,
	namespaced_reflog_expire,
	namespaced_render_ref,
};


