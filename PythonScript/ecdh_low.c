#include "ecdh_low.h"

/* file: EC_KEY_new_by_curve_name : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_key.c */
EC_KEY *EC_KEY_new_by_curve_name(int nid)
	{
	EC_KEY *ret = EC_KEY_new();
	if (ret == NULL)
		return NULL;
	ret->group = EC_GROUP_new_by_curve_name(nid);
	if (ret->group == NULL)
		{
		EC_KEY_free(ret);
		return NULL;
		}
	return ret;
	}
/* file: EC_KEY_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_key.c */
EC_KEY *EC_KEY_new(void)
	{
	EC_KEY *ret;

	ret=(EC_KEY *)OPENSSL_malloc(sizeof(EC_KEY));
	if (ret == NULL)
		{
		ECerr(EC_F_EC_KEY_NEW, ERR_R_MALLOC_FAILURE);
		return(NULL);
		}

	ret->version = 1;	
	ret->flags = 0;
	ret->group   = NULL;
	ret->pub_key = NULL;
	ret->priv_key= NULL;
	ret->enc_flag= 0; 
	ret->conv_form = POINT_CONVERSION_UNCOMPRESSED;
	ret->references= 1;
	ret->method_data = NULL;
	return(ret);
	}
/* file: CRYPTO_malloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
void *CRYPTO_malloc(int num, const char *file, int line)
	{
	void *ret = NULL;

	if (num <= 0) return NULL;

	allow_customize = 0;
	if (malloc_debug_func != NULL)
		{
		allow_customize_debug = 0;
		malloc_debug_func(NULL, num, file, line, 0);
		}
	ret = malloc_ex_func(num,file,line);
#ifdef LEVITTE_DEBUG_MEM
	fprintf(stderr, "LEVITTE_DEBUG_MEM:         > 0x%p (%d)\n", ret, num);
#endif
	if (malloc_debug_func != NULL)
		malloc_debug_func(ret, num, file, line, 1);

#ifndef OPENSSL_CPUID_OBJ
        /* Create a dependency on the value of 'cleanse_ctr' so our memory
         * sanitisation function can't be optimised out. NB: We only do
         * this for >2Kb so the overhead doesn't bother us. */
        if(ret && (num > 2048))
	{	extern unsigned char cleanse_ctr;
                ((unsigned char *)ret)[0] = cleanse_ctr;
	}
#endif

	return ret;
	}
/* file: CRYPTO_dbg_malloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem_dbg.c */
void CRYPTO_dbg_malloc(void *addr, int num, const char *file, int line,
	int before_p)
	{
	MEM *m,*mm;
	APP_INFO tmp,*amim;

	switch(before_p & 127)
		{
	case 0:
		break;
	case 1:
		if (addr == NULL)
			break;

		if (is_MemCheck_on())
			{
			MemCheck_off(); /* make sure we hold MALLOC2 lock */
			if ((m=(MEM *)OPENSSL_malloc(sizeof(MEM))) == NULL)
				{
				OPENSSL_free(addr);
				MemCheck_on(); /* release MALLOC2 lock
				                * if num_disabled drops to 0 */
				return;
				}
			if (mh == NULL)
				{
				if ((mh=lh_MEM_new()) == NULL)
					{
					OPENSSL_free(addr);
					OPENSSL_free(m);
					addr=NULL;
					goto err;
					}
				}

			m->addr=addr;
			m->file=file;
			m->line=line;
			m->num=num;
			if (options & V_CRYPTO_MDEBUG_THREAD)
				CRYPTO_THREADID_current(&m->threadid);
			else
				memset(&m->threadid, 0, sizeof(m->threadid));

			if (order == break_order_num)
				{
				/* BREAK HERE */
				m->order=order;
				}
			m->order=order++;
#ifdef LEVITTE_DEBUG_MEM
			fprintf(stderr, "LEVITTE_DEBUG_MEM: [%5ld] %c 0x%p (%d)\n",
				m->order,
				(before_p & 128) ? '*' : '+',
				m->addr, m->num);
#endif
			if (options & V_CRYPTO_MDEBUG_TIME)
				m->time=time(NULL);
			else
				m->time=0;

			CRYPTO_THREADID_current(&tmp.threadid);
			m->app_info=NULL;
			if (amih != NULL
			    && (amim=lh_APP_INFO_retrieve(amih,&tmp)) != NULL)
				{
				m->app_info = amim;
				amim->references++;
				}

			if ((mm=lh_MEM_insert(mh, m)) != NULL)
				{
				/* Not good, but don't sweat it */
				if (mm->app_info != NULL)
					{
					mm->app_info->references--;
					}
				OPENSSL_free(mm);
				}
		err:
			MemCheck_on(); /* release MALLOC2 lock
			                * if num_disabled drops to 0 */
			}
		break;
		}
	return;
	}
/* file: CRYPTO_is_mem_check_on : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem_dbg.c */
int CRYPTO_is_mem_check_on(void)
	{
	int ret = 0;

	if (mh_mode & CRYPTO_MEM_CHECK_ON)
		{
		CRYPTO_THREADID cur;
		CRYPTO_THREADID_current(&cur);
		CRYPTO_r_lock(CRYPTO_LOCK_MALLOC);

		ret = (mh_mode & CRYPTO_MEM_CHECK_ENABLE)
		        || CRYPTO_THREADID_cmp(&disabling_threadid, &cur);

		CRYPTO_r_unlock(CRYPTO_LOCK_MALLOC);
		}
	return(ret);
	}	
/* file: CRYPTO_THREADID_current : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
void CRYPTO_THREADID_current(CRYPTO_THREADID *id)
	{
	if (threadid_callback)
		{
		threadid_callback(id);
		return;
		}
#ifndef OPENSSL_NO_DEPRECATED
	/* If the deprecated callback was set, fall back to that */
	if (id_callback)
		{
		CRYPTO_THREADID_set_numeric(id, id_callback());
		return;
		}
#endif
	/* Else pick a backup */
#ifdef OPENSSL_SYS_WIN16
	CRYPTO_THREADID_set_numeric(id, (unsigned long)GetCurrentTask());
#elif defined(OPENSSL_SYS_WIN32)
	CRYPTO_THREADID_set_numeric(id, (unsigned long)GetCurrentThreadId());
#elif defined(OPENSSL_SYS_BEOS)
	CRYPTO_THREADID_set_numeric(id, (unsigned long)find_thread(NULL));
#else
	/* For everything else, default to using the address of 'errno' */
	CRYPTO_THREADID_set_pointer(id, (void*)&errno);
#endif
	}
/* file: CRYPTO_THREADID_set_numeric : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id, unsigned long val)
	{
	memset(id, 0, sizeof(*id));
	id->val = val;
	}
/* file: CRYPTO_THREADID_set_pointer : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
void CRYPTO_THREADID_set_pointer(CRYPTO_THREADID *id, void *ptr)
	{
	unsigned char *dest = (void *)&id->val;
	unsigned int accum = 0;
	unsigned char dnum = sizeof(id->val);

	memset(id, 0, sizeof(*id));
	id->ptr = ptr;
	if (sizeof(id->val) >= sizeof(id->ptr))
		{
		/* 'ptr' can be embedded in 'val' without loss of uniqueness */
		id->val = (unsigned long)id->ptr;
		return;
		}
	/* hash ptr ==> val. Each byte of 'val' gets the mod-256 total of a
	 * linear function over the bytes in 'ptr', the co-efficients of which
	 * are a sequence of low-primes (hash_coeffs is an 8-element cycle) -
	 * the starting prime for the sequence varies for each byte of 'val'
	 * (unique polynomials unless pointers are >64-bit). For added spice,
	 * the totals accumulate rather than restarting from zero, and the index
	 * of the 'val' byte is added each time (position dependence). If I was
	 * a black-belt, I'd scan big-endian pointers in reverse to give
	 * low-order bits more play, but this isn't crypto and I'd prefer nobody
	 * mistake it as such. Plus I'm lazy. */
	while (dnum--)
		{
		const unsigned char *src = (void *)&id->ptr;
		unsigned char snum = sizeof(id->ptr);
		while (snum--)
			accum += *(src++) * hash_coeffs[(snum + dnum) & 7];
		accum += dnum;
		*(dest++) = accum & 255;
		}
	}
/* file: CRYPTO_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
void CRYPTO_lock(int mode, int type, const char *file, int line)
	{
#ifdef LOCK_DEBUG
		{
		CRYPTO_THREADID id;
		char *rw_text,*operation_text;

		if (mode & CRYPTO_LOCK)
			operation_text="lock  ";
		else if (mode & CRYPTO_UNLOCK)
			operation_text="unlock";
		else
			operation_text="ERROR ";

		if (mode & CRYPTO_READ)
			rw_text="r";
		else if (mode & CRYPTO_WRITE)
			rw_text="w";
		else
			rw_text="ERROR";

		CRYPTO_THREADID_current(&id);
		fprintf(stderr,"lock:%08lx:(%s)%s %-18s %s:%d\n",
			CRYPTO_THREADID_hash(&id), rw_text, operation_text,
			CRYPTO_get_lock_name(type), file, line);
		}
#endif
	if (type < 0)
		{
		if (dynlock_lock_callback != NULL)
			{
			struct CRYPTO_dynlock_value *pointer
				= CRYPTO_get_dynlock_value(type);

			OPENSSL_assert(pointer != NULL);

			dynlock_lock_callback(mode, pointer, file, line);

			CRYPTO_destroy_dynlockid(type);
			}
		}
	else
		if (locking_callback != NULL)
			locking_callback(mode,type,file,line);
	}
/* file: CRYPTO_THREADID_hash : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
unsigned long CRYPTO_THREADID_hash(const CRYPTO_THREADID *id)
	{
	return id->val;
	}
/* file: CRYPTO_get_lock_name : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
const char *CRYPTO_get_lock_name(int type)
	{
	if (type < 0)
		return("dynamic");
	else if (type < CRYPTO_NUM_LOCKS)
		return(lock_names[type]);
	else if (type-CRYPTO_NUM_LOCKS > sk_OPENSSL_STRING_num(app_locks))
		return("ERROR");
	else
		return(sk_OPENSSL_STRING_value(app_locks,type-CRYPTO_NUM_LOCKS));
	}
/* file: sk_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.c */
int sk_num(const _STACK *st)
{
	if(st == NULL) return -1;
	return st->num;
}
/* file: STACK_OF : /Volumes/work/Phd/ECDH/kv_openssl/appscms.c */
#ifndef OPENSSL_NO_CMS
static STACK_OF(GENERAL_NAMES) *make_names_stack(STACK_OF(OPENSSL_STRING) *ns)
	{
	int i;
	STACK_OF(GENERAL_NAMES) *ret;
	GENERAL_NAMES *gens = NULL;
	GENERAL_NAME *gen = NULL;
	ret = sk_GENERAL_NAMES_new_null();
	if (!ret)
		goto err;
	for (i = 0; i < sk_OPENSSL_STRING_num(ns); i++)
		{
		char *str = sk_OPENSSL_STRING_value(ns, i);
		gen = a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_EMAIL, str, 0);
		if (!gen)
			goto err;
		gens = GENERAL_NAMES_new();
		if (!gens)
			goto err;
		if (!sk_GENERAL_NAME_push(gens, gen))
			goto err;
		gen = NULL;
		if (!sk_GENERAL_NAMES_push(ret, gens))
			goto err;
		gens = NULL;
		}

	return ret;

	err:
	if (ret)
		sk_GENERAL_NAMES_pop_free(ret, GENERAL_NAMES_free);
	if (gens)
		GENERAL_NAMES_free(gens);
	if (gen)
		GENERAL_NAME_free(gen);
	return NULL;
	}
#endif
/* file: sk_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.c */
void *sk_value(const _STACK *st, int i)
{
	if(!st || (i < 0) || (i >= st->num)) return NULL;
	return st->data[i];
}
/* file: a2i_GENERAL_NAME : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_alt.c */
GENERAL_NAME *a2i_GENERAL_NAME(GENERAL_NAME *out,
			       const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
			       int gen_type, char *value, int is_nc)
	{
	char is_string = 0;
	GENERAL_NAME *gen = NULL;

	if(!value)
		{
		X509V3err(X509V3_F_A2I_GENERAL_NAME,X509V3_R_MISSING_VALUE);
		return NULL;
		}

	if (out)
		gen = out;
	else
		{
		gen = GENERAL_NAME_new();
		if(gen == NULL)
			{
			X509V3err(X509V3_F_A2I_GENERAL_NAME,ERR_R_MALLOC_FAILURE);
			return NULL;
			}
		}

	switch (gen_type)
		{
		case GEN_URI:
		case GEN_EMAIL:
		case GEN_DNS:
		is_string = 1;
		break;
		
		case GEN_RID:
		{
		ASN1_OBJECT *obj;
		if(!(obj = OBJ_txt2obj(value,0)))
			{
			X509V3err(X509V3_F_A2I_GENERAL_NAME,X509V3_R_BAD_OBJECT);
			ERR_add_error_data(2, "value=", value);
			goto err;
			}
		gen->d.rid = obj;
		}
		break;

		case GEN_IPADD:
		if (is_nc)
			gen->d.ip = a2i_IPADDRESS_NC(value);
		else
			gen->d.ip = a2i_IPADDRESS(value);
		if(gen->d.ip == NULL)
			{
			X509V3err(X509V3_F_A2I_GENERAL_NAME,X509V3_R_BAD_IP_ADDRESS);
			ERR_add_error_data(2, "value=", value);
			goto err;
			}
		break;

		case GEN_DIRNAME:
		if (!do_dirname(gen, value, ctx))
			{
			X509V3err(X509V3_F_A2I_GENERAL_NAME,X509V3_R_DIRNAME_ERROR);
			goto err;
			}
		break;

		case GEN_OTHERNAME:
		if (!do_othername(gen, value, ctx))
			{
			X509V3err(X509V3_F_A2I_GENERAL_NAME,X509V3_R_OTHERNAME_ERROR);
			goto err;
			}
		break;
		default:
		X509V3err(X509V3_F_A2I_GENERAL_NAME,X509V3_R_UNSUPPORTED_TYPE);
		goto err;
		}

	if(is_string)
		{
		if(!(gen->d.ia5 = M_ASN1_IA5STRING_new()) ||
			      !ASN1_STRING_set(gen->d.ia5, (unsigned char*)value,
					       strlen(value)))
			{
			X509V3err(X509V3_F_A2I_GENERAL_NAME,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		}

	gen->type = gen_type;

	return gen;

	err:
	if (!out)
		GENERAL_NAME_free(gen);
	return NULL;
	}
/* file: ERR_put_error : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
void ERR_put_error(int lib, int func, int reason, const char *file,
	     int line)
	{
	ERR_STATE *es;

#ifdef _OSD_POSIX
	/* In the BS2000-OSD POSIX subsystem, the compiler generates
	 * path names in the form "*POSIX(/etc/passwd)".
	 * This dirty hack strips them to something sensible.
	 * @@@ We shouldn't modify a const string, though.
	 */
	if (strncmp(file,"*POSIX(", sizeof("*POSIX(")-1) == 0) {
		char *end;

		/* Skip the "*POSIX(" prefix */
		file += sizeof("*POSIX(")-1;
		end = &file[strlen(file)-1];
		if (*end == ')')
			*end = '\0';
		/* Optional: use the basename of the path only. */
		if ((end = strrchr(file, '/')) != NULL)
			file = &end[1];
	}
#endif
	es=ERR_get_state();

	es->top=(es->top+1)%ERR_NUM_ERRORS;
	if (es->top == es->bottom)
		es->bottom=(es->bottom+1)%ERR_NUM_ERRORS;
	es->err_flags[es->top]=0;
	es->err_buffer[es->top]=ERR_PACK(lib,func,reason);
	es->err_file[es->top]=file;
	es->err_line[es->top]=line;
	err_clear_data(es,es->top);
	}
/* file: ERR_get_state : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
ERR_STATE *ERR_get_state(void)
	{
	static ERR_STATE fallback;
	ERR_STATE *ret,tmp,*tmpp=NULL;
	int i;
	CRYPTO_THREADID tid;

	err_fns_check();
	CRYPTO_THREADID_current(&tid);
	CRYPTO_THREADID_cpy(&tmp.tid, &tid);
	ret=ERRFN(thread_get_item)(&tmp);

	/* ret == the error state, if NULL, make a new one */
	if (ret == NULL)
		{
		ret=(ERR_STATE *)OPENSSL_malloc(sizeof(ERR_STATE));
		if (ret == NULL) return(&fallback);
		CRYPTO_THREADID_cpy(&ret->tid, &tid);
		ret->top=0;
		ret->bottom=0;
		for (i=0; i<ERR_NUM_ERRORS; i++)
			{
			ret->err_data[i]=NULL;
			ret->err_data_flags[i]=0;
			}
		tmpp = ERRFN(thread_set_item)(ret);
		/* To check if insertion failed, do a get. */
		if (ERRFN(thread_get_item)(ret) != ret)
			{
			ERR_STATE_free(ret); /* could not insert it */
			return(&fallback);
			}
		/* If a race occured in this function and we came second, tmpp
		 * is the first one that we just replaced. */
		if (tmpp)
			ERR_STATE_free(tmpp);
		}
	return ret;
	}
/* file: CRYPTO_THREADID_cpy : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
void CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest, const CRYPTO_THREADID *src)
	{
	memcpy(dest, src, sizeof(*src));
	}
/* file: ERR_STATE_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
static void ERR_STATE_free(ERR_STATE *s)
	{
	int i;

	if (s == NULL)
	    return;

	for (i=0; i<ERR_NUM_ERRORS; i++)
		{
		err_clear_data(s,i);
		}
	OPENSSL_free(s);
	}
/* file: CRYPTO_free : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
void CRYPTO_free(void *str)
	{
	if (free_debug_func != NULL)
		free_debug_func(str, 0);
#ifdef LEVITTE_DEBUG_MEM
	fprintf(stderr, "LEVITTE_DEBUG_MEM:         < 0x%p\n", str);
#endif
	free_func(str);
	if (free_debug_func != NULL)
		free_debug_func(NULL, 1);
	}
/* file: CRYPTO_dbg_free : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem_dbg.c */
void CRYPTO_dbg_free(void *addr, int before_p)
	{
	MEM m,*mp;

	switch(before_p)
		{
	case 0:
		if (addr == NULL)
			break;

		if (is_MemCheck_on() && (mh != NULL))
			{
			MemCheck_off(); /* make sure we hold MALLOC2 lock */

			m.addr=addr;
			mp=lh_MEM_delete(mh,&m);
			if (mp != NULL)
				{
#ifdef LEVITTE_DEBUG_MEM
			fprintf(stderr, "LEVITTE_DEBUG_MEM: [%5ld] - 0x%p (%d)\n",
				mp->order, mp->addr, mp->num);
#endif
				if (mp->app_info != NULL)
					app_info_free(mp->app_info);
				OPENSSL_free(mp);
				}

			MemCheck_on(); /* release MALLOC2 lock
			                * if num_disabled drops to 0 */
			}
		break;
	case 1:
		break;
		}
	}
/* file: CRYPTO_mem_ctrl : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem_dbg.c */
int CRYPTO_mem_ctrl(int mode)
	{
	int ret=mh_mode;

	CRYPTO_w_lock(CRYPTO_LOCK_MALLOC);
	switch (mode)
		{
	/* for applications (not to be called while multiple threads
	 * use the library): */
	case CRYPTO_MEM_CHECK_ON: /* aka MemCheck_start() */
		mh_mode = CRYPTO_MEM_CHECK_ON|CRYPTO_MEM_CHECK_ENABLE;
		num_disable = 0;
		break;
	case CRYPTO_MEM_CHECK_OFF: /* aka MemCheck_stop() */
		mh_mode = 0;
		num_disable = 0; /* should be true *before* MemCheck_stop is used,
		                    or there'll be a lot of confusion */
		break;

	/* switch off temporarily (for library-internal use): */
	case CRYPTO_MEM_CHECK_DISABLE: /* aka MemCheck_off() */
		if (mh_mode & CRYPTO_MEM_CHECK_ON)
			{
			CRYPTO_THREADID cur;
			CRYPTO_THREADID_current(&cur);
			if (!num_disable || CRYPTO_THREADID_cmp(&disabling_threadid, &cur)) /* otherwise we already have the MALLOC2 lock */
				{
				/* Long-time lock CRYPTO_LOCK_MALLOC2 must not be claimed while
				 * we're holding CRYPTO_LOCK_MALLOC, or we'll deadlock if
				 * somebody else holds CRYPTO_LOCK_MALLOC2 (and cannot release
				 * it because we block entry to this function).
				 * Give them a chance, first, and then claim the locks in
				 * appropriate order (long-time lock first).
				 */
				CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC);
				/* Note that after we have waited for CRYPTO_LOCK_MALLOC2
				 * and CRYPTO_LOCK_MALLOC, we'll still be in the right
				 * "case" and "if" branch because MemCheck_start and
				 * MemCheck_stop may never be used while there are multiple
				 * OpenSSL threads. */
				CRYPTO_w_lock(CRYPTO_LOCK_MALLOC2);
				CRYPTO_w_lock(CRYPTO_LOCK_MALLOC);
				mh_mode &= ~CRYPTO_MEM_CHECK_ENABLE;
				CRYPTO_THREADID_cpy(&disabling_threadid, &cur);
				}
			num_disable++;
			}
		break;
	case CRYPTO_MEM_CHECK_ENABLE: /* aka MemCheck_on() */
		if (mh_mode & CRYPTO_MEM_CHECK_ON)
			{
			if (num_disable) /* always true, or something is going wrong */
				{
				num_disable--;
				if (num_disable == 0)
					{
					mh_mode|=CRYPTO_MEM_CHECK_ENABLE;
					CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC2);
					}
				}
			}
		break;

	default:
		break;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC);
	return(ret);
	}
/* file: CRYPTO_THREADID_cmp : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
int CRYPTO_THREADID_cmp(const CRYPTO_THREADID *a, const CRYPTO_THREADID *b)
	{
	return memcmp(a, b, sizeof(*a));
	}
/* file: app_info_free : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem_dbg.c */
static void app_info_free(APP_INFO *inf)
	{
	if (--(inf->references) <= 0)
		{
		if (inf->next != NULL)
			{
			app_info_free(inf->next);
			}
		OPENSSL_free(inf);
		}
	}
/* file: OBJ_sn2nid : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobj_dat.c */
int OBJ_sn2nid(const char *s)
	{
	ASN1_OBJECT o;
	const ASN1_OBJECT *oo= &o;
	ADDED_OBJ ad,*adp;
	const unsigned int *op;

	o.sn=s;
	if (added != NULL)
		{
		ad.type=ADDED_SNAME;
		ad.obj= &o;
		adp=lh_ADDED_OBJ_retrieve(added,&ad);
		if (adp != NULL) return (adp->obj->nid);
		}
	op=OBJ_bsearch_sn(&oo, sn_objs, NUM_SN);
	if (op == NULL) return(NID_undef);
	return(nid_objs[*op].nid);
	}
/* file: OBJ_ln2nid : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobj_dat.c */
int OBJ_ln2nid(const char *s)
	{
	ASN1_OBJECT o;
	const ASN1_OBJECT *oo= &o;
	ADDED_OBJ ad,*adp;
	const unsigned int *op;

	o.ln=s;
	if (added != NULL)
		{
		ad.type=ADDED_LNAME;
		ad.obj= &o;
		adp=lh_ADDED_OBJ_retrieve(added,&ad);
		if (adp != NULL) return (adp->obj->nid);
		}
	op=OBJ_bsearch_ln(&oo, ln_objs, NUM_LN);
	if (op == NULL) return(NID_undef);
	return(nid_objs[*op].nid);
	}
/* file: a2d_ASN1_OBJECT : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_object.c */
int a2d_ASN1_OBJECT(unsigned char *out, int olen, const char *buf, int num)
	{
	int i,first,len=0,c, use_bn;
	char ftmp[24], *tmp = ftmp;
	int tmpsize = sizeof ftmp;
	const char *p;
	unsigned long l;
	BIGNUM *bl = NULL;

	if (num == 0)
		return(0);
	else if (num == -1)
		num=strlen(buf);

	p=buf;
	c= *(p++);
	num--;
	if ((c >= '0') && (c <= '2'))
		{
		first= c-'0';
		}
	else
		{
		ASN1err(ASN1_F_A2D_ASN1_OBJECT,ASN1_R_FIRST_NUM_TOO_LARGE);
		goto err;
		}

	if (num <= 0)
		{
		ASN1err(ASN1_F_A2D_ASN1_OBJECT,ASN1_R_MISSING_SECOND_NUMBER);
		goto err;
		}
	c= *(p++);
	num--;
	for (;;)
		{
		if (num <= 0) break;
		if ((c != '.') && (c != ' '))
			{
			ASN1err(ASN1_F_A2D_ASN1_OBJECT,ASN1_R_INVALID_SEPARATOR);
			goto err;
			}
		l=0;
		use_bn = 0;
		for (;;)
			{
			if (num <= 0) break;
			num--;
			c= *(p++);
			if ((c == ' ') || (c == '.'))
				break;
			if ((c < '0') || (c > '9'))
				{
				ASN1err(ASN1_F_A2D_ASN1_OBJECT,ASN1_R_INVALID_DIGIT);
				goto err;
				}
			if (!use_bn && l >= ((ULONG_MAX - 80) / 10L))
				{
				use_bn = 1;
				if (!bl)
					bl = BN_new();
				if (!bl || !BN_set_word(bl, l))
					goto err;
				}
			if (use_bn)
				{
				if (!BN_mul_word(bl, 10L)
					|| !BN_add_word(bl, c-'0'))
					goto err;
				}
			else
				l=l*10L+(long)(c-'0');
			}
		if (len == 0)
			{
			if ((first < 2) && (l >= 40))
				{
				ASN1err(ASN1_F_A2D_ASN1_OBJECT,ASN1_R_SECOND_NUMBER_TOO_LARGE);
				goto err;
				}
			if (use_bn)
				{
				if (!BN_add_word(bl, first * 40))
					goto err;
				}
			else
				l+=(long)first*40;
			}
		i=0;
		if (use_bn)
			{
			int blsize;
			blsize = BN_num_bits(bl);
			blsize = (blsize + 6)/7;
			if (blsize > tmpsize)
				{
				if (tmp != ftmp)
					OPENSSL_free(tmp);
				tmpsize = blsize + 32;
				tmp = OPENSSL_malloc(tmpsize);
				if (!tmp)
					goto err;
				}
			while(blsize--)
				tmp[i++] = (unsigned char)BN_div_word(bl, 0x80L);
			}
		else
			{
					
			for (;;)
				{
				tmp[i++]=(unsigned char)l&0x7f;
				l>>=7L;
				if (l == 0L) break;
				}

			}
		if (out != NULL)
			{
			if (len+i > olen)
				{
				ASN1err(ASN1_F_A2D_ASN1_OBJECT,ASN1_R_BUFFER_TOO_SMALL);
				goto err;
				}
			while (--i > 0)
				out[len++]=tmp[i]|0x80;
			out[len++]=tmp[0];
			}
		else
			len+=i;
		}
	if (tmp != ftmp)
		OPENSSL_free(tmp);
	if (bl)
		BN_free(bl);
	return(len);
err:
	if (tmp != ftmp)
		OPENSSL_free(tmp);
	if (bl)
		BN_free(bl);
	return(0);
	}
/* file: BN_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
BIGNUM *BN_new(void)
	{
	BIGNUM *ret;

	if ((ret=(BIGNUM *)OPENSSL_malloc(sizeof(BIGNUM))) == NULL)
		{
		BNerr(BN_F_BN_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	ret->flags=BN_FLG_MALLOCED;
	ret->top=0;
	ret->neg=0;
	ret->dmax=0;
	ret->d=NULL;
	bn_check_top(ret);
	return(ret);
	}
/* file: RAND_pseudo_bytes : /Volumes/work/Phd/ECDH/kv_openssl/crypto/randrand_lib.c */
int RAND_pseudo_bytes(unsigned char *buf, int num)
	{
	const RAND_METHOD *meth = RAND_get_rand_method();
	if (meth && meth->pseudorand)
		return meth->pseudorand(buf,num);
	return(-1);
	}
/* file: RAND_get_rand_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/randrand_lib.c */
const RAND_METHOD *RAND_get_rand_method(void)
	{
	if (!default_RAND_meth)
		{
#ifndef OPENSSL_NO_ENGINE
		ENGINE *e = ENGINE_get_default_RAND();
		if(e)
			{
			default_RAND_meth = ENGINE_get_RAND(e);
			if(!default_RAND_meth)
				{
				ENGINE_finish(e);
				e = NULL;
				}
			}
		if(e)
			funct_ref = e;
		else
#endif
			default_RAND_meth = RAND_SSLeay();
		}
	return default_RAND_meth;
	}
/* file: ENGINE_get_default_RAND : /Volumes/work/Phd/ECDH/kv_openssl/crypto/enginetb_rand.c */
ENGINE *ENGINE_get_default_RAND(void)
	{
	return engine_table_select(&rand_table, dummy_nid);
	}
/* file: engine_table_select_tmp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_table.c */
#ifndef ENGINE_TABLE_DEBUG
ENGINE *engine_table_select_tmp(ENGINE_TABLE **table, int nid, const char *f, int l)
#endif
	{
	ENGINE *ret = NULL;
	ENGINE_PILE tmplate, *fnd=NULL;
	int initres, loop = 0;

	if(!(*table))
		{
#ifdef ENGINE_TABLE_DEBUG
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, nothing "
			"registered!\n", f, l, nid);
#endif
		return NULL;
		}
	ERR_set_mark();
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	/* Check again inside the lock otherwise we could race against cleanup
	 * operations. But don't worry about a fprintf(stderr). */
	if(!int_table_check(table, 0)) goto end;
	tmplate.nid = nid;
	fnd = lh_ENGINE_PILE_retrieve(&(*table)->piles, &tmplate);
	if(!fnd) goto end;
	if(fnd->funct && engine_unlocked_init(fnd->funct))
		{
#ifdef ENGINE_TABLE_DEBUG
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, using "
			"ENGINE '%s' cached\n", f, l, nid, fnd->funct->id);
#endif
		ret = fnd->funct;
		goto end;
		}
	if(fnd->uptodate)
		{
		ret = fnd->funct;
		goto end;
		}
trynext:
	ret = sk_ENGINE_value(fnd->sk, loop++);
	if(!ret)
		{
#ifdef ENGINE_TABLE_DEBUG
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, no "
				"registered implementations would initialise\n",
				f, l, nid);
#endif
		goto end;
		}
	/* Try to initialise the ENGINE? */
	if((ret->funct_ref > 0) || !(table_flags & ENGINE_TABLE_FLAG_NOINIT))
		initres = engine_unlocked_init(ret);
	else
		initres = 0;
	if(initres)
		{
		/* Update 'funct' */
		if((fnd->funct != ret) && engine_unlocked_init(ret))
			{
			/* If there was a previous default we release it. */
			if(fnd->funct)
				engine_unlocked_finish(fnd->funct, 0);
			fnd->funct = ret;
#ifdef ENGINE_TABLE_DEBUG
			fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, "
				"setting default to '%s'\n", f, l, nid, ret->id);
#endif
			}
#ifdef ENGINE_TABLE_DEBUG
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, using "
				"newly initialised '%s'\n", f, l, nid, ret->id);
#endif
		goto end;
		}
	goto trynext;
end:
	/* If it failed, it is unlikely to succeed again until some future
	 * registrations have taken place. In all cases, we cache. */
	if(fnd) fnd->uptodate = 1;
#ifdef ENGINE_TABLE_DEBUG
	if(ret)
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, caching "
				"ENGINE '%s'\n", f, l, nid, ret->id);
	else
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, caching "
				"'no matching ENGINE'\n", f, l, nid);
#endif
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	/* Whatever happened, any failed init()s are not failures in this
	 * context, so clear our error state. */
	ERR_pop_to_mark();
	return ret;
	}
/* file: ERR_set_mark : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
int ERR_set_mark(void)
	{
	ERR_STATE *es;

	es=ERR_get_state();

	if (es->bottom == es->top) return 0;
	es->err_flags[es->top]|=ERR_FLAG_MARK;
	return 1;
	}
/* file: LHASH_OF : /Volumes/work/Phd/ECDH/kv_openssl/appsopenssl.c */
static LHASH_OF(FUNCTION) *prog_init(void)
	{
	LHASH_OF(FUNCTION) *ret;
	FUNCTION *f;
	size_t i;

	/* Purely so it looks nice when the user hits ? */
	for(i=0,f=functions ; f->name != NULL ; ++f,++i)
	    ;
	qsort(functions,i,sizeof *functions,SortFnByName);

	if ((ret=lh_FUNCTION_new()) == NULL)
		return(NULL);

	for (f=functions; f->name != NULL; f++)
		(void)lh_FUNCTION_insert(ret,f);
	return(ret);
	}
/* file: engine_unlocked_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_init.c */
int engine_unlocked_init(ENGINE *e)
	{
	int to_return = 1;

	if((e->funct_ref == 0) && e->init)
		/* This is the first functional reference and the engine
		 * requires initialisation so we do it now. */
		to_return = e->init(e);
	if(to_return)
		{
		/* OK, we return a functional reference which is also a
		 * structural reference. */
		e->struct_ref++;
		e->funct_ref++;
		engine_ref_debug(e, 0, 1)
		engine_ref_debug(e, 1, 1)
		}
	return to_return;
	}
/* file: engine_unlocked_finish : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_init.c */
int engine_unlocked_finish(ENGINE *e, int unlock_for_handlers)
	{
	int to_return = 1;

	/* Reduce the functional reference count here so if it's the terminating
	 * case, we can release the lock safely and call the finish() handler
	 * without risk of a race. We get a race if we leave the count until
	 * after and something else is calling "finish" at the same time -
	 * there's a chance that both threads will together take the count from
	 * 2 to 0 without either calling finish(). */
	e->funct_ref--;
	engine_ref_debug(e, 1, -1);
	if((e->funct_ref == 0) && e->finish)
		{
		if(unlock_for_handlers)
			CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
		to_return = e->finish(e);
		if(unlock_for_handlers)
			CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
		if(!to_return)
			return 0;
		}
#ifdef REF_CHECK
	if(e->funct_ref < 0)
		{
		fprintf(stderr,"ENGINE_finish, bad functional reference count\n");
		abort();
		}
#endif
	/* Release the structural reference too */
	if(!engine_free_util(e, 0))
		{
		ENGINEerr(ENGINE_F_ENGINE_UNLOCKED_FINISH,ENGINE_R_FINISH_FAILED);
		return 0;
		}
	return to_return;
	}
/* file: engine_free_util : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_lib.c */
int engine_free_util(ENGINE *e, int locked)
	{
	int i;

	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_FREE_UTIL,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	if(locked)
		i = CRYPTO_add(&e->struct_ref,-1,CRYPTO_LOCK_ENGINE);
	else
		i = --e->struct_ref;
	engine_ref_debug(e, 0, -1)
	if (i > 0) return 1;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"ENGINE_free, bad structural reference count\n");
		abort();
		}
#endif
	/* Free up any dynamically allocated public key methods */
	engine_pkey_meths_free(e);
	engine_pkey_asn1_meths_free(e);
	/* Give the ENGINE a chance to do any structural cleanup corresponding
	 * to allocation it did in its constructor (eg. unload error strings) */
	if(e->destroy)
		e->destroy(e);
	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ENGINE, e, &e->ex_data);
	OPENSSL_free(e);
	return 1;
	}
/* file: CRYPTO_add_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
int CRYPTO_add_lock(int *pointer, int amount, int type, const char *file,
	     int line)
	{
	int ret = 0;

	if (add_lock_callback != NULL)
		{
#ifdef LOCK_DEBUG
		int before= *pointer;
#endif

		ret=add_lock_callback(pointer,amount,type,file,line);
#ifdef LOCK_DEBUG
		{
		CRYPTO_THREADID id;
		CRYPTO_THREADID_current(&id);
		fprintf(stderr,"ladd:%08lx:%2d+%2d->%2d %-18s %s:%d\n",
			CRYPTO_THREADID_hash(&id), before,amount,ret,
			CRYPTO_get_lock_name(type),
			file,line);
		}
#endif
		}
	else
		{
		CRYPTO_lock(CRYPTO_LOCK|CRYPTO_WRITE,type,file,line);

		ret= *pointer+amount;
#ifdef LOCK_DEBUG
		{
		CRYPTO_THREADID id;
		CRYPTO_THREADID_current(&id);
		fprintf(stderr,"ladd:%08lx:%2d+%2d->%2d %-18s %s:%d\n",
			CRYPTO_THREADID_hash(&id),
			*pointer,amount,ret,
			CRYPTO_get_lock_name(type),
			file,line);
		}
#endif
		*pointer=ret;
		CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE,type,file,line);
		}
	return(ret);
	}
/* file: engine_pkey_meths_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/enginetb_pkmeth.c */
void engine_pkey_meths_free(ENGINE *e)
	{
	int i;
	EVP_PKEY_METHOD *pkm;
	if (e->pkey_meths)
		{
		const int *pknids;
		int npknids;
		npknids = e->pkey_meths(e, NULL, &pknids, 0);
		for (i = 0; i < npknids; i++)
			{
			if (e->pkey_meths(e, &pkm, NULL, pknids[i]))
				{
				EVP_PKEY_meth_free(pkm);
				}
			}
		}
	}
/* file: EVP_PKEY_meth_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/evppmeth_lib.c */
void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth)
	{
	if (pmeth && (pmeth->flags & EVP_PKEY_FLAG_DYNAMIC))
		OPENSSL_free(pmeth);
	}
/* file: engine_pkey_asn1_meths_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/enginetb_asnmth.c */
void engine_pkey_asn1_meths_free(ENGINE *e)
	{
	int i;
	EVP_PKEY_ASN1_METHOD *pkm;
	if (e->pkey_asn1_meths)
		{
		const int *pknids;
		int npknids;
		npknids = e->pkey_asn1_meths(e, NULL, &pknids, 0);
		for (i = 0; i < npknids; i++)
			{
			if (e->pkey_asn1_meths(e, &pkm, NULL, pknids[i]))
				{
				EVP_PKEY_asn1_free(pkm);
				}
			}
		}
	}
/* file: EVP_PKEY_asn1_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1ameth_lib.c */
void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth)
	{
	if (ameth && (ameth->pkey_flags & ASN1_PKEY_DYNAMIC))
		{
		if (ameth->pem_str)
			OPENSSL_free(ameth->pem_str);
		if (ameth->info)
			OPENSSL_free(ameth->info);
		OPENSSL_free(ameth);
		}
	}
/* file: CRYPTO_free_ex_data : /Volumes/work/Phd/ECDH/kv_openssl/cryptoex_data.c */
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
	{
	IMPL_CHECK
	EX_IMPL(free_ex_data)(class_index, obj, ad);
	}
/* file: ERR_pop_to_mark : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
int ERR_pop_to_mark(void)
	{
	ERR_STATE *es;

	es=ERR_get_state();

	while(es->bottom != es->top
		&& (es->err_flags[es->top] & ERR_FLAG_MARK) == 0)
		{
		err_clear(es,es->top);
		es->top-=1;
		if (es->top == -1) es->top=ERR_NUM_ERRORS-1;
		}
		
	if (es->bottom == es->top) return 0;
	es->err_flags[es->top]&=~ERR_FLAG_MARK;
	return 1;
	}
/* file: ENGINE_get_RAND : /Volumes/work/Phd/ECDH/kv_openssl/crypto/enginetb_rand.c */
const RAND_METHOD *ENGINE_get_RAND(const ENGINE *e)
	{
	return e->rand_meth;
	}
/* file: ENGINE_finish : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_init.c */
int ENGINE_finish(ENGINE *e)
	{
	int to_return = 1;

	if(e == NULL)
		{
		ENGINEerr(ENGINE_F_ENGINE_FINISH,ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	to_return = engine_unlocked_finish(e, 1);
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	if(!to_return)
		{
		ENGINEerr(ENGINE_F_ENGINE_FINISH,ENGINE_R_FINISH_FAILED);
		return 0;
		}
	return to_return;
	}
/* file: RAND_SSLeay : /Volumes/work/Phd/ECDH/kv_openssl/crypto/randmd_rand.c */
RAND_METHOD *RAND_SSLeay(void)
	{
	return(&rand_ssleay_meth);
	}
/* file: BN_set_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
int BN_set_word(BIGNUM *a, BN_ULONG w)
	{
	bn_check_top(a);
	if (bn_expand(a,(int)sizeof(BN_ULONG)*8) == NULL) return(0);
	a->neg = 0;
	a->d[0] = w;
	a->top = (w ? 1 : 0);
	bn_check_top(a);
	return(1);
	}
/* file: bn_expand2 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
BIGNUM *bn_expand2(BIGNUM *b, int words)
	{
	bn_check_top(b);

	if (words > b->dmax)
		{
		BN_ULONG *a = bn_expand_internal(b, words);
		if(!a) return NULL;
		if(b->d) OPENSSL_free(b->d);
		b->d=a;
		b->dmax=words;
		}

/* None of this should be necessary because of what b->top means! */
#if 0
	/* NB: bn_wexpand() calls this only if the BIGNUM really has to grow */
	if (b->top < b->dmax)
		{
		int i;
		BN_ULONG *A = &(b->d[b->top]);
		for (i=(b->dmax - b->top)>>3; i>0; i--,A+=8)
			{
			A[0]=0; A[1]=0; A[2]=0; A[3]=0;
			A[4]=0; A[5]=0; A[6]=0; A[7]=0;
			}
		for (i=(b->dmax - b->top)&7; i>0; i--,A++)
			A[0]=0;
		assert(A == &(b->d[b->dmax]));
		}
#endif
	bn_check_top(b);
	return b;
	}
/* file: BN_mul_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_word.c */
int BN_mul_word(BIGNUM *a, BN_ULONG w)
	{
	BN_ULONG ll;

	bn_check_top(a);
	w&=BN_MASK2;
	if (a->top)
		{
		if (w == 0)
			BN_zero(a);
		else
			{
			ll=bn_mul_words(a->d,a->d,a->top,w);
			if (ll)
				{
				if (bn_wexpand(a,a->top+1) == NULL) return(0);
				a->d[a->top++]=ll;
				}
			}
		}
	bn_check_top(a);
	return(1);
	}
/* file: bn_mul_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
#if defined(BN_LLONG) || defined(BN_UMULT_HIGH)
BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
	{
	BN_ULONG c1=0;

	assert(num >= 0);
	if (num <= 0) return(c1);

#ifndef OPENSSL_SMALL_FOOTPRINT
	while (num&~3)
		{
		mul(rp[0],ap[0],w,c1);
		mul(rp[1],ap[1],w,c1);
		mul(rp[2],ap[2],w,c1);
		mul(rp[3],ap[3],w,c1);
		ap+=4; rp+=4; num-=4;
		}
#endif
	while (num)
		{
		mul(rp[0],ap[0],w,c1);
		ap++; rp++; num--;
		}
	return(c1);
	} 
#else /* !(defined(BN_LLONG) || defined(BN_UMULT_HIGH)) */
/* file: bn_mul_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
	{
	BN_ULONG carry=0;
	BN_ULONG bl,bh;

	assert(num >= 0);
	if (num <= 0) return((BN_ULONG)0);

	bl=LBITS(w);
	bh=HBITS(w);

#ifndef OPENSSL_SMALL_FOOTPRINT
	while (num&~3)
		{
		mul(rp[0],ap[0],bl,bh,carry);
		mul(rp[1],ap[1],bl,bh,carry);
		mul(rp[2],ap[2],bl,bh,carry);
		mul(rp[3],ap[3],bl,bh,carry);
		ap+=4; rp+=4; num-=4;
		}
#endif
	while (num)
		{
		mul(rp[0],ap[0],bl,bh,carry);
		ap++; rp++; num--;
		}
	return(carry);
	} 
#endif /* !(defined(BN_LLONG) || defined(BN_UMULT_HIGH)) */
/* file: BN_add_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_word.c */
int BN_add_word(BIGNUM *a, BN_ULONG w)
	{
	BN_ULONG l;
	int i;

	bn_check_top(a);
	w &= BN_MASK2;

	/* degenerate case: w is zero */
	if (!w) return 1;
	/* degenerate case: a is zero */
	if(BN_is_zero(a)) return BN_set_word(a, w);
	/* handle 'a' when negative */
	if (a->neg)
		{
		a->neg=0;
		i=BN_sub_word(a,w);
		if (!BN_is_zero(a))
			a->neg=!(a->neg);
		return(i);
		}
	for (i=0;w!=0 && i<a->top;i++)
		{
		a->d[i] = l = (a->d[i]+w)&BN_MASK2;
		w = (w>l)?1:0;
		}
	if (w && i==a->top)
		{
		if (bn_wexpand(a,a->top+1) == NULL) return 0;
		a->top++;
		a->d[i]=w;
		}
	bn_check_top(a);
	return(1);
	}
/* file: BN_sub_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_word.c */
int BN_sub_word(BIGNUM *a, BN_ULONG w)
	{
	int i;

	bn_check_top(a);
	w &= BN_MASK2;

	/* degenerate case: w is zero */
	if (!w) return 1;
	/* degenerate case: a is zero */
	if(BN_is_zero(a))
		{
		i = BN_set_word(a,w);
		if (i != 0)
			BN_set_negative(a, 1);
		return i;
		}
	/* handle 'a' when negative */
	if (a->neg)
		{
		a->neg=0;
		i=BN_add_word(a,w);
		a->neg=1;
		return(i);
		}

	if ((a->top == 1) && (a->d[0] < w))
		{
		a->d[0]=w-a->d[0];
		a->neg=1;
		return(1);
		}
	i=0;
	for (;;)
		{
		if (a->d[i] >= w)
			{
			a->d[i]-=w;
			break;
			}
		else
			{
			a->d[i]=(a->d[i]-w)&BN_MASK2;
			i++;
			w=1;
			}
		}
	if ((a->d[i] == 0) && (i == (a->top-1)))
		a->top--;
	bn_check_top(a);
	return(1);
	}
/* file: BN_set_negative : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
void BN_set_negative(BIGNUM *a, int b)
	{
	if (b && !BN_is_zero(a))
		a->neg = 1;
	else
		a->neg = 0;
	}
/* file: BN_num_bits : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
int BN_num_bits(const BIGNUM *a)
	{
	int i = a->top - 1;
	bn_check_top(a);

	if (BN_is_zero(a)) return 0;
	return ((i*BN_BITS2) + BN_num_bits_word(a->d[i]));
	}
/* file: BN_num_bits_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
int BN_num_bits_word(BN_ULONG l)
	{
	static const unsigned char bits[256]={
		0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,
		5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
		6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
		6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		};

#if defined(SIXTY_FOUR_BIT_LONG)
	if (l & 0xffffffff00000000L)
		{
		if (l & 0xffff000000000000L)
			{
			if (l & 0xff00000000000000L)
				{
				return(bits[(int)(l>>56)]+56);
				}
			else	return(bits[(int)(l>>48)]+48);
			}
		else
			{
			if (l & 0x0000ff0000000000L)
				{
				return(bits[(int)(l>>40)]+40);
				}
			else	return(bits[(int)(l>>32)]+32);
			}
		}
	else
#else
#ifdef SIXTY_FOUR_BIT
	if (l & 0xffffffff00000000LL)
		{
		if (l & 0xffff000000000000LL)
			{
			if (l & 0xff00000000000000LL)
				{
				return(bits[(int)(l>>56)]+56);
				}
			else	return(bits[(int)(l>>48)]+48);
			}
		else
			{
			if (l & 0x0000ff0000000000LL)
				{
				return(bits[(int)(l>>40)]+40);
				}
			else	return(bits[(int)(l>>32)]+32);
			}
		}
	else
#endif
#endif
		{
#if defined(THIRTY_TWO_BIT) || defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
		if (l & 0xffff0000L)
			{
			if (l & 0xff000000L)
				return(bits[(int)(l>>24L)]+24);
			else	return(bits[(int)(l>>16L)]+16);
			}
		else
#endif
			{
#if defined(THIRTY_TWO_BIT) || defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
			if (l & 0xff00L)
				return(bits[(int)(l>>8)]+8);
			else	
#endif
				return(bits[(int)(l   )]  );
			}
		}
	}
/* file: BN_div_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_word.c */
BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w)
	{
	BN_ULONG ret = 0;
	int i, j;

	bn_check_top(a);
	w &= BN_MASK2;

	if (!w)
		/* actually this an error (division by zero) */
		return (BN_ULONG)-1;
	if (a->top == 0)
		return 0;

	/* normalize input (so bn_div_words doesn't complain) */
	j = BN_BITS2 - BN_num_bits_word(w);
	w <<= j;
	if (!BN_lshift(a, a, j))
		return (BN_ULONG)-1;

	for (i=a->top-1; i>=0; i--)
		{
		BN_ULONG l,d;
		
		l=a->d[i];
		d=bn_div_words(ret,l,w);
		ret=(l-((d*w)&BN_MASK2))&BN_MASK2;
		a->d[i]=d;
		}
	if ((a->top > 0) && (a->d[a->top-1] == 0))
		a->top--;
	ret >>= j;
	bn_check_top(a);
	return(ret);
	}
/* file: BN_lshift : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_shift.c */
int BN_lshift(BIGNUM *r, const BIGNUM *a, int n)
	{
	int i,nw,lb,rb;
	BN_ULONG *t,*f;
	BN_ULONG l;

	bn_check_top(r);
	bn_check_top(a);

	r->neg=a->neg;
	nw=n/BN_BITS2;
	if (bn_wexpand(r,a->top+nw+1) == NULL) return(0);
	lb=n%BN_BITS2;
	rb=BN_BITS2-lb;
	f=a->d;
	t=r->d;
	t[a->top+nw]=0;
	if (lb == 0)
		for (i=a->top-1; i>=0; i--)
			t[nw+i]=f[i];
	else
		for (i=a->top-1; i>=0; i--)
			{
			l=f[i];
			t[nw+i+1]|=(l>>rb)&BN_MASK2;
			t[nw+i]=(l<<lb)&BN_MASK2;
			}
	memset(t,0,nw*sizeof(t[0]));
/*	for (i=0; i<nw; i++)
		t[i]=0;*/
	r->top=a->top+nw+1;
	bn_correct_top(r);
	bn_check_top(r);
	return(1);
	}
/* file: bn_div_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
#if defined(BN_LLONG) && defined(BN_DIV2W)
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d)
	{
	return((BN_ULONG)(((((BN_ULLONG)h)<<BN_BITS2)|l)/(BN_ULLONG)d));
	}
#else
/* file: bn_div_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d)
	{
	BN_ULONG dh,dl,q,ret=0,th,tl,t;
	int i,count=2;

	if (d == 0) return(BN_MASK2);

	i=BN_num_bits_word(d);
	assert((i == BN_BITS2) || (h <= (BN_ULONG)1<<i));

	i=BN_BITS2-i;
	if (h >= d) h-=d;

	if (i)
		{
		d<<=i;
		h=(h<<i)|(l>>(BN_BITS2-i));
		l<<=i;
		}
	dh=(d&BN_MASK2h)>>BN_BITS4;
	dl=(d&BN_MASK2l);
	for (;;)
		{
		if ((h>>BN_BITS4) == dh)
			q=BN_MASK2l;
		else
			q=h/dh;

		th=q*dh;
		tl=dl*q;
		for (;;)
			{
			t=h-th;
			if ((t&BN_MASK2h) ||
				((tl) <= (
					(t<<BN_BITS4)|
					((l&BN_MASK2h)>>BN_BITS4))))
				break;
			q--;
			th-=dh;
			tl-=dl;
			}
		t=(tl>>BN_BITS4);
		tl=(tl<<BN_BITS4)&BN_MASK2h;
		th+=t;

		if (l < tl) th++;
		l-=tl;
		if (h < th)
			{
			h+=d;
			q--;
			}
		h-=th;

		if (--count == 0) break;

		ret=q<<BN_BITS4;
		h=((h<<BN_BITS4)|(l>>BN_BITS4))&BN_MASK2;
		l=(l&BN_MASK2l)<<BN_BITS4;
		}
	ret|=q;
	return(ret);
	}
#endif /* !defined(BN_LLONG) && defined(BN_DIV2W) */
/* file: BN_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
void BN_free(BIGNUM *a)
	{
	if (a == NULL) return;
	bn_check_top(a);
	if ((a->d != NULL) && !(BN_get_flags(a,BN_FLG_STATIC_DATA)))
		OPENSSL_free(a->d);
	if (a->flags & BN_FLG_MALLOCED)
		OPENSSL_free(a);
	else
		{
#ifndef OPENSSL_NO_DEPRECATED
		a->flags|=BN_FLG_FREE;
#endif
		a->d = NULL;
		}
	}
/* file: ASN1_object_size : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_lib.c */
int ASN1_object_size(int constructed, int length, int tag)
	{
	int ret;

	ret=length;
	ret++;
	if (tag >= 31)
		{
		while (tag > 0)
			{
			tag>>=7;
			ret++;
			}
		}
	if (constructed == 2)
		return ret + 3;
	ret++;
	if (length > 127)
		{
		while (length > 0)
			{
			length>>=8;
			ret++;
			}
		}
	return(ret);
	}
/* file: ASN1_put_object : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_lib.c */
void ASN1_put_object(unsigned char **pp, int constructed, int length, int tag,
	     int xclass)
	{
	
	unsigned char *p= *pp;
	int i, t
	tag;

	i=(constructed)?V_ASN1_CONSTRUCTED:0;
	i|=(xclass&V_ASN1_PRIVATE);
	if (tag < 31)
		*(p++)=i|(tag&V_ASN1_PRIMITIVE_TAG);
	else
		{
		*(p++)=i|V_ASN1_PRIMITIVE_TAG;
		for(i = 0, ttag = tag; ttag > 0; i++) ttag >>=7;
		ttag = i;
		while(i-- > 0)
			{
			p[i] = tag & 0x7f;
			if(i != (ttag - 1)) p[i] |= 0x80;
			tag >>= 7;
			}
		p += ttag;
		}
	if (constructed == 2)
		*(p++)=0x80;
	else
		asn1_put_length(&p,length);
	*pp=p;
	}
/* file: asn1_put_length : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_lib.c */
static void asn1_put_length(unsigned char **pp, int length)
	{
	unsigned char *p= *pp;
	int i,l;
	if (length <= 127)
		*(p++)=(unsigned char)length;
	else
		{
		l=length;
		for (i=0; l > 0; i++)
			l>>=8;
		*(p++)=i|0x80;
		l=i;
		while (i-- > 0)
			{
			p[i]=length&0xff;
			length>>=8;
			}
		p+=l;
		}
	*pp=p;
	}
/* file: ASN1_get_object : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_lib.c */
int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
	int *pclass, long omax)
	{
	int i,ret;
	long l;
	const unsigned char *p= *pp;
	int tag,xclass,inf;
	long max=omax;

	if (!max) goto err;
	ret=(*p&V_ASN1_CONSTRUCTED);
	xclass=(*p&V_ASN1_PRIVATE);
	i= *p&V_ASN1_PRIMITIVE_TAG;
	if (i == V_ASN1_PRIMITIVE_TAG)
		{		/* high-tag */
		p++;
		if (--max == 0) goto err;
		l=0;
		while (*p&0x80)
			{
			l<<=7L;
			l|= *(p++)&0x7f;
			if (--max == 0) goto err;
			if (l > (INT_MAX >> 7L)) goto err;
			}
		l<<=7L;
		l|= *(p++)&0x7f;
		tag=(int)l;
		if (--max == 0) goto err;
		}
	else
		{ 
		tag=i;
		p++;
		if (--max == 0) goto err;
		}
	*ptag=tag;
	*pclass=xclass;
	if (!asn1_get_length(&p,&inf,plength,(int)max)) goto err;

#if 0
	fprintf(stderr,"p=%d + *plength=%ld > omax=%ld + *pp=%d  (%d > %d)\n", 
		(int)p,*plength,omax,(int)*pp,(int)(p+ *plength),
		(int)(omax+ *pp));

#endif
	if (*plength > (omax - (p - *pp)))
		{
		ASN1err(ASN1_F_ASN1_GET_OBJECT,ASN1_R_TOO_LONG);
		/* Set this so that even if things are not long enough
		 * the values are set correctly */
		ret|=0x80;
		}
	*pp=p;
	return(ret|inf);
err:
	ASN1err(ASN1_F_ASN1_GET_OBJECT,ASN1_R_HEADER_TOO_LONG);
	return(0x80);
	}
/* file: asn1_get_length : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_lib.c */
static int asn1_get_length(const unsigned char **pp, int *inf, long *rl, int max)
	{
	const unsigned char *p= *pp;
	unsigned long ret=0;
	unsigned int i;

	if (max-- < 1) return(0);
	if (*p == 0x80)
		{
		*inf=1;
		ret=0;
		p++;
		}
	else
		{
		*inf=0;
		i= *p&0x7f;
		if (*(p++) & 0x80)
			{
			if (i > sizeof(long))
				return 0;
			if (max-- == 0) return(0);
			while (i-- > 0)
				{
				ret<<=8L;
				ret|= *(p++);
				if (max-- == 0) return(0);
				}
			}
		else
			ret=i;
		}
	if (ret > LONG_MAX)
		return 0;
	*pp=p;
	*rl=(long)ret;
	return(1);
	}
/* file: ASN1_OBJECT_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_object.c */
void ASN1_OBJECT_free(ASN1_OBJECT *a)
	{
	if (a == NULL) return;
	if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC_STRINGS)
		{
#ifndef CONST_STRICT /* disable purely for compile-time strict const checking. Doing this on a "real" compile will cause memory leaks */
		if (a->sn != NULL) OPENSSL_free((void *)a->sn);
		if (a->ln != NULL) OPENSSL_free((void *)a->ln);
#endif
		a->sn=a->ln=NULL;
		}
	if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC_DATA)
		{
		if (a->data != NULL) OPENSSL_free((void *)a->data);
		a->data=NULL;
		a->length=0;
		}
	if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC)
		OPENSSL_free(a);
	}
/* file: ERR_add_error_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
void ERR_add_error_data(int num, ...)
	{
	va_list args;
	va_start(args, num);
	ERR_add_error_vdata(num, args);
	va_end(args);
	}
/* file: ERR_add_error_vdata : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
void ERR_add_error_vdata(int num, va_list args)
	{
	int i,n,s;
	char *str,*p,*a;

	s=80;
	str=OPENSSL_malloc(s+1);
	if (str == NULL) return;
	str[0]='\0';

	n=0;
	for (i=0; i<num; i++)
		{
		a=va_arg(args, char*);
		/* ignore NULLs, thanks to Bob Beck <beck@obtuse.com> */
		if (a != NULL)
			{
			n+=strlen(a);
			if (n > s)
				{
				s=n+20;
				p=OPENSSL_realloc(str,s+1);
				if (p == NULL)
					{
					OPENSSL_free(str);
					return;
					}
				else
					str=p;
				}
			BUF_strlcat(str,a,(size_t)s+1);
			}
		}
	ERR_set_error_data(str,ERR_TXT_MALLOCED|ERR_TXT_STRING);
	}
/* file: CRYPTO_realloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
void *CRYPTO_realloc(void *str, int num, const char *file, int line)
	{
	void *ret = NULL;

	if (str == NULL)
		return CRYPTO_malloc(num, file, line);

	if (num <= 0) return NULL;

	if (realloc_debug_func != NULL)
		realloc_debug_func(str, NULL, num, file, line, 0);
	ret = realloc_ex_func(str,num,file,line);
#ifdef LEVITTE_DEBUG_MEM
	fprintf(stderr, "LEVITTE_DEBUG_MEM:         | 0x%p -> 0x%p (%d)\n", str, ret, num);
#endif
	if (realloc_debug_func != NULL)
		realloc_debug_func(str, ret, num, file, line, 1);

	return ret;
	}
/* file: CRYPTO_dbg_realloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem_dbg.c */
void CRYPTO_dbg_realloc(void *addr1, void *addr2, int num,
	const char *file, int line, int before_p)
	{
	MEM m,*mp;

#ifdef LEVITTE_DEBUG_MEM
	fprintf(stderr, "LEVITTE_DEBUG_MEM: --> CRYPTO_dbg_malloc(addr1 = %p, addr2 = %p, num = %d, file = \"%s\", line = %d, before_p = %d)\n",
		addr1, addr2, num, file, line, before_p);
#endif

	switch(before_p)
		{
	case 0:
		break;
	case 1:
		if (addr2 == NULL)
			break;

		if (addr1 == NULL)
			{
			CRYPTO_dbg_malloc(addr2, num, file, line, 128 | before_p);
			break;
			}

		if (is_MemCheck_on())
			{
			MemCheck_off(); /* make sure we hold MALLOC2 lock */

			m.addr=addr1;
			mp=lh_MEM_delete(mh,&m);
			if (mp != NULL)
				{
#ifdef LEVITTE_DEBUG_MEM
				fprintf(stderr, "LEVITTE_DEBUG_MEM: [%5ld] * 0x%p (%d) -> 0x%p (%d)\n",
					mp->order,
					mp->addr, mp->num,
					addr2, num);
#endif
				mp->addr=addr2;
				mp->num=num;
				(void)lh_MEM_insert(mh,mp);
				}

			MemCheck_on(); /* release MALLOC2 lock
			                * if num_disabled drops to 0 */
			}
		break;
		}
	return;
	}
/* file: BUF_strlcat : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bufferbuf_str.c */
size_t BUF_strlcat(char *dst, const char *src, size_t size)
	{
	size_t l = 0;
	for(; size > 0 && *dst; size--, dst++)
		l++;
	return l + BUF_strlcpy(dst, src, size);
	}
/* file: BUF_strlcpy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bufferbuf_str.c */
size_t BUF_strlcpy(char *dst, const char *src, size_t size)
	{
	size_t l = 0;
	for(; size > 1 && *src; size--)
		{
		*dst++ = *src++;
		l++;
		}
	if (size)
		*dst = '\0';
	return l + strlen(src);
	}
/* file: ERR_set_error_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
void ERR_set_error_data(char *data, int flags)
	{
	ERR_STATE *es;
	int i;

	es=ERR_get_state();

	i=es->top;
	if (i == 0)
		i=ERR_NUM_ERRORS-1;

	err_clear_data(es,i);
	es->err_data[i]=data;
	es->err_data_flags[i]=flags;
	}
/* file: a2i_IPADDRESS_NC : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
ASN1_OCTET_STRING *a2i_IPADDRESS_NC(const char *ipasc)
	{
	ASN1_OCTET_STRING *ret = NULL;
	unsigned char ipout[32];
	char *iptmp = NULL, *p;
	int iplen1, iplen2;
	p = strchr(ipasc,'/');
	if (!p)
		return NULL;
	iptmp = BUF_strdup(ipasc);
	if (!iptmp)
		return NULL;
	p = iptmp + (p - ipasc);
	*p++ = 0;

	iplen1 = a2i_ipadd(ipout, iptmp);

	if (!iplen1)
		goto err;

	iplen2 = a2i_ipadd(ipout + iplen1, p);

	OPENSSL_free(iptmp);
	iptmp = NULL;

	if (!iplen2 || (iplen1 != iplen2))
		goto err;

	ret = ASN1_OCTET_STRING_new();
	if (!ret)
		goto err;
	if (!ASN1_OCTET_STRING_set(ret, ipout, iplen1 + iplen2))
		goto err;

	return ret;

	err:
	if (iptmp)
		OPENSSL_free(iptmp);
	if (ret)
		ASN1_OCTET_STRING_free(ret);
	return NULL;
	}
/* file: a2i_ipadd : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
int a2i_ipadd(unsigned char *ipout, const char *ipasc)
	{
	/* If string contains a ':' assume IPv6 */

	if (strchr(ipasc, ':'))
		{
		if (!ipv6_from_asc(ipout, ipasc))
			return 0;
		return 16;
		}
	else
		{
		if (!ipv4_from_asc(ipout, ipasc))
			return 0;
		return 4;
		}
	}
/* file: ipv6_from_asc : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
static int ipv6_from_asc(unsigned char *v6, const char *in)
	{
	IPV6_STAT v6stat;
	v6stat.total = 0;
	v6stat.zero_pos = -1;
	v6stat.zero_cnt = 0;
	/* Treat the IPv6 representation as a list of values
	 * separated by ':'. The presence of a '::' will parse
 	 * as one, two or three zero length elements.
	 */
	if (!CONF_parse_list(in, ':', 0, ipv6_cb, &v6stat))
		return 0;

	/* Now for some sanity checks */

	if (v6stat.zero_pos == -1)
		{
		/* If no '::' must have exactly 16 bytes */
		if (v6stat.total != 16)
			return 0;
		}
	else 
		{
		/* If '::' must have less than 16 bytes */
		if (v6stat.total == 16)
			return 0;
		/* More than three zeroes is an error */
		if (v6stat.zero_cnt > 3)
			return 0;
		/* Can only have three zeroes if nothing else present */
		else if (v6stat.zero_cnt == 3)
			{
			if (v6stat.total > 0)
				return 0;
			}
		/* Can only have two zeroes if at start or end */
		else if (v6stat.zero_cnt == 2)
			{
			if ((v6stat.zero_pos != 0)
				&& (v6stat.zero_pos != v6stat.total))
				return 0;
			}
		else 
		/* Can only have one zero if *not* start or end */
			{
			if ((v6stat.zero_pos == 0)
				|| (v6stat.zero_pos == v6stat.total))
				return 0;
			}
		}

	/* Format result */

	if (v6stat.zero_pos >= 0)
		{
		/* Copy initial part */
		memcpy(v6, v6stat.tmp, v6stat.zero_pos);
		/* Zero middle */
		memset(v6 + v6stat.zero_pos, 0, 16 - v6stat.total);
		/* Copy final part */
		if (v6stat.total != v6stat.zero_pos)
			memcpy(v6 + v6stat.zero_pos + 16 - v6stat.total,
				v6stat.tmp + v6stat.zero_pos,
				v6stat.total - v6stat.zero_pos);
		}
	else
		memcpy(v6, v6stat.tmp, 16);

	return 1;
	}
/* file: CONF_parse_list : /Volumes/work/Phd/ECDH/kv_openssl/crypto/confconf_mod.c */
int CONF_parse_list(const char *list_, int sep, int nospc,
	int (*list_cb)(const char *elem, int len, void *usr), void *arg)
	{
	int ret;
	const char *lstart, *tmpend, *p;

	if(list_ == NULL)
		{
		CONFerr(CONF_F_CONF_PARSE_LIST, CONF_R_LIST_CANNOT_BE_NULL);
		return 0;
		}

	lstart = list_;
	for(;;)
		{
		if (nospc)
			{
			while(*lstart && isspace((unsigned char)*lstart))
				lstart++;
			}
		p = strchr(lstart, sep);
		if (p == lstart || !*lstart)
			ret = list_cb(NULL, 0, arg);
		else
			{
			if (p)
				tmpend = p - 1;
			else 
				tmpend = lstart + strlen(lstart) - 1;
			if (nospc)
				{
				while(isspace((unsigned char)*tmpend))
					tmpend--;
				}
			ret = list_cb(lstart, tmpend - lstart + 1, arg);
			}
		if (ret <= 0)
			return ret;
		if (p == NULL)
			return 1;
		lstart = p + 1;
		}
	}
/* file: ipv4_from_asc : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
static int ipv4_from_asc(unsigned char *v4, const char *in)
	{
	int a0, a1, a2, a3;
	if (sscanf(in, "%d.%d.%d.%d", &a0, &a1, &a2, &a3) != 4)
		return 0;
	if ((a0 < 0) || (a0 > 255) || (a1 < 0) || (a1 > 255)
		|| (a2 < 0) || (a2 > 255) || (a3 < 0) || (a3 > 255))
		return 0;
	v4[0] = a0;
	v4[1] = a1;
	v4[2] = a2;
	v4[3] = a3;
	return 1;
	}
/* file: ASN1_OCTET_STRING_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_octet.c */
int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *x, const unsigned char *d, int len)
{ return M_ASN1_OCTET_STRING_set(x, d, len); }
/* file: a2i_IPADDRESS : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
ASN1_OCTET_STRING *a2i_IPADDRESS(const char *ipasc)
	{
	unsigned char ipout[16];
	ASN1_OCTET_STRING *ret;
	int iplen;

	/* If string contains a ':' assume IPv6 */

	iplen = a2i_ipadd(ipout, ipasc);

	if (!iplen)
		return NULL;

	ret = ASN1_OCTET_STRING_new();
	if (!ret)
		return NULL;
	if (!ASN1_OCTET_STRING_set(ret, ipout, iplen))
		{
		ASN1_OCTET_STRING_free(ret);
		return NULL;
		}
	return ret;
	}
/* file: do_dirname : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_alt.c */
static int do_dirname(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx)
	{
	int ret;
	STACK_OF(CONF_VALUE) *sk;
	X509_NAME *nm;
	if (!(nm = X509_NAME_new()))
		return 0;
	sk = X509V3_get_section(ctx, value);
	if (!sk)
		{
		X509V3err(X509V3_F_DO_DIRNAME,X509V3_R_SECTION_NOT_FOUND);
		ERR_add_error_data(2, "section=", value);
		X509_NAME_free(nm);
		return 0;
		}
	/* FIXME: should allow other character types... */
	ret = X509V3_NAME_from_section(nm, sk, MBSTRING_ASC);
	if (!ret)
		X509_NAME_free(nm);
	gen->d.dirn = nm;
	X509V3_section_free(ctx, sk);
		
	return ret;
	}
/* file: X509V3_NAME_from_section : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
int X509V3_NAME_from_section(X509_NAME *nm, STACK_OF(CONF_VALUE)*dn_sk,
						unsigned long chtype)
	{
	CONF_VALUE *v;
	int i, mval;
	char *p, *type;
	if (!nm)
		return 0;

	for (i = 0; i < sk_CONF_VALUE_num(dn_sk); i++)
		{
		v=sk_CONF_VALUE_value(dn_sk,i);
		type=v->name;
		/* Skip past any leading X. X: X, etc to allow for
		 * multiple instances 
		 */
		for(p = type; *p ; p++) 
#ifndef CHARSET_EBCDIC
			if ((*p == ':') || (*p == ',') || (*p == '.'))
#else
			if ((*p == os_toascii[':']) || (*p == os_toascii[',']) || (*p == os_toascii['.']))
#endif
				{
				p++;
				if(*p) type = p;
				break;
				}
#ifndef CHARSET_EBCDIC
		if (*type == '+')
#else
		if (*type == os_toascii['+'])
#endif
			{
			mval = -1;
			type++;
			}
		else
			mval = 0;
		if (!X509_NAME_add_entry_by_txt(nm,type, chtype,
				(unsigned char *) v->value,-1,-1,mval))
					return 0;

		}
	return 1;
	}
/* file: X509_NAME_add_entry_by_txt : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509name.c */
int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type,
			const unsigned char *bytes, int len, int loc, int set)
{
	X509_NAME_ENTRY *ne;
	int ret;
	ne = X509_NAME_ENTRY_create_by_txt(NULL, field, type, bytes, len);
	if(!ne) return 0;
	ret = X509_NAME_add_entry(name, ne, loc, set);
	X509_NAME_ENTRY_free(ne);
	return ret;
}
/* file: X509_NAME_ENTRY_create_by_txt : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509name.c */
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne,
		const char *field, int type, const unsigned char *bytes, int len)
	{
	ASN1_OBJECT *obj;
	X509_NAME_ENTRY *nentry;

	obj=OBJ_txt2obj(field, 0);
	if (obj == NULL)
		{
		X509err(X509_F_X509_NAME_ENTRY_CREATE_BY_TXT,
						X509_R_INVALID_FIELD_NAME);
		ERR_add_error_data(2, "name=", field);
		return(NULL);
		}
	nentry = X509_NAME_ENTRY_create_by_OBJ(ne,obj,type,bytes,len);
	ASN1_OBJECT_free(obj);
	return nentry;
	}
/* file: X509_NAME_ENTRY_create_by_OBJ : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509name.c */
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_OBJ(X509_NAME_ENTRY **ne,
	     ASN1_OBJECT *obj, int type, const unsigned char *bytes, int len)
	{
	X509_NAME_ENTRY *ret;

	if ((ne == NULL) || (*ne == NULL))
		{
		if ((ret=X509_NAME_ENTRY_new()) == NULL)
			return(NULL);
		}
	else
		ret= *ne;

	if (!X509_NAME_ENTRY_set_object(ret,obj))
		goto err;
	if (!X509_NAME_ENTRY_set_data(ret,type,bytes,len))
		goto err;

	if ((ne != NULL) && (*ne == NULL)) *ne=ret;
	return(ret);
err:
	if ((ne == NULL) || (ret != *ne))
		X509_NAME_ENTRY_free(ret);
	return(NULL);
	}
/* file: X509_NAME_ENTRY_set_object : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509name.c */
int X509_NAME_ENTRY_set_object(X509_NAME_ENTRY *ne, ASN1_OBJECT *obj)
	{
	if ((ne == NULL) || (obj == NULL))
		{
		X509err(X509_F_X509_NAME_ENTRY_SET_OBJECT,ERR_R_PASSED_NULL_PARAMETER);
		return(0);
		}
	ASN1_OBJECT_free(ne->object);
	ne->object=OBJ_dup(obj);
	return((ne->object == NULL)?0:1);
	}
/* file: X509_NAME_ENTRY_set_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509name.c */
int X509_NAME_ENTRY_set_data(X509_NAME_ENTRY *ne, int type,
	     const unsigned char *bytes, int len)
	{
	int i;

	if ((ne == NULL) || ((bytes == NULL) && (len != 0))) return(0);
	if((type > 0) && (type & MBSTRING_FLAG)) 
		return ASN1_STRING_set_by_NID(&ne->value, bytes,
						len, type,
					OBJ_obj2nid(ne->object)) ? 1 : 0;
	if (len < 0) len=strlen((const char *)bytes);
	i=ASN1_STRING_set(ne->value,bytes,len);
	if (!i) return(0);
	if (type != V_ASN1_UNDEF)
		{
		if (type == V_ASN1_APP_CHOOSE)
			ne->value->type=ASN1_PRINTABLE_type(bytes,len);
		else
			ne->value->type=type;
		}
	return(1);
	}
/* file: ASN1_STRING_set_by_NID : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_strnid.c */
ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out, const unsigned char *in,
					int inlen, int inform, int nid)
{
	ASN1_STRING_TABLE *tbl;
	ASN1_STRING *str = NULL;
	unsigned long mask;
	int ret;
	if(!out) out = &str;
	tbl = ASN1_STRING_TABLE_get(nid);
	if(tbl) {
		mask = tbl->mask;
		if(!(tbl->flags & STABLE_NO_MASK)) mask &= global_mask;
		ret = ASN1_mbstring_ncopy(out, in, inlen, inform, mask,
					tbl->minsize, tbl->maxsize);
	} else ret = ASN1_mbstring_copy(out, in, inlen, inform, DIRSTRING_TYPE & global_mask);
	if(ret <= 0) return NULL;
	return *out;
}
/* file: ASN1_STRING_TABLE_get : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_strnid.c */
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid)
{
	int idx;
	ASN1_STRING_TABLE *ttmp;
	ASN1_STRING_TABLE fnd;
	fnd.nid = nid;
	ttmp = OBJ_bsearch_table(&fnd, tbl_standard, 
			   sizeof(tbl_standard)/sizeof(ASN1_STRING_TABLE));
	if(ttmp) return ttmp;
	if(!stable) return NULL;
	idx = sk_ASN1_STRING_TABLE_find(stable, &fnd);
	if(idx < 0) return NULL;
	return sk_ASN1_STRING_TABLE_value(stable, idx);
}
/* file: sk_find : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.c */
int sk_find(_STACK *st, void *data)
	{
	return internal_find(st, data, OBJ_BSEARCH_FIRST_VALUE_ON_MATCH);
	}
/* file: sk_sort : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.c */
void sk_sort(_STACK *st)
	{
	if (st && !st->sorted)
		{
		int (*comp_func)(const void *,const void *);

		/* same comment as in sk_find ... previously st->comp was declared
		 * as a (void*,void*) callback type, but this made the population
		 * of the callback pointer illogical - our callbacks compare
		 * type** with type**, so we leave the casting until absolutely
		 * necessary (ie. "now"). */
		comp_func=(int (*)(const void *,const void *))(st->comp);
		qsort(st->data,st->num,sizeof(char *), comp_func);
		st->sorted=1;
		}
	}
/* file: ASN1_mbstring_ncopy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_mbstr.c */
int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
					int inform, unsigned long mask, 
					long minsize, long maxsize)
{
	int str_type;
	int ret;
	char free_out;
	int outform, outlen = 0;
	ASN1_STRING *dest;
	unsigned char *p;
	int nchar;
	char strbuf[32];
	int (*cpyfunc)(unsigned long,void *) = NULL;
	if(len == -1) len = strlen((const char *)in);
	if(!mask) mask = DIRSTRING_TYPE;

	/* First do a string check and work out the number of characters */
	switch(inform) {

		case MBSTRING_BMP:
		if(len & 1) {
			ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY,
					 ASN1_R_INVALID_BMPSTRING_LENGTH);
			return -1;
		}
		nchar = len >> 1;
		break;

		case MBSTRING_UNIV:
		if(len & 3) {
			ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY,
					 ASN1_R_INVALID_UNIVERSALSTRING_LENGTH);
			return -1;
		}
		nchar = len >> 2;
		break;

		case MBSTRING_UTF8:
		nchar = 0;
		/* This counts the characters and does utf8 syntax checking */
		ret = traverse_string(in, len, MBSTRING_UTF8, in_utf8, &nchar);
		if(ret < 0) {
			ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY,
						 ASN1_R_INVALID_UTF8STRING);
			return -1;
		}
		break;

		case MBSTRING_ASC:
		nchar = len;
		break;

		default:
		ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_UNKNOWN_FORMAT);
		return -1;
	}

	if((minsize > 0) && (nchar < minsize)) {
		ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_STRING_TOO_SHORT);
		BIO_snprintf(strbuf, sizeof strbuf, "%ld", minsize);
		ERR_add_error_data(2, "minsize=", strbuf);
		return -1;
	}

	if((maxsize > 0) && (nchar > maxsize)) {
		ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_STRING_TOO_LONG);
		BIO_snprintf(strbuf, sizeof strbuf, "%ld", maxsize);
		ERR_add_error_data(2, "maxsize=", strbuf);
		return -1;
	}

	/* Now work out minimal type (if any) */
	if(traverse_string(in, len, inform, type_str, &mask) < 0) {
		ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_ILLEGAL_CHARACTERS);
		return -1;
	}


	/* Now work out output format and string type */
	outform = MBSTRING_ASC;
	if(mask & B_ASN1_PRINTABLESTRING) str_type = V_ASN1_PRINTABLESTRING;
	else if(mask & B_ASN1_IA5STRING) str_type = V_ASN1_IA5STRING;
	else if(mask & B_ASN1_T61STRING) str_type = V_ASN1_T61STRING;
	else if(mask & B_ASN1_BMPSTRING) {
		str_type = V_ASN1_BMPSTRING;
		outform = MBSTRING_BMP;
	} else if(mask & B_ASN1_UNIVERSALSTRING) {
		str_type = V_ASN1_UNIVERSALSTRING;
		outform = MBSTRING_UNIV;
	} else {
		str_type = V_ASN1_UTF8STRING;
		outform = MBSTRING_UTF8;
	}
	if(!out) return str_type;
	if(*out) {
		free_out = 0;
		dest = *out;
		if(dest->data) {
			dest->length = 0;
			OPENSSL_free(dest->data);
			dest->data = NULL;
		}
		dest->type = str_type;
	} else {
		free_out = 1;
		dest = ASN1_STRING_type_new(str_type);
		if(!dest) {
			ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY,
							ERR_R_MALLOC_FAILURE);
			return -1;
		}
		*out = dest;
	}
	/* If both the same type just copy across */
	if(inform == outform) {
		if(!ASN1_STRING_set(dest, in, len)) {
			ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY,ERR_R_MALLOC_FAILURE);
			return -1;
		}
		return str_type;
	} 

	/* Work out how much space the destination will need */
	switch(outform) {
		case MBSTRING_ASC:
		outlen = nchar;
		cpyfunc = cpy_asc;
		break;

		case MBSTRING_BMP:
		outlen = nchar << 1;
		cpyfunc = cpy_bmp;
		break;

		case MBSTRING_UNIV:
		outlen = nchar << 2;
		cpyfunc = cpy_univ;
		break;

		case MBSTRING_UTF8:
		outlen = 0;
		traverse_string(in, len, inform, out_utf8, &outlen);
		cpyfunc = cpy_utf8;
		break;
	}
	if(!(p = OPENSSL_malloc(outlen + 1))) {
		if(free_out) ASN1_STRING_free(dest);
		ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY,ERR_R_MALLOC_FAILURE);
		return -1;
	}
	dest->length = outlen;
	dest->data = p;
	p[outlen] = 0;
	traverse_string(in, len, inform, cpyfunc, &p);
	return str_type;	
}
/* file: traverse_string : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_mbstr.c FixMe
static int traverse_string(const unsigned char *p, int len, int inform,
		 int (*rfunc)(unsigned long value, void *in), void *arg);
static int in_utf8(unsigned long value, void *arg);
static int out_utf8(unsigned long value, void *arg);
static int type_str(unsigned long value, void *arg);
static int cpy_asc(unsigned long value, void *arg);
static int cpy_bmp(unsigned long value, void *arg);
static int cpy_univ(unsigned long value, void *arg);
static int cpy_utf8(unsigned long value, void *arg);
static int is_printable(unsigned long value); */

/* These functions take a string in UTF8, ASCII or multibyte form and
 * a mask of permissible ASN1 string types. It then works out the minimal
 * type (using the order Printable < IA5 < T61 < BMP < Universal < UTF8)
 * and creates a string of the correct type with the supplied data.
 * Yes this is horrible: it has to be :-(
 * The 'ncopy' form checks minimum and maximum size limits too.
 */

int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
					int inform, unsigned long mask)
{
	return ASN1_mbstring_ncopy(out, in, len, inform, mask, 0, 0);
}
/* file: BIO_snprintf : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
	{
	va_list args;
	int ret;

	va_start(args, format);

	ret = BIO_vsnprintf(buf, n, format, args);

	va_end(args);
	return(ret);
	}
/* file: BIO_vsnprintf : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
	{
	size_t retlen;
	int truncated;

	_dopr(&buf, NULL, &n, &retlen, &truncated, format, args);

	if (truncated)
		/* In case of truncation, return -1 like traditional snprintf.
		 * (Current drafts for ISO/IEC 9899 say snprintf should return
		 * the number of characters that would have been written,
		 * had the buffer been large enough.) */
		return -1;
	else
		return (retlen <= INT_MAX) ? (int)retlen : -1;
	}
/* file: _dopr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
static void _dopr(char **sbuffer, char **buffer,
		  size_t *maxlen, size_t *retlen, int *truncated,
		  const char *format, va_list args);

/* format read states */
#define DP_S_DEFAULT    0
#define DP_S_FLAGS      1
#define DP_S_MIN        2
#define DP_S_DOT        3
#define DP_S_MAX        4
#define DP_S_MOD        5
#define DP_S_CONV       6
#define DP_S_DONE       7

/* format flags - Bits */
#define DP_F_MINUS      (1 << 0)
#define DP_F_PLUS       (1 << 1)
#define DP_F_SPACE      (1 << 2)
#define DP_F_NUM        (1 << 3)
#define DP_F_ZERO       (1 << 4)
#define DP_F_UP         (1 << 5)
#define DP_F_UNSIGNED   (1 << 6)

/* conversion flags */
#define DP_C_SHORT      1
#define DP_C_LONG       2
#define DP_C_LDOUBLE    3
#define DP_C_LLONG      4

/* some handy macros */
#define char_to_int(p) (p - '0')
#define OSSL_MAX(p,q) ((p >= q) ? p : q)

static void
_dopr(
    char **sbuffer,
    char **buffer,
    size_t *maxlen,
    size_t *retlen,
    int *truncated,
    const char *format,
    va_list args)
{
    char ch;
    LLONG value;
    LDOUBLE fvalue;
    char *strvalue;
    int min;
    int max;
    int state;
    int flags;
    int cflags;
    size_t currlen;

    state = DP_S_DEFAULT;
    flags = currlen = cflags = min = 0;
    max = -1;
    ch = *format++;

    while (state != DP_S_DONE) {
        if (ch == '\0' || (buffer == NULL && currlen >= *maxlen))
            state = DP_S_DONE;

        switch (state) {
        case DP_S_DEFAULT:
            if (ch == '%')
                state = DP_S_FLAGS;
            else
                doapr_outch(sbuffer,buffer, &currlen, maxlen, ch);
            ch = *format++;
            break;
        case DP_S_FLAGS:
            switch (ch) {
            case '-':
                flags |= DP_F_MINUS;
                ch = *format++;
                break;
            case '+':
                flags |= DP_F_PLUS;
                ch = *format++;
                break;
            case ' ':
                flags |= DP_F_SPACE;
                ch = *format++;
                break;
            case '#':
                flags |= DP_F_NUM;
                ch = *format++;
                break;
            case '0':
                flags |= DP_F_ZERO;
                ch = *format++;
                break;
            default:
                state = DP_S_MIN;
                break;
            }
            break;
        case DP_S_MIN:
            if (isdigit((unsigned char)ch)) {
                min = 10 * min + char_to_int(ch);
                ch = *format++;
            } else if (ch == '*') {
                min = va_arg(args, int);
                ch = *format++;
                state = DP_S_DOT;
            } else
                state = DP_S_DOT;
            break;
        case DP_S_DOT:
            if (ch == '.') {
                state = DP_S_MAX;
                ch = *format++;
            } else
                state = DP_S_MOD;
            break;
        case DP_S_MAX:
            if (isdigit((unsigned char)ch)) {
                if (max < 0)
                    max = 0;
                max = 10 * max + char_to_int(ch);
                ch = *format++;
            } else if (ch == '*') {
                max = va_arg(args, int);
                ch = *format++;
                state = DP_S_MOD;
            } else
                state = DP_S_MOD;
            break;
        case DP_S_MOD:
            switch (ch) {
            case 'h':
                cflags = DP_C_SHORT;
                ch = *format++;
                break;
            case 'l':
                if (*format == 'l') {
                    cflags = DP_C_LLONG;
                    format++;
                } else
                    cflags = DP_C_LONG;
                ch = *format++;
                break;
            case 'q':
                cflags = DP_C_LLONG;
                ch = *format++;
                break;
            case 'L':
                cflags = DP_C_LDOUBLE;
                ch = *format++;
                break;
            default:
                break;
            }
            state = DP_S_CONV;
            break;
        case DP_S_CONV:
            switch (ch) {
            case 'd':
            case 'i':
                switch (cflags) {
                case DP_C_SHORT:
                    value = (short int)va_arg(args, int);
                    break;
                case DP_C_LONG:
                    value = va_arg(args, long int);
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, LLONG);
                    break;
                default:
                    value = va_arg(args, int);
                    break;
                }
                fmtint(sbuffer, buffer, &currlen, maxlen,
                       value, 10, min, max, flags);
                break;
            case 'X':
                flags |= DP_F_UP;
                /* FALLTHROUGH */
            case 'x':
            case 'o':
            case 'u':
                flags |= DP_F_UNSIGNED;
                switch (cflags) {
                case DP_C_SHORT:
                    value = (unsigned short int)va_arg(args, unsigned int);
                    break;
                case DP_C_LONG:
                    value = (LLONG) va_arg(args,
                        unsigned long int);
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, unsigned LLONG);
                    break;
                default:
                    value = (LLONG) va_arg(args,
                        unsigned int);
                    break;
                }
                fmtint(sbuffer, buffer, &currlen, maxlen, value,
                       ch == 'o' ? 8 : (ch == 'u' ? 10 : 16),
                       min, max, flags);
                break;
            case 'f':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                fmtfp(sbuffer, buffer, &currlen, maxlen,
                      fvalue, min, max, flags);
                break;
            case 'E':
                flags |= DP_F_UP;
            case 'e':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                break;
            case 'G':
                flags |= DP_F_UP;
            case 'g':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                break;
            case 'c':
                doapr_outch(sbuffer, buffer, &currlen, maxlen,
                    va_arg(args, int));
                break;
            case 's':
                strvalue = va_arg(args, char *);
                if (max < 0) {
		    if (buffer)
			max = INT_MAX;
		    else
			max = *maxlen;
		}
                fmtstr(sbuffer, buffer, &currlen, maxlen, strvalue,
                       flags, min, max);
                break;
            case 'p':
                value = (long)va_arg(args, void *);
                fmtint(sbuffer, buffer, &currlen, maxlen,
                    value, 16, min, max, flags|DP_F_NUM);
                break;
            case 'n': /* XXX */
                if (cflags == DP_C_SHORT) {
                    short int *num;
                    num = va_arg(args, short int *);
                    *num = currlen;
                } else if (cflags == DP_C_LONG) { /* XXX */
                    long int *num;
                    num = va_arg(args, long int *);
                    *num = (long int) currlen;
                } else if (cflags == DP_C_LLONG) { /* XXX */
                    LLONG *num;
                    num = va_arg(args, LLONG *);
                    *num = (LLONG) currlen;
                } else {
                    int    *num;
                    num = va_arg(args, int *);
                    *num = currlen;
                }
                break;
            case '%':
                doapr_outch(sbuffer, buffer, &currlen, maxlen, ch);
                break;
            case 'w':
                /* not supported yet, treat as next char */
                ch = *format++;
                break;
            default:
                /* unknown, skip */
                break;
            }
            ch = *format++;
            state = DP_S_DEFAULT;
            flags = cflags = min = 0;
            max = -1;
            break;
        case DP_S_DONE:
            break;
        default:
            break;
        }
    }
    *truncated = (currlen > *maxlen - 1);
    if (*truncated)
        currlen = *maxlen - 1;
    doapr_outch(sbuffer, buffer, &currlen, maxlen, '\0');
    *retlen = currlen - 1;
    return;
}
/* file: fmtint : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c FixMe
static void fmtint     (char **, char **, size_t *, size_t *,
			LLONG, int, int, int, int);
static void fmtfp      (char **, char **, size_t *, size_t *,
			LDOUBLE, int, int, int);
static void doapr_outch (char **, char **, size_t *, size_t *, int);
static void _dopr(char **sbuffer, char **buffer,
		  size_t *maxlen, size_t *retlen, int *truncated,
		  const char *format, va_list args); */

/* format read states */
#define DP_S_DEFAULT    0
#define DP_S_FLAGS      1
#define DP_S_MIN        2
#define DP_S_DOT        3
#define DP_S_MAX        4
#define DP_S_MOD        5
#define DP_S_CONV       6
#define DP_S_DONE       7

/* format flags - Bits */
#define DP_F_MINUS      (1 << 0)
#define DP_F_PLUS       (1 << 1)
#define DP_F_SPACE      (1 << 2)
#define DP_F_NUM        (1 << 3)
#define DP_F_ZERO       (1 << 4)
#define DP_F_UP         (1 << 5)
#define DP_F_UNSIGNED   (1 << 6)

/* conversion flags */
#define DP_C_SHORT      1
#define DP_C_LONG       2
#define DP_C_LDOUBLE    3
#define DP_C_LLONG      4

/* some handy macros */
#define char_to_int(p) (p - '0')
#define OSSL_MAX(p,q) ((p >= q) ? p : q)

static void
_dopr(
    char **sbuffer,
    char **buffer,
    size_t *maxlen,
    size_t *retlen,
    int *truncated,
    const char *format,
    va_list args)
{
    char ch;
    LLONG value;
    LDOUBLE fvalue;
    char *strvalue;
    int min;
    int max;
    int state;
    int flags;
    int cflags;
    size_t currlen;

    state = DP_S_DEFAULT;
    flags = currlen = cflags = min = 0;
    max = -1;
    ch = *format++;

    while (state != DP_S_DONE) {
        if (ch == '\0' || (buffer == NULL && currlen >= *maxlen))
            state = DP_S_DONE;

        switch (state) {
        case DP_S_DEFAULT:
            if (ch == '%')
                state = DP_S_FLAGS;
            else
                doapr_outch(sbuffer,buffer, &currlen, maxlen, ch);
            ch = *format++;
            break;
        case DP_S_FLAGS:
            switch (ch) {
            case '-':
                flags |= DP_F_MINUS;
                ch = *format++;
                break;
            case '+':
                flags |= DP_F_PLUS;
                ch = *format++;
                break;
            case ' ':
                flags |= DP_F_SPACE;
                ch = *format++;
                break;
            case '#':
                flags |= DP_F_NUM;
                ch = *format++;
                break;
            case '0':
                flags |= DP_F_ZERO;
                ch = *format++;
                break;
            default:
                state = DP_S_MIN;
                break;
            }
            break;
        case DP_S_MIN:
            if (isdigit((unsigned char)ch)) {
                min = 10 * min + char_to_int(ch);
                ch = *format++;
            } else if (ch == '*') {
                min = va_arg(args, int);
                ch = *format++;
                state = DP_S_DOT;
            } else
                state = DP_S_DOT;
            break;
        case DP_S_DOT:
            if (ch == '.') {
                state = DP_S_MAX;
                ch = *format++;
            } else
                state = DP_S_MOD;
            break;
        case DP_S_MAX:
            if (isdigit((unsigned char)ch)) {
                if (max < 0)
                    max = 0;
                max = 10 * max + char_to_int(ch);
                ch = *format++;
            } else if (ch == '*') {
                max = va_arg(args, int);
                ch = *format++;
                state = DP_S_MOD;
            } else
                state = DP_S_MOD;
            break;
        case DP_S_MOD:
            switch (ch) {
            case 'h':
                cflags = DP_C_SHORT;
                ch = *format++;
                break;
            case 'l':
                if (*format == 'l') {
                    cflags = DP_C_LLONG;
                    format++;
                } else
                    cflags = DP_C_LONG;
                ch = *format++;
                break;
            case 'q':
                cflags = DP_C_LLONG;
                ch = *format++;
                break;
            case 'L':
                cflags = DP_C_LDOUBLE;
                ch = *format++;
                break;
            default:
                break;
            }
            state = DP_S_CONV;
            break;
        case DP_S_CONV:
            switch (ch) {
            case 'd':
            case 'i':
                switch (cflags) {
                case DP_C_SHORT:
                    value = (short int)va_arg(args, int);
                    break;
                case DP_C_LONG:
                    value = va_arg(args, long int);
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, LLONG);
                    break;
                default:
                    value = va_arg(args, int);
                    break;
                }
                fmtint(sbuffer, buffer, &currlen, maxlen,
                       value, 10, min, max, flags);
                break;
            case 'X':
                flags |= DP_F_UP;
                /* FALLTHROUGH */
            case 'x':
            case 'o':
            case 'u':
                flags |= DP_F_UNSIGNED;
                switch (cflags) {
                case DP_C_SHORT:
                    value = (unsigned short int)va_arg(args, unsigned int);
                    break;
                case DP_C_LONG:
                    value = (LLONG) va_arg(args,
                        unsigned long int);
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, unsigned LLONG);
                    break;
                default:
                    value = (LLONG) va_arg(args,
                        unsigned int);
                    break;
                }
                fmtint(sbuffer, buffer, &currlen, maxlen, value,
                       ch == 'o' ? 8 : (ch == 'u' ? 10 : 16),
                       min, max, flags);
                break;
            case 'f':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                fmtfp(sbuffer, buffer, &currlen, maxlen,
                      fvalue, min, max, flags);
                break;
            case 'E':
                flags |= DP_F_UP;
            case 'e':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                break;
            case 'G':
                flags |= DP_F_UP;
            case 'g':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                break;
            case 'c':
                doapr_outch(sbuffer, buffer, &currlen, maxlen,
                    va_arg(args, int));
                break;
            case 's':
                strvalue = va_arg(args, char *);
                if (max < 0) {
		    if (buffer)
			max = INT_MAX;
		    else
			max = *maxlen;
		}
                fmtstr(sbuffer, buffer, &currlen, maxlen, strvalue,
                       flags, min, max);
                break;
            case 'p':
                value = (long)va_arg(args, void *);
                fmtint(sbuffer, buffer, &currlen, maxlen,
                    value, 16, min, max, flags|DP_F_NUM);
                break;
            case 'n': /* XXX */
                if (cflags == DP_C_SHORT) {
                    short int *num;
                    num = va_arg(args, short int *);
                    *num = currlen;
                } else if (cflags == DP_C_LONG) { /* XXX */
                    long int *num;
                    num = va_arg(args, long int *);
                    *num = (long int) currlen;
                } else if (cflags == DP_C_LLONG) { /* XXX */
                    LLONG *num;
                    num = va_arg(args, LLONG *);
                    *num = (LLONG) currlen;
                } else {
                    int    *num;
                    num = va_arg(args, int *);
                    *num = currlen;
                }
                break;
            case '%':
                doapr_outch(sbuffer, buffer, &currlen, maxlen, ch);
                break;
            case 'w':
                /* not supported yet, treat as next char */
                ch = *format++;
                break;
            default:
                /* unknown, skip */
                break;
            }
            ch = *format++;
            state = DP_S_DEFAULT;
            flags = cflags = min = 0;
            max = -1;
            break;
        case DP_S_DONE:
            break;
        default:
            break;
        }
    }
    *truncated = (currlen > *maxlen - 1);
    if (*truncated)
        currlen = *maxlen - 1;
    doapr_outch(sbuffer, buffer, &currlen, maxlen, '\0');
    *retlen = currlen - 1;
    return;
}
/* file: fmtfp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c FixMe
static void fmtfp      (char **, char **, size_t *, size_t *,
			LDOUBLE, int, int, int);
static void doapr_outch (char **, char **, size_t *, size_t *, int);
static void _dopr(char **sbuffer, char **buffer,
		  size_t *maxlen, size_t *retlen, int *truncated,
		  const char *format, va_list args); */

/* format read states */
#define DP_S_DEFAULT    0
#define DP_S_FLAGS      1
#define DP_S_MIN        2
#define DP_S_DOT        3
#define DP_S_MAX        4
#define DP_S_MOD        5
#define DP_S_CONV       6
#define DP_S_DONE       7

/* format flags - Bits */
#define DP_F_MINUS      (1 << 0)
#define DP_F_PLUS       (1 << 1)
#define DP_F_SPACE      (1 << 2)
#define DP_F_NUM        (1 << 3)
#define DP_F_ZERO       (1 << 4)
#define DP_F_UP         (1 << 5)
#define DP_F_UNSIGNED   (1 << 6)

/* conversion flags */
#define DP_C_SHORT      1
#define DP_C_LONG       2
#define DP_C_LDOUBLE    3
#define DP_C_LLONG      4

/* some handy macros */
#define char_to_int(p) (p - '0')
#define OSSL_MAX(p,q) ((p >= q) ? p : q)

static void
_dopr(
    char **sbuffer,
    char **buffer,
    size_t *maxlen,
    size_t *retlen,
    int *truncated,
    const char *format,
    va_list args)
{
    char ch;
    LLONG value;
    LDOUBLE fvalue;
    char *strvalue;
    int min;
    int max;
    int state;
    int flags;
    int cflags;
    size_t currlen;

    state = DP_S_DEFAULT;
    flags = currlen = cflags = min = 0;
    max = -1;
    ch = *format++;

    while (state != DP_S_DONE) {
        if (ch == '\0' || (buffer == NULL && currlen >= *maxlen))
            state = DP_S_DONE;

        switch (state) {
        case DP_S_DEFAULT:
            if (ch == '%')
                state = DP_S_FLAGS;
            else
                doapr_outch(sbuffer,buffer, &currlen, maxlen, ch);
            ch = *format++;
            break;
        case DP_S_FLAGS:
            switch (ch) {
            case '-':
                flags |= DP_F_MINUS;
                ch = *format++;
                break;
            case '+':
                flags |= DP_F_PLUS;
                ch = *format++;
                break;
            case ' ':
                flags |= DP_F_SPACE;
                ch = *format++;
                break;
            case '#':
                flags |= DP_F_NUM;
                ch = *format++;
                break;
            case '0':
                flags |= DP_F_ZERO;
                ch = *format++;
                break;
            default:
                state = DP_S_MIN;
                break;
            }
            break;
        case DP_S_MIN:
            if (isdigit((unsigned char)ch)) {
                min = 10 * min + char_to_int(ch);
                ch = *format++;
            } else if (ch == '*') {
                min = va_arg(args, int);
                ch = *format++;
                state = DP_S_DOT;
            } else
                state = DP_S_DOT;
            break;
        case DP_S_DOT:
            if (ch == '.') {
                state = DP_S_MAX;
                ch = *format++;
            } else
                state = DP_S_MOD;
            break;
        case DP_S_MAX:
            if (isdigit((unsigned char)ch)) {
                if (max < 0)
                    max = 0;
                max = 10 * max + char_to_int(ch);
                ch = *format++;
            } else if (ch == '*') {
                max = va_arg(args, int);
                ch = *format++;
                state = DP_S_MOD;
            } else
                state = DP_S_MOD;
            break;
        case DP_S_MOD:
            switch (ch) {
            case 'h':
                cflags = DP_C_SHORT;
                ch = *format++;
                break;
            case 'l':
                if (*format == 'l') {
                    cflags = DP_C_LLONG;
                    format++;
                } else
                    cflags = DP_C_LONG;
                ch = *format++;
                break;
            case 'q':
                cflags = DP_C_LLONG;
                ch = *format++;
                break;
            case 'L':
                cflags = DP_C_LDOUBLE;
                ch = *format++;
                break;
            default:
                break;
            }
            state = DP_S_CONV;
            break;
        case DP_S_CONV:
            switch (ch) {
            case 'd':
            case 'i':
                switch (cflags) {
                case DP_C_SHORT:
                    value = (short int)va_arg(args, int);
                    break;
                case DP_C_LONG:
                    value = va_arg(args, long int);
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, LLONG);
                    break;
                default:
                    value = va_arg(args, int);
                    break;
                }
                fmtint(sbuffer, buffer, &currlen, maxlen,
                       value, 10, min, max, flags);
                break;
            case 'X':
                flags |= DP_F_UP;
                /* FALLTHROUGH */
            case 'x':
            case 'o':
            case 'u':
                flags |= DP_F_UNSIGNED;
                switch (cflags) {
                case DP_C_SHORT:
                    value = (unsigned short int)va_arg(args, unsigned int);
                    break;
                case DP_C_LONG:
                    value = (LLONG) va_arg(args,
                        unsigned long int);
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, unsigned LLONG);
                    break;
                default:
                    value = (LLONG) va_arg(args,
                        unsigned int);
                    break;
                }
                fmtint(sbuffer, buffer, &currlen, maxlen, value,
                       ch == 'o' ? 8 : (ch == 'u' ? 10 : 16),
                       min, max, flags);
                break;
            case 'f':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                fmtfp(sbuffer, buffer, &currlen, maxlen,
                      fvalue, min, max, flags);
                break;
            case 'E':
                flags |= DP_F_UP;
            case 'e':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                break;
            case 'G':
                flags |= DP_F_UP;
            case 'g':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                break;
            case 'c':
                doapr_outch(sbuffer, buffer, &currlen, maxlen,
                    va_arg(args, int));
                break;
            case 's':
                strvalue = va_arg(args, char *);
                if (max < 0) {
		    if (buffer)
			max = INT_MAX;
		    else
			max = *maxlen;
		}
                fmtstr(sbuffer, buffer, &currlen, maxlen, strvalue,
                       flags, min, max);
                break;
            case 'p':
                value = (long)va_arg(args, void *);
                fmtint(sbuffer, buffer, &currlen, maxlen,
                    value, 16, min, max, flags|DP_F_NUM);
                break;
            case 'n': /* XXX */
                if (cflags == DP_C_SHORT) {
                    short int *num;
                    num = va_arg(args, short int *);
                    *num = currlen;
                } else if (cflags == DP_C_LONG) { /* XXX */
                    long int *num;
                    num = va_arg(args, long int *);
                    *num = (long int) currlen;
                } else if (cflags == DP_C_LLONG) { /* XXX */
                    LLONG *num;
                    num = va_arg(args, LLONG *);
                    *num = (LLONG) currlen;
                } else {
                    int    *num;
                    num = va_arg(args, int *);
                    *num = currlen;
                }
                break;
            case '%':
                doapr_outch(sbuffer, buffer, &currlen, maxlen, ch);
                break;
            case 'w':
                /* not supported yet, treat as next char */
                ch = *format++;
                break;
            default:
                /* unknown, skip */
                break;
            }
            ch = *format++;
            state = DP_S_DEFAULT;
            flags = cflags = min = 0;
            max = -1;
            break;
        case DP_S_DONE:
            break;
        default:
            break;
        }
    }
    *truncated = (currlen > *maxlen - 1);
    if (*truncated)
        currlen = *maxlen - 1;
    doapr_outch(sbuffer, buffer, &currlen, maxlen, '\0');
    *retlen = currlen - 1;
    return;
}
/* file: fmtstr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c FixMe
static void fmtstr     (char **, char **, size_t *, size_t *,
			const char *, int, int, int);
static void fmtint     (char **, char **, size_t *, size_t *,
			LLONG, int, int, int, int);
static void fmtfp      (char **, char **, size_t *, size_t *,
			LDOUBLE, int, int, int);
static void doapr_outch (char **, char **, size_t *, size_t *, int);
static void _dopr(char **sbuffer, char **buffer,
		  size_t *maxlen, size_t *retlen, int *truncated,
		  const char *format, va_list args); */

/* format read states */
#define DP_S_DEFAULT    0
#define DP_S_FLAGS      1
#define DP_S_MIN        2
#define DP_S_DOT        3
#define DP_S_MAX        4
#define DP_S_MOD        5
#define DP_S_CONV       6
#define DP_S_DONE       7

/* format flags - Bits */
#define DP_F_MINUS      (1 << 0)
#define DP_F_PLUS       (1 << 1)
#define DP_F_SPACE      (1 << 2)
#define DP_F_NUM        (1 << 3)
#define DP_F_ZERO       (1 << 4)
#define DP_F_UP         (1 << 5)
#define DP_F_UNSIGNED   (1 << 6)

/* conversion flags */
#define DP_C_SHORT      1
#define DP_C_LONG       2
#define DP_C_LDOUBLE    3
#define DP_C_LLONG      4

/* some handy macros */
#define char_to_int(p) (p - '0')
#define OSSL_MAX(p,q) ((p >= q) ? p : q)

static void
_dopr(
    char **sbuffer,
    char **buffer,
    size_t *maxlen,
    size_t *retlen,
    int *truncated,
    const char *format,
    va_list args)
{
    char ch;
    LLONG value;
    LDOUBLE fvalue;
    char *strvalue;
    int min;
    int max;
    int state;
    int flags;
    int cflags;
    size_t currlen;

    state = DP_S_DEFAULT;
    flags = currlen = cflags = min = 0;
    max = -1;
    ch = *format++;

    while (state != DP_S_DONE) {
        if (ch == '\0' || (buffer == NULL && currlen >= *maxlen))
            state = DP_S_DONE;

        switch (state) {
        case DP_S_DEFAULT:
            if (ch == '%')
                state = DP_S_FLAGS;
            else
                doapr_outch(sbuffer,buffer, &currlen, maxlen, ch);
            ch = *format++;
            break;
        case DP_S_FLAGS:
            switch (ch) {
            case '-':
                flags |= DP_F_MINUS;
                ch = *format++;
                break;
            case '+':
                flags |= DP_F_PLUS;
                ch = *format++;
                break;
            case ' ':
                flags |= DP_F_SPACE;
                ch = *format++;
                break;
            case '#':
                flags |= DP_F_NUM;
                ch = *format++;
                break;
            case '0':
                flags |= DP_F_ZERO;
                ch = *format++;
                break;
            default:
                state = DP_S_MIN;
                break;
            }
            break;
        case DP_S_MIN:
            if (isdigit((unsigned char)ch)) {
                min = 10 * min + char_to_int(ch);
                ch = *format++;
            } else if (ch == '*') {
                min = va_arg(args, int);
                ch = *format++;
                state = DP_S_DOT;
            } else
                state = DP_S_DOT;
            break;
        case DP_S_DOT:
            if (ch == '.') {
                state = DP_S_MAX;
                ch = *format++;
            } else
                state = DP_S_MOD;
            break;
        case DP_S_MAX:
            if (isdigit((unsigned char)ch)) {
                if (max < 0)
                    max = 0;
                max = 10 * max + char_to_int(ch);
                ch = *format++;
            } else if (ch == '*') {
                max = va_arg(args, int);
                ch = *format++;
                state = DP_S_MOD;
            } else
                state = DP_S_MOD;
            break;
        case DP_S_MOD:
            switch (ch) {
            case 'h':
                cflags = DP_C_SHORT;
                ch = *format++;
                break;
            case 'l':
                if (*format == 'l') {
                    cflags = DP_C_LLONG;
                    format++;
                } else
                    cflags = DP_C_LONG;
                ch = *format++;
                break;
            case 'q':
                cflags = DP_C_LLONG;
                ch = *format++;
                break;
            case 'L':
                cflags = DP_C_LDOUBLE;
                ch = *format++;
                break;
            default:
                break;
            }
            state = DP_S_CONV;
            break;
        case DP_S_CONV:
            switch (ch) {
            case 'd':
            case 'i':
                switch (cflags) {
                case DP_C_SHORT:
                    value = (short int)va_arg(args, int);
                    break;
                case DP_C_LONG:
                    value = va_arg(args, long int);
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, LLONG);
                    break;
                default:
                    value = va_arg(args, int);
                    break;
                }
                fmtint(sbuffer, buffer, &currlen, maxlen,
                       value, 10, min, max, flags);
                break;
            case 'X':
                flags |= DP_F_UP;
                /* FALLTHROUGH */
            case 'x':
            case 'o':
            case 'u':
                flags |= DP_F_UNSIGNED;
                switch (cflags) {
                case DP_C_SHORT:
                    value = (unsigned short int)va_arg(args, unsigned int);
                    break;
                case DP_C_LONG:
                    value = (LLONG) va_arg(args,
                        unsigned long int);
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, unsigned LLONG);
                    break;
                default:
                    value = (LLONG) va_arg(args,
                        unsigned int);
                    break;
                }
                fmtint(sbuffer, buffer, &currlen, maxlen, value,
                       ch == 'o' ? 8 : (ch == 'u' ? 10 : 16),
                       min, max, flags);
                break;
            case 'f':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                fmtfp(sbuffer, buffer, &currlen, maxlen,
                      fvalue, min, max, flags);
                break;
            case 'E':
                flags |= DP_F_UP;
            case 'e':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                break;
            case 'G':
                flags |= DP_F_UP;
            case 'g':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                break;
            case 'c':
                doapr_outch(sbuffer, buffer, &currlen, maxlen,
                    va_arg(args, int));
                break;
            case 's':
                strvalue = va_arg(args, char *);
                if (max < 0) {
		    if (buffer)
			max = INT_MAX;
		    else
			max = *maxlen;
		}
                fmtstr(sbuffer, buffer, &currlen, maxlen, strvalue,
                       flags, min, max);
                break;
            case 'p':
                value = (long)va_arg(args, void *);
                fmtint(sbuffer, buffer, &currlen, maxlen,
                    value, 16, min, max, flags|DP_F_NUM);
                break;
            case 'n': /* XXX */
                if (cflags == DP_C_SHORT) {
                    short int *num;
                    num = va_arg(args, short int *);
                    *num = currlen;
                } else if (cflags == DP_C_LONG) { /* XXX */
                    long int *num;
                    num = va_arg(args, long int *);
                    *num = (long int) currlen;
                } else if (cflags == DP_C_LLONG) { /* XXX */
                    LLONG *num;
                    num = va_arg(args, LLONG *);
                    *num = (LLONG) currlen;
                } else {
                    int    *num;
                    num = va_arg(args, int *);
                    *num = currlen;
                }
                break;
            case '%':
                doapr_outch(sbuffer, buffer, &currlen, maxlen, ch);
                break;
            case 'w':
                /* not supported yet, treat as next char */
                ch = *format++;
                break;
            default:
                /* unknown, skip */
                break;
            }
            ch = *format++;
            state = DP_S_DEFAULT;
            flags = cflags = min = 0;
            max = -1;
            break;
        case DP_S_DONE:
            break;
        default:
            break;
        }
    }
    *truncated = (currlen > *maxlen - 1);
    if (*truncated)
        currlen = *maxlen - 1;
    doapr_outch(sbuffer, buffer, &currlen, maxlen, '\0');
    *retlen = currlen - 1;
    return;
}
/* file: ASN1_STRING_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_lib.c */
int ASN1_STRING_set(ASN1_STRING *str, const void *_data, int len)
	{
	unsigned char *c;
	const char *data=_data;

	if (len < 0)
		{
		if (data == NULL)
			return(0);
		else
			len=strlen(data);
		}
	if ((str->length < len) || (str->data == NULL))
		{
		c=str->data;
		if (c == NULL)
			str->data=OPENSSL_malloc(len+1);
		else
			str->data=OPENSSL_realloc(c,len+1);

		if (str->data == NULL)
			{
			ASN1err(ASN1_F_ASN1_STRING_SET,ERR_R_MALLOC_FAILURE);
			str->data=c;
			return(0);
			}
		}
	str->length=len;
	if (data != NULL)
		{
		memcpy(str->data,data,len);
		/* an allowance for strings :-) */
		str->data[len]='\0';
		}
	return(1);
	}
/* file: ASN1_STRING_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_lib.c */
void ASN1_STRING_free(ASN1_STRING *a)
	{
	if (a == NULL) return;
	if (a->data && !(a->flags & ASN1_STRING_FLAG_NDEF))
		OPENSSL_free(a->data);
	OPENSSL_free(a);
	}
/* file: ASN1_mbstring_copy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_mbstr.c */
int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
					int inform, unsigned long mask)
{
	return ASN1_mbstring_ncopy(out, in, len, inform, mask, 0, 0);
}
/* file: OBJ_obj2nid : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobj_dat.c */
int OBJ_obj2nid(const ASN1_OBJECT *a)
	{
	const unsigned int *op;
	ADDED_OBJ ad,*adp;

	if (a == NULL)
		return(NID_undef);
	if (a->nid != 0)
		return(a->nid);

	if (added != NULL)
		{
		ad.type=ADDED_DATA;
		ad.obj=(ASN1_OBJECT *)a; /* XXX: ugly but harmless */
		adp=lh_ADDED_OBJ_retrieve(added,&ad);
		if (adp != NULL) return (adp->obj->nid);
		}
	op=OBJ_bsearch_obj(&a, obj_objs, NUM_OBJ);
	if (op == NULL)
		return(NID_undef);
	return(nid_objs[*op].nid);
	}
/* file: ASN1_PRINTABLE_type : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_print.c */
int ASN1_PRINTABLE_type(const unsigned char *s, int len)
	{
	int c;
	int ia5=0;
	int t61=0;

	if (len <= 0) len= -1;
	if (s == NULL) return(V_ASN1_PRINTABLESTRING);

	while ((*s) && (len-- != 0))
		{
		c= *(s++);
#ifndef CHARSET_EBCDIC
		if (!(	((c >= 'a') && (c <= 'z')) ||
			((c >= 'A') && (c <= 'Z')) ||
			(c == ' ') ||
			((c >= '0') && (c <= '9')) ||
			(c == ' ') || (c == '\'') ||
			(c == '(') || (c == ')') ||
			(c == '+') || (c == ',') ||
			(c == '-') || (c == '.') ||
			(c == '/') || (c == ':') ||
			(c == '=') || (c == '?')))
			ia5=1;
		if (c&0x80)
			t61=1;
#else
		if (!isalnum(c) && (c != ' ') &&
		    strchr("'()+,-./:=?", c) == NULL)
			ia5=1;
		if (os_toascii[c] & 0x80)
			t61=1;
#endif
		}
	if (t61) return(V_ASN1_T61STRING);
	if (ia5) return(V_ASN1_IA5STRING);
	return(V_ASN1_PRINTABLESTRING);
	}
/* file: X509_NAME_add_entry : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509name.c */
int X509_NAME_add_entry(X509_NAME *name, X509_NAME_ENTRY *ne, int loc,
	     int set)
	{
	X509_NAME_ENTRY *new_name=NULL;
	int n,i,inc;
	STACK_OF(X509_NAME_ENTRY) *sk;

	if (name == NULL) return(0);
	sk=name->entries;
	n=sk_X509_NAME_ENTRY_num(sk);
	if (loc > n) loc=n;
	else if (loc < 0) loc=n;

	name->modified=1;

	if (set == -1)
		{
		if (loc == 0)
			{
			set=0;
			inc=1;
			}
		else
			{
			set=sk_X509_NAME_ENTRY_value(sk,loc-1)->set;
			inc=0;
			}
		}
	else /* if (set >= 0) */
		{
		if (loc >= n)
			{
			if (loc != 0)
				set=sk_X509_NAME_ENTRY_value(sk,loc-1)->set+1;
			else
				set=0;
			}
		else
			set=sk_X509_NAME_ENTRY_value(sk,loc)->set;
		inc=(set == 0)?1:0;
		}

	if ((new_name=X509_NAME_ENTRY_dup(ne)) == NULL)
		goto err;
	new_name->set=set;
	if (!sk_X509_NAME_ENTRY_insert(sk,new_name,loc))
		{
		X509err(X509_F_X509_NAME_ADD_ENTRY,ERR_R_MALLOC_FAILURE);
		goto err;
		}
	if (inc)
		{
		n=sk_X509_NAME_ENTRY_num(sk);
		for (i=loc+1; i<n; i++)
			sk_X509_NAME_ENTRY_value(sk,i-1)->set+=1;
		}	
	return(1);
err:
	if (new_name != NULL)
		X509_NAME_ENTRY_free(new_name);
	return(0);
	}
/* file: sk_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.c */
int sk_insert(_STACK *st, void *data, int loc)
	{
	char **s;

	if(st == NULL) return 0;
	if (st->num_alloc <= st->num+1)
		{
		s=OPENSSL_realloc((char *)st->data,
			(unsigned int)sizeof(char *)*st->num_alloc*2);
		if (s == NULL)
			return(0);
		st->data=s;
		st->num_alloc*=2;
		}
	if ((loc >= (int)st->num) || (loc < 0))
		st->data[st->num]=data;
	else
		{
		int i;
		char **f,**t;

		f=st->data;
		t=&(st->data[1]);
		for (i=st->num; i>=loc; i--)
			t[i]=f[i];
			
#ifdef undef /* no memmove on sunos :-( */
		memmove(&(st->data[loc+1]),
			&(st->data[loc]),
			sizeof(char *)*(st->num-loc));
#endif
		st->data[loc]=data;
		}
	st->num++;
	st->sorted=0;
	return(st->num);
	}
/* file: X509V3_section_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_conf.c */
void X509V3_section_free(X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section)
	{
	if (!section) return;
	if (ctx->db_meth->free_section)
			ctx->db_meth->free_section(ctx->db, section);
	}
/* file: do_othername : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_alt.c */
static int do_othername(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx)
	{
	char *objtmp = NULL, *p;
	int objlen;
	if (!(p = strchr(value, ';')))
		return 0;
	if (!(gen->d.otherName = OTHERNAME_new()))
		return 0;
	/* Free this up because we will overwrite it.
	 * no need to free type_id because it is static
	 */
	ASN1_TYPE_free(gen->d.otherName->value);
	if (!(gen->d.otherName->value = ASN1_generate_v3(p + 1, ctx)))
		return 0;
	objlen = p - value;
	objtmp = OPENSSL_malloc(objlen + 1);
	strncpy(objtmp, value, objlen);
	objtmp[objlen] = 0;
	gen->d.otherName->type_id = OBJ_txt2obj(objtmp, 0);
	OPENSSL_free(objtmp);	
	if (!gen->d.otherName->type_id)
		return 0;
	return 1;
	}
/* file: ASN1_generate_v3 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_gen.c */
ASN1_TYPE *ASN1_generate_v3(char *str, X509V3_CTX *cnf)
	{
	ASN1_TYPE *ret;
	tag_exp_arg asn1_tags;
	tag_exp_type *etmp;

	int i, len;

	unsigned char *orig_der = NULL, *new_der = NULL;
	const unsigned char *cpy_start;
	unsigned char *p;
	const unsigned char *cp;
	int cpy_len;
	long hdr_len;
	int hdr_constructed = 0, hdr_tag, hdr_class;
	int r;

	asn1_tags.imp_tag = -1;
	asn1_tags.imp_class = -1;
	asn1_tags.format = ASN1_GEN_FORMAT_ASCII;
	asn1_tags.exp_count = 0;
	if (CONF_parse_list(str, ',', 1, asn1_cb, &asn1_tags) != 0)
		return NULL;

	if ((asn1_tags.utype == V_ASN1_SEQUENCE) || (asn1_tags.utype == V_ASN1_SET))
		{
		if (!cnf)
			{
			ASN1err(ASN1_F_ASN1_GENERATE_V3, ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG);
			return NULL;
			}
		ret = asn1_multi(asn1_tags.utype, asn1_tags.str, cnf);
		}
	else
		ret = asn1_str2type(asn1_tags.str, asn1_tags.format, asn1_tags.utype);

	if (!ret)
		return NULL;

	/* If no tagging return base type */
	if ((asn1_tags.imp_tag == -1) && (asn1_tags.exp_count == 0))
		return ret;

	/* Generate the encoding */
	cpy_len = i2d_ASN1_TYPE(ret, &orig_der);
	ASN1_TYPE_free(ret);
	ret = NULL;
	/* Set point to start copying for modified encoding */
	cpy_start = orig_der;

	/* Do we need IMPLICIT tagging? */
	if (asn1_tags.imp_tag != -1)
		{
		/* If IMPLICIT we will replace the underlying tag */
		/* Skip existing tag+len */
		r = ASN1_get_object(&cpy_start, &hdr_len, &hdr_tag, &hdr_class, cpy_len);
		if (r & 0x80)
			goto err;
		/* Update copy length */
		cpy_len -= cpy_start - orig_der;
		/* For IMPLICIT tagging the length should match the
		 * original length and constructed flag should be
		 * consistent.
		 */
		if (r & 0x1)
			{
			/* Indefinite length constructed */
			hdr_constructed = 2;
			hdr_len = 0;
			}
		else
			/* Just retain constructed flag */
			hdr_constructed = r & V_ASN1_CONSTRUCTED;
		/* Work out new length with IMPLICIT tag: ignore constructed
		 * because it will mess up if indefinite length
		 */
		len = ASN1_object_size(0, hdr_len, asn1_tags.imp_tag);
		}
	else
		len = cpy_len;

	/* Work out length in any EXPLICIT, starting from end */

	for(i = 0, etmp = asn1_tags.exp_list + asn1_tags.exp_count - 1; i < asn1_tags.exp_count; i++, etmp--)
		{
		/* Content length: number of content octets + any padding */
		len += etmp->exp_pad;
		etmp->exp_len = len;
		/* Total object length: length including new header */
		len = ASN1_object_size(0, len, etmp->exp_tag);
		}

	/* Allocate buffer for new encoding */

	new_der = OPENSSL_malloc(len);
	if (!new_der)
		goto err;

	/* Generate tagged encoding */

	p = new_der;

	/* Output explicit tags first */

	for (i = 0, etmp = asn1_tags.exp_list; i < asn1_tags.exp_count; i++, etmp++)
		{
		ASN1_put_object(&p, etmp->exp_constructed, etmp->exp_len,
					etmp->exp_tag, etmp->exp_class);
		if (etmp->exp_pad)
			*p++ = 0;
		}

	/* If IMPLICIT, output tag */

	if (asn1_tags.imp_tag != -1)
		{
		if (asn1_tags.imp_class == V_ASN1_UNIVERSAL 
		    && (asn1_tags.imp_tag == V_ASN1_SEQUENCE
		     || asn1_tags.imp_tag == V_ASN1_SET) )
			hdr_constructed = V_ASN1_CONSTRUCTED;
		ASN1_put_object(&p, hdr_constructed, hdr_len,
					asn1_tags.imp_tag, asn1_tags.imp_class);
		}

	/* Copy across original encoding */
	memcpy(p, cpy_start, cpy_len);

	cp = new_der;

	/* Obtain new ASN1_TYPE structure */
	ret = d2i_ASN1_TYPE(NULL, &cp, len);

	err:
	if (orig_der)
		OPENSSL_free(orig_der);
	if (new_der)
		OPENSSL_free(new_der);

	return ret;

	}
/* file: asn1_multi : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_gen.c */
static ASN1_TYPE *asn1_multi(int utype, const char *section, X509V3_CTX *cnf)
	{
	ASN1_TYPE *ret = NULL;
	STACK_OF(ASN1_TYPE) *sk = NULL;
	STACK_OF(CONF_VALUE) *sect = NULL;
	unsigned char *der = NULL;
	int derlen;
	int i;
	sk = sk_ASN1_TYPE_new_null();
	if (!sk)
		goto bad;
	if (section)
		{
		if (!cnf)
			goto bad;
		sect = X509V3_get_section(cnf, (char *)section);
		if (!sect)
			goto bad;
		for (i = 0; i < sk_CONF_VALUE_num(sect); i++)
			{
			ASN1_TYPE *typ = ASN1_generate_v3(sk_CONF_VALUE_value(sect, i)->value, cnf);
			if (!typ)
				goto bad;
			if (!sk_ASN1_TYPE_push(sk, typ))
				goto bad;
			}
		}

	/* Now we has a STACK of the components, convert to the correct form */

	if (utype == V_ASN1_SET)
		derlen = i2d_ASN1_SET_ANY(sk, &der);
	else
		derlen = i2d_ASN1_SEQUENCE_ANY(sk, &der);

	if (derlen < 0)
		goto bad;

	if (!(ret = ASN1_TYPE_new()))
		goto bad;

	if (!(ret->value.asn1_string = ASN1_STRING_type_new(utype)))
		goto bad;

	ret->type = utype;

	ret->value.asn1_string->data = der;
	ret->value.asn1_string->length = derlen;

	der = NULL;

	bad:

	if (der)
		OPENSSL_free(der);

	if (sk)
		sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
	if (sect)
		X509V3_section_free(cnf, sect);

	return ret;
	}
/* file: sk_push : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.c */
int sk_push(_STACK *st, void *data)
	{
	return(sk_insert(st,data,st->num));
	}
/* file: asn1_str2type : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_gen.c */
static ASN1_TYPE *asn1_str2type(const char *str, int format, int utype)
	{
	ASN1_TYPE *atmp = NULL;

	CONF_VALUE vtmp;

	unsigned char *rdata;
	long rdlen;

	int no_unused = 1;

	if (!(atmp = ASN1_TYPE_new()))
		{
		ASN1err(ASN1_F_ASN1_STR2TYPE, ERR_R_MALLOC_FAILURE);
		return NULL;
		}

	if (!str)
		str = "";

	switch(utype)
		{

		case V_ASN1_NULL:
		if (str && *str)
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ASN1_R_ILLEGAL_NULL_VALUE);
			goto bad_form;
			}
		break;
		
		case V_ASN1_BOOLEAN:
		if (format != ASN1_GEN_FORMAT_ASCII)
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ASN1_R_NOT_ASCII_FORMAT);
			goto bad_form;
			}
		vtmp.name = NULL;
		vtmp.section = NULL;
		vtmp.value = (char *)str;
		if (!X509V3_get_value_bool(&vtmp, &atmp->value.boolean))
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ASN1_R_ILLEGAL_BOOLEAN);
			goto bad_str;
			}
		break;

		case V_ASN1_INTEGER:
		case V_ASN1_ENUMERATED:
		if (format != ASN1_GEN_FORMAT_ASCII)
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ASN1_R_INTEGER_NOT_ASCII_FORMAT);
			goto bad_form;
			}
		if (!(atmp->value.integer = s2i_ASN1_INTEGER(NULL, (char *)str)))
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ASN1_R_ILLEGAL_INTEGER);
			goto bad_str;
			}
		break;

		case V_ASN1_OBJECT:
		if (format != ASN1_GEN_FORMAT_ASCII)
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ASN1_R_OBJECT_NOT_ASCII_FORMAT);
			goto bad_form;
			}
		if (!(atmp->value.object = OBJ_txt2obj(str, 0)))
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ASN1_R_ILLEGAL_OBJECT);
			goto bad_str;
			}
		break;

		case V_ASN1_UTCTIME:
		case V_ASN1_GENERALIZEDTIME:
		if (format != ASN1_GEN_FORMAT_ASCII)
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ASN1_R_TIME_NOT_ASCII_FORMAT);
			goto bad_form;
			}
		if (!(atmp->value.asn1_string = ASN1_STRING_new()))
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ERR_R_MALLOC_FAILURE);
			goto bad_str;
			}
		if (!ASN1_STRING_set(atmp->value.asn1_string, str, -1))
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ERR_R_MALLOC_FAILURE);
			goto bad_str;
			}
		atmp->value.asn1_string->type = utype;
		if (!ASN1_TIME_check(atmp->value.asn1_string))
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ASN1_R_ILLEGAL_TIME_VALUE);
			goto bad_str;
			}

		break;

		case V_ASN1_BMPSTRING:
		case V_ASN1_PRINTABLESTRING:
		case V_ASN1_IA5STRING:
		case V_ASN1_T61STRING:
		case V_ASN1_UTF8STRING:
		case V_ASN1_VISIBLESTRING:
		case V_ASN1_UNIVERSALSTRING:
		case V_ASN1_GENERALSTRING:
		case V_ASN1_NUMERICSTRING:

		if (format == ASN1_GEN_FORMAT_ASCII)
			format = MBSTRING_ASC;
		else if (format == ASN1_GEN_FORMAT_UTF8)
			format = MBSTRING_UTF8;
		else
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ASN1_R_ILLEGAL_FORMAT);
			goto bad_form;
			}


		if (ASN1_mbstring_copy(&atmp->value.asn1_string, (unsigned char *)str,
						-1, format, ASN1_tag2bit(utype)) <= 0)
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ERR_R_MALLOC_FAILURE);
			goto bad_str;
			}
		

		break;

		case V_ASN1_BIT_STRING:

		case V_ASN1_OCTET_STRING:

		if (!(atmp->value.asn1_string = ASN1_STRING_new()))
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ERR_R_MALLOC_FAILURE);
			goto bad_form;
			}

		if (format == ASN1_GEN_FORMAT_HEX)
			{

			if (!(rdata = string_to_hex((char *)str, &rdlen)))
				{
				ASN1err(ASN1_F_ASN1_STR2TYPE, ASN1_R_ILLEGAL_HEX);
				goto bad_str;
				}

			atmp->value.asn1_string->data = rdata;
			atmp->value.asn1_string->length = rdlen;
			atmp->value.asn1_string->type = utype;

			}
		else if (format == ASN1_GEN_FORMAT_ASCII)
			ASN1_STRING_set(atmp->value.asn1_string, str, -1);
		else if ((format == ASN1_GEN_FORMAT_BITLIST) && (utype == V_ASN1_BIT_STRING))
			{
			if (!CONF_parse_list(str, ',', 1, bitstr_cb, atmp->value.bit_string))
				{
				ASN1err(ASN1_F_ASN1_STR2TYPE, ASN1_R_LIST_ERROR);
				goto bad_str;
				}
			no_unused = 0;
			
			}
		else 
			{
			ASN1err(ASN1_F_ASN1_STR2TYPE, ASN1_R_ILLEGAL_BITSTRING_FORMAT);
			goto bad_form;
			}

		if ((utype == V_ASN1_BIT_STRING) && no_unused)
			{
			atmp->value.asn1_string->flags
				&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
        		atmp->value.asn1_string->flags
				|= ASN1_STRING_FLAG_BITS_LEFT;
			}


		break;

		default:
		ASN1err(ASN1_F_ASN1_STR2TYPE, ASN1_R_UNSUPPORTED_TYPE);
		goto bad_str;
		break;
		}


	atmp->type = utype;
	return atmp;


	bad_str:
	ERR_add_error_data(2, "string=", str);
	bad_form:

	ASN1_TYPE_free(atmp);
	return NULL;

	}
/* file: X509V3_get_value_bool : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
int X509V3_get_value_bool(CONF_VALUE *value, int *asn1_bool)
{
	char *btmp;
	if(!(btmp = value->value)) goto err;
	if(!strcmp(btmp, "TRUE") || !strcmp(btmp, "true")
		 || !strcmp(btmp, "Y") || !strcmp(btmp, "y")
		|| !strcmp(btmp, "YES") || !strcmp(btmp, "yes")) {
		*asn1_bool = 0xff;
		return 1;
	} else if(!strcmp(btmp, "FALSE") || !strcmp(btmp, "false")
		 || !strcmp(btmp, "N") || !strcmp(btmp, "n")
		|| !strcmp(btmp, "NO") || !strcmp(btmp, "no")) {
		*asn1_bool = 0;
		return 1;
	}
	err:
	X509V3err(X509V3_F_X509V3_GET_VALUE_BOOL,X509V3_R_INVALID_BOOLEAN_STRING);
	X509V3_conf_err(value);
	return 0;
}
/* file: BN_hex2bn : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_print.c */
int BN_hex2bn(BIGNUM **bn, const char *a)
	{
	BIGNUM *ret=NULL;
	BN_ULONG l=0;
	int neg=0,h,m,i,j,k,c;
	int num;

	if ((a == NULL) || (*a == '\0')) return(0);

	if (*a == '-') { neg=1; a++; }

	for (i=0; isxdigit((unsigned char) a[i]); i++)
		;

	num=i+neg;
	if (bn == NULL) return(num);

	/* a is the start of the hex digits, and it is 'i' long */
	if (*bn == NULL)
		{
		if ((ret=BN_new()) == NULL) return(0);
		}
	else
		{
		ret= *bn;
		BN_zero(ret);
		}

	/* i is the number of hex digests; */
	if (bn_expand(ret,i*4) == NULL) goto err;

	j=i; /* least significant 'hex' */
	m=0;
	h=0;
	while (j > 0)
		{
		m=((BN_BYTES*2) <= j)?(BN_BYTES*2):j;
		l=0;
		for (;;)
			{
			c=a[j-m];
			if ((c >= '0') && (c <= '9')) k=c-'0';
			else if ((c >= 'a') && (c <= 'f')) k=c-'a'+10;
			else if ((c >= 'A') && (c <= 'F')) k=c-'A'+10;
			else k=0; /* paranoia */
			l=(l<<4)|k;

			if (--m <= 0)
				{
				ret->d[h++]=l;
				break;
				}
			}
		j-=(BN_BYTES*2);
		}
	ret->top=h;
	bn_correct_top(ret);
	ret->neg=neg;

	*bn=ret;
	bn_check_top(ret);
	return(num);
err:
	if (*bn == NULL) BN_free(ret);
	return(0);
	}
/* file: BN_dec2bn : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_print.c */
int BN_dec2bn(BIGNUM **bn, const char *a)
	{
	BIGNUM *ret=NULL;
	BN_ULONG l=0;
	int neg=0,i,j;
	int num;

	if ((a == NULL) || (*a == '\0')) return(0);
	if (*a == '-') { neg=1; a++; }

	for (i=0; isdigit((unsigned char) a[i]); i++)
		;

	num=i+neg;
	if (bn == NULL) return(num);

	/* a is the start of the digits, and it is 'i' long.
	 * We chop it into BN_DEC_NUM digits at a time */
	if (*bn == NULL)
		{
		if ((ret=BN_new()) == NULL) return(0);
		}
	else
		{
		ret= *bn;
		BN_zero(ret);
		}

	/* i is the number of digests, a bit of an over expand; */
	if (bn_expand(ret,i*4) == NULL) goto err;

	j=BN_DEC_NUM-(i%BN_DEC_NUM);
	if (j == BN_DEC_NUM) j=0;
	l=0;
	while (*a)
		{
		l*=10;
		l+= *a-'0';
		a++;
		if (++j == BN_DEC_NUM)
			{
			BN_mul_word(ret,BN_DEC_CONV);
			BN_add_word(ret,l);
			l=0;
			j=0;
			}
		}
	ret->neg=neg;

	bn_correct_top(ret);
	*bn=ret;
	bn_check_top(ret);
	return(num);
err:
	if (*bn == NULL) BN_free(ret);
	return(0);
	}
/* file: BN_to_ASN1_INTEGER : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_int.c */
ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai)
	{
	ASN1_INTEGER *ret;
	int len,j;

	if (ai == NULL)
		ret=M_ASN1_INTEGER_new();
	else
		ret=ai;
	if (ret == NULL)
		{
		ASN1err(ASN1_F_BN_TO_ASN1_INTEGER,ERR_R_NESTED_ASN1_ERROR);
		goto err;
		}
	if (BN_is_negative(bn))
		ret->type = V_ASN1_NEG_INTEGER;
	else ret->type=V_ASN1_INTEGER;
	j=BN_num_bits(bn);
	len=((j == 0)?0:((j/8)+1));
	if (ret->length < len+4)
		{
		unsigned char *new_data=OPENSSL_realloc(ret->data, len+4);
		if (!new_data)
			{
			ASN1err(ASN1_F_BN_TO_ASN1_INTEGER,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		ret->data=new_data;
		}
	ret->length=BN_bn2bin(bn,ret->data);
	/* Correct zero case */
	if(!ret->length)
		{
		ret->data[0] = 0;
		ret->length = 1;
		}
	return(ret);
err:
	if (ret != ai) M_ASN1_INTEGER_free(ret);
	return(NULL);
	}
/* file: BN_bn2bin : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
int BN_bn2bin(const BIGNUM *a, unsigned char *to)
	{
	int n,i;
	BN_ULONG l;

	bn_check_top(a);
	n=i=BN_num_bytes(a);
	while (i--)
		{
		l=a->d[i/BN_BYTES];
		*(to++)=(unsigned char)(l>>(8*(i%BN_BYTES)))&0xff;
		}
	return(n);
	}
/* file: ASN1_TIME_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_time.c */
int ASN1_TIME_check(ASN1_TIME *t)
	{
	if (t->type == V_ASN1_GENERALIZEDTIME)
		return ASN1_GENERALIZEDTIME_check(t);
	else if (t->type == V_ASN1_UTCTIME)
		return ASN1_UTCTIME_check(t);
	return 0;
	}
/* file: ASN1_GENERALIZEDTIME_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_gentm.c */
int ASN1_GENERALIZEDTIME_check(ASN1_GENERALIZEDTIME *d)
	{
	static const int min[9]={ 0, 0, 1, 1, 0, 0, 0, 0, 0};
	static const int max[9]={99, 99,12,31,23,59,59,12,59};
	char *a;
	int n,i,l,o;

	if (d->type != V_ASN1_GENERALIZEDTIME) return(0);
	l=d->length;
	a=(char *)d->data;
	o=0;
	/* GENERALIZEDTIME is similar to UTCTIME except the year is
         * represented as YYYY. This stuff treats everything as a two digit
         * field so make first two fields 00 to 99
         */
	if (l < 13) goto err;
	for (i=0; i<7; i++)
		{
		if ((i == 6) && ((a[o] == 'Z') ||
			(a[o] == '+') || (a[o] == '-')))
			{ i++; break; }
		if ((a[o] < '0') || (a[o] > '9')) goto err;
		n= a[o]-'0';
		if (++o > l) goto err;

		if ((a[o] < '0') || (a[o] > '9')) goto err;
		n=(n*10)+ a[o]-'0';
		if (++o > l) goto err;

		if ((n < min[i]) || (n > max[i])) goto err;
		}
	/* Optional fractional seconds: decimal point followed by one
	 * or more digits.
	 */
	if (a[o] == '.')
		{
		if (++o > l) goto err;
		i = o;
		while ((a[o] >= '0') && (a[o] <= '9') && (o <= l))
			o++;
		/* Must have at least one digit after decimal point */
		if (i == o) goto err;
		}

	if (a[o] == 'Z')
		o++;
	else if ((a[o] == '+') || (a[o] == '-'))
		{
		o++;
		if (o+4 > l) goto err;
		for (i=7; i<9; i++)
			{
			if ((a[o] < '0') || (a[o] > '9')) goto err;
			n= a[o]-'0';
			o++;
			if ((a[o] < '0') || (a[o] > '9')) goto err;
			n=(n*10)+ a[o]-'0';
			if ((n < min[i]) || (n > max[i])) goto err;
			o++;
			}
		}
	else
		{
		/* Missing time zone information. */
		goto err;
		}
	return(o == l);
err:
	return(0);
	}
/* file: ASN1_UTCTIME_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_utctm.c */
int ASN1_UTCTIME_check(ASN1_UTCTIME *d)
	{
	static const int min[8]={ 0, 1, 1, 0, 0, 0, 0, 0};
	static const int max[8]={99,12,31,23,59,59,12,59};
	char *a;
	int n,i,l,o;

	if (d->type != V_ASN1_UTCTIME) return(0);
	l=d->length;
	a=(char *)d->data;
	o=0;

	if (l < 11) goto err;
	for (i=0; i<6; i++)
		{
		if ((i == 5) && ((a[o] == 'Z') ||
			(a[o] == '+') || (a[o] == '-')))
			{ i++; break; }
		if ((a[o] < '0') || (a[o] > '9')) goto err;
		n= a[o]-'0';
		if (++o > l) goto err;

		if ((a[o] < '0') || (a[o] > '9')) goto err;
		n=(n*10)+ a[o]-'0';
		if (++o > l) goto err;

		if ((n < min[i]) || (n > max[i])) goto err;
		}
	if (a[o] == 'Z')
		o++;
	else if ((a[o] == '+') || (a[o] == '-'))
		{
		o++;
		if (o+4 > l) goto err;
		for (i=6; i<8; i++)
			{
			if ((a[o] < '0') || (a[o] > '9')) goto err;
			n= a[o]-'0';
			o++;
			if ((a[o] < '0') || (a[o] > '9')) goto err;
			n=(n*10)+ a[o]-'0';
			if ((n < min[i]) || (n > max[i])) goto err;
			o++;
			}
		}
	return(o == l);
err:
	return(0);
	}
/* file: ASN1_tag2bit : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1tasn_dec.c */
unsigned long ASN1_tag2bit(int tag)
	{
	if ((tag < 0) || (tag > 30)) return 0;
	return tag2bit[tag];
	}
/* file: string_to_hex : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
unsigned char *string_to_hex(const char *str, long *len)
{
	unsigned char *hexbuf, *q;
	unsigned char ch, cl, *p;
	if(!str) {
		X509V3err(X509V3_F_STRING_TO_HEX,X509V3_R_INVALID_NULL_ARGUMENT);
		return NULL;
	}
	if(!(hexbuf = OPENSSL_malloc(strlen(str) >> 1))) goto err;
	for(p = (unsigned char *)str, q = hexbuf; *p;) {
		ch = *p++;
#ifdef CHARSET_EBCDIC
		ch = os_toebcdic[ch];
#endif
		if(ch == ':') continue;
		cl = *p++;
#ifdef CHARSET_EBCDIC
		cl = os_toebcdic[cl];
#endif
		if(!cl) {
			X509V3err(X509V3_F_STRING_TO_HEX,X509V3_R_ODD_NUMBER_OF_DIGITS);
			OPENSSL_free(hexbuf);
			return NULL;
		}
		if(isupper(ch)) ch = tolower(ch);
		if(isupper(cl)) cl = tolower(cl);

		if((ch >= '0') && (ch <= '9')) ch -= '0';
		else if ((ch >= 'a') && (ch <= 'f')) ch -= 'a' - 10;
		else goto badhex;

		if((cl >= '0') && (cl <= '9')) cl -= '0';
		else if ((cl >= 'a') && (cl <= 'f')) cl -= 'a' - 10;
		else goto badhex;

		*q++ = (ch << 4) | cl;
	}

	if(len) *len = q - hexbuf;

	return hexbuf;

	err:
	if(hexbuf) OPENSSL_free(hexbuf);
	X509V3err(X509V3_F_STRING_TO_HEX,ERR_R_MALLOC_FAILURE);
	return NULL;

	badhex:
	OPENSSL_free(hexbuf);
	X509V3err(X509V3_F_STRING_TO_HEX,X509V3_R_ILLEGAL_HEX_DIGIT);
	return NULL;

}
/* file: CRYPTO_get_dynlock_value : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
struct CRYPTO_dynlock_value *CRYPTO_get_dynlock_value(int i)
	{
	CRYPTO_dynlock *pointer = NULL;
	if (i)
		i = -i-1;

	CRYPTO_w_lock(CRYPTO_LOCK_DYNLOCK);

	if (dyn_locks != NULL && i < sk_CRYPTO_dynlock_num(dyn_locks))
		pointer = sk_CRYPTO_dynlock_value(dyn_locks, i);
	if (pointer)
		pointer->references++;

	CRYPTO_w_unlock(CRYPTO_LOCK_DYNLOCK);

	if (pointer)
		return pointer->data;
	return NULL;
	}
/* file: OpenSSLDie : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
void OpenSSLDie(const char *file,int line,const char *assertion)
	{
	OPENSSL_showfatal(
		"%s(%d): OpenSSL internal error, assertion failed: %s\n",
		file,line,assertion);
#if !defined(_WIN32) || defined(__CYGWIN__)
	abort();
#else
	/* Win32 abort() customarily shows a dialog, but we just did that... */
	raise(SIGABRT);
	_exit(3);
#endif
	}
/* file: OPENSSL_showfatal : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
#if defined(_WIN32) && !defined(__CYGWIN__)
void OPENSSL_showfatal (const char *fmta,...)
{ va_list ap;
  TCHAR buf[256];
  const TCHAR *fmt;
#ifdef STD_ERROR_HANDLE	/* what a dirty trick! */
  HANDLE h;

    if ((h=GetStdHandle(STD_ERROR_HANDLE)) != NULL &&
	GetFileType(h)!=FILE_TYPE_UNKNOWN)
    {	/* must be console application */
	va_start (ap,fmta);
	vfprintf (stderr,fmta,ap);
	va_end (ap);
	return;
    }
#endif

    if (sizeof(TCHAR)==sizeof(char))
	fmt=(const TCHAR *)fmta;
    else do
    { int    keepgoing;
      size_t len_0=strlen(fmta)+1,i;
      WCHAR *fmtw;

	fmtw = (WCHAR *)alloca(len_0*sizeof(WCHAR));
	if (fmtw == NULL) { fmt=(const TCHAR *)L"no stack?"; break; }

#ifndef OPENSSL_NO_MULTIBYTE
	if (!MultiByteToWideChar(CP_ACP,0,fmta,len_0,fmtw,len_0))
#endif
	    for (i=0;i<len_0;i++) fmtw[i]=(WCHAR)fmta[i];

	for (i=0;i<len_0;i++)
	{   if (fmtw[i]==L'%') do
	    {	keepgoing=0;
		switch (fmtw[i+1])
		{   case L'0': case L'1': case L'2': case L'3': case L'4':
		    case L'5': case L'6': case L'7': case L'8': case L'9':
		    case L'.': case L'*':
		    case L'-':	i++; keepgoing=1; break;
		    case L's':	fmtw[i+1]=L'S';   break;
		    case L'S':	fmtw[i+1]=L's';   break;
		    case L'c':	fmtw[i+1]=L'C';   break;
		    case L'C':	fmtw[i+1]=L'c';   break;
		}
	    } while (keepgoing);
	}
	fmt = (const TCHAR *)fmtw;
    } while (0);

    va_start (ap,fmta);
    _vsntprintf (buf,sizeof(buf)/sizeof(TCHAR)-1,fmt,ap);
    buf [sizeof(buf)/sizeof(TCHAR)-1] = _T('\0');
    va_end (ap);

#if defined(_WIN32_WINNT) && _WIN32_WINNT>=0x0333
    /* this -------------v--- guards NT-specific calls */
    if (GetVersion() < 0x80000000 && OPENSSL_isservice() > 0)
    {	HANDLE h = RegisterEventSource(0,_T("OPENSSL"));
	const TCHAR *pmsg=buf;
	ReportEvent(h,EVENTLOG_ERROR_TYPE,0,0,0,1,0,&pmsg,0);
	DeregisterEventSource(h);
    }
    else
#endif
	MessageBox (NULL,buf,_T("OpenSSL: FATAL"),MB_OK|MB_ICONSTOP);
}
#else
/* file: OPENSSL_showfatal : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
void OPENSSL_showfatal (const char *fmta,...)
{ va_list ap;

    va_start (ap,fmta);
    vfprintf (stderr,fmta,ap);
    va_end (ap);
}
#endif
/* file: OPENSSL_isservice : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
#if defined(_WIN32) && !defined(__CYGWIN__)
#if defined(_WIN32_WINNT) && _WIN32_WINNT>=0x0333
int OPENSSL_isservice(void)
{ HWINSTA h;
  DWORD len;
  WCHAR *name;
  static union { void *p; int (*f)(void); } _OPENSSL_isservice = { NULL };

    if (_OPENSSL_isservice.p == NULL) {
	HANDLE h = GetModuleHandle(NULL);
	if (h != NULL)
	    _OPENSSL_isservice.p = GetProcAddress(h,"_OPENSSL_isservice");
	if (_OPENSSL_isservice.p == NULL)
	    _OPENSSL_isservice.p = (void *)-1;
    }

    if (_OPENSSL_isservice.p != (void *)-1)
	return (*_OPENSSL_isservice.f)();

    (void)GetDesktopWindow(); /* return value is ignored */

    h = GetProcessWindowStation();
    if (h==NULL) return -1;

    if (GetUserObjectInformationW (h,UOI_NAME,NULL,0,&len) ||
	GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	return -1;

    if (len>512) return -1;		/* paranoia */
    len++,len&=~1;			/* paranoia */
    name=(WCHAR *)alloca(len+sizeof(WCHAR));
    if (!GetUserObjectInformationW (h,UOI_NAME,name,len,&len))
	return -1;

    len++,len&=~1;			/* paranoia */
    name[len/sizeof(WCHAR)]=L'\0';	/* paranoia */
#if 1
    /* This doesn't cover "interactive" services [working with real
     * WinSta0's] nor programs started non-interactively by Task
     * Scheduler [those are working with SAWinSta]. */
    if (wcsstr(name,L"Service-0x"))	return 1;
#else
    /* This covers all non-interactive programs such as services. */
    if (!wcsstr(name,L"WinSta0"))	return 1;
#endif
    else				return 0;
}
#else
/* file: OPENSSL_isservice : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
int OPENSSL_isservice(void) { return 0; }
#endif
#endif
/* file: CRYPTO_destroy_dynlockid : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
void CRYPTO_destroy_dynlockid(int i)
	{
	CRYPTO_dynlock *pointer = NULL;
	if (i)
		i = -i-1;
	if (dynlock_destroy_callback == NULL)
		return;

	CRYPTO_w_lock(CRYPTO_LOCK_DYNLOCK);

	if (dyn_locks == NULL || i >= sk_CRYPTO_dynlock_num(dyn_locks))
		{
		CRYPTO_w_unlock(CRYPTO_LOCK_DYNLOCK);
		return;
		}
	pointer = sk_CRYPTO_dynlock_value(dyn_locks, i);
	if (pointer != NULL)
		{
		--pointer->references;
#ifdef REF_CHECK
		if (pointer->references < 0)
			{
			fprintf(stderr,"CRYPTO_destroy_dynlockid, bad reference count\n");
			abort();
			}
		else
#endif
			if (pointer->references <= 0)
				{
				(void)sk_CRYPTO_dynlock_set(dyn_locks, i, NULL);
				}
			else
				pointer = NULL;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_DYNLOCK);

	if (pointer)
		{
		dynlock_destroy_callback(pointer->data,__FILE__,__LINE__);
		OPENSSL_free(pointer);
		}
	}
/* file: EC_GROUP_new_by_curve_name : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_curve.c */
EC_GROUP *EC_GROUP_new_by_curve_name(int nid)
	{
	size_t i;
	EC_GROUP *ret = NULL;

	if (nid <= 0)
		return NULL;

	for (i=0; i<curve_list_length; i++)
		if (curve_list[i].nid == nid)
			{
			ret = ec_group_new_from_data(curve_list[i]);
			break;
			}

	if (ret == NULL)
		{
		ECerr(EC_F_EC_GROUP_NEW_BY_CURVE_NAME, EC_R_UNKNOWN_GROUP);
		return NULL;
		}

	EC_GROUP_set_curve_name(ret, nid);

	return ret;
	}
/* file: BN_CTX_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
BN_CTX *BN_CTX_new(void)
	{
	BN_CTX *ret = OPENSSL_malloc(sizeof(BN_CTX));
	if(!ret)
		{
		BNerr(BN_F_BN_CTX_NEW,ERR_R_MALLOC_FAILURE);
		return NULL;
		}
	/* Initialise the structure */
	BN_POOL_init(&ret->pool);
	BN_STACK_init(&ret->stack);
	ret->used = 0;
	ret->err_stack = 0;
	ret->too_many = 0;
	return ret;
	}
/* file: BN_POOL_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void BN_POOL_init(BN_POOL *p)
	{
	p->head = p->current = p->tail = NULL;
	p->used = p->size = 0;
	}
/* file: BN_STACK_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void BN_STACK_init(BN_STACK *st)
	{
	st->indexes = NULL;
	st->depth = st->size = 0;
	}
/* file: BN_bin2bn : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
	{
	unsigned int i,m;
	unsigned int n;
	BN_ULONG l;
	BIGNUM  *bn = NULL;

	if (ret == NULL)
		ret = bn = BN_new();
	if (ret == NULL) return(NULL);
	bn_check_top(ret);
	l=0;
	n=len;
	if (n == 0)
		{
		ret->top=0;
		return(ret);
		}
	i=((n-1)/BN_BYTES)+1;
	m=((n-1)%(BN_BYTES));
	if (bn_wexpand(ret, (int)i) == NULL)
		{
		if (bn) BN_free(bn);
		return NULL;
		}
	ret->top=i;
	ret->neg=0;
	while (n--)
		{
		l=(l<<8L)| *(s++);
		if (m-- == 0)
			{
			ret->d[--i]=l;
			l=0;
			m=BN_BYTES-1;
			}
		}
	/* need to call this due to clear byte at top if avoiding
	 * having the top bit set (-ve number) */
	bn_correct_top(ret);
	return(ret);
	}
/* file: EC_GROUP_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
EC_GROUP *EC_GROUP_new(const EC_METHOD *meth)
	{
	EC_GROUP *ret;

	if (meth == NULL)
		{
		ECerr(EC_F_EC_GROUP_NEW, EC_R_SLOT_FULL);
		return NULL;
		}
	if (meth->group_init == 0)
		{
		ECerr(EC_F_EC_GROUP_NEW, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return NULL;
		}

	ret = OPENSSL_malloc(sizeof *ret);
	if (ret == NULL)
		{
		ECerr(EC_F_EC_GROUP_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
		}

	ret->meth = meth;

	ret->extra_data = NULL;

	ret->generator = NULL;
	BN_init(&ret->order);
	BN_init(&ret->cofactor);

	ret->curve_name = 0;	
	ret->asn1_flag  = 0;
	ret->asn1_form  = POINT_CONVERSION_UNCOMPRESSED;

	ret->seed = NULL;
	ret->seed_len = 0;

	if (!meth->group_init(ret))
		{
		OPENSSL_free(ret);
		return NULL;
		}
	
	return ret;
	}
/* file: BN_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
void BN_init(BIGNUM *a)
	{
	memset(a,0,sizeof(BIGNUM));
	bn_check_top(a);
	}
/* file: EC_GROUP_new_curve_GFp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_cvt.c */
EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	const EC_METHOD *meth;
	EC_GROUP *ret;

#if defined(OPENSSL_BN_ASM_MONT)
	/*
	 * This might appear controversial, but the fact is that generic
	 * prime method was observed to deliver better performance even
	 * for NIST primes on a range of platforms, e.g.: 60%-15%
	 * improvement on IA-64, ~25% on ARM, 30%-90% on P4, 20%-25%
	 * in 32-bit build and 35%--12% in 64-bit build on Core2...
	 * Coefficients are relative to optimized bn_nist.c for most
	 * intensive ECDSA verify and ECDH operations for 192- and 521-
	 * bit keys respectively. Choice of these boundary values is
	 * arguable, because the dependency of improvement coefficient
	 * from key length is not a "monotone" curve. For example while
	 * 571-bit result is 23% on ARM, 384-bit one is -1%. But it's
	 * generally faster, sometimes "respectfully" faster, sometimes
	 * "tolerably" slower... What effectively happens is that loop
	 * with bn_mul_add_words is put against bn_mul_mont, and the
	 * latter "wins" on short vectors. Correct solution should be
	 * implementing dedicated NxN multiplication subroutines for
	 * small N. But till it materializes, let's stick to generic
	 * prime method...
	 *						<appro>
	 */
	meth = EC_GFp_mont_method();
#else
	meth = EC_GFp_nist_method();
#endif
	
	ret = EC_GROUP_new(meth);
	if (ret == NULL)
		return NULL;

	if (!EC_GROUP_set_curve_GFp(ret, p, a, b, ctx))
		{
		unsigned long err;
		  
		err = ERR_peek_last_error();

		if (!(ERR_GET_LIB(err) == ERR_LIB_EC &&
			((ERR_GET_REASON(err) == EC_R_NOT_A_NIST_PRIME) ||
			 (ERR_GET_REASON(err) == EC_R_NOT_A_SUPPORTED_NIST_PRIME))))
			{
			/* real error */
			
			EC_GROUP_clear_free(ret);
			return NULL;
			}
			
		
		/* not an actual error, we just cannot use EC_GFp_nist_method */

		ERR_clear_error();

		EC_GROUP_clear_free(ret);
		meth = EC_GFp_mont_method();

		ret = EC_GROUP_new(meth);
		if (ret == NULL)
			return NULL;

		if (!EC_GROUP_set_curve_GFp(ret, p, a, b, ctx))
			{
			EC_GROUP_clear_free(ret);
			return NULL;
			}
		}

	return ret;
	}
/* file: EC_GFp_mont_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ececp_mont.c */
const EC_METHOD *EC_GFp_mont_method(void)
	{
#ifdef OPENSSL_FIPS
	return fips_ec_gfp_mont_method();
#else
	static const EC_METHOD ret = {
		EC_FLAGS_DEFAULT_OCT,
		NID_X9_62_prime_field,
		/*ec_GFp_mont_group_init, FixMe
		ec_GFp_mont_group_finish,
		ec_GFp_mont_group_clear_finish,
		ec_GFp_mont_group_copy,
		ec_GFp_mont_group_set_curve,
		ec_GFp_simple_group_get_curve,
		ec_GFp_simple_group_get_degree,
		ec_GFp_simple_group_check_discriminant,
		ec_GFp_simple_point_init,
		ec_GFp_simple_point_finish,
		ec_GFp_simple_point_clear_finish,
		ec_GFp_simple_point_copy,
		ec_GFp_simple_point_set_to_infinity,
		ec_GFp_simple_set_Jprojective_coordinates_GFp,
		ec_GFp_simple_get_Jprojective_coordinates_GFp,
		ec_GFp_simple_point_set_affine_coordinates,
		ec_GFp_simple_point_get_affine_coordinates,
		0,0,0,
		ec_GFp_simple_add,
		ec_GFp_simple_dbl,
		ec_GFp_simple_invert,
		ec_GFp_simple_is_at_infinity,
		ec_GFp_simple_is_on_curve,
		ec_GFp_simple_cmp,
		ec_GFp_simple_make_affine,
		ec_GFp_simple_points_make_affine,*/
		0 /* mul */,
		0 /* precompute_mult */,
		0 /* have_precompute_mult */,	
		/*ec_GFp_mont_field_mul,
		ec_GFp_mont_field_sqr,*/
		0 /* field_div */,
		/*ec_GFp_mont_field_encode,
		ec_GFp_mont_field_decode,
		ec_GFp_mont_field_set_to_one*/ };

	return &ret;
#endif
	}
/* file: EC_GFp_nist_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ececp_nist.c */
const EC_METHOD *EC_GFp_nist_method(void)
	{
#ifdef OPENSSL_FIPS
	return fips_ec_gfp_nist_method();
#else
	static const EC_METHOD ret = {
		EC_FLAGS_DEFAULT_OCT,
		NID_X9_62_prime_field,
		ec_GFp_simple_group_init,
		ec_GFp_simple_group_finish,
		ec_GFp_simple_group_clear_finish,
		ec_GFp_nist_group_copy,
		ec_GFp_nist_group_set_curve,
		ec_GFp_simple_group_get_curve,
		ec_GFp_simple_group_get_degree,
		ec_GFp_simple_group_check_discriminant,
		ec_GFp_simple_point_init,
		ec_GFp_simple_point_finish,
		ec_GFp_simple_point_clear_finish,
		ec_GFp_simple_point_copy,
		ec_GFp_simple_point_set_to_infinity,
		ec_GFp_simple_set_Jprojective_coordinates_GFp,
		ec_GFp_simple_get_Jprojective_coordinates_GFp,
		ec_GFp_simple_point_set_affine_coordinates,
		ec_GFp_simple_point_get_affine_coordinates,
		0,0,0,
		ec_GFp_simple_add,
		ec_GFp_simple_dbl,
		ec_GFp_simple_invert,
		ec_GFp_simple_is_at_infinity,
		ec_GFp_simple_is_on_curve,
		ec_GFp_simple_cmp,
		ec_GFp_simple_make_affine,
		ec_GFp_simple_points_make_affine,
		0 /* mul */,
		0 /* precompute_mult */,
		0 /* have_precompute_mult */,	
		ec_GFp_nist_field_mul,
		ec_GFp_nist_field_sqr,
		0 /* field_div */,
		0 /* field_encode */,
		0 /* field_decode */,
		0 /* field_set_to_one */ };

	return &ret;
#endif
	}
/* file: EC_GROUP_set_curve_GFp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	if (group->meth->group_set_curve == 0)
		{
		ECerr(EC_F_EC_GROUP_SET_CURVE_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	return group->meth->group_set_curve(group, p, a, b, ctx);
	}
/* file: ERR_peek_last_error : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
unsigned long ERR_peek_last_error(void)
	{ return(get_error_values(0,1,NULL,NULL,NULL,NULL)); }
/* file: EC_GROUP_clear_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
void EC_GROUP_clear_free(EC_GROUP *group)
	{
	if (!group) return;

	if (group->meth->group_clear_finish != 0)
		group->meth->group_clear_finish(group);
	else if (group->meth->group_finish != 0)
		group->meth->group_finish(group);

	EC_EX_DATA_clear_free_all_data(&group->extra_data);

	if (group->generator != NULL)
		EC_POINT_clear_free(group->generator);
	BN_clear_free(&group->order);
	BN_clear_free(&group->cofactor);

	if (group->seed)
		{
		OPENSSL_cleanse(group->seed, group->seed_len);
		OPENSSL_free(group->seed);
		}

	OPENSSL_cleanse(group, sizeof *group);
	OPENSSL_free(group);
	}
/* file: EC_EX_DATA_clear_free_all_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
void EC_EX_DATA_clear_free_all_data(EC_EXTRA_DATA **ex_data)
	{
	EC_EXTRA_DATA *d;

	if (ex_data == NULL)
		return;

	d = *ex_data;
	while (d)
		{
		EC_EXTRA_DATA *next = d->next;
		
		d->clear_free_func(d->data);
		OPENSSL_free(d);
		
		d = next;
		}
	*ex_data = NULL;
	}
/* file: EC_POINT_clear_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
void EC_POINT_clear_free(EC_POINT *point)
	{
	if (!point) return;

	if (point->meth->point_clear_finish != 0)
		point->meth->point_clear_finish(point);
	else if (point->meth->point_finish != 0)
		point->meth->point_finish(point);
	OPENSSL_cleanse(point, sizeof *point);
	OPENSSL_free(point);
	}
/* file: OPENSSL_cleanse : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem_clr.c */
void OPENSSL_cleanse(void *ptr, size_t len)
	{
	unsigned char *p = ptr;
	size_t loop = len, ctr = cleanse_ctr;
	while(loop--)
		{
		*(p++) = (unsigned char)ctr;
		ctr += (17 + ((size_t)p & 0xF));
		}
	p=memchr(ptr, (unsigned char)ctr, len);
	if(p)
		ctr += (63 + (size_t)p);
	cleanse_ctr = (unsigned char)ctr;
	}
/* file: BN_clear_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
void BN_clear_free(BIGNUM *a)
	{
	int i;

	if (a == NULL) return;
	bn_check_top(a);
	if (a->d != NULL)
		{
		OPENSSL_cleanse(a->d,a->dmax*sizeof(a->d[0]));
		if (!(BN_get_flags(a,BN_FLG_STATIC_DATA)))
			OPENSSL_free(a->d);
		}
	i=BN_get_flags(a,BN_FLG_MALLOCED);
	OPENSSL_cleanse(a,sizeof(BIGNUM));
	if (i)
		OPENSSL_free(a);
	}
/* file: ERR_clear_error : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
void ERR_clear_error(void)
	{
	int i;
	ERR_STATE *es;

	es=ERR_get_state();

	for (i=0; i<ERR_NUM_ERRORS; i++)
		{
		err_clear(es,i);
		}
	es->top=es->bottom=0;
	}
/* file: EC_GROUP_new_curve_GF2m : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_cvt.c */
#ifndef OPENSSL_NO_EC2M
EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	const EC_METHOD *meth;
	EC_GROUP *ret;
	
	meth = EC_GF2m_simple_method();
	
	ret = EC_GROUP_new(meth);
	if (ret == NULL)
		return NULL;

	if (!EC_GROUP_set_curve_GF2m(ret, p, a, b, ctx))
		{
		EC_GROUP_clear_free(ret);
		return NULL;
		}

	return ret;
	}
#endif
/* file: EC_GF2m_simple_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec2_smpl.c */
#ifndef OPENSSL_NO_EC2M
const EC_METHOD *EC_GF2m_simple_method(void)
	{
#ifdef OPENSSL_FIPS
	return fips_ec_gf2m_simple_method();
#else
	static const EC_METHOD ret = {
		EC_FLAGS_DEFAULT_OCT,
		/*NID_X9_62_characteristic_two_field, FixMe
		ec_GF2m_simple_group_init,
		ec_GF2m_simple_group_finish,
		ec_GF2m_simple_group_clear_finish,
		ec_GF2m_simple_group_copy,
		ec_GF2m_simple_group_set_curve,
		ec_GF2m_simple_group_get_curve,
		ec_GF2m_simple_group_get_degree,
		ec_GF2m_simple_group_check_discriminant,
		ec_GF2m_simple_point_init,
		ec_GF2m_simple_point_finish,
		ec_GF2m_simple_point_clear_finish,
		ec_GF2m_simple_point_copy,
		ec_GF2m_simple_point_set_to_infinity,*/
		0 /* set_Jprojective_coordinates_GFp */,
		0 /* get_Jprojective_coordinates_GFp */,
		/*ec_GF2m_simple_point_set_affine_coordinates,
		ec_GF2m_simple_point_get_affine_coordinates,
		0,0,0,
		ec_GF2m_simple_add,
		ec_GF2m_simple_dbl,
		ec_GF2m_simple_invert,
		ec_GF2m_simple_is_at_infinity,
		ec_GF2m_simple_is_on_curve,
		ec_GF2m_simple_cmp,
		ec_GF2m_simple_make_affine,
		ec_GF2m_simple_points_make_affine,*/

		/* the following three method functions are defined in ec2_mult.c */
		/*ec_GF2m_simple_mul,
		ec_GF2m_precompute_mult,
		ec_GF2m_have_precompute_mult,

		ec_GF2m_simple_field_mul,
		ec_GF2m_simple_field_sqr,
		ec_GF2m_simple_field_div,*/
		0 /* field_encode */,
		0 /* field_decode */,
		0 /* field_set_to_one */ };

	return &ret;
#endif
	}
#endif
/* file: EC_GROUP_set_curve_GF2m : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
#ifndef OPENSSL_NO_EC2M
int EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	if (group->meth->group_set_curve == 0)
		{
		ECerr(EC_F_EC_GROUP_SET_CURVE_GF2M, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	return group->meth->group_set_curve(group, p, a, b, ctx);
	}
#endif
/* file: EC_POINT_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
EC_POINT *EC_POINT_new(const EC_GROUP *group)
	{
	EC_POINT *ret;

	if (group == NULL)
		{
		ECerr(EC_F_EC_POINT_NEW, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}
	if (group->meth->point_init == 0)
		{
		ECerr(EC_F_EC_POINT_NEW, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return NULL;
		}

	ret = OPENSSL_malloc(sizeof *ret);
	if (ret == NULL)
		{
		ECerr(EC_F_EC_POINT_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
		}

	ret->meth = group->meth;
	
	if (!ret->meth->point_init(ret))
		{
		OPENSSL_free(ret);
		return NULL;
		}
	
	return ret;
	}
/* file: EC_POINT_set_affine_coordinates_GFp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *point,
	const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)
	{
	if (group->meth->point_set_affine_coordinates == 0)
		{
		ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != point->meth)
		{
		ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->point_set_affine_coordinates(group, point, x, y, ctx);
	}
/* file: EC_GROUP_set_generator : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor)
	{
	if (generator == NULL)
		{
		ECerr(EC_F_EC_GROUP_SET_GENERATOR, ERR_R_PASSED_NULL_PARAMETER);
		return 0   ;
		}

	if (group->generator == NULL)
		{
		group->generator = EC_POINT_new(group);
		if (group->generator == NULL) return 0;
		}
	if (!EC_POINT_copy(group->generator, generator)) return 0;

	if (order != NULL)
		{ if (!BN_copy(&group->order, order)) return 0; }	
	else
		BN_zero(&group->order);

	if (cofactor != NULL)
		{ if (!BN_copy(&group->cofactor, cofactor)) return 0; }	
	else
		BN_zero(&group->cofactor);

	return 1;
	}
/* file: EC_POINT_copy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_POINT_copy(EC_POINT *dest, const EC_POINT *src)
	{
	if (dest->meth->point_copy == 0)
		{
		ECerr(EC_F_EC_POINT_COPY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (dest->meth != src->meth)
		{
		ECerr(EC_F_EC_POINT_COPY, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	if (dest == src)
		return 1;
	return dest->meth->point_copy(dest, src);
	}
/* file: BN_copy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)
	{
	int i;
	BN_ULONG *A;
	const BN_ULONG *B;

	bn_check_top(b);

	if (a == b) return(a);
	if (bn_wexpand(a,b->top) == NULL) return(NULL);

#if 1
	A=a->d;
	B=b->d;
	for (i=b->top>>2; i>0; i--,A+=4,B+=4)
		{
		BN_ULONG a0,a1,a2,a3;
		a0=B[0]; a1=B[1]; a2=B[2]; a3=B[3];
		A[0]=a0; A[1]=a1; A[2]=a2; A[3]=a3;
		}
	switch (b->top&3)
		{
		case 3: A[2]=B[2];
		case 2: A[1]=B[1];
		case 1: A[0]=B[0];
		case 0: ; /* ultrix cc workaround, see comments in bn_expand_internal */
		}
#else
	memcpy(a->d,b->d,sizeof(b->d[0])*b->top);
#endif

	a->top=b->top;
	a->neg=b->neg;
	bn_check_top(a);
	return(a);
	}
/* file: EC_GROUP_set_seed : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
size_t EC_GROUP_set_seed(EC_GROUP *group, const unsigned char *p, size_t len)
	{
	if (group->seed)
		{
		OPENSSL_free(group->seed);
		group->seed = NULL;
		group->seed_len = 0;
		}

	if (!len || !p)
		return 1;

	if ((group->seed = OPENSSL_malloc(len)) == NULL)
		return 0;
	memcpy(group->seed, p, len);
	group->seed_len = len;

	return len;
	}
/* file: EC_GROUP_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
void EC_GROUP_free(EC_GROUP *group)
	{
	if (!group) return;

	if (group->meth->group_finish != 0)
		group->meth->group_finish(group);

	EC_EX_DATA_free_all_data(&group->extra_data);

	if (group->generator != NULL)
		EC_POINT_free(group->generator);
	BN_free(&group->order);
	BN_free(&group->cofactor);

	if (group->seed)
		OPENSSL_free(group->seed);

	OPENSSL_free(group);
	}
/* file: EC_EX_DATA_free_all_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
void EC_EX_DATA_free_all_data(EC_EXTRA_DATA **ex_data)
	{
	EC_EXTRA_DATA *d;

	if (ex_data == NULL)
		return;

	d = *ex_data;
	while (d)
		{
		EC_EXTRA_DATA *next = d->next;
		
		d->free_func(d->data);
		OPENSSL_free(d);
		
		d = next;
		}
	*ex_data = NULL;
	}
/* file: EC_POINT_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
void EC_POINT_free(EC_POINT *point)
	{
	if (!point) return;

	if (point->meth->point_finish != 0)
		point->meth->point_finish(point);
	OPENSSL_free(point);
	}
/* file: BN_CTX_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
void BN_CTX_free(BN_CTX *ctx)
	{
	if (ctx == NULL)
		return;
#ifdef BN_CTX_DEBUG
	{
	BN_POOL_ITEM *pool = ctx->pool.head;
	fprintf(stderr,"BN_CTX_free, stack-size=%d, pool-bignums=%d\n",
		ctx->stack.size, ctx->pool.size);
	fprintf(stderr,"dmaxs: ");
	while(pool) {
		unsigned loop = 0;
		while(loop < BN_CTX_POOL_SIZE)
			fprintf(stderr,"%02x ", pool->vals[loop++].dmax);
		pool = pool->next;
	}
	fprintf(stderr,"\n");
	}
#endif
	BN_STACK_finish(&ctx->stack);
	BN_POOL_finish(&ctx->pool);
	OPENSSL_free(ctx);
	}
/* file: BN_STACK_finish : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void BN_STACK_finish(BN_STACK *st)
	{
	if(st->size) OPENSSL_free(st->indexes);
	}
/* file: BN_POOL_finish : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void BN_POOL_finish(BN_POOL *p)
	{
	while(p->head)
		{
		unsigned int loop = 0;
		BIGNUM *bn = p->head->vals;
		while(loop++ < BN_CTX_POOL_SIZE)
			{
			if(bn->d) BN_clear_free(bn);
			bn++;
			}
		p->current = p->head->next;
		OPENSSL_free(p->head);
		p->head = p->current;
		}
	}
/* file: EC_GROUP_set_curve_name : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
void EC_GROUP_set_curve_name(EC_GROUP *group, int nid)
	{
	group->curve_name = nid;
	}
/* file: EC_KEY_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_key.c */
void EC_KEY_free(EC_KEY *r)
	{
	int i;

	if (r == NULL) return;

	i=CRYPTO_add(&r->references,-1,CRYPTO_LOCK_EC);
#ifdef REF_PRINT
	REF_PRINT("EC_KEY",r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"EC_KEY_free, bad reference count\n");
		abort();
		}
#endif

	if (r->group    != NULL) 
		EC_GROUP_free(r->group);
	if (r->pub_key  != NULL)
		EC_POINT_free(r->pub_key);
	if (r->priv_key != NULL)
		BN_clear_free(r->priv_key);

	EC_EX_DATA_free_all_data(&r->method_data);

	OPENSSL_cleanse((void *)r, sizeof(EC_KEY));

	OPENSSL_free(r);
	}
/* file: EC_KEY_generate_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_key.c */
int EC_KEY_generate_key(EC_KEY *eckey)
	{	
	int	ok = 0;
	BN_CTX	*ctx = NULL;
	BIGNUM	*priv_key = NULL, *order = NULL;
	EC_POINT *pub_key = NULL;

#ifdef OPENSSL_FIPS
	if (FIPS_mode())
		return FIPS_ec_key_generate_key(eckey);
#endif

	if (!eckey || !eckey->group)
		{
		ECerr(EC_F_EC_KEY_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}

	if ((order = BN_new()) == NULL) goto err;
	if ((ctx = BN_CTX_new()) == NULL) goto err;

	if (eckey->priv_key == NULL)
		{
		priv_key = BN_new();
		if (priv_key == NULL)
			goto err;
		}
	else
		priv_key = eckey->priv_key;

	if (!EC_GROUP_get_order(eckey->group, order, ctx))
		goto err;

	do
		if (!BN_rand_range(priv_key, order))
			goto err;
	while (BN_is_zero(priv_key));

	if (eckey->pub_key == NULL)
		{
		pub_key = EC_POINT_new(eckey->group);
		if (pub_key == NULL)
			goto err;
		}
	else
		pub_key = eckey->pub_key;

	if (!EC_POINT_mul(eckey->group, pub_key, priv_key, NULL, NULL, ctx))
		goto err;

	eckey->priv_key = priv_key;
	eckey->pub_key  = pub_key;

	ok=1;

err:	
	if (order)
		BN_free(order);
	if (pub_key  != NULL && eckey->pub_key  == NULL)
		EC_POINT_free(pub_key);
	if (priv_key != NULL && eckey->priv_key == NULL)
		BN_free(priv_key);
	if (ctx != NULL)
		BN_CTX_free(ctx);
	return(ok);
	}
/* file: FIPS_mode : /Volumes/work/Phd/ECDH/kv_openssl/cryptoo_fips.c */
int FIPS_mode(void)
	{
	OPENSSL_init();
#ifdef OPENSSL_FIPS
	return FIPS_module_mode();
#else
	return 0;
#endif
	}
/* file: OPENSSL_init : /Volumes/work/Phd/ECDH/kv_openssl/cryptoo_init.c */
void OPENSSL_init(void)
	{
	static int done = 0;
	if (done)
		return;
	done = 1;
#ifdef OPENSSL_FIPS
	FIPS_set_locking_callbacks(CRYPTO_lock, CRYPTO_add_lock);
	FIPS_set_error_callbacks(ERR_put_error, ERR_add_error_vdata);
	FIPS_set_malloc_callbacks(CRYPTO_malloc, CRYPTO_free);
	RAND_init_fips();
#endif
#if 0
	fprintf(stderr, "Called OPENSSL_init\n");
#endif
	}
/* file: RAND_init_fips : /Volumes/work/Phd/ECDH/kv_openssl/crypto/randrand_lib.c */
#ifdef OPENSSL_FIPS
int RAND_init_fips(void)
	{
	DRBG_CTX *dctx;
	size_t plen;
	unsigned char pers[32], *p;
#ifndef OPENSSL_ALLOW_DUAL_EC_DRBG
	if (fips_drbg_type >> 16)
		{
		RANDerr(RAND_F_RAND_INIT_FIPS, RAND_R_DUAL_EC_DRBG_DISABLED);
		return 0;
		}
#endif
		
	dctx = FIPS_get_default_drbg();
        if (FIPS_drbg_init(dctx, fips_drbg_type, fips_drbg_flags) <= 0)
		{
		RANDerr(RAND_F_RAND_INIT_FIPS, RAND_R_ERROR_INITIALISING_DRBG);
		return 0;
		}
		
        FIPS_drbg_set_callbacks(dctx,
				drbg_get_entropy, drbg_free_entropy, 20,
				drbg_get_entropy, drbg_free_entropy);
	FIPS_drbg_set_rand_callbacks(dctx, drbg_get_adin, 0,
					drbg_rand_seed, drbg_rand_add);
	/* Personalisation string: a string followed by date time vector */
	strcpy((char *)pers, "OpenSSL DRBG2.0");
	plen = drbg_get_adin(dctx, &p);
	memcpy(pers + 16, p, plen);

        if (FIPS_drbg_instantiate(dctx, pers, sizeof(pers)) <= 0)
		{
		RANDerr(RAND_F_RAND_INIT_FIPS, RAND_R_ERROR_INSTANTIATING_DRBG);
		return 0;
		}
        FIPS_rand_set_method(FIPS_drbg_method());
	return 1;
	}
#endif
/* file: EC_GROUP_get_order : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx)
	{
	if (!BN_copy(order, &group->order))
		return 0;

	return !BN_is_zero(order);
	}
/* file: BN_rand_range : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_rand.c */
int	BN_rand_range(BIGNUM *r, const BIGNUM *range)
	{
	return bn_rand_range(0, r, range);
	}
/* file: BN_is_bit_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
int BN_is_bit_set(const BIGNUM *a, int n)
	{
	int i,j;

	bn_check_top(a);
	if (n < 0) return 0;
	i=n/BN_BITS2;
	j=n%BN_BITS2;
	if (a->top <= i) return 0;
	return (int)(((a->d[i])>>j)&((BN_ULONG)1));
	}
/* file: BN_cmp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
int BN_cmp(const BIGNUM *a, const BIGNUM *b)
	{
	int i;
	int gt,lt;
	BN_ULONG t1,t2;

	if ((a == NULL) || (b == NULL))
		{
		if (a != NULL)
			return(-1);
		else if (b != NULL)
			return(1);
		else
			return(0);
		}

	bn_check_top(a);
	bn_check_top(b);

	if (a->neg != b->neg)
		{
		if (a->neg)
			return(-1);
		else	return(1);
		}
	if (a->neg == 0)
		{ gt=1; lt= -1; }
	else	{ gt= -1; lt=1; }

	if (a->top > b->top) return(gt);
	if (a->top < b->top) return(lt);
	for (i=a->top-1; i>=0; i--)
		{
		t1=a->d[i];
		t2=b->d[i];
		if (t1 > t2) return(gt);
		if (t1 < t2) return(lt);
		}
	return(0);
	}
/* file: BN_sub : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_add.c */
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
	{
	int max;
	int add=0,neg=0;
	const BIGNUM *tmp;

	bn_check_top(a);
	bn_check_top(b);

	/*  a -  b	a-b
	 *  a - -b	a+b
	 * -a -  b	-(a+b)
	 * -a - -b	b-a
	 */
	if (a->neg)
		{
		if (b->neg)
			{ tmp=a; a=b; b=tmp; }
		else
			{ add=1; neg=1; }
		}
	else
		{
		if (b->neg) { add=1; neg=0; }
		}

	if (add)
		{
		if (!BN_uadd(r,a,b)) return(0);
		r->neg=neg;
		return(1);
		}

	/* We are actually doing a - b :-) */

	max=(a->top > b->top)?a->top:b->top;
	if (bn_wexpand(r,max) == NULL) return(0);
	if (BN_ucmp(a,b) < 0)
		{
		if (!BN_usub(r,b,a)) return(0);
		r->neg=1;
		}
	else
		{
		if (!BN_usub(r,a,b)) return(0);
		r->neg=0;
		}
	bn_check_top(r);
	return(1);
	}
/* file: BN_uadd : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_add.c */
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
	{
	int max,min,dif;
	BN_ULONG *ap,*bp,*rp,carry,t1,t2;
	const BIGNUM *tmp;

	bn_check_top(a);
	bn_check_top(b);

	if (a->top < b->top)
		{ tmp=a; a=b; b=tmp; }
	max = a->top;
	min = b->top;
	dif = max - min;

	if (bn_wexpand(r,max+1) == NULL)
		return 0;

	r->top=max;


	ap=a->d;
	bp=b->d;
	rp=r->d;

	carry=bn_add_words(rp,ap,bp,min);
	rp+=min;
	ap+=min;
	bp+=min;

	if (carry)
		{
		while (dif)
			{
			dif--;
			t1 = *(ap++);
			t2 = (t1+1) & BN_MASK2;
			*(rp++) = t2;
			if (t2)
				{
				carry=0;
				break;
				}
			}
		if (carry)
			{
			/* carry != 0 => dif == 0 */
			*rp = 1;
			r->top++;
			}
		}
	if (dif && rp != ap)
		while (dif--)
			/* copy remaining words if ap != rp */
			*(rp++) = *(ap++);
	r->neg = 0;
	bn_check_top(r);
	return 1;
	}
/* file: bn_add_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
#ifdef BN_LLONG
BN_ULONG bn_add_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n)
        {
	BN_ULLONG ll=0;

	assert(n >= 0);
	if (n <= 0) return((BN_ULONG)0);

#ifndef OPENSSL_SMALL_FOOTPRINT
	while (n&~3)
		{
		ll+=(BN_ULLONG)a[0]+b[0];
		r[0]=(BN_ULONG)ll&BN_MASK2;
		ll>>=BN_BITS2;
		ll+=(BN_ULLONG)a[1]+b[1];
		r[1]=(BN_ULONG)ll&BN_MASK2;
		ll>>=BN_BITS2;
		ll+=(BN_ULLONG)a[2]+b[2];
		r[2]=(BN_ULONG)ll&BN_MASK2;
		ll>>=BN_BITS2;
		ll+=(BN_ULLONG)a[3]+b[3];
		r[3]=(BN_ULONG)ll&BN_MASK2;
		ll>>=BN_BITS2;
		a+=4; b+=4; r+=4; n-=4;
		}
#endif
	while (n)
		{
		ll+=(BN_ULLONG)a[0]+b[0];
		r[0]=(BN_ULONG)ll&BN_MASK2;
		ll>>=BN_BITS2;
		a++; b++; r++; n--;
		}
	return((BN_ULONG)ll);
	}
#else /* !BN_LLONG */
/* file: bn_add_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
BN_ULONG bn_add_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n)
        {
	BN_ULONG c,l,t;

	assert(n >= 0);
	if (n <= 0) return((BN_ULONG)0);

	c=0;
#ifndef OPENSSL_SMALL_FOOTPRINT
	while (n&~3)
		{
		t=a[0];
		t=(t+c)&BN_MASK2;
		c=(t < c);
		l=(t+b[0])&BN_MASK2;
		c+=(l < t);
		r[0]=l;
		t=a[1];
		t=(t+c)&BN_MASK2;
		c=(t < c);
		l=(t+b[1])&BN_MASK2;
		c+=(l < t);
		r[1]=l;
		t=a[2];
		t=(t+c)&BN_MASK2;
		c=(t < c);
		l=(t+b[2])&BN_MASK2;
		c+=(l < t);
		r[2]=l;
		t=a[3];
		t=(t+c)&BN_MASK2;
		c=(t < c);
		l=(t+b[3])&BN_MASK2;
		c+=(l < t);
		r[3]=l;
		a+=4; b+=4; r+=4; n-=4;
		}
#endif
	while(n)
		{
		t=a[0];
		t=(t+c)&BN_MASK2;
		c=(t < c);
		l=(t+b[0])&BN_MASK2;
		c+=(l < t);
		r[0]=l;
		a++; b++; r++; n--;
		}
	return((BN_ULONG)c);
	}
#endif /* !BN_LLONG */
/* file: BN_ucmp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
int BN_ucmp(const BIGNUM *a, const BIGNUM *b)
	{
	int i;
	BN_ULONG t1,t2,*ap,*bp;

	bn_check_top(a);
	bn_check_top(b);

	i=a->top-b->top;
	if (i != 0) return(i);
	ap=a->d;
	bp=b->d;
	for (i=a->top-1; i>=0; i--)
		{
		t1= ap[i];
		t2= bp[i];
		if (t1 != t2)
			return((t1 > t2) ? 1 : -1);
		}
	return(0);
	}
/* file: BN_usub : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_add.c */
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
	{
	int max,min,dif;
	register BN_ULONG t1,t2,*ap,*bp,*rp;
	int i,carry;
#if defined(IRIX_CC_BUG) && !defined(LINT)
	int dummy;
#endif

	bn_check_top(a);
	bn_check_top(b);

	max = a->top;
	min = b->top;
	dif = max - min;

	if (dif < 0)	/* hmm... should not be happening */
		{
		BNerr(BN_F_BN_USUB,BN_R_ARG2_LT_ARG3);
		return(0);
		}

	if (bn_wexpand(r,max) == NULL) return(0);

	ap=a->d;
	bp=b->d;
	rp=r->d;

#if 1
	carry=0;
	for (i = min; i != 0; i--)
		{
		t1= *(ap++);
		t2= *(bp++);
		if (carry)
			{
			carry=(t1 <= t2);
			t1=(t1-t2-1)&BN_MASK2;
			}
		else
			{
			carry=(t1 < t2);
			t1=(t1-t2)&BN_MASK2;
			}
#if defined(IRIX_CC_BUG) && !defined(LINT)
		dummy=t1;
#endif
		*(rp++)=t1&BN_MASK2;
		}
#else
	carry=bn_sub_words(rp,ap,bp,min);
	ap+=min;
	bp+=min;
	rp+=min;
#endif
	if (carry) /* subtracted */
		{
		if (!dif)
			/* error: a < b */
			return 0;
		while (dif)
			{
			dif--;
			t1 = *(ap++);
			t2 = (t1-1)&BN_MASK2;
			*(rp++) = t2;
			if (t1)
				break;
			}
		}
#if 0
	memcpy(rp,ap,sizeof(*rp)*(max-i));
#else
	if (rp != ap)
		{
		for (;;)
			{
			if (!dif--) break;
			rp[0]=ap[0];
			if (!dif--) break;
			rp[1]=ap[1];
			if (!dif--) break;
			rp[2]=ap[2];
			if (!dif--) break;
			rp[3]=ap[3];
			rp+=4;
			ap+=4;
			}
		}
#endif

	r->top=max;
	r->neg=0;
	bn_correct_top(r);
	return(1);
	}
/* file: bn_sub_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
BN_ULONG bn_sub_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n)
        {
	BN_ULONG t1,t2;
	int c=0;

	assert(n >= 0);
	if (n <= 0) return((BN_ULONG)0);

#ifndef OPENSSL_SMALL_FOOTPRINT
	while (n&~3)
		{
		t1=a[0]; t2=b[0];
		r[0]=(t1-t2-c)&BN_MASK2;
		if (t1 != t2) c=(t1 < t2);
		t1=a[1]; t2=b[1];
		r[1]=(t1-t2-c)&BN_MASK2;
		if (t1 != t2) c=(t1 < t2);
		t1=a[2]; t2=b[2];
		r[2]=(t1-t2-c)&BN_MASK2;
		if (t1 != t2) c=(t1 < t2);
		t1=a[3]; t2=b[3];
		r[3]=(t1-t2-c)&BN_MASK2;
		if (t1 != t2) c=(t1 < t2);
		a+=4; b+=4; r+=4; n-=4;
		}
#endif
	while (n)
		{
		t1=a[0]; t2=b[0];
		r[0]=(t1-t2-c)&BN_MASK2;
		if (t1 != t2) c=(t1 < t2);
		a++; b++; r++; n--;
		}
	return(c);
	}
/* file: EC_POINT_mul : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar,
	const EC_POINT *point, const BIGNUM *p_scalar, BN_CTX *ctx)
	{
	/* just a convenient interface to EC_POINTs_mul() */

	const EC_POINT *points[1];
	const BIGNUM *scalars[1];

	points[0] = point;
	scalars[0] = p_scalar;

	return EC_POINTs_mul(group, r, g_scalar, (point != NULL && p_scalar != NULL), points, scalars, ctx);
	}
/* file: EC_POINTs_mul : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
	size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *ctx)
	{
	if (group->meth->mul == 0)
		/* use default */
		return ec_wNAF_mul(group, r, scalar, num, points, scalars, ctx);

	return group->meth->mul(group, r, scalar, num, points, scalars, ctx);
	}
/* file: ec_wNAF_mul : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_mult.c */
int ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
	size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *ctx)
	{
	BN_CTX *new_ctx = NULL;
	const EC_POINT *generator = NULL;
	EC_POINT *tmp = NULL;
	size_t totalnum;
	size_t blocksize = 0, numblocks = 0; /* for wNAF splitting */
	size_t pre_points_per_block = 0;
	size_t i, j;
	int k;
	int r_is_inverted = 0;
	int r_is_at_infinity = 1;
	size_t *wsize = NULL; /* individual window sizes */
	signed char **wNAF = NULL; /* individual wNAFs */
	size_t *wNAF_len = NULL;
	size_t max_len = 0;
	size_t num_val;
	EC_POINT **val = NULL; /* precomputation */
	EC_POINT **v;
	EC_POINT ***val_sub = NULL; /* pointers to sub-arrays of 'val' or 'pre_comp->points' */
	const EC_PRE_COMP *pre_comp = NULL;
	int num_scalar = 0; /* flag: will be set to 1 if 'scalar' must be treated like other scalars,
	                     * i.e. precomputation is not available */
	int ret = 0;
	
	if (group->meth != r->meth)
		{
		ECerr(EC_F_EC_WNAF_MUL, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}

	if ((scalar == NULL) && (num == 0))
		{
		return EC_POINT_set_to_infinity(group, r);
		}

	for (i = 0; i < num; i++)
		{
		if (group->meth != points[i]->meth)
			{
			ECerr(EC_F_EC_WNAF_MUL, EC_R_INCOMPATIBLE_OBJECTS);
			return 0;
			}
		}

	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			goto err;
		}

	if (scalar != NULL)
		{
		generator = EC_GROUP_get0_generator(group);
		if (generator == NULL)
			{
			ECerr(EC_F_EC_WNAF_MUL, EC_R_UNDEFINED_GENERATOR);
			goto err;
			}
		
		/* look if we can use precomputed multiples of generator */

		pre_comp = EC_EX_DATA_get_data(group->extra_data, ec_pre_comp_dup, ec_pre_comp_free, ec_pre_comp_clear_free);

		if (pre_comp && pre_comp->numblocks && (EC_POINT_cmp(group, generator, pre_comp->points[0], ctx) == 0))
			{
			blocksize = pre_comp->blocksize;

			/* determine maximum number of blocks that wNAF splitting may yield
			 * (NB: maximum wNAF length is bit length plus one) */
			numblocks = (BN_num_bits(scalar) / blocksize) + 1;

			/* we cannot use more blocks than we have precomputation for */
			if (numblocks > pre_comp->numblocks)
				numblocks = pre_comp->numblocks;

			pre_points_per_block = (size_t)1 << (pre_comp->w - 1);

			/* check that pre_comp looks sane */
			if (pre_comp->num != (pre_comp->numblocks * pre_points_per_block))
				{
				ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
				goto err;
				}
			}
		else
			{
			/* can't use precomputation */
			pre_comp = NULL;
			numblocks = 1;
			num_scalar = 1; /* treat 'scalar' like 'num'-th element of 'scalars' */
			}
		}
	
	totalnum = num + numblocks;

	wsize    = OPENSSL_malloc(totalnum * sizeof wsize[0]);
	wNAF_len = OPENSSL_malloc(totalnum * sizeof wNAF_len[0]);
	wNAF     = OPENSSL_malloc((totalnum + 1) * sizeof wNAF[0]); /* includes space for pivot */
	val_sub  = OPENSSL_malloc(totalnum * sizeof val_sub[0]);
		 
	if (!wsize || !wNAF_len || !wNAF || !val_sub)
		{
		ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
		goto err;
		}

	wNAF[0] = NULL;	/* preliminary pivot */

	/* num_val will be the total number of temporarily precomputed points */
	num_val = 0;

	for (i = 0; i < num + num_scalar; i++)
		{
		size_t bits;

		bits = i < num ? BN_num_bits(scalars[i]) : BN_num_bits(scalar);
		wsize[i] = EC_window_bits_for_scalar_size(bits);
		num_val += (size_t)1 << (wsize[i] - 1);
		wNAF[i + 1] = NULL; /* make sure we always have a pivot */
		wNAF[i] = compute_wNAF((i < num ? scalars[i] : scalar), wsize[i], &wNAF_len[i]);
		if (wNAF[i] == NULL)
			goto err;
		if (wNAF_len[i] > max_len)
			max_len = wNAF_len[i];
		}

	if (numblocks)
		{
		/* we go here iff scalar != NULL */
		
		if (pre_comp == NULL)
			{
			if (num_scalar != 1)
				{
				ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
				goto err;
				}
			/* we have already generated a wNAF for 'scalar' */
			}
		else
			{
			signed char *tmp_wNAF = NULL;
			size_t tmp_len = 0;
			
			if (num_scalar != 0)
				{
				ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
				goto err;
				}

			/* use the window size for which we have precomputation */
			wsize[num] = pre_comp->w;
			tmp_wNAF = compute_wNAF(scalar, wsize[num], &tmp_len);
			if (!tmp_wNAF)
				goto err;

			if (tmp_len <= max_len)
				{
				/* One of the other wNAFs is at least as long
				 * as the wNAF belonging to the generator,
				 * so wNAF splitting will not buy us anything. */

				numblocks = 1;
				totalnum = num + 1; /* don't use wNAF splitting */
				wNAF[num] = tmp_wNAF;
				wNAF[num + 1] = NULL;
				wNAF_len[num] = tmp_len;
				if (tmp_len > max_len)
					max_len = tmp_len;
				/* pre_comp->points starts with the points that we need here: */
				val_sub[num] = pre_comp->points;
				}
			else
				{
				/* don't include tmp_wNAF directly into wNAF array
				 * - use wNAF splitting and include the blocks */

				signed char *pp;
				EC_POINT **tmp_points;
				
				if (tmp_len < numblocks * blocksize)
					{
					/* possibly we can do with fewer blocks than estimated */
					numblocks = (tmp_len + blocksize - 1) / blocksize;
					if (numblocks > pre_comp->numblocks)
						{
						ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
						goto err;
						}
					totalnum = num + numblocks;
					}
				
				/* split wNAF in 'numblocks' parts */
				pp = tmp_wNAF;
				tmp_points = pre_comp->points;

				for (i = num; i < totalnum; i++)
					{
					if (i < totalnum - 1)
						{
						wNAF_len[i] = blocksize;
						if (tmp_len < blocksize)
							{
							ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
							goto err;
							}
						tmp_len -= blocksize;
						}
					else
						/* last block gets whatever is left
						 * (this could be more or less than 'blocksize'!) */
						wNAF_len[i] = tmp_len;
					
					wNAF[i + 1] = NULL;
					wNAF[i] = OPENSSL_malloc(wNAF_len[i]);
					if (wNAF[i] == NULL)
						{
						ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
						OPENSSL_free(tmp_wNAF);
						goto err;
						}
					memcpy(wNAF[i], pp, wNAF_len[i]);
					if (wNAF_len[i] > max_len)
						max_len = wNAF_len[i];

					if (*tmp_points == NULL)
						{
						ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
						OPENSSL_free(tmp_wNAF);
						goto err;
						}
					val_sub[i] = tmp_points;
					tmp_points += pre_points_per_block;
					pp += blocksize;
					}
				OPENSSL_free(tmp_wNAF);
				}
			}
		}

	/* All points we precompute now go into a single array 'val'.
	 * 'val_sub[i]' is a pointer to the subarray for the i-th point,
	 * or to a subarray of 'pre_comp->points' if we already have precomputation. */
	val = OPENSSL_malloc((num_val + 1) * sizeof val[0]);
	if (val == NULL)
		{
		ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
		goto err;
		}
	val[num_val] = NULL; /* pivot element */

	/* allocate points for precomputation */
	v = val;
	for (i = 0; i < num + num_scalar; i++)
		{
		val_sub[i] = v;
		for (j = 0; j < ((size_t)1 << (wsize[i] - 1)); j++)
			{
			*v = EC_POINT_new(group);
			if (*v == NULL) goto err;
			v++;
			}
		}
	if (!(v == val + num_val))
		{
		ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
		goto err;
		}

	if (!(tmp = EC_POINT_new(group)))
		goto err;

	/* prepare precomputed values:
	 *    val_sub[i][0] :=     points[i]
	 *    val_sub[i][1] := 3 * points[i]
	 *    val_sub[i][2] := 5 * points[i]
	 *    ...
	 */
	for (i = 0; i < num + num_scalar; i++)
		{
		if (i < num)
			{
			if (!EC_POINT_copy(val_sub[i][0], points[i])) goto err;
			}
		else
			{
			if (!EC_POINT_copy(val_sub[i][0], generator)) goto err;
			}

		if (wsize[i] > 1)
			{
			if (!EC_POINT_dbl(group, tmp, val_sub[i][0], ctx)) goto err;
			for (j = 1; j < ((size_t)1 << (wsize[i] - 1)); j++)
				{
				if (!EC_POINT_add(group, val_sub[i][j], val_sub[i][j - 1], tmp, ctx)) goto err;
				}
			}
		}

#if 1 /* optional; EC_window_bits_for_scalar_size assumes we do this step */
	if (!EC_POINTs_make_affine(group, num_val, val, ctx))
		goto err;
#endif

	r_is_at_infinity = 1;

	for (k = max_len - 1; k >= 0; k--)
		{
		if (!r_is_at_infinity)
			{
			if (!EC_POINT_dbl(group, r, r, ctx)) goto err;
			}
		
		for (i = 0; i < totalnum; i++)
			{
			if (wNAF_len[i] > (size_t)k)
				{
				int digit = wNAF[i][k];
				int is_neg;

				if (digit) 
					{
					is_neg = digit < 0;

					if (is_neg)
						digit = -digit;

					if (is_neg != r_is_inverted)
						{
						if (!r_is_at_infinity)
							{
							if (!EC_POINT_invert(group, r, ctx)) goto err;
							}
						r_is_inverted = !r_is_inverted;
						}

					/* digit > 0 */

					if (r_is_at_infinity)
						{
						if (!EC_POINT_copy(r, val_sub[i][digit >> 1])) goto err;
						r_is_at_infinity = 0;
						}
					else
						{
						if (!EC_POINT_add(group, r, r, val_sub[i][digit >> 1], ctx)) goto err;
						}
					}
				}
			}
		}

	if (r_is_at_infinity)
		{
		if (!EC_POINT_set_to_infinity(group, r)) goto err;
		}
	else
		{
		if (r_is_inverted)
			if (!EC_POINT_invert(group, r, ctx)) goto err;
		}
	
	ret = 1;

 err:
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	if (tmp != NULL)
		EC_POINT_free(tmp);
	if (wsize != NULL)
		OPENSSL_free(wsize);
	if (wNAF_len != NULL)
		OPENSSL_free(wNAF_len);
	if (wNAF != NULL)
		{
		signed char **w;
		
		for (w = wNAF; *w != NULL; w++)
			OPENSSL_free(*w);
		
		OPENSSL_free(wNAF);
		}
	if (val != NULL)
		{
		for (v = val; *v != NULL; v++)
			EC_POINT_clear_free(*v);

		OPENSSL_free(val);
		}
	if (val_sub != NULL)
		{
		OPENSSL_free(val_sub);
		}
	return ret;
	}
/* file: EC_POINT_set_to_infinity : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point)
	{
	if (group->meth->point_set_to_infinity == 0)
		{
		ECerr(EC_F_EC_POINT_SET_TO_INFINITY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != point->meth)
		{
		ECerr(EC_F_EC_POINT_SET_TO_INFINITY, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->point_set_to_infinity(group, point);
	}
/* file: EC_GROUP_get0_generator : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group)
	{
	return group->generator;
	}
/* file: EC_EX_DATA_get_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
void *EC_EX_DATA_get_data(const EC_EXTRA_DATA *ex_data,
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *))
	{
	const EC_EXTRA_DATA *d;

	for (d = ex_data; d != NULL; d = d->next)
		{
		if (d->dup_func == dup_func && d->free_func == free_func && d->clear_free_func == clear_free_func)
			return d->data;
		}
	
	return NULL;
	}
/* file: EC_POINT_cmp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx)
	{
	if (group->meth->point_cmp == 0)
		{
		ECerr(EC_F_EC_POINT_CMP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return -1;
		}
	if ((group->meth != a->meth) || (a->meth != b->meth))
		{
		ECerr(EC_F_EC_POINT_CMP, EC_R_INCOMPATIBLE_OBJECTS);
		return -1;
		}
	return group->meth->point_cmp(group, a, b, ctx);
	}
/* file: EC_POINT_dbl : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx)
	{
	if (group->meth->dbl == 0)
		{
		ECerr(EC_F_EC_POINT_DBL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if ((group->meth != r->meth) || (r->meth != a->meth))
		{
		ECerr(EC_F_EC_POINT_DBL, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->dbl(group, r, a, ctx);
	}
/* file: EC_POINT_add : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx)
	{
	if (group->meth->add == 0)
		{
		ECerr(EC_F_EC_POINT_ADD, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if ((group->meth != r->meth) || (r->meth != a->meth) || (a->meth != b->meth))
		{
		ECerr(EC_F_EC_POINT_ADD, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->add(group, r, a, b, ctx);
	}
/* file: EC_POINTs_make_affine : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_POINTs_make_affine(const EC_GROUP *group, size_t num, EC_POINT *points[], BN_CTX *ctx)
	{
	size_t i;

	if (group->meth->points_make_affine == 0)
		{
		ECerr(EC_F_EC_POINTS_MAKE_AFFINE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	for (i = 0; i < num; i++)
		{
		if (group->meth != points[i]->meth)
			{
			ECerr(EC_F_EC_POINTS_MAKE_AFFINE, EC_R_INCOMPATIBLE_OBJECTS);
			return 0;
			}
		}
	return group->meth->points_make_affine(group, num, points, ctx);
	}
/* file: EC_POINT_invert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx)
	{
	if (group->meth->dbl == 0)
		{
		ECerr(EC_F_EC_POINT_INVERT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	if (group->meth != a->meth)
		{
		ECerr(EC_F_EC_POINT_INVERT, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}
	return group->meth->invert(group, a, ctx);
	}
/* file: EC_GROUP_get_degree : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_GROUP_get_degree(const EC_GROUP *group)
	{
	if (group->meth->group_get_degree == 0)
		{
		ECerr(EC_F_EC_GROUP_GET_DEGREE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	return group->meth->group_get_degree(group);
	}
/* file: EC_KEY_get0_group : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_key.c */
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key)
	{
	return key->group;
	}
/* file: ECDH_compute_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhech_key.c */
int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
	EC_KEY *eckey,
	void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
{
	ECDH_DATA *ecdh = ecdh_check(eckey);
	if (ecdh == NULL)
		return 0;
	return ecdh->meth->compute_key(out, outlen, pub_key, eckey, KDF);
}
/* file: ecdh_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhech_lib.c */
ECDH_DATA *ecdh_check(EC_KEY *key)
	{
	ECDH_DATA *ecdh_data;
 
	void *data = EC_KEY_get_key_method_data(key, ecdh_data_dup,
					ecdh_data_free, ecdh_data_free);
	if (data == NULL)
	{
		ecdh_data = (ECDH_DATA *)ecdh_data_new();
		if (ecdh_data == NULL)
			return NULL;
		data = EC_KEY_insert_key_method_data(key, (void *)ecdh_data,
			   ecdh_data_dup, ecdh_data_free, ecdh_data_free);
		if (data != NULL)
			{
			/* Another thread raced us to install the key_method
			 * data and won. */
			ecdh_data_free(ecdh_data);
			ecdh_data = (ECDH_DATA *)data;
			}
	}
	else
		ecdh_data = (ECDH_DATA *)data;
#ifdef OPENSSL_FIPS
	if (FIPS_mode() && !(ecdh_data->flags & ECDH_FLAG_FIPS_METHOD)
			&& !(EC_KEY_get_flags(key) & EC_FLAG_NON_FIPS_ALLOW))
		{
		ECDHerr(ECDH_F_ECDH_CHECK, ECDH_R_NON_FIPS_METHOD);
		return NULL;
		}
#endif
	

	return ecdh_data;
	}
/* file: EC_KEY_get_key_method_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_key.c */
void *EC_KEY_get_key_method_data(EC_KEY *key,
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *))
	{
	void *ret;

	CRYPTO_r_lock(CRYPTO_LOCK_EC);
	ret = EC_EX_DATA_get_data(key->method_data, dup_func, free_func, clear_free_func);
	CRYPTO_r_unlock(CRYPTO_LOCK_EC);

	return ret;
	}
/* file: ecdh_data_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhech_lib.c */
static void *ecdh_data_new(void)
	{
	return (void *)ECDH_DATA_new_method(NULL);
	}
/* file: ECDH_get_default_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhech_lib.c */
const ECDH_METHOD *ECDH_get_default_method(void)
	{
	if(!default_ECDH_method) 
		{
#ifdef OPENSSL_FIPS
		if (FIPS_mode())
			return FIPS_ecdh_openssl();
		else
			return ECDH_OpenSSL();
#else
		default_ECDH_method = ECDH_OpenSSL();
#endif
		}
	return default_ECDH_method;
	}
/* file: ECDH_OpenSSL : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhech_ossl.c */
const ECDH_METHOD *ECDH_OpenSSL(void)
	{
	return &openssl_ecdh_meth;
	}
/* file: ENGINE_get_default_ECDH : /Volumes/work/Phd/ECDH/kv_openssl/crypto/enginetb_ecdh.c */
ENGINE *ENGINE_get_default_ECDH(void)
	{
	return engine_table_select(&ecdh_table, dummy_nid);
	}
/* file: ENGINE_get_ECDH : /Volumes/work/Phd/ECDH/kv_openssl/crypto/enginetb_ecdh.c */
const ECDH_METHOD *ENGINE_get_ECDH(const ENGINE *e)
	{
	return e->ecdh_meth;
	}
/* file: CRYPTO_new_ex_data : /Volumes/work/Phd/ECDH/kv_openssl/cryptoex_data.c */
int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
	{
	IMPL_CHECK
	return EX_IMPL(new_ex_data)(class_index, obj, ad);
	}
/* file: EC_KEY_insert_key_method_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_key.c */
void *EC_KEY_insert_key_method_data(EC_KEY *key, void *data,
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *))
	{
	EC_EXTRA_DATA *ex_data;

	CRYPTO_w_lock(CRYPTO_LOCK_EC);
	ex_data = EC_EX_DATA_get_data(key->method_data, dup_func, free_func, clear_free_func);
	if (ex_data == NULL)
		EC_EX_DATA_set_data(&key->method_data, data, dup_func, free_func, clear_free_func);
	CRYPTO_w_unlock(CRYPTO_LOCK_EC);

	return ex_data;
	}
/* file: EC_EX_DATA_set_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lib.c */
int EC_EX_DATA_set_data(EC_EXTRA_DATA **ex_data, void *data,
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *))
	{
	EC_EXTRA_DATA *d;

	if (ex_data == NULL)
		return 0;

	for (d = *ex_data; d != NULL; d = d->next)
		{
		if (d->dup_func == dup_func && d->free_func == free_func && d->clear_free_func == clear_free_func)
			{
			ECerr(EC_F_EC_EX_DATA_SET_DATA, EC_R_SLOT_FULL);
			return 0;
			}
		}

	if (data == NULL)
		/* no explicit entry needed */
		return 1;

	d = OPENSSL_malloc(sizeof *d);
	if (d == NULL)
		return 0;

	d->data = data;
	d->dup_func = dup_func;
	d->free_func = free_func;
	d->clear_free_func = clear_free_func;

	d->next = *ex_data;
	*ex_data = d;

	return 1;
	}
/* file: ecdh_data_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhech_lib.c */
void ecdh_data_free(void *data)
	{
	ECDH_DATA *r = (ECDH_DATA *)data;

#ifndef OPENSSL_NO_ENGINE
	if (r->engine)
		ENGINE_finish(r->engine);
#endif

	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ECDH, r, &r->ex_data);

	OPENSSL_cleanse((void *)r, sizeof(ECDH_DATA));

	OPENSSL_free(r);
	}
/* file: EC_KEY_get_flags : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_key.c */
int EC_KEY_get_flags(const EC_KEY *key)
	{
	return key->flags;
	}
/* file: compute_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/dhdh_key.c */
static int compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
	{
	BN_CTX *ctx=NULL;
	BN_MONT_CTX *mont=NULL;
	BIGNUM *tmp;
	int ret= -1;
        int check_result;

	if (BN_num_bits(dh->p) > OPENSSL_DH_MAX_MODULUS_BITS)
		{
		DHerr(DH_F_COMPUTE_KEY,DH_R_MODULUS_TOO_LARGE);
		goto err;
		}

	ctx = BN_CTX_new();
	if (ctx == NULL) goto err;
	BN_CTX_start(ctx);
	tmp = BN_CTX_get(ctx);
	
	if (dh->priv_key == NULL)
		{
		DHerr(DH_F_COMPUTE_KEY,DH_R_NO_PRIVATE_VALUE);
		goto err;
		}

	if (dh->flags & DH_FLAG_CACHE_MONT_P)
		{
		mont = BN_MONT_CTX_set_locked(&dh->method_mont_p,
				CRYPTO_LOCK_DH, dh->p, ctx);
		if ((dh->flags & DH_FLAG_NO_EXP_CONSTTIME) == 0)
			{
			/* XXX */
			BN_set_flags(dh->priv_key, BN_FLG_CONSTTIME);
			}
		if (!mont)
			goto err;
		}

        if (!DH_check_pub_key(dh, pub_key, &check_result) || check_result)
		{
		DHerr(DH_F_COMPUTE_KEY,DH_R_INVALID_PUBKEY);
		goto err;
		}

	if (!dh->meth->bn_mod_exp(dh, tmp, pub_key, dh->priv_key,dh->p,ctx,mont))
		{
		DHerr(DH_F_COMPUTE_KEY,ERR_R_BN_LIB);
		goto err;
		}

	ret=BN_bn2bin(tmp,key);
err:
	if (ctx != NULL)
		{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
		}
	return(ret);
	}
/* file: BN_CTX_start : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
void BN_CTX_start(BN_CTX *ctx)
	{
	CTXDBG_ENTRY("BN_CTX_start", ctx);
	/* If we're already overflowing ... */
	if(ctx->err_stack || ctx->too_many)
		ctx->err_stack++;
	/* (Try to) get a new frame pointer */
	else if(!BN_STACK_push(&ctx->stack, ctx->used))
		{
		BNerr(BN_F_BN_CTX_START,BN_R_TOO_MANY_TEMPORARY_VARIABLES);
		ctx->err_stack++;
		}
	CTXDBG_EXIT(ctx);
	}
/* file: BN_STACK_push : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static int BN_STACK_push(BN_STACK *st, unsigned int idx)
	{
	if(st->depth == st->size)
		/* Need to expand */
		{
		unsigned int newsize = (st->size ?
				(st->size * 3 / 2) : BN_CTX_START_FRAMES);
		unsigned int *newitems = OPENSSL_malloc(newsize *
						sizeof(unsigned int));
		if(!newitems) return 0;
		if(st->depth)
			memcpy(newitems, st->indexes, st->depth *
						sizeof(unsigned int));
		if(st->size) OPENSSL_free(st->indexes);
		st->indexes = newitems;
		st->size = newsize;
		}
	st->indexes[(st->depth)++] = idx;
	return 1;
	}
/* file: BN_CTX_get : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
BIGNUM *BN_CTX_get(BN_CTX *ctx)
	{
	BIGNUM *ret;
	CTXDBG_ENTRY("BN_CTX_get", ctx);
	if(ctx->err_stack || ctx->too_many) return NULL;
	if((ret = BN_POOL_get(&ctx->pool)) == NULL)
		{
		/* Setting too_many prevents repeated "get" attempts from
		 * cluttering the error stack. */
		ctx->too_many = 1;
		BNerr(BN_F_BN_CTX_GET,BN_R_TOO_MANY_TEMPORARY_VARIABLES);
		return NULL;
		}
	/* OK, make sure the returned bignum is "zero" */
	BN_zero(ret);
	ctx->used++;
	CTXDBG_RET(ctx, ret);
	return ret;
	}
/* file: BN_MONT_CTX_set_locked : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_mont.c */
BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, int lock,
					const BIGNUM *mod, BN_CTX *ctx)
	{
	int got_write_lock = 0;
	BN_MONT_CTX *ret;

	CRYPTO_r_lock(lock);
	if (!*pmont)
		{
		CRYPTO_r_unlock(lock);
		CRYPTO_w_lock(lock);
		got_write_lock = 1;

		if (!*pmont)
			{
			ret = BN_MONT_CTX_new();
			if (ret && !BN_MONT_CTX_set(ret, mod, ctx))
				BN_MONT_CTX_free(ret);
			else
				*pmont = ret;
			}
		}
	
	ret = *pmont;
	
	if (got_write_lock)
		CRYPTO_w_unlock(lock);
	else
		CRYPTO_r_unlock(lock);
		
	return ret;
	}
/* file: BN_MONT_CTX_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_mont.c */
BN_MONT_CTX *BN_MONT_CTX_new(void)
	{
	BN_MONT_CTX *ret;

	if ((ret=(BN_MONT_CTX *)OPENSSL_malloc(sizeof(BN_MONT_CTX))) == NULL)
		return(NULL);

	BN_MONT_CTX_init(ret);
	ret->flags=BN_FLG_MALLOCED;
	return(ret);
	}
/* file: BN_MONT_CTX_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_mont.c */
void BN_MONT_CTX_init(BN_MONT_CTX *ctx)
	{
	ctx->ri=0;
	BN_init(&(ctx->RR));
	BN_init(&(ctx->N));
	BN_init(&(ctx->Ni));
	ctx->n0[0] = ctx->n0[1] = 0;
	ctx->flags=0;
	}
/* file: BN_MONT_CTX_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_mont.c */
int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx)
	{
	int ret = 0;
	BIGNUM *Ri,*R;

	BN_CTX_start(ctx);
	if((Ri = BN_CTX_get(ctx)) == NULL) goto err;
	R= &(mont->RR);					/* grab RR as a temp */
	if (!BN_copy(&(mont->N),mod)) goto err;		/* Set N */
	mont->N.neg = 0;

#ifdef MONT_WORD
		{
		BIGNUM tmod;
		BN_ULONG buf[2];

		BN_init(&tmod);
		tmod.d=buf;
		tmod.dmax=2;
		tmod.neg=0;

		mont->ri=(BN_num_bits(mod)+(BN_BITS2-1))/BN_BITS2*BN_BITS2;

#if defined(OPENSSL_BN_ASM_MONT) && (BN_BITS2<=32)
		/* Only certain BN_BITS2<=32 platforms actually make use of
		 * n0[1], and we could use the #else case (with a shorter R
		 * value) for the others.  However, currently only the assembler
		 * files do know which is which. */

		BN_zero(R);
		if (!(BN_set_bit(R,2*BN_BITS2))) goto err;

								tmod.top=0;
		if ((buf[0] = mod->d[0]))			tmod.top=1;
		if ((buf[1] = mod->top>1 ? mod->d[1] : 0))	tmod.top=2;

		if ((BN_mod_inverse(Ri,R,&tmod,ctx)) == NULL)
			goto err;
		if (!BN_lshift(Ri,Ri,2*BN_BITS2)) goto err; /* R*Ri */
		if (!BN_is_zero(Ri))
			{
			if (!BN_sub_word(Ri,1)) goto err;
			}
		else /* if N mod word size == 1 */
			{
			if (bn_expand(Ri,(int)sizeof(BN_ULONG)*2) == NULL)
				goto err;
			/* Ri-- (mod double word size) */
			Ri->neg=0;
			Ri->d[0]=BN_MASK2;
			Ri->d[1]=BN_MASK2;
			Ri->top=2;
			}
		if (!BN_div(Ri,NULL,Ri,&tmod,ctx)) goto err;
		/* Ni = (R*Ri-1)/N,
		 * keep only couple of least significant words: */
		mont->n0[0] = (Ri->top > 0) ? Ri->d[0] : 0;
		mont->n0[1] = (Ri->top > 1) ? Ri->d[1] : 0;
#else
		BN_zero(R);
		if (!(BN_set_bit(R,BN_BITS2))) goto err;	/* R */

		buf[0]=mod->d[0]; /* tmod = N mod word size */
		buf[1]=0;
		tmod.top = buf[0] != 0 ? 1 : 0;
							/* Ri = R^-1 mod N*/
		if ((BN_mod_inverse(Ri,R,&tmod,ctx)) == NULL)
			goto err;
		if (!BN_lshift(Ri,Ri,BN_BITS2)) goto err; /* R*Ri */
		if (!BN_is_zero(Ri))
			{
			if (!BN_sub_word(Ri,1)) goto err;
			}
		else /* if N mod word size == 1 */
			{
			if (!BN_set_word(Ri,BN_MASK2)) goto err;  /* Ri-- (mod word size) */
			}
		if (!BN_div(Ri,NULL,Ri,&tmod,ctx)) goto err;
		/* Ni = (R*Ri-1)/N,
		 * keep only least significant word: */
		mont->n0[0] = (Ri->top > 0) ? Ri->d[0] : 0;
		mont->n0[1] = 0;
#endif
		}
#else /* !MONT_WORD */
		{ /* bignum version */
		mont->ri=BN_num_bits(&mont->N);
		BN_zero(R);
		if (!BN_set_bit(R,mont->ri)) goto err;  /* R = 2^ri */
		                                        /* Ri = R^-1 mod N*/
		if ((BN_mod_inverse(Ri,R,&mont->N,ctx)) == NULL)
			goto err;
		if (!BN_lshift(Ri,Ri,mont->ri)) goto err; /* R*Ri */
		if (!BN_sub_word(Ri,1)) goto err;
							/* Ni = (R*Ri-1) / N */
		if (!BN_div(&(mont->Ni),NULL,Ri,&mont->N,ctx)) goto err;
		}
#endif

	/* setup RR for conversions */
	BN_zero(&(mont->RR));
	if (!BN_set_bit(&(mont->RR),mont->ri*2)) goto err;
	if (!BN_mod(&(mont->RR),&(mont->RR),&(mont->N),ctx)) goto err;

	ret = 1;
err:
	BN_CTX_end(ctx);
	return ret;
	}
/* file: BN_set_bit : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
int BN_set_bit(BIGNUM *a, int n)
	{
	int i,j,k;

	if (n < 0)
		return 0;

	i=n/BN_BITS2;
	j=n%BN_BITS2;
	if (a->top <= i)
		{
		if (bn_wexpand(a,i+1) == NULL) return(0);
		for(k=a->top; k<i+1; k++)
			a->d[k]=0;
		a->top=i+1;
		}

	a->d[i]|=(((BN_ULONG)1)<<j);
	bn_check_top(a);
	return(1);
	}
/* file: BN_mod_inverse : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_gcd.c */
BIGNUM *BN_mod_inverse(BIGNUM *in,
	const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
	{
	BIGNUM *A,*B,*X,*Y,*M,*D,*T,*R=NULL;
	BIGNUM *ret=NULL;
	int sign;

	if ((BN_get_flags(a, BN_FLG_CONSTTIME) != 0) || (BN_get_flags(n, BN_FLG_CONSTTIME) != 0))
		{
		return BN_mod_inverse_no_branch(in, a, n, ctx);
		}

	bn_check_top(a);
	bn_check_top(n);

	BN_CTX_start(ctx);
	A = BN_CTX_get(ctx);
	B = BN_CTX_get(ctx);
	X = BN_CTX_get(ctx);
	D = BN_CTX_get(ctx);
	M = BN_CTX_get(ctx);
	Y = BN_CTX_get(ctx);
	T = BN_CTX_get(ctx);
	if (T == NULL) goto err;

	if (in == NULL)
		R=BN_new();
	else
		R=in;
	if (R == NULL) goto err;

	BN_one(X);
	BN_zero(Y);
	if (BN_copy(B,a) == NULL) goto err;
	if (BN_copy(A,n) == NULL) goto err;
	A->neg = 0;
	if (B->neg || (BN_ucmp(B, A) >= 0))
		{
		if (!BN_nnmod(B, B, A, ctx)) goto err;
		}
	sign = -1;
	/* From  B = a mod |n|,  A = |n|  it follows that
	 *
	 *      0 <= B < A,
	 *     -sign*X*a  ==  B   (mod |n|),
	 *      sign*Y*a  ==  A   (mod |n|).
	 */

	if (BN_is_odd(n) && (BN_num_bits(n) <= (BN_BITS <= 32 ? 450 : 2048)))
		{
		/* Binary inversion algorithm; requires odd modulus.
		 * This is faster than the general algorithm if the modulus
		 * is sufficiently small (about 400 .. 500 bits on 32-bit
		 * sytems, but much more on 64-bit systems) */
		int shift;
		
		while (!BN_is_zero(B))
			{
			/*
			 *      0 < B < |n|,
			 *      0 < A <= |n|,
			 * (1) -sign*X*a  ==  B   (mod |n|),
			 * (2)  sign*Y*a  ==  A   (mod |n|)
			 */

			/* Now divide  B  by the maximum possible power of two in the integers,
			 * and divide  X  by the same value mod |n|.
			 * When we're done, (1) still holds. */
			shift = 0;
			while (!BN_is_bit_set(B, shift)) /* note that 0 < B */
				{
				shift++;
				
				if (BN_is_odd(X))
					{
					if (!BN_uadd(X, X, n)) goto err;
					}
				/* now X is even, so we can easily divide it by two */
				if (!BN_rshift1(X, X)) goto err;
				}
			if (shift > 0)
				{
				if (!BN_rshift(B, B, shift)) goto err;
				}


			/* Same for  A  and  Y.  Afterwards, (2) still holds. */
			shift = 0;
			while (!BN_is_bit_set(A, shift)) /* note that 0 < A */
				{
				shift++;
				
				if (BN_is_odd(Y))
					{
					if (!BN_uadd(Y, Y, n)) goto err;
					}
				/* now Y is even */
				if (!BN_rshift1(Y, Y)) goto err;
				}
			if (shift > 0)
				{
				if (!BN_rshift(A, A, shift)) goto err;
				}

			
			/* We still have (1) and (2).
			 * Both  A  and  B  are odd.
			 * The following computations ensure that
			 *
			 *     0 <= B < |n|,
			 *      0 < A < |n|,
			 * (1) -sign*X*a  ==  B   (mod |n|),
			 * (2)  sign*Y*a  ==  A   (mod |n|),
			 *
			 * and that either  A  or  B  is even in the next iteration.
			 */
			if (BN_ucmp(B, A) >= 0)
				{
				/* -sign*(X + Y)*a == B - A  (mod |n|) */
				if (!BN_uadd(X, X, Y)) goto err;
				/* NB: we could use BN_mod_add_quick(X, X, Y, n), but that
				 * actually makes the algorithm slower */
				if (!BN_usub(B, B, A)) goto err;
				}
			else
				{
				/*  sign*(X + Y)*a == A - B  (mod |n|) */
				if (!BN_uadd(Y, Y, X)) goto err;
				/* as above, BN_mod_add_quick(Y, Y, X, n) would slow things down */
				if (!BN_usub(A, A, B)) goto err;
				}
			}
		}
	else
		{
		/* general inversion algorithm */

		while (!BN_is_zero(B))
			{
			BIGNUM *tmp;
			
			/*
			 *      0 < B < A,
			 * (*) -sign*X*a  ==  B   (mod |n|),
			 *      sign*Y*a  ==  A   (mod |n|)
			 */
			
			/* (D, M) := (A/B, A%B) ... */
			if (BN_num_bits(A) == BN_num_bits(B))
				{
				if (!BN_one(D)) goto err;
				if (!BN_sub(M,A,B)) goto err;
				}
			else if (BN_num_bits(A) == BN_num_bits(B) + 1)
				{
				/* A/B is 1, 2, or 3 */
				if (!BN_lshift1(T,B)) goto err;
				if (BN_ucmp(A,T) < 0)
					{
					/* A < 2*B, so D=1 */
					if (!BN_one(D)) goto err;
					if (!BN_sub(M,A,B)) goto err;
					}
				else
					{
					/* A >= 2*B, so D=2 or D=3 */
					if (!BN_sub(M,A,T)) goto err;
					if (!BN_add(D,T,B)) goto err; /* use D (:= 3*B) as temp */
					if (BN_ucmp(A,D) < 0)
						{
						/* A < 3*B, so D=2 */
						if (!BN_set_word(D,2)) goto err;
						/* M (= A - 2*B) already has the correct value */
						}
					else
						{
						/* only D=3 remains */
						if (!BN_set_word(D,3)) goto err;
						/* currently  M = A - 2*B,  but we need  M = A - 3*B */
						if (!BN_sub(M,M,B)) goto err;
						}
					}
				}
			else
				{
				if (!BN_div(D,M,A,B,ctx)) goto err;
				}
			
			/* Now
			 *      A = D*B + M;
			 * thus we have
			 * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
			 */
			
			tmp=A; /* keep the BIGNUM object, the value does not matter */
			
			/* (A, B) := (B, A mod B) ... */
			A=B;
			B=M;
			/* ... so we have  0 <= B < A  again */
			
			/* Since the former  M  is now  B  and the former  B  is now  A,
			 * (**) translates into
			 *       sign*Y*a  ==  D*A + B    (mod |n|),
			 * i.e.
			 *       sign*Y*a - D*A  ==  B    (mod |n|).
			 * Similarly, (*) translates into
			 *      -sign*X*a  ==  A          (mod |n|).
			 *
			 * Thus,
			 *   sign*Y*a + D*sign*X*a  ==  B  (mod |n|),
			 * i.e.
			 *        sign*(Y + D*X)*a  ==  B  (mod |n|).
			 *
			 * So if we set  (X, Y, sign) := (Y + D*X, X, -sign),  we arrive back at
			 *      -sign*X*a  ==  B   (mod |n|),
			 *       sign*Y*a  ==  A   (mod |n|).
			 * Note that  X  and  Y  stay non-negative all the time.
			 */
			
			/* most of the time D is very small, so we can optimize tmp := D*X+Y */
			if (BN_is_one(D))
				{
				if (!BN_add(tmp,X,Y)) goto err;
				}
			else
				{
				if (BN_is_word(D,2))
					{
					if (!BN_lshift1(tmp,X)) goto err;
					}
				else if (BN_is_word(D,4))
					{
					if (!BN_lshift(tmp,X,2)) goto err;
					}
				else if (D->top == 1)
					{
					if (!BN_copy(tmp,X)) goto err;
					if (!BN_mul_word(tmp,D->d[0])) goto err;
					}
				else
					{
					if (!BN_mul(tmp,D,X,ctx)) goto err;
					}
				if (!BN_add(tmp,tmp,Y)) goto err;
				}
			
			M=Y; /* keep the BIGNUM object, the value does not matter */
			Y=X;
			X=tmp;
			sign = -sign;
			}
		}
		
	/*
	 * The while loop (Euclid's algorithm) ends when
	 *      A == gcd(a,n);
	 * we have
	 *       sign*Y*a  ==  A  (mod |n|),
	 * where  Y  is non-negative.
	 */

	if (sign < 0)
		{
		if (!BN_sub(Y,n,Y)) goto err;
		}
	/* Now  Y*a  ==  A  (mod |n|).  */
	

	if (BN_is_one(A))
		{
		/* Y*a == 1  (mod |n|) */
		if (!Y->neg && BN_ucmp(Y,n) < 0)
			{
			if (!BN_copy(R,Y)) goto err;
			}
		else
			{
			if (!BN_nnmod(R,Y,n,ctx)) goto err;
			}
		}
	else
		{
		BNerr(BN_F_BN_MOD_INVERSE,BN_R_NO_INVERSE);
		goto err;
		}
	ret=R;
err:
	if ((ret == NULL) && (in == NULL)) BN_free(R);
	BN_CTX_end(ctx);
	bn_check_top(ret);
	return(ret);
	}
/* file: BN_mod_inverse_no_branch : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_gcd.c */
static BIGNUM *BN_mod_inverse_no_branch(BIGNUM *in,
        const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

BIGNUM *BN_mod_inverse(BIGNUM *in,
	const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
	{
	BIGNUM *A,*B,*X,*Y,*M,*D,*T,*R=NULL;
	BIGNUM *ret=NULL;
	int sign;

	if ((BN_get_flags(a, BN_FLG_CONSTTIME) != 0) || (BN_get_flags(n, BN_FLG_CONSTTIME) != 0))
		{
		return BN_mod_inverse_no_branch(in, a, n, ctx);
		}

	bn_check_top(a);
	bn_check_top(n);

	BN_CTX_start(ctx);
	A = BN_CTX_get(ctx);
	B = BN_CTX_get(ctx);
	X = BN_CTX_get(ctx);
	D = BN_CTX_get(ctx);
	M = BN_CTX_get(ctx);
	Y = BN_CTX_get(ctx);
	T = BN_CTX_get(ctx);
	if (T == NULL) goto err;

	if (in == NULL)
		R=BN_new();
	else
		R=in;
	if (R == NULL) goto err;

	BN_one(X);
	BN_zero(Y);
	if (BN_copy(B,a) == NULL) goto err;
	if (BN_copy(A,n) == NULL) goto err;
	A->neg = 0;
	if (B->neg || (BN_ucmp(B, A) >= 0))
		{
		if (!BN_nnmod(B, B, A, ctx)) goto err;
		}
	sign = -1;
	/* From  B = a mod |n|,  A = |n|  it follows that
	 *
	 *      0 <= B < A,
	 *     -sign*X*a  ==  B   (mod |n|),
	 *      sign*Y*a  ==  A   (mod |n|).
	 */

	if (BN_is_odd(n) && (BN_num_bits(n) <= (BN_BITS <= 32 ? 450 : 2048)))
		{
		/* Binary inversion algorithm; requires odd modulus.
		 * This is faster than the general algorithm if the modulus
		 * is sufficiently small (about 400 .. 500 bits on 32-bit
		 * sytems, but much more on 64-bit systems) */
		int shift;
		
		while (!BN_is_zero(B))
			{
			/*
			 *      0 < B < |n|,
			 *      0 < A <= |n|,
			 * (1) -sign*X*a  ==  B   (mod |n|),
			 * (2)  sign*Y*a  ==  A   (mod |n|)
			 */

			/* Now divide  B  by the maximum possible power of two in the integers,
			 * and divide  X  by the same value mod |n|.
			 * When we're done, (1) still holds. */
			shift = 0;
			while (!BN_is_bit_set(B, shift)) /* note that 0 < B */
				{
				shift++;
				
				if (BN_is_odd(X))
					{
					if (!BN_uadd(X, X, n)) goto err;
					}
				/* now X is even, so we can easily divide it by two */
				if (!BN_rshift1(X, X)) goto err;
				}
			if (shift > 0)
				{
				if (!BN_rshift(B, B, shift)) goto err;
				}


			/* Same for  A  and  Y.  Afterwards, (2) still holds. */
			shift = 0;
			while (!BN_is_bit_set(A, shift)) /* note that 0 < A */
				{
				shift++;
				
				if (BN_is_odd(Y))
					{
					if (!BN_uadd(Y, Y, n)) goto err;
					}
				/* now Y is even */
				if (!BN_rshift1(Y, Y)) goto err;
				}
			if (shift > 0)
				{
				if (!BN_rshift(A, A, shift)) goto err;
				}

			
			/* We still have (1) and (2).
			 * Both  A  and  B  are odd.
			 * The following computations ensure that
			 *
			 *     0 <= B < |n|,
			 *      0 < A < |n|,
			 * (1) -sign*X*a  ==  B   (mod |n|),
			 * (2)  sign*Y*a  ==  A   (mod |n|),
			 *
			 * and that either  A  or  B  is even in the next iteration.
			 */
			if (BN_ucmp(B, A) >= 0)
				{
				/* -sign*(X + Y)*a == B - A  (mod |n|) */
				if (!BN_uadd(X, X, Y)) goto err;
				/* NB: we could use BN_mod_add_quick(X, X, Y, n), but that
				 * actually makes the algorithm slower */
				if (!BN_usub(B, B, A)) goto err;
				}
			else
				{
				/*  sign*(X + Y)*a == A - B  (mod |n|) */
				if (!BN_uadd(Y, Y, X)) goto err;
				/* as above, BN_mod_add_quick(Y, Y, X, n) would slow things down */
				if (!BN_usub(A, A, B)) goto err;
				}
			}
		}
	else
		{
		/* general inversion algorithm */

		while (!BN_is_zero(B))
			{
			BIGNUM *tmp;
			
			/*
			 *      0 < B < A,
			 * (*) -sign*X*a  ==  B   (mod |n|),
			 *      sign*Y*a  ==  A   (mod |n|)
			 */
			
			/* (D, M) := (A/B, A%B) ... */
			if (BN_num_bits(A) == BN_num_bits(B))
				{
				if (!BN_one(D)) goto err;
				if (!BN_sub(M,A,B)) goto err;
				}
			else if (BN_num_bits(A) == BN_num_bits(B) + 1)
				{
				/* A/B is 1, 2, or 3 */
				if (!BN_lshift1(T,B)) goto err;
				if (BN_ucmp(A,T) < 0)
					{
					/* A < 2*B, so D=1 */
					if (!BN_one(D)) goto err;
					if (!BN_sub(M,A,B)) goto err;
					}
				else
					{
					/* A >= 2*B, so D=2 or D=3 */
					if (!BN_sub(M,A,T)) goto err;
					if (!BN_add(D,T,B)) goto err; /* use D (:= 3*B) as temp */
					if (BN_ucmp(A,D) < 0)
						{
						/* A < 3*B, so D=2 */
						if (!BN_set_word(D,2)) goto err;
						/* M (= A - 2*B) already has the correct value */
						}
					else
						{
						/* only D=3 remains */
						if (!BN_set_word(D,3)) goto err;
						/* currently  M = A - 2*B,  but we need  M = A - 3*B */
						if (!BN_sub(M,M,B)) goto err;
						}
					}
				}
			else
				{
				if (!BN_div(D,M,A,B,ctx)) goto err;
				}
			
			/* Now
			 *      A = D*B + M;
			 * thus we have
			 * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
			 */
			
			tmp=A; /* keep the BIGNUM object, the value does not matter */
			
			/* (A, B) := (B, A mod B) ... */
			A=B;
			B=M;
			/* ... so we have  0 <= B < A  again */
			
			/* Since the former  M  is now  B  and the former  B  is now  A,
			 * (**) translates into
			 *       sign*Y*a  ==  D*A + B    (mod |n|),
			 * i.e.
			 *       sign*Y*a - D*A  ==  B    (mod |n|).
			 * Similarly, (*) translates into
			 *      -sign*X*a  ==  A          (mod |n|).
			 *
			 * Thus,
			 *   sign*Y*a + D*sign*X*a  ==  B  (mod |n|),
			 * i.e.
			 *        sign*(Y + D*X)*a  ==  B  (mod |n|).
			 *
			 * So if we set  (X, Y, sign) := (Y + D*X, X, -sign),  we arrive back at
			 *      -sign*X*a  ==  B   (mod |n|),
			 *       sign*Y*a  ==  A   (mod |n|).
			 * Note that  X  and  Y  stay non-negative all the time.
			 */
			
			/* most of the time D is very small, so we can optimize tmp := D*X+Y */
			if (BN_is_one(D))
				{
				if (!BN_add(tmp,X,Y)) goto err;
				}
			else
				{
				if (BN_is_word(D,2))
					{
					if (!BN_lshift1(tmp,X)) goto err;
					}
				else if (BN_is_word(D,4))
					{
					if (!BN_lshift(tmp,X,2)) goto err;
					}
				else if (D->top == 1)
					{
					if (!BN_copy(tmp,X)) goto err;
					if (!BN_mul_word(tmp,D->d[0])) goto err;
					}
				else
					{
					if (!BN_mul(tmp,D,X,ctx)) goto err;
					}
				if (!BN_add(tmp,tmp,Y)) goto err;
				}
			
			M=Y; /* keep the BIGNUM object, the value does not matter */
			Y=X;
			X=tmp;
			sign = -sign;
			}
		}
		
	/*
	 * The while loop (Euclid's algorithm) ends when
	 *      A == gcd(a,n);
	 * we have
	 *       sign*Y*a  ==  A  (mod |n|),
	 * where  Y  is non-negative.
	 */

	if (sign < 0)
		{
		if (!BN_sub(Y,n,Y)) goto err;
		}
	/* Now  Y*a  ==  A  (mod |n|).  */
	

	if (BN_is_one(A))
		{
		/* Y*a == 1  (mod |n|) */
		if (!Y->neg && BN_ucmp(Y,n) < 0)
			{
			if (!BN_copy(R,Y)) goto err;
			}
		else
			{
			if (!BN_nnmod(R,Y,n,ctx)) goto err;
			}
		}
	else
		{
		BNerr(BN_F_BN_MOD_INVERSE,BN_R_NO_INVERSE);
		goto err;
		}
	ret=R;
err:
	if ((ret == NULL) && (in == NULL)) BN_free(R);
	BN_CTX_end(ctx);
	bn_check_top(ret);
	return(ret);
	}
/* file: BN_nnmod : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_mod.c */
int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
	{
	/* like BN_mod, but returns non-negative remainder
	 * (i.e.,  0 <= r < |d|  always holds) */

	if (!(BN_mod(r,m,d,ctx)))
		return 0;
	if (!r->neg)
		return 1;
	/* now   -|d| < r < 0,  so we have to set  r := r + |d| */
	return (d->neg ? BN_sub : BN_add)(r, r, d);
}
/* file: BN_div : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_div.c */
#if 0
int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
	   BN_CTX *ctx)
	{
	int i,nm,nd;
	int ret = 0;
	BIGNUM *D;

	bn_check_top(m);
	bn_check_top(d);
	if (BN_is_zero(d))
		{
		BNerr(BN_F_BN_DIV,BN_R_DIV_BY_ZERO);
		return(0);
		}

	if (BN_ucmp(m,d) < 0)
		{
		if (rem != NULL)
			{ if (BN_copy(rem,m) == NULL) return(0); }
		if (dv != NULL) BN_zero(dv);
		return(1);
		}

	BN_CTX_start(ctx);
	D = BN_CTX_get(ctx);
	if (dv == NULL) dv = BN_CTX_get(ctx);
	if (rem == NULL) rem = BN_CTX_get(ctx);
	if (D == NULL || dv == NULL || rem == NULL)
		goto end;

	nd=BN_num_bits(d);
	nm=BN_num_bits(m);
	if (BN_copy(D,d) == NULL) goto end;
	if (BN_copy(rem,m) == NULL) goto end;

	/* The next 2 are needed so we can do a dv->d[0]|=1 later
	 * since BN_lshift1 will only work once there is a value :-) */
	BN_zero(dv);
	if(bn_wexpand(dv,1) == NULL) goto end;
	dv->top=1;

	if (!BN_lshift(D,D,nm-nd)) goto end;
	for (i=nm-nd; i>=0; i--)
		{
		if (!BN_lshift1(dv,dv)) goto end;
		if (BN_ucmp(rem,D) >= 0)
			{
			dv->d[0]|=1;
			if (!BN_usub(rem,rem,D)) goto end;
			}
/* CAN IMPROVE (and have now :=) */
		if (!BN_rshift1(D,D)) goto end;
		}
	rem->neg=BN_is_zero(rem)?0:m->neg;
	dv->neg=m->neg^d->neg;
	ret = 1;
 end:
	BN_CTX_end(ctx);
	return(ret);
	}
#else
/* file: BN_div : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_div.c */
#  elif defined(__x86_64) && defined(SIXTY_FOUR_BIT_LONG)
int BN_div(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num, const BIGNUM *divisor,
	   BN_CTX *ctx)
	{
	int norm_shift,i,loop;
	BIGNUM *tmp,wnum,*snum,*sdiv,*res;
	BN_ULONG *resp,*wnump;
	BN_ULONG d0,d1;
	int num_n,div_n;
	int no_branch=0;

	/* Invalid zero-padding would have particularly bad consequences
	 * in the case of 'num', so don't just rely on bn_check_top() for this one
	 * (bn_check_top() works only for BN_DEBUG builds) */
	if (num->top > 0 && num->d[num->top - 1] == 0)
		{
		BNerr(BN_F_BN_DIV,BN_R_NOT_INITIALIZED);
		return 0;
		}

	bn_check_top(num);

	if ((BN_get_flags(num, BN_FLG_CONSTTIME) != 0) || (BN_get_flags(divisor, BN_FLG_CONSTTIME) != 0))
		{
		no_branch=1;
		}

	bn_check_top(dv);
	bn_check_top(rm);
	/* bn_check_top(num); */ /* 'num' has been checked already */
	bn_check_top(divisor);

	if (BN_is_zero(divisor))
		{
		BNerr(BN_F_BN_DIV,BN_R_DIV_BY_ZERO);
		return(0);
		}

	if (!no_branch && BN_ucmp(num,divisor) < 0)
		{
		if (rm != NULL)
			{ if (BN_copy(rm,num) == NULL) return(0); }
		if (dv != NULL) BN_zero(dv);
		return(1);
		}

	BN_CTX_start(ctx);
	tmp=BN_CTX_get(ctx);
	snum=BN_CTX_get(ctx);
	sdiv=BN_CTX_get(ctx);
	if (dv == NULL)
		res=BN_CTX_get(ctx);
	else	res=dv;
	if (sdiv == NULL || res == NULL || tmp == NULL || snum == NULL)
		goto err;

	/* First we normalise the numbers */
	norm_shift=BN_BITS2-((BN_num_bits(divisor))%BN_BITS2);
	if (!(BN_lshift(sdiv,divisor,norm_shift))) goto err;
	sdiv->neg=0;
	norm_shift+=BN_BITS2;
	if (!(BN_lshift(snum,num,norm_shift))) goto err;
	snum->neg=0;

	if (no_branch)
		{
		/* Since we don't know whether snum is larger than sdiv,
		 * we pad snum with enough zeroes without changing its
		 * value. 
		 */
		if (snum->top <= sdiv->top+1) 
			{
			if (bn_wexpand(snum, sdiv->top + 2) == NULL) goto err;
			for (i = snum->top; i < sdiv->top + 2; i++) snum->d[i] = 0;
			snum->top = sdiv->top + 2;
			}
		else
			{
			if (bn_wexpand(snum, snum->top + 1) == NULL) goto err;
			snum->d[snum->top] = 0;
			snum->top ++;
			}
		}

	div_n=sdiv->top;
	num_n=snum->top;
	loop=num_n-div_n;
	/* Lets setup a 'window' into snum
	 * This is the part that corresponds to the current
	 * 'area' being divided */
	wnum.neg   = 0;
	wnum.d     = &(snum->d[loop]);
	wnum.top   = div_n;
	/* only needed when BN_ucmp messes up the values between top and max */
	wnum.dmax  = snum->dmax - loop; /* so we don't step out of bounds */

	/* Get the top 2 words of sdiv */
	/* div_n=sdiv->top; */
	d0=sdiv->d[div_n-1];
	d1=(div_n == 1)?0:sdiv->d[div_n-2];

	/* pointer to the 'top' of snum */
	wnump= &(snum->d[num_n-1]);

	/* Setup to 'res' */
	res->neg= (num->neg^divisor->neg);
	if (!bn_wexpand(res,(loop+1))) goto err;
	res->top=loop-no_branch;
	resp= &(res->d[loop-1]);

	/* space for temp */
	if (!bn_wexpand(tmp,(div_n+1))) goto err;

	if (!no_branch)
		{
		if (BN_ucmp(&wnum,sdiv) >= 0)
			{
			/* If BN_DEBUG_RAND is defined BN_ucmp changes (via
			 * bn_pollute) the const bignum arguments =>
			 * clean the values between top and max again */
			bn_clear_top2max(&wnum);
			bn_sub_words(wnum.d, wnum.d, sdiv->d, div_n);
			*resp=1;
			}
		else
			res->top--;
		}

	/* if res->top == 0 then clear the neg value otherwise decrease
	 * the resp pointer */
	if (res->top == 0)
		res->neg = 0;
	else
		resp--;

	for (i=0; i<loop-1; i++, wnump--, resp--)
		{
		BN_ULONG q,l0;
		/* the first part of the loop uses the top two words of
		 * snum and sdiv to calculate a BN_ULONG q such that
		 * | wnum - sdiv * q | < sdiv */
#if defined(BN_DIV3W) && !defined(OPENSSL_NO_ASM)
		BN_ULONG bn_div_3_words(BN_ULONG*,BN_ULONG,BN_ULONG);
		q=bn_div_3_words(wnump,d1,d0);
#else
		BN_ULONG n0,n1,rem=0;

		n0=wnump[0];
		n1=wnump[-1];
		if (n0 == d0)
			q=BN_MASK2;
		else 			/* n0 < d0 */
			{
#ifdef BN_LLONG
			BN_ULLONG t2;

#if defined(BN_LLONG) && defined(BN_DIV2W) && !defined(bn_div_words)
			q=(BN_ULONG)(((((BN_ULLONG)n0)<<BN_BITS2)|n1)/d0);
#else
			q=bn_div_words(n0,n1,d0);
#ifdef BN_DEBUG_LEVITTE
			fprintf(stderr,"DEBUG: bn_div_words(0x%08X,0x%08X,0x%08\
X) -> 0x%08X\n",
				n0, n1, d0, q);
#endif
#endif

#ifndef REMAINDER_IS_ALREADY_CALCULATED
			/*
			 * rem doesn't have to be BN_ULLONG. The least we
			 * know it's less that d0, isn't it?
			 */
			rem=(n1-q*d0)&BN_MASK2;
#endif
			t2=(BN_ULLONG)d1*q;

			for (;;)
				{
				if (t2 <= ((((BN_ULLONG)rem)<<BN_BITS2)|wnump[-2]))
					break;
				q--;
				rem += d0;
				if (rem < d0) break; /* don't let rem overflow */
				t2 -= d1;
				}
#else /* !BN_LLONG */
			BN_ULONG t2l,t2h;

			q=bn_div_words(n0,n1,d0);
#ifdef BN_DEBUG_LEVITTE
			fprintf(stderr,"DEBUG: bn_div_words(0x%08X,0x%08X,0x%08\
X) -> 0x%08X\n",
				n0, n1, d0, q);
#endif
#ifndef REMAINDER_IS_ALREADY_CALCULATED
			rem=(n1-q*d0)&BN_MASK2;
#endif

#if defined(BN_UMULT_LOHI)
			BN_UMULT_LOHI(t2l,t2h,d1,q);
#elif defined(BN_UMULT_HIGH)
			t2l = d1 * q;
			t2h = BN_UMULT_HIGH(d1,q);
#else
			{
			BN_ULONG ql, qh;
			t2l=LBITS(d1); t2h=HBITS(d1);
			ql =LBITS(q);  qh =HBITS(q);
			mul64(t2l,t2h,ql,qh); /* t2=(BN_ULLONG)d1*q; */
			}
#endif

			for (;;)
				{
				if ((t2h < rem) ||
					((t2h == rem) && (t2l <= wnump[-2])))
					break;
				q--;
				rem += d0;
				if (rem < d0) break; /* don't let rem overflow */
				if (t2l < d1) t2h--; t2l -= d1;
				}
#endif /* !BN_LLONG */
			}
#endif /* !BN_DIV3W */

		l0=bn_mul_words(tmp->d,sdiv->d,div_n,q);
		tmp->d[div_n]=l0;
		wnum.d--;
		/* ingore top values of the bignums just sub the two 
		 * BN_ULONG arrays with bn_sub_words */
		if (bn_sub_words(wnum.d, wnum.d, tmp->d, div_n+1))
			{
			/* Note: As we have considered only the leading
			 * two BN_ULONGs in the calculation of q, sdiv * q
			 * might be greater than wnum (but then (q-1) * sdiv
			 * is less or equal than wnum)
			 */
			q--;
			if (bn_add_words(wnum.d, wnum.d, sdiv->d, div_n))
				/* we can't have an overflow here (assuming
				 * that q != 0, but if q == 0 then tmp is
				 * zero anyway) */
				(*wnump)++;
			}
		/* store part of the result */
		*resp = q;
		}
	bn_correct_top(snum);
	if (rm != NULL)
		{
		/* Keep a copy of the neg flag in num because if rm==num
		 * BN_rshift() will overwrite it.
		 */
		int neg = num->neg;
		BN_rshift(rm,snum,norm_shift);
		if (!BN_is_zero(rm))
			rm->neg = neg;
		bn_check_top(rm);
		}
	if (no_branch)	bn_correct_top(res);
	BN_CTX_end(ctx);
	return(1);
err:
	bn_check_top(rm);
	BN_CTX_end(ctx);
	return(0);
	}
#endif
/* file: BN_lshift1 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_shift.c */
int BN_lshift1(BIGNUM *r, const BIGNUM *a)
	{
	register BN_ULONG *ap,*rp,t,c;
	int i;

	bn_check_top(r);
	bn_check_top(a);

	if (r != a)
		{
		r->neg=a->neg;
		if (bn_wexpand(r,a->top+1) == NULL) return(0);
		r->top=a->top;
		}
	else
		{
		if (bn_wexpand(r,a->top+1) == NULL) return(0);
		}
	ap=a->d;
	rp=r->d;
	c=0;
	for (i=0; i<a->top; i++)
		{
		t= *(ap++);
		*(rp++)=((t<<1)|c)&BN_MASK2;
		c=(t & BN_TBIT)?1:0;
		}
	if (c)
		{
		*rp=1;
		r->top++;
		}
	bn_check_top(r);
	return(1);
	}
/* file: BN_rshift1 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_shift.c */
int BN_rshift1(BIGNUM *r, const BIGNUM *a)
	{
	BN_ULONG *ap,*rp,t,c;
	int i,j;

	bn_check_top(r);
	bn_check_top(a);

	if (BN_is_zero(a))
		{
		BN_zero(r);
		return(1);
		}
	i = a->top;
	ap= a->d;
	j = i-(ap[i-1]==1);
	if (a != r)
		{
		if (bn_wexpand(r,j) == NULL) return(0);
		r->neg=a->neg;
		}
	rp=r->d;
	t=ap[--i];
	c=(t&1)?BN_TBIT:0;
	if (t>>=1) rp[i]=t;
	while (i>0)
		{
		t=ap[--i];
		rp[i]=((t>>1)&BN_MASK2)|c;
		c=(t&1)?BN_TBIT:0;
		}
	r->top=j;
	bn_check_top(r);
	return(1);
	}
/* file: BN_CTX_end : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
void BN_CTX_end(BN_CTX *ctx)
	{
	CTXDBG_ENTRY("BN_CTX_end", ctx);
	if(ctx->err_stack)
		ctx->err_stack--;
	else
		{
		unsigned int fp = BN_STACK_pop(&ctx->stack);
		/* Does this stack frame have anything to release? */
		if(fp < ctx->used)
			BN_POOL_release(&ctx->pool, ctx->used - fp);
		ctx->used = fp;
		/* Unjam "too_many" in case "get" had failed */
		ctx->too_many = 0;
		}
	CTXDBG_EXIT(ctx);
	}
/* file: BN_STACK_pop : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static unsigned int BN_STACK_pop(BN_STACK *st)
	{
	return st->indexes[--(st->depth)];
	}
/* file: BN_POOL_release : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void BN_POOL_release(BN_POOL *p, unsigned int num)
	{
	unsigned int offset = (p->used - 1) % BN_CTX_POOL_SIZE;
	p->used -= num;
	while(num--)
		{
		bn_check_top(p->current->vals + offset);
		if(!offset)
			{
			offset = BN_CTX_POOL_SIZE - 1;
			p->current = p->current->prev;
			}
		else
			offset--;
		}
	}
/* file: BN_rshift : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_shift.c */
int BN_rshift(BIGNUM *r, const BIGNUM *a, int n)
	{
	int i,j,nw,lb,rb;
	BN_ULONG *t,*f;
	BN_ULONG l,tmp;

	bn_check_top(r);
	bn_check_top(a);

	nw=n/BN_BITS2;
	rb=n%BN_BITS2;
	lb=BN_BITS2-rb;
	if (nw >= a->top || a->top == 0)
		{
		BN_zero(r);
		return(1);
		}
	i = (BN_num_bits(a)-n+(BN_BITS2-1))/BN_BITS2;
	if (r != a)
		{
		r->neg=a->neg;
		if (bn_wexpand(r,i) == NULL) return(0);
		}
	else
		{
		if (n == 0)
			return 1; /* or the copying loop will go berserk */
		}

	f= &(a->d[nw]);
	t=r->d;
	j=a->top-nw;
	r->top=i;

	if (rb == 0)
		{
		for (i=j; i != 0; i--)
			*(t++)= *(f++);
		}
	else
		{
		l= *(f++);
		for (i=j-1; i != 0; i--)
			{
			tmp =(l>>rb)&BN_MASK2;
			l= *(f++);
			*(t++) =(tmp|(l<<lb))&BN_MASK2;
			}
		if ((l = (l>>rb)&BN_MASK2)) *(t) = l;
		}
	bn_check_top(r);
	return(1);
	}
/* file: BN_add : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_add.c */
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
	{
	const BIGNUM *tmp;
	int a_neg = a->neg, ret;

	bn_check_top(a);
	bn_check_top(b);

	/*  a +  b	a+b
	 *  a + -b	a-b
	 * -a +  b	b-a
	 * -a + -b	-(a+b)
	 */
	if (a_neg ^ b->neg)
		{
		/* only one is negative */
		if (a_neg)
			{ tmp=a; a=b; b=tmp; }

		/* we are now a - b */

		if (BN_ucmp(a,b) < 0)
			{
			if (!BN_usub(r,b,a)) return(0);
			r->neg=1;
			}
		else
			{
			if (!BN_usub(r,a,b)) return(0);
			r->neg=0;
			}
		return(1);
		}

	ret = BN_uadd(r,a,b);
	r->neg = a_neg;
	bn_check_top(r);
	return ret;
	}
/* file: BN_mul : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_mul.c */
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	int ret=0;
	int top,al,bl;
	BIGNUM *rr;
#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
	int i;
#endif
#ifdef BN_RECURSION
	BIGNUM *t=NULL;
	int j=0,k;
#endif

#ifdef BN_COUNT
	fprintf(stderr,"BN_mul %d * %d\n",a->top,b->top);
#endif

	bn_check_top(a);
	bn_check_top(b);
	bn_check_top(r);

	al=a->top;
	bl=b->top;

	if ((al == 0) || (bl == 0))
		{
		BN_zero(r);
		return(1);
		}
	top=al+bl;

	BN_CTX_start(ctx);
	if ((r == a) || (r == b))
		{
		if ((rr = BN_CTX_get(ctx)) == NULL) goto err;
		}
	else
		rr = r;
	rr->neg=a->neg^b->neg;

#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
	i = al-bl;
#endif
#ifdef BN_MUL_COMBA
	if (i == 0)
		{
# if 0
		if (al == 4)
			{
			if (bn_wexpand(rr,8) == NULL) goto err;
			rr->top=8;
			bn_mul_comba4(rr->d,a->d,b->d);
			goto end;
			}
# endif
		if (al == 8)
			{
			if (bn_wexpand(rr,16) == NULL) goto err;
			rr->top=16;
			bn_mul_comba8(rr->d,a->d,b->d);
			goto end;
			}
		}
#endif /* BN_MUL_COMBA */
#ifdef BN_RECURSION
	if ((al >= BN_MULL_SIZE_NORMAL) && (bl >= BN_MULL_SIZE_NORMAL))
		{
		if (i >= -1 && i <= 1)
			{
			/* Find out the power of two lower or equal
			   to the longest of the two numbers */
			if (i >= 0)
				{
				j = BN_num_bits_word((BN_ULONG)al);
				}
			if (i == -1)
				{
				j = BN_num_bits_word((BN_ULONG)bl);
				}
			j = 1<<(j-1);
			assert(j <= al || j <= bl);
			k = j+j;
			t = BN_CTX_get(ctx);
			if (t == NULL)
				goto err;
			if (al > j || bl > j)
				{
				if (bn_wexpand(t,k*4) == NULL) goto err;
				if (bn_wexpand(rr,k*4) == NULL) goto err;
				bn_mul_part_recursive(rr->d,a->d,b->d,
					j,al-j,bl-j,t->d);
				}
			else	/* al <= j || bl <= j */
				{
				if (bn_wexpand(t,k*2) == NULL) goto err;
				if (bn_wexpand(rr,k*2) == NULL) goto err;
				bn_mul_recursive(rr->d,a->d,b->d,
					j,al-j,bl-j,t->d);
				}
			rr->top=top;
			goto end;
			}
#if 0
		if (i == 1 && !BN_get_flags(b,BN_FLG_STATIC_DATA))
			{
			BIGNUM *tmp_bn = (BIGNUM *)b;
			if (bn_wexpand(tmp_bn,al) == NULL) goto err;
			tmp_bn->d[bl]=0;
			bl++;
			i--;
			}
		else if (i == -1 && !BN_get_flags(a,BN_FLG_STATIC_DATA))
			{
			BIGNUM *tmp_bn = (BIGNUM *)a;
			if (bn_wexpand(tmp_bn,bl) == NULL) goto err;
			tmp_bn->d[al]=0;
			al++;
			i++;
			}
		if (i == 0)
			{
			/* symmetric and > 4 */
			/* 16 or larger */
			j=BN_num_bits_word((BN_ULONG)al);
			j=1<<(j-1);
			k=j+j;
			t = BN_CTX_get(ctx);
			if (al == j) /* exact multiple */
				{
				if (bn_wexpand(t,k*2) == NULL) goto err;
				if (bn_wexpand(rr,k*2) == NULL) goto err;
				bn_mul_recursive(rr->d,a->d,b->d,al,t->d);
				}
			else
				{
				if (bn_wexpand(t,k*4) == NULL) goto err;
				if (bn_wexpand(rr,k*4) == NULL) goto err;
				bn_mul_part_recursive(rr->d,a->d,b->d,al-j,j,t->d);
				}
			rr->top=top;
			goto end;
			}
#endif
		}
#endif /* BN_RECURSION */
	if (bn_wexpand(rr,top) == NULL) goto err;
	rr->top=top;
	bn_mul_normal(rr->d,a->d,al,b->d,bl);

#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
end:
#endif
	bn_correct_top(rr);
	if (r != rr) BN_copy(r,rr);
	ret=1;
err:
	bn_check_top(r);
	BN_CTX_end(ctx);
	return(ret);
	}
/* file: bn_mul_comba4 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
#if defined(BN_MUL_COMBA) && !defined(OPENSSL_SMALL_FOOTPRINT)
void bn_mul_comba4(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
	{
#ifdef BN_LLONG
	BN_ULLONG t;
#else
	BN_ULONG bl,bh;
#endif
	BN_ULONG t1,t2;
	BN_ULONG c1,c2,c3;

	c1=0;
	c2=0;
	c3=0;
	mul_add_c(a[0],b[0],c1,c2,c3);
	r[0]=c1;
	c1=0;
	mul_add_c(a[0],b[1],c2,c3,c1);
	mul_add_c(a[1],b[0],c2,c3,c1);
	r[1]=c2;
	c2=0;
	mul_add_c(a[2],b[0],c3,c1,c2);
	mul_add_c(a[1],b[1],c3,c1,c2);
	mul_add_c(a[0],b[2],c3,c1,c2);
	r[2]=c3;
	c3=0;
	mul_add_c(a[0],b[3],c1,c2,c3);
	mul_add_c(a[1],b[2],c1,c2,c3);
	mul_add_c(a[2],b[1],c1,c2,c3);
	mul_add_c(a[3],b[0],c1,c2,c3);
	r[3]=c1;
	c1=0;
	mul_add_c(a[3],b[1],c2,c3,c1);
	mul_add_c(a[2],b[2],c2,c3,c1);
	mul_add_c(a[1],b[3],c2,c3,c1);
	r[4]=c2;
	c2=0;
	mul_add_c(a[2],b[3],c3,c1,c2);
	mul_add_c(a[3],b[2],c3,c1,c2);
	r[5]=c3;
	c3=0;
	mul_add_c(a[3],b[3],c1,c2,c3);
	r[6]=c1;
	r[7]=c2;
	}
#else /* !BN_MUL_COMBA */
/* file: bn_mul_comba4 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
void bn_mul_comba4(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
	{
	r[4]=bn_mul_words(    &(r[0]),a,4,b[0]);
	r[5]=bn_mul_add_words(&(r[1]),a,4,b[1]);
	r[6]=bn_mul_add_words(&(r[2]),a,4,b[2]);
	r[7]=bn_mul_add_words(&(r[3]),a,4,b[3]);
	}
#endif /* !BN_MUL_COMBA */
/* file: bn_mul_add_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
#if defined(BN_LLONG) || defined(BN_UMULT_HIGH)
BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
	{
	BN_ULONG c1=0;

	assert(num >= 0);
	if (num <= 0) return(c1);

#ifndef OPENSSL_SMALL_FOOTPRINT
	while (num&~3)
		{
		mul_add(rp[0],ap[0],w,c1);
		mul_add(rp[1],ap[1],w,c1);
		mul_add(rp[2],ap[2],w,c1);
		mul_add(rp[3],ap[3],w,c1);
		ap+=4; rp+=4; num-=4;
		}
#endif
	while (num)
		{
		mul_add(rp[0],ap[0],w,c1);
		ap++; rp++; num--;
		}
	
	return(c1);
	} 
#else /* !(defined(BN_LLONG) || defined(BN_UMULT_HIGH)) */
/* file: bn_mul_add_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
	{
	BN_ULONG c=0;
	BN_ULONG bl,bh;

	assert(num >= 0);
	if (num <= 0) return((BN_ULONG)0);

	bl=LBITS(w);
	bh=HBITS(w);

#ifndef OPENSSL_SMALL_FOOTPRINT
	while (num&~3)
		{
		mul_add(rp[0],ap[0],bl,bh,c);
		mul_add(rp[1],ap[1],bl,bh,c);
		mul_add(rp[2],ap[2],bl,bh,c);
		mul_add(rp[3],ap[3],bl,bh,c);
		ap+=4; rp+=4; num-=4;
		}
#endif
	while (num)
		{
		mul_add(rp[0],ap[0],bl,bh,c);
		ap++; rp++; num--;
		}
	return(c);
	} 
#endif /* !(defined(BN_LLONG) || defined(BN_UMULT_HIGH)) */
/* file: bn_mul_comba8 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
#if defined(BN_MUL_COMBA) && !defined(OPENSSL_SMALL_FOOTPRINT)
void bn_mul_comba8(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
	{
#ifdef BN_LLONG
	BN_ULLONG t;
#else
	BN_ULONG bl,bh;
#endif
	BN_ULONG t1,t2;
	BN_ULONG c1,c2,c3;

	c1=0;
	c2=0;
	c3=0;
	mul_add_c(a[0],b[0],c1,c2,c3);
	r[0]=c1;
	c1=0;
	mul_add_c(a[0],b[1],c2,c3,c1);
	mul_add_c(a[1],b[0],c2,c3,c1);
	r[1]=c2;
	c2=0;
	mul_add_c(a[2],b[0],c3,c1,c2);
	mul_add_c(a[1],b[1],c3,c1,c2);
	mul_add_c(a[0],b[2],c3,c1,c2);
	r[2]=c3;
	c3=0;
	mul_add_c(a[0],b[3],c1,c2,c3);
	mul_add_c(a[1],b[2],c1,c2,c3);
	mul_add_c(a[2],b[1],c1,c2,c3);
	mul_add_c(a[3],b[0],c1,c2,c3);
	r[3]=c1;
	c1=0;
	mul_add_c(a[4],b[0],c2,c3,c1);
	mul_add_c(a[3],b[1],c2,c3,c1);
	mul_add_c(a[2],b[2],c2,c3,c1);
	mul_add_c(a[1],b[3],c2,c3,c1);
	mul_add_c(a[0],b[4],c2,c3,c1);
	r[4]=c2;
	c2=0;
	mul_add_c(a[0],b[5],c3,c1,c2);
	mul_add_c(a[1],b[4],c3,c1,c2);
	mul_add_c(a[2],b[3],c3,c1,c2);
	mul_add_c(a[3],b[2],c3,c1,c2);
	mul_add_c(a[4],b[1],c3,c1,c2);
	mul_add_c(a[5],b[0],c3,c1,c2);
	r[5]=c3;
	c3=0;
	mul_add_c(a[6],b[0],c1,c2,c3);
	mul_add_c(a[5],b[1],c1,c2,c3);
	mul_add_c(a[4],b[2],c1,c2,c3);
	mul_add_c(a[3],b[3],c1,c2,c3);
	mul_add_c(a[2],b[4],c1,c2,c3);
	mul_add_c(a[1],b[5],c1,c2,c3);
	mul_add_c(a[0],b[6],c1,c2,c3);
	r[6]=c1;
	c1=0;
	mul_add_c(a[0],b[7],c2,c3,c1);
	mul_add_c(a[1],b[6],c2,c3,c1);
	mul_add_c(a[2],b[5],c2,c3,c1);
	mul_add_c(a[3],b[4],c2,c3,c1);
	mul_add_c(a[4],b[3],c2,c3,c1);
	mul_add_c(a[5],b[2],c2,c3,c1);
	mul_add_c(a[6],b[1],c2,c3,c1);
	mul_add_c(a[7],b[0],c2,c3,c1);
	r[7]=c2;
	c2=0;
	mul_add_c(a[7],b[1],c3,c1,c2);
	mul_add_c(a[6],b[2],c3,c1,c2);
	mul_add_c(a[5],b[3],c3,c1,c2);
	mul_add_c(a[4],b[4],c3,c1,c2);
	mul_add_c(a[3],b[5],c3,c1,c2);
	mul_add_c(a[2],b[6],c3,c1,c2);
	mul_add_c(a[1],b[7],c3,c1,c2);
	r[8]=c3;
	c3=0;
	mul_add_c(a[2],b[7],c1,c2,c3);
	mul_add_c(a[3],b[6],c1,c2,c3);
	mul_add_c(a[4],b[5],c1,c2,c3);
	mul_add_c(a[5],b[4],c1,c2,c3);
	mul_add_c(a[6],b[3],c1,c2,c3);
	mul_add_c(a[7],b[2],c1,c2,c3);
	r[9]=c1;
	c1=0;
	mul_add_c(a[7],b[3],c2,c3,c1);
	mul_add_c(a[6],b[4],c2,c3,c1);
	mul_add_c(a[5],b[5],c2,c3,c1);
	mul_add_c(a[4],b[6],c2,c3,c1);
	mul_add_c(a[3],b[7],c2,c3,c1);
	r[10]=c2;
	c2=0;
	mul_add_c(a[4],b[7],c3,c1,c2);
	mul_add_c(a[5],b[6],c3,c1,c2);
	mul_add_c(a[6],b[5],c3,c1,c2);
	mul_add_c(a[7],b[4],c3,c1,c2);
	r[11]=c3;
	c3=0;
	mul_add_c(a[7],b[5],c1,c2,c3);
	mul_add_c(a[6],b[6],c1,c2,c3);
	mul_add_c(a[5],b[7],c1,c2,c3);
	r[12]=c1;
	c1=0;
	mul_add_c(a[6],b[7],c2,c3,c1);
	mul_add_c(a[7],b[6],c2,c3,c1);
	r[13]=c2;
	c2=0;
	mul_add_c(a[7],b[7],c3,c1,c2);
	r[14]=c3;
	r[15]=c1;
	}
#else /* !BN_MUL_COMBA */
/* file: bn_mul_comba8 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
void bn_mul_comba8(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
	{
	r[ 8]=bn_mul_words(    &(r[0]),a,8,b[0]);
	r[ 9]=bn_mul_add_words(&(r[1]),a,8,b[1]);
	r[10]=bn_mul_add_words(&(r[2]),a,8,b[2]);
	r[11]=bn_mul_add_words(&(r[3]),a,8,b[3]);
	r[12]=bn_mul_add_words(&(r[4]),a,8,b[4]);
	r[13]=bn_mul_add_words(&(r[5]),a,8,b[5]);
	r[14]=bn_mul_add_words(&(r[6]),a,8,b[6]);
	r[15]=bn_mul_add_words(&(r[7]),a,8,b[7]);
	}
#endif /* !BN_MUL_COMBA */
/* file: bn_mul_part_recursive : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_mul.c */
#ifdef BN_RECURSION
void bn_mul_part_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n,
	     int tna, int tnb, BN_ULONG *t)
	{
	int i,j,n2=n*2;
	int c1,c2,neg;
	BN_ULONG ln,lo,*p;

# ifdef BN_COUNT
	fprintf(stderr," bn_mul_part_recursive (%d%+d) * (%d%+d)\n",
		n, tna, n, tnb);
# endif
	if (n < 8)
		{
		bn_mul_normal(r,a,n+tna,b,n+tnb);
		return;
		}

	/* r=(a[0]-a[1])*(b[1]-b[0]) */
	c1=bn_cmp_part_words(a,&(a[n]),tna,n-tna);
	c2=bn_cmp_part_words(&(b[n]),b,tnb,tnb-n);
	neg=0;
	switch (c1*3+c2)
		{
	case -4:
		bn_sub_part_words(t,      &(a[n]),a,      tna,tna-n); /* - */
		bn_sub_part_words(&(t[n]),b,      &(b[n]),tnb,n-tnb); /* - */
		break;
	case -3:
		/* break; */
	case -2:
		bn_sub_part_words(t,      &(a[n]),a,      tna,tna-n); /* - */
		bn_sub_part_words(&(t[n]),&(b[n]),b,      tnb,tnb-n); /* + */
		neg=1;
		break;
	case -1:
	case 0:
	case 1:
		/* break; */
	case 2:
		bn_sub_part_words(t,      a,      &(a[n]),tna,n-tna); /* + */
		bn_sub_part_words(&(t[n]),b,      &(b[n]),tnb,n-tnb); /* - */
		neg=1;
		break;
	case 3:
		/* break; */
	case 4:
		bn_sub_part_words(t,      a,      &(a[n]),tna,n-tna);
		bn_sub_part_words(&(t[n]),&(b[n]),b,      tnb,tnb-n);
		break;
		}
		/* The zero case isn't yet implemented here. The speedup
		   would probably be negligible. */
# if 0
	if (n == 4)
		{
		bn_mul_comba4(&(t[n2]),t,&(t[n]));
		bn_mul_comba4(r,a,b);
		bn_mul_normal(&(r[n2]),&(a[n]),tn,&(b[n]),tn);
		memset(&(r[n2+tn*2]),0,sizeof(BN_ULONG)*(n2-tn*2));
		}
	else
# endif
	if (n == 8)
		{
		bn_mul_comba8(&(t[n2]),t,&(t[n]));
		bn_mul_comba8(r,a,b);
		bn_mul_normal(&(r[n2]),&(a[n]),tna,&(b[n]),tnb);
		memset(&(r[n2+tna+tnb]),0,sizeof(BN_ULONG)*(n2-tna-tnb));
		}
	else
		{
		p= &(t[n2*2]);
		bn_mul_recursive(&(t[n2]),t,&(t[n]),n,0,0,p);
		bn_mul_recursive(r,a,b,n,0,0,p);
		i=n/2;
		/* If there is only a bottom half to the number,
		 * just do it */
		if (tna > tnb)
			j = tna - i;
		else
			j = tnb - i;
		if (j == 0)
			{
			bn_mul_recursive(&(r[n2]),&(a[n]),&(b[n]),
				i,tna-i,tnb-i,p);
			memset(&(r[n2+i*2]),0,sizeof(BN_ULONG)*(n2-i*2));
			}
		else if (j > 0) /* eg, n == 16, i == 8 and tn == 11 */
				{
				bn_mul_part_recursive(&(r[n2]),&(a[n]),&(b[n]),
					i,tna-i,tnb-i,p);
				memset(&(r[n2+tna+tnb]),0,
					sizeof(BN_ULONG)*(n2-tna-tnb));
				}
		else /* (j < 0) eg, n == 16, i == 8 and tn == 5 */
			{
			memset(&(r[n2]),0,sizeof(BN_ULONG)*n2);
			if (tna < BN_MUL_RECURSIVE_SIZE_NORMAL
				&& tnb < BN_MUL_RECURSIVE_SIZE_NORMAL)
				{
				bn_mul_normal(&(r[n2]),&(a[n]),tna,&(b[n]),tnb);
				}
			else
				{
				for (;;)
					{
					i/=2;
					/* these simplified conditions work
					 * exclusively because difference
					 * between tna and tnb is 1 or 0 */
					if (i < tna || i < tnb)
						{
						bn_mul_part_recursive(&(r[n2]),
							&(a[n]),&(b[n]),
							i,tna-i,tnb-i,p);
						break;
						}
					else if (i == tna || i == tnb)
						{
						bn_mul_recursive(&(r[n2]),
							&(a[n]),&(b[n]),
							i,tna-i,tnb-i,p);
						break;
						}
					}
				}
			}
		}

	/* t[32] holds (a[0]-a[1])*(b[1]-b[0]), c1 is the sign
	 * r[10] holds (a[0]*b[0])
	 * r[32] holds (b[1]*b[1])
	 */

	c1=(int)(bn_add_words(t,r,&(r[n2]),n2));

	if (neg) /* if t[32] is negative */
		{
		c1-=(int)(bn_sub_words(&(t[n2]),t,&(t[n2]),n2));
		}
	else
		{
		/* Might have a carry */
		c1+=(int)(bn_add_words(&(t[n2]),&(t[n2]),t,n2));
		}

	/* t[32] holds (a[0]-a[1])*(b[1]-b[0])+(a[0]*b[0])+(a[1]*b[1])
	 * r[10] holds (a[0]*b[0])
	 * r[32] holds (b[1]*b[1])
	 * c1 holds the carry bits
	 */
	c1+=(int)(bn_add_words(&(r[n]),&(r[n]),&(t[n2]),n2));
	if (c1)
		{
		p= &(r[n+n2]);
		lo= *p;
		ln=(lo+c1)&BN_MASK2;
		*p=ln;

		/* The overflow will stop before we over write
		 * words we should not overwrite */
		if (ln < (BN_ULONG)c1)
			{
			do	{
				p++;
				lo= *p;
				ln=(lo+1)&BN_MASK2;
				*p=ln;
				} while (ln == 0);
			}
		}
	}
#endif /* BN_RECURSION */
/* file: bn_mul_normal : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_mul.c */
void bn_mul_normal(BN_ULONG *r, BN_ULONG *a, int na, BN_ULONG *b, int nb)
	{
	BN_ULONG *rr;

#ifdef BN_COUNT
	fprintf(stderr," bn_mul_normal %d * %d\n",na,nb);
#endif

	if (na < nb)
		{
		int itmp;
		BN_ULONG *ltmp;

		itmp=na; na=nb; nb=itmp;
		ltmp=a;   a=b;   b=ltmp;

		}
	rr= &(r[na]);
	if (nb <= 0)
		{
		(void)bn_mul_words(r,a,na,0);
		return;
		}
	else
		rr[0]=bn_mul_words(r,a,na,b[0]);

	for (;;)
		{
		if (--nb <= 0) return;
		rr[1]=bn_mul_add_words(&(r[1]),a,na,b[1]);
		if (--nb <= 0) return;
		rr[2]=bn_mul_add_words(&(r[2]),a,na,b[2]);
		if (--nb <= 0) return;
		rr[3]=bn_mul_add_words(&(r[3]),a,na,b[3]);
		if (--nb <= 0) return;
		rr[4]=bn_mul_add_words(&(r[4]),a,na,b[4]);
		rr+=4;
		r+=4;
		b+=4;
		}
	}
/* file: bn_cmp_part_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
int bn_cmp_part_words(const BN_ULONG *a, const BN_ULONG *b,
	int cl, int dl)
	{
	int n,i;
	n = cl-1;

	if (dl < 0)
		{
		for (i=dl; i<0; i++)
			{
			if (b[n-i] != 0)
				return -1; /* a < b */
			}
		}
	if (dl > 0)
		{
		for (i=dl; i>0; i--)
			{
			if (a[n+i] != 0)
				return 1; /* a > b */
			}
		}
	return bn_cmp_words(a,b,cl);
	}
/* file: bn_cmp_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
int bn_cmp_words(const BN_ULONG *a, const BN_ULONG *b, int n)
	{
	int i;
	BN_ULONG aa,bb;

	aa=a[n-1];
	bb=b[n-1];
	if (aa != bb) return((aa > bb)?1:-1);
	for (i=n-2; i>=0; i--)
		{
		aa=a[i];
		bb=b[i];
		if (aa != bb) return((aa > bb)?1:-1);
		}
	return(0);
	}
/* file: bn_sub_part_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_mul.c */
#if defined(OPENSSL_NO_ASM) || !defined(OPENSSL_BN_ASM_PART_WORDS)
BN_ULONG bn_sub_part_words(BN_ULONG *r,
	const BN_ULONG *a, const BN_ULONG *b,
	int cl, int dl)
	{
	BN_ULONG c, t;

	assert(cl >= 0);
	c = bn_sub_words(r, a, b, cl);

	if (dl == 0)
		return c;

	r += cl;
	a += cl;
	b += cl;

	if (dl < 0)
		{
#ifdef BN_COUNT
		fprintf(stderr, "  bn_sub_part_words %d + %d (dl < 0, c = %d)\n", cl, dl, c);
#endif
		for (;;)
			{
			t = b[0];
			r[0] = (0-t-c)&BN_MASK2;
			if (t != 0) c=1;
			if (++dl >= 0) break;

			t = b[1];
			r[1] = (0-t-c)&BN_MASK2;
			if (t != 0) c=1;
			if (++dl >= 0) break;

			t = b[2];
			r[2] = (0-t-c)&BN_MASK2;
			if (t != 0) c=1;
			if (++dl >= 0) break;

			t = b[3];
			r[3] = (0-t-c)&BN_MASK2;
			if (t != 0) c=1;
			if (++dl >= 0) break;

			b += 4;
			r += 4;
			}
		}
	else
		{
		int save_dl = dl;
#ifdef BN_COUNT
		fprintf(stderr, "  bn_sub_part_words %d + %d (dl > 0, c = %d)\n", cl, dl, c);
#endif
		while(c)
			{
			t = a[0];
			r[0] = (t-c)&BN_MASK2;
			if (t != 0) c=0;
			if (--dl <= 0) break;

			t = a[1];
			r[1] = (t-c)&BN_MASK2;
			if (t != 0) c=0;
			if (--dl <= 0) break;

			t = a[2];
			r[2] = (t-c)&BN_MASK2;
			if (t != 0) c=0;
			if (--dl <= 0) break;

			t = a[3];
			r[3] = (t-c)&BN_MASK2;
			if (t != 0) c=0;
			if (--dl <= 0) break;

			save_dl = dl;
			a += 4;
			r += 4;
			}
		if (dl > 0)
			{
#ifdef BN_COUNT
			fprintf(stderr, "  bn_sub_part_words %d + %d (dl > 0, c == 0)\n", cl, dl);
#endif
			if (save_dl > dl)
				{
				switch (save_dl - dl)
					{
				case 1:
					r[1] = a[1];
					if (--dl <= 0) break;
				case 2:
					r[2] = a[2];
					if (--dl <= 0) break;
				case 3:
					r[3] = a[3];
					if (--dl <= 0) break;
					}
				a += 4;
				r += 4;
				}
			}
		if (dl > 0)
			{
#ifdef BN_COUNT
			fprintf(stderr, "  bn_sub_part_words %d + %d (dl > 0, copy)\n", cl, dl);
#endif
			for(;;)
				{
				r[0] = a[0];
				if (--dl <= 0) break;
				r[1] = a[1];
				if (--dl <= 0) break;
				r[2] = a[2];
				if (--dl <= 0) break;
				r[3] = a[3];
				if (--dl <= 0) break;

				a += 4;
				r += 4;
				}
			}
		}
	return c;
	}
#endif
/* file: bn_mul_recursive : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_mul.c */
#ifdef BN_RECURSION
void bn_mul_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n2,
	int dna, int dnb, BN_ULONG *t)
	{
	int n=n2/2,c1,c2;
	int tna=n+dna, tnb=n+dnb;
	unsigned int neg,zero;
	BN_ULONG ln,lo,*p;

# ifdef BN_COUNT
	fprintf(stderr," bn_mul_recursive %d%+d * %d%+d\n",n2,dna,n2,dnb);
# endif
# ifdef BN_MUL_COMBA
#  if 0
	if (n2 == 4)
		{
		bn_mul_comba4(r,a,b);
		return;
		}
#  endif
	/* Only call bn_mul_comba 8 if n2 == 8 and the
	 * two arrays are complete [steve]
	 */
	if (n2 == 8 && dna == 0 && dnb == 0)
		{
		bn_mul_comba8(r,a,b);
		return; 
		}
# endif /* BN_MUL_COMBA */
	/* Else do normal multiply */
	if (n2 < BN_MUL_RECURSIVE_SIZE_NORMAL)
		{
		bn_mul_normal(r,a,n2+dna,b,n2+dnb);
		if ((dna + dnb) < 0)
			memset(&r[2*n2 + dna + dnb], 0,
				sizeof(BN_ULONG) * -(dna + dnb));
		return;
		}
	/* r=(a[0]-a[1])*(b[1]-b[0]) */
	c1=bn_cmp_part_words(a,&(a[n]),tna,n-tna);
	c2=bn_cmp_part_words(&(b[n]),b,tnb,tnb-n);
	zero=neg=0;
	switch (c1*3+c2)
		{
	case -4:
		bn_sub_part_words(t,      &(a[n]),a,      tna,tna-n); /* - */
		bn_sub_part_words(&(t[n]),b,      &(b[n]),tnb,n-tnb); /* - */
		break;
	case -3:
		zero=1;
		break;
	case -2:
		bn_sub_part_words(t,      &(a[n]),a,      tna,tna-n); /* - */
		bn_sub_part_words(&(t[n]),&(b[n]),b,      tnb,tnb-n); /* + */
		neg=1;
		break;
	case -1:
	case 0:
	case 1:
		zero=1;
		break;
	case 2:
		bn_sub_part_words(t,      a,      &(a[n]),tna,n-tna); /* + */
		bn_sub_part_words(&(t[n]),b,      &(b[n]),tnb,n-tnb); /* - */
		neg=1;
		break;
	case 3:
		zero=1;
		break;
	case 4:
		bn_sub_part_words(t,      a,      &(a[n]),tna,n-tna);
		bn_sub_part_words(&(t[n]),&(b[n]),b,      tnb,tnb-n);
		break;
		}

# ifdef BN_MUL_COMBA
	if (n == 4 && dna == 0 && dnb == 0) /* XXX: bn_mul_comba4 could take
					       extra args to do this well */
		{
		if (!zero)
			bn_mul_comba4(&(t[n2]),t,&(t[n]));
		else
			memset(&(t[n2]),0,8*sizeof(BN_ULONG));
		
		bn_mul_comba4(r,a,b);
		bn_mul_comba4(&(r[n2]),&(a[n]),&(b[n]));
		}
	else if (n == 8 && dna == 0 && dnb == 0) /* XXX: bn_mul_comba8 could
						    take extra args to do this
						    well */
		{
		if (!zero)
			bn_mul_comba8(&(t[n2]),t,&(t[n]));
		else
			memset(&(t[n2]),0,16*sizeof(BN_ULONG));
		
		bn_mul_comba8(r,a,b);
		bn_mul_comba8(&(r[n2]),&(a[n]),&(b[n]));
		}
	else
# endif /* BN_MUL_COMBA */
		{
		p= &(t[n2*2]);
		if (!zero)
			bn_mul_recursive(&(t[n2]),t,&(t[n]),n,0,0,p);
		else
			memset(&(t[n2]),0,n2*sizeof(BN_ULONG));
		bn_mul_recursive(r,a,b,n,0,0,p);
		bn_mul_recursive(&(r[n2]),&(a[n]),&(b[n]),n,dna,dnb,p);
		}

	/* t[32] holds (a[0]-a[1])*(b[1]-b[0]), c1 is the sign
	 * r[10] holds (a[0]*b[0])
	 * r[32] holds (b[1]*b[1])
	 */

	c1=(int)(bn_add_words(t,r,&(r[n2]),n2));

	if (neg) /* if t[32] is negative */
		{
		c1-=(int)(bn_sub_words(&(t[n2]),t,&(t[n2]),n2));
		}
	else
		{
		/* Might have a carry */
		c1+=(int)(bn_add_words(&(t[n2]),&(t[n2]),t,n2));
		}

	/* t[32] holds (a[0]-a[1])*(b[1]-b[0])+(a[0]*b[0])+(a[1]*b[1])
	 * r[10] holds (a[0]*b[0])
	 * r[32] holds (b[1]*b[1])
	 * c1 holds the carry bits
	 */
	c1+=(int)(bn_add_words(&(r[n]),&(r[n]),&(t[n2]),n2));
	if (c1)
		{
		p= &(r[n+n2]);
		lo= *p;
		ln=(lo+c1)&BN_MASK2;
		*p=ln;

		/* The overflow will stop before we over write
		 * words we should not overwrite */
		if (ln < (BN_ULONG)c1)
			{
			do	{
				p++;
				lo= *p;
				ln=(lo+1)&BN_MASK2;
				*p=ln;
				} while (ln == 0);
			}
		}
	}
#endif /* BN_RECURSION */
/* file: BN_MONT_CTX_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_mont.c */
void BN_MONT_CTX_free(BN_MONT_CTX *mont)
	{
	if(mont == NULL)
	    return;

	BN_free(&(mont->RR));
	BN_free(&(mont->N));
	BN_free(&(mont->Ni));
	if (mont->flags & BN_FLG_MALLOCED)
		OPENSSL_free(mont);
	}
/* file: DH_check_pub_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/dhdh_check.c */
int DH_check_pub_key(const DH *dh, const BIGNUM *pub_key, int *ret)
	{
	int ok=0;
	BIGNUM *q=NULL;

	*ret=0;
	q=BN_new();
	if (q == NULL) goto err;
	BN_set_word(q,1);
	if (BN_cmp(pub_key,q)<=0)
		*ret|=DH_CHECK_PUBKEY_TOO_SMALL;
	BN_copy(q,dh->p);
	BN_sub_word(q,1);
	if (BN_cmp(pub_key,q)>=0)
		*ret|=DH_CHECK_PUBKEY_TOO_LARGE;

	ok = 1;
err:
	if (q != NULL) BN_free(q);
	return(ok);
	}
/* file: EC_KEY_get0_public_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_key.c */
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key)
	{
	return key->pub_key;
	}
	
/* file: s2i_ASN1_INTEGER : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
ASN1_INTEGER *s2i_ASN1_INTEGER(X509V3_EXT_METHOD *method, char *value) {
	BIGNUM *bn = NULL;
	ASN1_INTEGER *aint;
	int isneg, ishex;
	int ret;
	if (!value) {   X509V3err(X509V3_F_S2I_ASN1_INTEGER,X509V3_R_INVALID_NULL_VALUE); 		return 0;
	}
	bn = BN_new();  if (value[0] == '-') { 		value++;
		isneg = 1;
	} else isneg = 0;
	
	if (value[0] == '0' && ((value[1] == 'x') || (value[1] == 'X'))) { 		value += 2;
		ishex = 1;
	} else ishex = 0;
	
	if (ishex) ret = BN_hex2bn(&bn, value);  else ret = BN_dec2bn(&bn, value); 
	if (!ret || value[ret]) {   BN_free(bn);   X509V3err(X509V3_F_S2I_ASN1_INTEGER,X509V3_R_BN_DEC2BN_ERROR); 		return 0;
	}
	
	if (isneg && BN_is_zero(bn)) isneg = 0; 
	aint = BN_to_ASN1_INTEGER(bn, NULL);  BN_free(bn);  if (!aint) {   X509V3err(X509V3_F_S2I_ASN1_INTEGER,X509V3_R_BN_TO_ASN1_INTEGER_ERROR); 		return 0;
	}
	if (isneg) aint->type |= V_ASN1_NEG; 	return aint;
}

/* file: ASN1_STRING_type_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_lib.c */
ASN1_STRING *ASN1_STRING_type_new(int type) 	{
	ASN1_STRING *ret;
	
	ret=(ASN1_STRING *)OPENSSL_malloc(sizeof(ASN1_STRING));  if (ret == NULL) 		{
		ASN1err(ASN1_F_ASN1_STRING_TYPE_NEW,ERR_R_MALLOC_FAILURE);   return(NULL); 		}
	ret->length=0;
	ret->type=type;
	ret->data=NULL;
	ret->flags=0;
	return(ret); 	}
	
/* file: OBJ_bsearch_ex_ : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobj_dat.c */
const void *OBJ_bsearch_ex_(const void *key, const void *base_, int num, 			    int size,
							int (*cmp)(const void *, const void *), 			    int flags)
{
	const char *base=base_;
	int l,h,i=0,c=0;
	const char *p = NULL;
	
	if (num == 0) return(NULL); 	l=0;
	h=num;
	while (l < h) 		{
		i=(l+h)/2;   p= &(base[i*size]);   c=(*cmp)(key,p);   if (c < 0) 			h=i;
		else if (c > 0) 			l=i+1;
		else
			break;
	}
#ifdef CHARSET_EBCDIC
	/* THIS IS A KLUDGE - Because the *_obj is sorted in ASCII order, and
	 * I don't have perl (yet), we revert to a *LINEAR* search
	 * when the object wasn't found in the binary search.
	 */
	if (c != 0) 		{
		for (i=0; i<num; ++i) 			{
			p= &(base[i*size]);    c = (*cmp)(key,p);    if (c == 0 || (c < 0 && (flags & OBJ_BSEARCH_VALUE_ON_NOMATCH))) 				return p;
		}
	}
#endif
	if (c != 0 && !(flags & OBJ_BSEARCH_VALUE_ON_NOMATCH)) 		p = NULL;
	else if (c == 0 && (flags & OBJ_BSEARCH_FIRST_VALUE_ON_MATCH)) 		{
		while(i > 0 && (*cmp)(key,&(base[(i-1)*size])) == 0) 			i--;
		p = &(base[i*size]); 		}
	return(p); 	}

/* file: OBJ_dup : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobj_lib.c */
ASN1_OBJECT *OBJ_dup(const ASN1_OBJECT *o) 	{
	ASN1_OBJECT *r;
	int i;
	char *ln=NULL,*sn=NULL;
	unsigned char *data=NULL;
	
	if (o == NULL) return(NULL);  if (!(o->flags & ASN1_OBJECT_FLAG_DYNAMIC))   return((ASN1_OBJECT *)o); /* XXX: ugh! Why? What kind of 					     duplication is this??? */
	
	r=ASN1_OBJECT_new();  if (r == NULL) 		{
		OBJerr(OBJ_F_OBJ_DUP,ERR_R_ASN1_LIB);   return(NULL); 		}
	data=OPENSSL_malloc(o->length);  if (data == NULL) 		goto err;
	if (o->data != NULL)   memcpy(data,o->data,o->length); 	/* once data attached to object it remains const */
	r->data = data;
	r->length=o->length;
	r->nid=o->nid;
	r->ln=r->sn=NULL;
	if (o->ln != NULL) 		{
		i=strlen(o->ln)+1;   ln=OPENSSL_malloc(i);   if (ln == NULL) goto err;   memcpy(ln,o->ln,i); 		r->ln=ln;
	}
	
	if (o->sn != NULL) 		{
		i=strlen(o->sn)+1;   sn=OPENSSL_malloc(i);   if (sn == NULL) goto err;   memcpy(sn,o->sn,i); 		r->sn=sn;
	}
	r->flags=o->flags|(ASN1_OBJECT_FLAG_DYNAMIC| 		ASN1_OBJECT_FLAG_DYNAMIC_STRINGS|ASN1_OBJECT_FLAG_DYNAMIC_DATA);
	return(r); err:
	OBJerr(OBJ_F_OBJ_DUP,ERR_R_MALLOC_FAILURE);  if (ln != NULL)  OPENSSL_free(ln);  if (sn != NULL)  OPENSSL_free(sn);  if (data != NULL) OPENSSL_free(data);  if (r != NULL)  OPENSSL_free(r);  return(NULL); 	}

/* file: internal_find : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.c */
static int internal_find(_STACK *st, void *data, int ret_val_options) 	{
	const void * const *r;
	int i;
	
	if(st == NULL) return -1; 
	if (st->comp == NULL) 		{
		for (i=0; i<st->num; i++)    if (st->data[i] == data)     return(i);   return(-1); 		}
	sk_sort(st);  if (data == NULL) return(-1);  r=OBJ_bsearch_ex_(&data,st->data,st->num,sizeof(void *),st->comp, 			  ret_val_options);
	if (r == NULL) return(-1);  return (int)((char **)r-st->data); 	}
	
/* file: BUF_strdup : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bufferbuf_str.c */
char *BUF_strdup(const char *str) 	{
	if (str == NULL) return(NULL);  return BUF_strndup(str, strlen(str)); 	}
/* file: BUF_strndup : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bufferbuf_str.c */
char *BUF_strndup(const char *str, size_t siz) 	{
	char *ret;
	
	if (str == NULL) return(NULL); 
	ret=OPENSSL_malloc(siz+1);  if (ret == NULL)  		{
		BUFerr(BUF_F_BUF_STRNDUP,ERR_R_MALLOC_FAILURE);   return(NULL); 		}
	BUF_strlcpy(ret,str,siz+1);  return(ret); 	}
	
/* file: c2i_ASN1_OBJECT : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_object.c */
ASN1_OBJECT *c2i_ASN1_OBJECT(ASN1_OBJECT **a, const unsigned char **pp, 	     long len)
{
	ASN1_OBJECT *ret=NULL;
	const unsigned char *p;
	unsigned char *data;
	int i;
	/* Sanity check OID encoding: can't have leading 0x80 in
	 * subidentifiers, see: X.690 8.19.2
	 */
	for (i = 0, p = *pp; i < len; i++, p++) 		{
		if (*p == 0x80 && (!i || !(p[-1] & 0x80))) 			{
			ASN1err(ASN1_F_C2I_ASN1_OBJECT,ASN1_R_INVALID_OBJECT_ENCODING); 			return NULL;
		}
	}
	
	/* only the ASN1_OBJECTs from the 'table' will have values
	 * for ->sn or ->ln */
	if ((a == NULL) || ((*a) == NULL) ||   !((*a)->flags & ASN1_OBJECT_FLAG_DYNAMIC)) 		{
		if ((ret=ASN1_OBJECT_new()) == NULL) return(NULL); 		}
	else ret=(*a); 
	p= *pp;
	/* detach data from object */
	data = (unsigned char *)ret->data; 	ret->data = NULL;
	/* once detached we can change it */
	if ((data == NULL) || (ret->length < len)) 		{
		ret->length=0;
		if (data != NULL) OPENSSL_free(data);   data=(unsigned char *)OPENSSL_malloc(len ? (int)len : 1);   if (data == NULL) 			{ i=ERR_R_MALLOC_FAILURE; goto err; }
		ret->flags|=ASN1_OBJECT_FLAG_DYNAMIC_DATA;
	}
	memcpy(data,p,(int)len); 	/* reattach data to object, after which it remains const */
	ret->data  =data;
	ret->length=(int)len; 	ret->sn=NULL;
	ret->ln=NULL;
	/* ret->flags=ASN1_OBJECT_FLAG_DYNAMIC; we know it is dynamic */
	p+=len;
	
	if (a != NULL) (*a)=ret; 	*pp=p;
	return(ret); err:
	ASN1err(ASN1_F_C2I_ASN1_OBJECT,i);  if ((ret != NULL) && ((a == NULL) || (*a != ret)))   ASN1_OBJECT_free(ret);  return(NULL); 	}

/* file: ASN1_OBJECT_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_object.c */
ASN1_OBJECT *ASN1_OBJECT_new(void) 	{
	ASN1_OBJECT *ret;
	
	ret=(ASN1_OBJECT *)OPENSSL_malloc(sizeof(ASN1_OBJECT));  if (ret == NULL) 		{
		ASN1err(ASN1_F_ASN1_OBJECT_NEW,ERR_R_MALLOC_FAILURE);   return(NULL); 		}
	ret->length=0;
	ret->data=NULL;
	ret->nid=0;
	ret->sn=NULL;
	ret->ln=NULL;
	ret->flags=ASN1_OBJECT_FLAG_DYNAMIC;
	return(ret); 	}


/* file: d2i_ASN1_OBJECT : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_object.c */
ASN1_OBJECT *d2i_ASN1_OBJECT(ASN1_OBJECT **a, const unsigned char **pp, 	     long length)
{
	const unsigned char *p;
	long len;
	int tag,xclass;
	int inf,i;
	ASN1_OBJECT *ret = NULL;
	p= *pp;
	inf=ASN1_get_object(&p,&len,&tag,&xclass,length);  if (inf & 0x80) 		{
		i=ASN1_R_BAD_OBJECT_HEADER;
		goto err;
	}
	
	if (tag != V_ASN1_OBJECT) 		{
		i=ASN1_R_EXPECTING_AN_OBJECT;
		goto err;
	}
	ret = c2i_ASN1_OBJECT(a, &p, len);  if(ret) *pp = p; 	return ret;
err:
	ASN1err(ASN1_F_D2I_ASN1_OBJECT,i);  return(NULL); }


/* FIXME : correct function body */	
/* file: bn_expand_internal : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lib.c */
static BN_ULONG *bn_expand_internal(const BIGNUM *b, int words) 	{
	BN_ULONG *A,*a = NULL;
	const BN_ULONG *B;
	int i;
	
	bn_check_top(b); 
	if (words > (INT_MAX/(4*BN_BITS2))) 		{
		BNerr(BN_F_BN_EXPAND_INTERNAL,BN_R_BIGNUM_TOO_LONG); 		return NULL;
	}
	if (BN_get_flags(b,BN_FLG_STATIC_DATA)) 		{
		BNerr(BN_F_BN_EXPAND_INTERNAL,BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);   return(NULL); 		}
	a=A=(BN_ULONG *)OPENSSL_malloc(sizeof(BN_ULONG)*words);  if (A == NULL) 		{
		BNerr(BN_F_BN_EXPAND_INTERNAL,ERR_R_MALLOC_FAILURE);   return(NULL); 		}
#if 1
	B=b->d;
	/* Check if the previous number needs to be copied */
	if (B != NULL) 		{
		for (i=b->top>>2; i>0; i--,A+=4,B+=4) 			{
			/*
			 * The fact that the loop is unrolled
			 * 4-wise is a tribute to Intel. It's
			 * the one that doesn't have enough
			 * registers to accomodate more data.
			 * I'd unroll it 8-wise otherwise:-)
			 *
			 *		<appro@fy.chalmers.se>
			 */
			BN_ULONG a0,a1,a2,a3;
			a0=B[0]; a1=B[1]; a2=B[2]; a3=B[3];
			A[0]=a0; A[1]=a1; A[2]=a2; A[3]=a3;
		}
		switch (b->top&3) 			{
			case 3:	A[2]=B[2];
			case 2:	A[1]=B[1];
			case 1:	A[0]=B[0];
			case 0: /* workaround for ultrix cc: without 'case 0', the optimizer does
					 * the switch table by doing a=top&3; a--; goto jump_table[a];
					 * which fails for top== 0 */
				;
		}
	}
	
#else
	memset(A,0,sizeof(BN_ULONG)*words); 
}

/* file: OBJ_nid2obj : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobj_dat.c */
ASN1_OBJECT *OBJ_nid2obj(int n) 	{
	ADDED_OBJ ad,*adp;
	ASN1_OBJECT ob;
	
	if ((n >= 0) && (n < NUM_NID)) 		{
		if ((n != NID_undef) && (nid_objs[n].nid == NID_undef)) 			{
			OBJerr(OBJ_F_OBJ_NID2OBJ,OBJ_R_UNKNOWN_NID);    return(NULL); 			}
		return((ASN1_OBJECT *)&(nid_objs[n])); 		}
	else if (added == NULL)   return(NULL); 	else
	{
		ad.type=ADDED_NID;
		ad.obj= &ob;
		ob.nid=n;
		adp=lh_ADDED_OBJ_retrieve(added,&ad);   if (adp != NULL)    return(adp->obj); 		else
		{
			OBJerr(OBJ_F_OBJ_NID2OBJ,OBJ_R_UNKNOWN_NID);    return(NULL); 			}
	}
}


/* file: OBJ_txt2obj : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobj_dat.c */
ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name) 	{
	int nid = NID_undef;
	ASN1_OBJECT *op=NULL;
	unsigned char *buf;
	unsigned char *p;
	const unsigned char *cp;
	int i, j;
	
	if(!no_name) {   if( ((nid = OBJ_sn2nid(s)) != NID_undef) ||    ((nid = OBJ_ln2nid(s)) != NID_undef) )       return OBJ_nid2obj(nid); 	}
	
	/* Work out size of content octets */
	i=a2d_ASN1_OBJECT(NULL,0,s,-1);  if (i <= 0) { 		/* Don't clear the error */
		/*ERR_clear_error();*/ 		return NULL;
	}
	/* Work out total size */
	j = ASN1_object_size(0,i,V_ASN1_OBJECT); 
	if((buf=(unsigned char *)OPENSSL_malloc(j)) == NULL) return NULL; 
	p = buf;
	/* Write out tag+length */
	ASN1_put_object(&p,0,i,V_ASN1_OBJECT,V_ASN1_UNIVERSAL); 	/* Write out contents */
	a2d_ASN1_OBJECT(p,i,s,-1); 
	cp=buf;
	op=d2i_ASN1_OBJECT(NULL,&cp,j);  OPENSSL_free(buf); 	return op;
}

/* file: _strlen31 : /Volumes/work/Phd/ECDH/kv_openssl/e_os.h */
#if (defined(WINDOWS) || defined(MSDOS))
#  ifdef WINDOWS
#    ifdef _WIN64
static unsigned int _strlen31(const char *str) 	{
	unsigned int len=0;
	while (*str && len<0x80000000U) str++, len++; 	return len&0x7FFFFFFF;
}
#    endif
#  endif
#  endif

/* file: ecdh_low : /Volumes/work/Phd/ECDH/kv_openssl/PythonScriptecdh_low.h */
unsigned char *ecdh_low(size_t *secret_len) { 	EC_KEY *key, *peerkey;
	int field_size;
	unsigned char *secret;
	
	/* Create an Elliptic Curve Key object and set it up to use the ANSI X9.62 Prime 256v1 curve */
	if(NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) handleErrors();   	/* Generate the private and public key */
	if(1 != EC_KEY_generate_key(key)) handleErrors();   	/* Get the peer's public key, and provide the peer with our public key -
															 * how this is done will be specific to your circumstances */
	peerkey = get_peerkey_low(key);   	/* Calculate the size of the buffer for the shared secret */
	field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));  *secret_len = (field_size+7)/8;   	/* Allocate the memory for the shared secret */
	if(NULL == (secret = OPENSSL_malloc(*secret_len))) handleErrors();   	/* Derive the shared secret */
	*secret_len = ECDH_compute_key(secret, *secret_len, EC_KEY_get0_public_key(peerkey),            key, NULL); 	
	/* Clean up */
	EC_KEY_free(key);  EC_KEY_free(peerkey);    if(*secret_len <= 0)  {   OPENSSL_free(secret);   return NULL; 	}
	
	return secret;
}/* file: EC_KEY_new_by_curve_name : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */

/* file: ec_group_new_from_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_curve.c */
static EC_GROUP *ec_group_new_from_data(const ec_list_element curve) 	{
	EC_GROUP *group=NULL;
	EC_POINT *P=NULL;
	BN_CTX	 *ctx=NULL;
	BIGNUM	 *p=NULL, *a=NULL, *b=NULL, *x=NULL, *y=NULL, *order=NULL;
	int	 ok=0;
	int	 seed_len,param_len;
	const EC_METHOD *meth;
	const EC_CURVE_DATA *data;
	const unsigned char *params;
	
	if ((ctx = BN_CTX_new()) == NULL) 		{
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_MALLOC_FAILURE); 		goto err;
	}
	
	data = curve.data;
	seed_len  = data->seed_len;
	param_len = data->param_len;
	params   = (const unsigned char *)(data+1); /* skip header */ 	params	 += seed_len;				/* skip seed   */
	
	if (!(p = BN_bin2bn(params+0*param_len, param_len, NULL))   || !(a = BN_bin2bn(params+1*param_len, param_len, NULL))   || !(b = BN_bin2bn(params+2*param_len, param_len, NULL))) 		{
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB); 		goto err;
	}
	
	if (curve.meth != 0) 		{
		meth = curve.meth();   if (((group = EC_GROUP_new(meth)) == NULL) ||    (!(group->meth->group_set_curve(group, p, a, b, ctx)))) 			{
			ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB); 			goto err;
		}
	}
	else if (data->field_type == NID_X9_62_prime_field) 		{
		if ((group = EC_GROUP_new_curve_GFp(p, a, b, ctx)) == NULL) 			{
			ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB); 			goto err;
		}
	}
#ifndef OPENSSL_NO_EC2M
	else	/* field_type == NID_X9_62_characteristic_two_field */
	{
		if ((group = EC_GROUP_new_curve_GF2m(p, a, b, ctx)) == NULL) 			{
			ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB); 			goto err;
		}
	}
#endif
	
	if ((P = EC_POINT_new(group)) == NULL) 		{
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB); 		goto err;
	}
	
	if (!(x = BN_bin2bn(params+3*param_len, param_len, NULL))   || !(y = BN_bin2bn(params+4*param_len, param_len, NULL))) 		{
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB); 		goto err;
	}
	if (!EC_POINT_set_affine_coordinates_GFp(group, P, x, y, ctx)) 		{
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB); 		goto err;
	}
	if (!(order = BN_bin2bn(params+5*param_len, param_len, NULL))   || !BN_set_word(x, (BN_ULONG)data->cofactor)) 		{
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB); 		goto err;
	}
	if (!EC_GROUP_set_generator(group, P, order, x)) 		{
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB); 		goto err;
	}
	if (seed_len) 		{
		if (!EC_GROUP_set_seed(group, params-seed_len, seed_len)) 			{
			ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB); 			goto err;
		}
	}
	ok=1;
err:
	if (!ok) 		{
		EC_GROUP_free(group); 		group = NULL;
	}
	if (P)   EC_POINT_free(P);  if (ctx)   BN_CTX_free(ctx);  if (p)   BN_free(p);  if (a)   BN_free(a);  if (b)   BN_free(b);  if (order)   BN_free(order);  if (x)   BN_free(x);  if (y)   BN_free(y); 	return group;
}

/* file: BN_POOL_get : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static BIGNUM *BN_POOL_get(BN_POOL *p) 	{
	if(p->used == p->size) 		{
		BIGNUM *bn;
		unsigned int loop = 0;
		BN_POOL_ITEM *item = OPENSSL_malloc(sizeof(BN_POOL_ITEM));   if(!item) return NULL; 		/* Initialise the structure */
		bn = item->vals;
		while(loop++ < BN_CTX_POOL_SIZE)    BN_init(bn++); 		item->prev = p->tail;
		item->next = NULL;
		/* Link it in */
		if(!p->head) 			p->head = p->current = p->tail = item;
		else
		{
			p->tail->next = item;
			p->tail = item;
			p->current = item;
		}
		p->size += BN_CTX_POOL_SIZE;
		p->used++;
		/* Return the first bignum from the new pool */
		return item->vals;
	}
	if(!p->used) 		p->current = p->head;
	else if((p->used % BN_CTX_POOL_SIZE) == 0) 		p->current = p->current->next;
	return p->current->vals + ((p->used++) % BN_CTX_POOL_SIZE); 	}
	
/* file: ctxdbg : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
#ifdef BN_CTX_DEBUG
static void ctxdbg(BN_CTX *ctx) 	{
	unsigned int bnidx = 0, fpidx = 0;
	BN_POOL_ITEM *item = ctx->pool.head;
	BN_STACK *stack = &ctx->stack;
	fprintf(stderr,"(%08x): ", (unsigned int)ctx);  while(bnidx < ctx->used) 		{
		fprintf(stderr,"%03x ", item->vals[bnidx++ % BN_CTX_POOL_SIZE].dmax);   if(!(bnidx % BN_CTX_POOL_SIZE)) 			item = item->next;
	}
	fprintf(stderr,"\n"); 	bnidx = 0;
	fprintf(stderr,"          : ");  while(fpidx < stack->depth) 		{
		while(bnidx++ < stack->indexes[fpidx])    fprintf(stderr,"    ");   fprintf(stderr,"^^^ "); 		bnidx++;
		fpidx++;
	}
	fprintf(stderr,"\n"); 	}
#endif

/* file: ECDH_DATA_new_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhech_lib.c */
static ECDH_DATA *ECDH_DATA_new_method(ENGINE *engine) 	{
	ECDH_DATA *ret;
	
	ret=(ECDH_DATA *)OPENSSL_malloc(sizeof(ECDH_DATA));  if (ret == NULL) 		{
		ECDHerr(ECDH_F_ECDH_DATA_NEW_METHOD, ERR_R_MALLOC_FAILURE);   return(NULL); 		}
	
	ret->init = NULL;
	
	ret->meth = ECDH_get_default_method(); 	ret->engine = engine;
#ifndef OPENSSL_NO_ENGINE
	if (!ret->engine)   ret->engine = ENGINE_get_default_ECDH();  if (ret->engine) 		{
		ret->meth = ENGINE_get_ECDH(ret->engine);   if (!ret->meth) 			{
			ECDHerr(ECDH_F_ECDH_DATA_NEW_METHOD, ERR_R_ENGINE_LIB);    ENGINE_finish(ret->engine);    OPENSSL_free(ret); 			return NULL;
		}
	}
#endif
	
	ret->flags = ret->meth->flags;
	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_ECDH, ret, &ret->ex_data); #if 0
		if ((ret->meth->init != NULL) && !ret->meth->init(ret)) 		{
			CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ECDH, ret, &ret->ex_data);   OPENSSL_free(ret); 		ret=NULL;
		}	
	return(ret); 	}
	
/* file: compute_wNAF : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_mult.c */
static signed char *compute_wNAF(const BIGNUM *scalar, int w, size_t *ret_len) 	{
	int window_val;
	int ok = 0;
	signed char *r = NULL;
	int sign = 1;
	int bit, next_bit, mask;
	size_t len = 0, j;
	
	if (BN_is_zero(scalar)) 		{
		r = OPENSSL_malloc(1);   if (!r) 			{
			ECerr(EC_F_COMPUTE_WNAF, ERR_R_MALLOC_FAILURE); 			goto err;
		}
		r[0] = 0;
		*ret_len = 1;
		return r;
	}
	
	if (w <= 0 || w > 7) /* 'signed char' can represent integers with absolute values less than 2^7 */ 		{
		ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR); 		goto err;
	}
	bit = 1 << w; /* at most 128 */
	next_bit = bit << 1; /* at most 256 */
	mask = next_bit - 1; /* at most 255 */
	
	if (BN_is_negative(scalar)) 		{
		sign = -1;
	}
	
	if (scalar->d == NULL || scalar->top == 0) 		{
		ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR); 		goto err;
	}
	
	len = BN_num_bits(scalar);  r = OPENSSL_malloc(len + 1); /* modified wNAF may be one digit longer than binary representation 	                              * (*ret_len will be set to the actual length, i.e. at most
															  * BN_num_bits(scalar) + 1) */
	if (r == NULL) 		{
		ECerr(EC_F_COMPUTE_WNAF, ERR_R_MALLOC_FAILURE); 		goto err;
	}
	window_val = scalar->d[0] & mask;
	j = 0;
	while ((window_val != 0) || (j + w + 1 < len)) /* if j+w+1 >= len, window_val will not increase */ 		{
		int digit = 0;
		
		/* 0 <= window_val <= 2^(w+1) */ 
		if (window_val & 1) 			{
			/* 0 < window_val < 2^(w+1) */ 
			if (window_val & bit) 				{
				digit = window_val - next_bit; /* -2^w < digit < 0 */
				
#if 1 /* modified wNAF */
				if (j + w + 1 >= len) 					{
					/* special case for generating modified wNAFs:
					 * no new bits will be added into window_val,
					 * so using a positive digit here will decrease
					 * the total length of the representation */
					
					digit = window_val & (mask >> 1); /* 0 < digit < 2^w */ 					}
#endif
			}
			else
			{
				digit = window_val; /* 0 < digit < 2^w */
			}
			
			if (digit <= -bit || digit >= bit || !(digit & 1)) 				{
				ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR); 				goto err;
			}
			
			window_val -= digit;
			
			/* now window_val is 0 or 2^(w+1) in standard wNAF generation; 			 * for modified window NAFs, it may also be 2^w
			 */
			if (window_val != 0 && window_val != next_bit && window_val != bit) 				{
				ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR); 				goto err;
			}
		}
		
		r[j++] = sign * digit;
		
		window_val >>= 1;
		window_val += bit * BN_is_bit_set(scalar, j + w); 
		if (window_val > next_bit) 			{
			ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR); 			goto err;
		}
	}
	
	if (j > len + 1) 		{
		ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR); 		goto err;
	}
	len = j;
	ok = 1;
	
err:
	if (!ok) 		{
		OPENSSL_free(r); 		r = NULL;
	}
	if (ok) 		*ret_len = len;
	return r;
}

/* file: bn_rand_range : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_rand.c */
static int bn_rand_range(int pseudo, BIGNUM *r, const BIGNUM *range) 	{
	int (*bn_rand)(BIGNUM *, int, int, int) = pseudo ? BN_pseudo_rand : BN_rand; 	int n;
	int count = 100;
	
	if (range->neg || BN_is_zero(range)) 		{
		BNerr(BN_F_BN_RAND_RANGE, BN_R_INVALID_RANGE); 		return 0;
	}
	
	n = BN_num_bits(range); /* n > 0 */ 
	/* BN_is_bit_set(range, n - 1) always holds */ 
	if (n == 1)   BN_zero(r);  else if (!BN_is_bit_set(range, n - 2) && !BN_is_bit_set(range, n - 3)) 		{
		/* range = 100..._2,
		 * so  3*range (= 11..._2)  is exactly one bit longer than  range */
		do
		{
			if (!bn_rand(r, n + 1, -1, 0)) return 0; 			/* If  r < 3*range,  use  r := r MOD range
																 * (which is either  r, r - range,  or  r - 2*range).
																 * Otherwise, iterate once more.
																 * Since  3*range = 11..._2, each iteration succeeds with
																 * probability >= .75. */
			if (BN_cmp(r ,range) >= 0) 				{
				if (!BN_sub(r, r, range)) return 0;     if (BN_cmp(r, range) >= 0)      if (!BN_sub(r, r, range)) return 0; 				}
			
			if (!--count) 				{
				BNerr(BN_F_BN_RAND_RANGE, BN_R_TOO_MANY_ITERATIONS); 				return 0;
			}
			
		}
		while (BN_cmp(r, range) >= 0); 		}
	else
	{
		do
		{
			/* range = 11..._2  or  range = 101..._2 */
			if (!bn_rand(r, n, -1, 0)) return 0; 
			if (!--count) 				{
				BNerr(BN_F_BN_RAND_RANGE, BN_R_TOO_MANY_ITERATIONS); 				return 0;
			}
		}
		while (BN_cmp(r, range) >= 0); 		}
	
	bn_check_top(r); 	return 1;
}

/* file: err_fns_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
static void err_fns_check(void) 	{
	if (err_fns) return; 	
	CRYPTO_w_lock(CRYPTO_LOCK_ERR);  if (!err_fns) 		err_fns = &err_defaults;
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR); 	}
	
	
#ifndef HAVE_CRYPTODEV
#else 
static int
cryptodev_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
				 const unsigned char *in, size_t inl)
{
	struct crypt_op cryp;
	struct dev_crypto_state *state = ctx->cipher_data;
	struct session_op *sess = &state->d_sess;
	const void *iiv;
	unsigned char save_iv[EVP_MAX_IV_LENGTH];
	
	if (state->d_fd < 0)
		return (0);
	if (!inl)
		return (1);
	if ((inl % ctx->cipher->block_size) != 0)
		return (0);
	
	memset(&cryp, 0, sizeof(cryp));
	
	cryp.ses = sess->ses;
	cryp.flags = 0;
	cryp.len = inl;
	cryp.mac = 0;
	
	cryp.op = ctx->encrypt ? COP_ENCRYPT : COP_DECRYPT;
	
	if (ctx->cipher->iv_len) {
		if (!ctx->encrypt) {
			iiv = in + inl - ctx->cipher->iv_len;
			memcpy(save_iv, iiv, ctx->cipher->iv_len);
		}
	} else
		cryp.iv = NULL;
	
	if (ioctl(state->d_fd, CIOCCRYPT, &cryp) == -1) {
		/* XXX need better errror handling
		 * this can fail for a number of different reasons.
		 */
		return (0);
	}
	
	if (ctx->cipher->iv_len) {
		if (ctx->encrypt)
			iiv = out + inl - ctx->cipher->iv_len;
		else
			iiv = save_iv;
		memcpy(ctx->iv, iiv, ctx->cipher->iv_len);
	}
	return (1);
}

static int
cryptodev_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
				   const unsigned char *iv, int enc)
{
	struct dev_crypto_state *state = ctx->cipher_data;
	struct session_op *sess = &state->d_sess;
	int cipher = -1, i;
	
	for (i = 0; ciphers[i].id; i++)
		if (ctx->cipher->nid == ciphers[i].nid &&
		    ctx->cipher->iv_len <= ciphers[i].ivmax &&
		    ctx->key_len == ciphers[i].keylen) {
			cipher = ciphers[i].id;
			break;
		}
	
	if (!ciphers[i].id) {
		state->d_fd = -1;
		return (0);
	}
	
	memset(sess, 0, sizeof(struct session_op));
	
	if ((state->d_fd = get_dev_crypto()) < 0)
		return (0);
	
	sess->keylen = ctx->key_len;
	sess->cipher = cipher;
	
	if (ioctl(state->d_fd, CIOCGSESSION, sess) == -1) {
		put_dev_crypto(state->d_fd);
		state->d_fd = -1;
		return (0);
	}
	return (1);
}

/*	struct dev_crypto_state *state = ctx->cipher_data; FIXME
 struct session_op *sess = &state->d_sess;*/
static int
cryptodev_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher,	
						 const int **nids, int nid)
{
	if (!cipher)
		
		switch (nid) {
			case NID_rc4:
				*cipher = &cryptodev_rc4;
				break;
			case NID_des_ede3_cbc:
				*cipher = &cryptodev_3des_cbc;
				break;
			case NID_des_cbc:
				*cipher = &cryptodev_des_cbc;
				break;
			case NID_bf_cbc:
				*cipher = &cryptodev_bf_cbc;
				break;
			case NID_cast5_cbc:
				*cipher = &cryptodev_cast_cbc;
				break;
			case NID_aes_128_cbc:
				*cipher = &cryptodev_aes_cbc;
				break;
			case NID_aes_192_cbc:
				*cipher = &cryptodev_aes_192_cbc;
				break;
			case NID_aes_256_cbc:
				*cipher = &cryptodev_aes_256_cbc;
				break;
			default:
				*cipher = NULL;
				break;
		}
	return (*cipher != NULL);
}

static int
cryptodev_engine_digests(ENGINE *e, const EVP_MD **digest,
						 const int **nids, int nid)
{
	if (!digest)
		
		switch (nid) {
#ifdef USE_CRYPTODEV_DIGESTS
			case NID_md5:
				*digest = &cryptodev_md5; 
				break;
			case NID_sha1:
				*digest = &cryptodev_sha1;
				break;
			default:
#endif /* USE_CRYPTODEV_DIGESTS */
				*digest = NULL;
				break;
		}
	return (*digest != NULL);
}

static int
cryptodev_dsa_dsa_mod_exp(DSA *dsa, BIGNUM *t1, BIGNUM *g,
						  BIGNUM *u1, BIGNUM *pub_key, BIGNUM *u2, BIGNUM *p,
						  BN_CTX *ctx, BN_MONT_CTX *mont)
{
	BIGNUM t2;
	int ret = 0;
	
	BN_init(&t2);
	
	/* v = ( g^u1 * y^u2 mod p ) mod q */
	/* let t1 = g ^ u1 mod p */
	ret = 0;
	
	if (!dsa->meth->bn_mod_exp(dsa,t1,dsa->g,u1,dsa->p,ctx,mont))
		goto err;
	
	/* let t2 = y ^ u2 mod p */
	if (!dsa->meth->bn_mod_exp(dsa,&t2,dsa->pub_key,u2,dsa->p,ctx,mont))
		goto err;
	/* let u1 = t1 * t2 mod p */
	if (!BN_mod_mul(u1,t1,&t2,dsa->p,ctx))
		goto err;
	
	BN_copy(t1,u1);
	
	ret = 1;
err:
	BN_free(&t2);
	return(ret);
}
#endif /* HAVE_CRYPTODEV */

static int surewarehk_dsa_mod_exp(DSA *dsa, BIGNUM *rr, BIGNUM *a1,
								  BIGNUM *p1, BIGNUM *a2, BIGNUM *p2, BIGNUM *m,
								  BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
	BIGNUM t;
	int to_return = 0;
	BN_init(&t);
	/* let rr = a1 ^ p1 mod m */
	if (!surewarehk_modexp(rr,a1,p1,m,ctx)) goto end;
	/* let t = a2 ^ p2 mod m */
	if (!surewarehk_modexp(&t,a2,p2,m,ctx)) goto end;
	/* let rr = rr * t mod m */
	if (!BN_mod_mul(rr,rr,&t,m,ctx)) goto end;
	to_return = 1;
end:
	BN_free(&t);
	return to_return;
}

#ifndef OPENSSL_NO_DH
/* Our internal DH_METHOD that we provide pointers to */
/* This function is aliased to mod_exp (with the dh and mont dropped). */
static int surewarehk_modexp_dh(const DH *dh, BIGNUM *r, const BIGNUM *a,
								const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
	return surewarehk_modexp(r, a, p, m, ctx);
}
#endif

static krb5_error_code
kssl_TKT2tkt(	/* IN     */	krb5_context	krb5context,
			 /* IN     */	KRB5_TKTBODY	*asn1ticket,
			 /* OUT    */	krb5_ticket	**krb5ticket,
			 /* OUT    */	KSSL_ERR *kssl_err  )
{
	krb5_error_code			krb5rc = KRB5KRB_ERR_GENERIC;
	krb5_ticket 			*new5ticket = NULL;
	ASN1_GENERALSTRING		*gstr_svc, *gstr_host;
	
	*krb5ticket = NULL;
	
	if (asn1ticket == NULL  ||  asn1ticket->realm == NULL  ||
		asn1ticket->sname == NULL  || 
		sk_ASN1_GENERALSTRING_num(asn1ticket->sname->namestring) < 2)
	{
		BIO_snprintf(kssl_err->text, KSSL_ERR_MAX,
					 "Null field in asn1ticket.\n");
		kssl_err->reason = SSL_R_KRB5_S_RD_REQ;
		return KRB5KRB_ERR_GENERIC;
	}
	
	kssl_err->reason = SSL_R_KRB5_S_RD_REQ;
	return ENOMEM;		/*  or  KRB5KRB_ERR_GENERIC;	*/
}

/* FIXME */

#ifndef OPENSSL_NO_KRB5
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)
#ifndef NO_DEF_KRB5_CCACHE
typedef	krb5_pointer	krb5_cc_cursor;	/* cursor for sequential lookup */
#endif /* NO_DEF_KRB5_CCACHE */
#endif  /* OPENSSL_SYS_WINDOWS || OPENSSL_SYS_WIN32 */
const EVP_CIPHER *
kssl_map_enc(krb5_enctype enctype)
{
	switch (enctype)
	{
		case ENCTYPE_DES_HMAC_SHA1:		/*    EVP_des_cbc();       */
		case ENCTYPE_DES_CBC_CRC:
		case ENCTYPE_DES_CBC_MD4:
		case ENCTYPE_DES_CBC_MD5:
		case ENCTYPE_DES_CBC_RAW:
			break;
		case ENCTYPE_DES3_CBC_SHA1:		/*    EVP_des_ede3_cbc();  */
		case ENCTYPE_DES3_CBC_SHA:
		case ENCTYPE_DES3_CBC_RAW:
			break;
		default:                return NULL;
			break;
	}
}
#endif	/* !OPENSSL_NO_KRB5	*/

/* file: default_malloc_ex : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
static void *default_malloc_ex(size_t num, const char *file, int line)  { return malloc_func(num); } 

/* file: int_table_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_table.c */
static int int_table_check(ENGINE_TABLE **t, int create) 	{
	LHASH_OF(ENGINE_PILE) *lh; 
	if(*t) return 1;  if(!create) return 0;  if((lh = lh_ENGINE_PILE_new()) == NULL) 		return 0;
	*t = (ENGINE_TABLE *)lh; 	return 1;
}

/* file: default_realloc_ex : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
static void *default_realloc_ex(void *str, size_t num, const char *file, int line)
{ return realloc_func(str,num); }

/* file: drbg_get_adin : /Volumes/work/Phd/ECDH/kv_openssl/crypto/randrand_lib.c */
#ifdef OPENSSL_FIPS
static size_t drbg_get_adin(DRBG_CTX *ctx, unsigned char **pout)     	{
	/* Use of static variables is OK as this happens under a lock */
	static unsigned char buf[16];
	static unsigned long counter;
	FIPS_get_timevec(buf, &counter); 	*pout = buf;
	return sizeof(buf); 	}
#endif