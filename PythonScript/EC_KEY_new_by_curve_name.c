/* file: EC_KEY_new_by_curve_name : D:\PhD\ECDH\kv_openssl\crypto\ecec_key.c */
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
/* file: EC_KEY_new : D:\PhD\ECDH\kv_openssl\crypto\ecec_key.c */
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
/* file: CRYPTO_malloc : D:\PhD\ECDH\kv_openssl\cryptomem.c */
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
/* file: CRYPTO_dbg_malloc : D:\PhD\ECDH\kv_openssl\cryptomem_dbg.c */
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
/* file: CRYPTO_is_mem_check_on : D:\PhD\ECDH\kv_openssl\cryptomem_dbg.c */
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
/* file: CRYPTO_THREADID_current : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
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
/* file: CRYPTO_THREADID_set_numeric : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id, unsigned long val)
	{
	memset(id, 0, sizeof(*id));
	id->val = val;
	}
/* file: CRYPTO_THREADID_set_pointer : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
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
/* file: CRYPTO_lock : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
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
/* file: CRYPTO_THREADID_hash : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
unsigned long CRYPTO_THREADID_hash(const CRYPTO_THREADID *id)
	{
	return id->val;
	}
/* file: CRYPTO_get_lock_name : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
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
/* file: sk_num : D:\PhD\ECDH\kv_openssl\crypto\stackstack.c */
int sk_num(const _STACK *st)
{
	if(st == NULL) return -1;
	return st->num;
}
/* file: STACK_OF : D:\PhD\ECDH\kv_openssl\appscms.c */
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
/* file: sk_value : D:\PhD\ECDH\kv_openssl\crypto\stackstack.c */
void *sk_value(const _STACK *st, int i)
{
	if(!st || (i < 0) || (i >= st->num)) return NULL;
	return st->data[i];
}
/* file: a2i_GENERAL_NAME : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_alt.c */
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
/* file: ERR_put_error : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
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
/* file: ERR_get_state : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
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
/* file: CRYPTO_THREADID_cpy : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
void CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest, const CRYPTO_THREADID *src)
	{
	memcpy(dest, src, sizeof(*src));
	}
/* file: ERRFN : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
#define ERRFN(a) err_fns->cb_##a

/* The internal state used by "err_defaults" - as such, the setting, reading,
 * creating, and deleting of this data should only be permitted via the
 * "err_defaults" functions. This way, a linked module can completely defer all
 * ERR state operation (together with requisite locking) to the implementations
 * and state in the loading application. */
static LHASH_OF(ERR_STRING_DATA) *int_error_hash = NULL;
static LHASH_OF(ERR_STATE) *int_thread_hash = NULL;
static int int_thread_hash_references = 0;
static int int_err_library_number= ERR_LIB_USER;

/* Internal function that checks whether "err_fns" is set and if not, sets it to
 * the defaults. */
static void err_fns_check(void)
	{
	if (err_fns) return;
	
	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	if (!err_fns)
		err_fns = &err_defaults;
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);
	}
/* file: ERR_STATE_free : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
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
/* file: CRYPTO_free : D:\PhD\ECDH\kv_openssl\cryptomem.c */
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
/* file: CRYPTO_dbg_free : D:\PhD\ECDH\kv_openssl\cryptomem_dbg.c */
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
/* file: CRYPTO_mem_ctrl : D:\PhD\ECDH\kv_openssl\cryptomem_dbg.c */
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
/* file: CRYPTO_THREADID_cmp : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
int CRYPTO_THREADID_cmp(const CRYPTO_THREADID *a, const CRYPTO_THREADID *b)
	{
	return memcmp(a, b, sizeof(*a));
	}
/* file: app_info_free : D:\PhD\ECDH\kv_openssl\cryptomem_dbg.c */
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
/* file: OBJ_sn2nid : D:\PhD\ECDH\kv_openssl\crypto\objectsobj_dat.c */
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
/* file: OBJ_ln2nid : D:\PhD\ECDH\kv_openssl\crypto\objectsobj_dat.c */
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
/* file: a2d_ASN1_OBJECT : D:\PhD\ECDH\kv_openssl\crypto\asn1a_object.c */
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
/* file: BN_new : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lib.c */
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
/* file: RAND_pseudo_bytes : D:\PhD\ECDH\kv_openssl\crypto\randrand_lib.c */
int RAND_pseudo_bytes(unsigned char *buf, int num)
	{
	const RAND_METHOD *meth = RAND_get_rand_method();
	if (meth && meth->pseudorand)
		return meth->pseudorand(buf,num);
	return(-1);
	}
/* file: RAND_get_rand_method : D:\PhD\ECDH\kv_openssl\crypto\randrand_lib.c */
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
/* file: ENGINE_get_default_RAND : D:\PhD\ECDH\kv_openssl\crypto\enginetb_rand.c */
ENGINE *ENGINE_get_default_RAND(void)
	{
	return engine_table_select(&rand_table, dummy_nid);
	}
/* file: engine_table_select_tmp : D:\PhD\ECDH\kv_openssl\crypto\engineeng_table.c */
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
/* file: ERR_set_mark : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
int ERR_set_mark(void)
	{
	ERR_STATE *es;

	es=ERR_get_state();

	if (es->bottom == es->top) return 0;
	es->err_flags[es->top]|=ERR_FLAG_MARK;
	return 1;
	}
/* file: LHASH_OF : D:\PhD\ECDH\kv_openssl\appsopenssl.c */
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
/* file: engine_unlocked_init : D:\PhD\ECDH\kv_openssl\crypto\engineeng_init.c */
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
/* file: engine_unlocked_finish : D:\PhD\ECDH\kv_openssl\crypto\engineeng_init.c */
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
/* file: engine_free_util : D:\PhD\ECDH\kv_openssl\crypto\engineeng_lib.c */
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
/* file: CRYPTO_add_lock : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
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
/* file: engine_pkey_meths_free : D:\PhD\ECDH\kv_openssl\crypto\enginetb_pkmeth.c */
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
/* file: EVP_PKEY_meth_free : D:\PhD\ECDH\kv_openssl\crypto\evppmeth_lib.c */
void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth)
	{
	if (pmeth && (pmeth->flags & EVP_PKEY_FLAG_DYNAMIC))
		OPENSSL_free(pmeth);
	}
/* file: engine_pkey_asn1_meths_free : D:\PhD\ECDH\kv_openssl\crypto\enginetb_asnmth.c */
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
/* file: EVP_PKEY_asn1_free : D:\PhD\ECDH\kv_openssl\crypto\asn1ameth_lib.c */
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
/* file: CRYPTO_free_ex_data : D:\PhD\ECDH\kv_openssl\cryptoex_data.c */
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
	{
	IMPL_CHECK
	EX_IMPL(free_ex_data)(class_index, obj, ad);
	}
/* file: EX_IMPL : D:\PhD\ECDH\kv_openssl\cryptoex_data.c */
#define EX_IMPL(a) impl->cb_##a

/* Predeclare the "default" ex_data implementation */
static int int_new_class(void);
static void int_cleanup(void);
static int int_get_new_index(int class_index, long argl, void *argp,
		CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
		CRYPTO_EX_free *free_func);
static int int_new_ex_data(int class_index, void *obj,
		CRYPTO_EX_DATA *ad);
static int int_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
		CRYPTO_EX_DATA *from);
static void int_free_ex_data(int class_index, void *obj,
		CRYPTO_EX_DATA *ad);
static CRYPTO_EX_DATA_IMPL impl_default =
	{
	int_new_class,
	int_cleanup,
	int_get_new_index,
	int_new_ex_data,
	int_dup_ex_data,
	int_free_ex_data
	};
/* file: ERR_pop_to_mark : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
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
/* file: ENGINE_get_RAND : D:\PhD\ECDH\kv_openssl\crypto\enginetb_rand.c */
const RAND_METHOD *ENGINE_get_RAND(const ENGINE *e)
	{
	return e->rand_meth;
	}
/* file: ENGINE_finish : D:\PhD\ECDH\kv_openssl\crypto\engineeng_init.c */
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
/* file: RAND_SSLeay : D:\PhD\ECDH\kv_openssl\crypto\randmd_rand.c */
RAND_METHOD *RAND_SSLeay(void)
	{
	return(&rand_ssleay_meth);
	}
/* file: BN_set_word : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lib.c */
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
/* file: bn_expand2 : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lib.c */
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
/* file: BN_mul_word : D:\PhD\ECDH\kv_openssl\crypto\bnbn_word.c */
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
/* file: bn_mul_words : D:\PhD\ECDH\kv_openssl\crypto\bnbn_asm.c */
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
/* file: bn_mul_words : D:\PhD\ECDH\kv_openssl\crypto\bnbn_asm.c */
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
/* file: BN_add_word : D:\PhD\ECDH\kv_openssl\crypto\bnbn_word.c */
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
/* file: BN_sub_word : D:\PhD\ECDH\kv_openssl\crypto\bnbn_word.c */
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
/* file: BN_set_negative : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lib.c */
void BN_set_negative(BIGNUM *a, int b)
	{
	if (b && !BN_is_zero(a))
		a->neg = 1;
	else
		a->neg = 0;
	}
/* file: BN_num_bits : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lib.c */
int BN_num_bits(const BIGNUM *a)
	{
	int i = a->top - 1;
	bn_check_top(a);

	if (BN_is_zero(a)) return 0;
	return ((i*BN_BITS2) + BN_num_bits_word(a->d[i]));
	}
/* file: BN_num_bits_word : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lib.c */
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
/* file: BN_div_word : D:\PhD\ECDH\kv_openssl\crypto\bnbn_word.c */
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
/* file: BN_lshift : D:\PhD\ECDH\kv_openssl\crypto\bnbn_shift.c */
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
/* file: bn_div_words : D:\PhD\ECDH\kv_openssl\crypto\bnbn_asm.c */
#if defined(BN_LLONG) && defined(BN_DIV2W)
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d)
	{
	return((BN_ULONG)(((((BN_ULLONG)h)<<BN_BITS2)|l)/(BN_ULLONG)d));
	}
#else
/* file: bn_div_words : D:\PhD\ECDH\kv_openssl\crypto\bnbn_asm.c */
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
/* file: BN_free : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lib.c */
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
/* file: ASN1_object_size : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_lib.c */
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
/* file: ASN1_put_object : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_lib.c */
void ASN1_put_object(unsigned char **pp, int constructed, int length, int tag,
	     int xclass)
	{
	unsigned char *p= *pp;
	int i, ttag;

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
/* file: asn1_put_length : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_lib.c */
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
/* file: ASN1_get_object : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_lib.c */
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
/* file: asn1_get_length : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_lib.c */
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
/* file: ASN1_OBJECT_free : D:\PhD\ECDH\kv_openssl\crypto\asn1a_object.c */
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
/* file: ERR_add_error_data : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
void ERR_add_error_data(int num, ...)
	{
	va_list args;
	va_start(args, num);
	ERR_add_error_vdata(num, args);
	va_end(args);
	}
/* file: ERR_add_error_vdata : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
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
/* file: CRYPTO_realloc : D:\PhD\ECDH\kv_openssl\cryptomem.c */
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
/* file: CRYPTO_dbg_realloc : D:\PhD\ECDH\kv_openssl\cryptomem_dbg.c */
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
/* file: BUF_strlcat : D:\PhD\ECDH\kv_openssl\crypto\bufferbuf_str.c */
size_t BUF_strlcat(char *dst, const char *src, size_t size)
	{
	size_t l = 0;
	for(; size > 0 && *dst; size--, dst++)
		l++;
	return l + BUF_strlcpy(dst, src, size);
	}
/* file: BUF_strlcpy : D:\PhD\ECDH\kv_openssl\crypto\bufferbuf_str.c */
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
/* file: ERR_set_error_data : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
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
/* file: a2i_IPADDRESS_NC : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_utl.c */
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
/* file: a2i_ipadd : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_utl.c */
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
/* file: ipv6_from_asc : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_utl.c */
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
/* file: CONF_parse_list : D:\PhD\ECDH\kv_openssl\crypto\confconf_mod.c */
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
/* file: ipv4_from_asc : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_utl.c */
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
/* file: ASN1_OCTET_STRING_set : D:\PhD\ECDH\kv_openssl\crypto\asn1a_octet.c */
int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *x, const unsigned char *d, int len)
{ return M_ASN1_OCTET_STRING_set(x, d, len); }
/* file: a2i_IPADDRESS : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_utl.c */
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
/* file: do_dirname : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_alt.c */
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
/* file: X509V3_NAME_from_section : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_utl.c */
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
/* file: X509_NAME_add_entry_by_txt : D:\PhD\ECDH\kv_openssl\crypto\x509x509name.c */
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
/* file: X509_NAME_ENTRY_create_by_txt : D:\PhD\ECDH\kv_openssl\crypto\x509x509name.c */
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
/* file: X509_NAME_ENTRY_create_by_OBJ : D:\PhD\ECDH\kv_openssl\crypto\x509x509name.c */
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
/* file: X509_NAME_ENTRY_set_object : D:\PhD\ECDH\kv_openssl\crypto\x509x509name.c */
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
/* file: X509_NAME_ENTRY_set_data : D:\PhD\ECDH\kv_openssl\crypto\x509x509name.c */
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
/* file: ASN1_STRING_set_by_NID : D:\PhD\ECDH\kv_openssl\crypto\asn1a_strnid.c */
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
/* file: ASN1_STRING_TABLE_get : D:\PhD\ECDH\kv_openssl\crypto\asn1a_strnid.c */
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
/* file: sk_find : D:\PhD\ECDH\kv_openssl\crypto\stackstack.c */
int sk_find(_STACK *st, void *data)
	{
	return internal_find(st, data, OBJ_BSEARCH_FIRST_VALUE_ON_MATCH);
	}
/* file: sk_sort : D:\PhD\ECDH\kv_openssl\crypto\stackstack.c */
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
/* file: ASN1_mbstring_ncopy : D:\PhD\ECDH\kv_openssl\crypto\asn1a_mbstr.c */
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
/* file: traverse_string : D:\PhD\ECDH\kv_openssl\crypto\asn1a_mbstr.c */
static int traverse_string(const unsigned char *p, int len, int inform,
		 int (*rfunc)(unsigned long value, void *in), void *arg);
static int in_utf8(unsigned long value, void *arg);
static int out_utf8(unsigned long value, void *arg);
static int type_str(unsigned long value, void *arg);
static int cpy_asc(unsigned long value, void *arg);
static int cpy_bmp(unsigned long value, void *arg);
static int cpy_univ(unsigned long value, void *arg);
static int cpy_utf8(unsigned long value, void *arg);
static int is_printable(unsigned long value);

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
/* file: BIO_snprintf : D:\PhD\ECDH\kv_openssl\crypto\biob_print.c */
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
	{
	va_list args;
	int ret;

	va_start(args, format);

	ret = BIO_vsnprintf(buf, n, format, args);

	va_end(args);
	return(ret);
	}
/* file: BIO_vsnprintf : D:\PhD\ECDH\kv_openssl\crypto\biob_print.c */
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
/* file: _dopr : D:\PhD\ECDH\kv_openssl\crypto\biob_print.c */
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
/* file: char_to_int : D:\PhD\ECDH\kv_openssl\crypto\biob_print.c */
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
/* file: fmtint : D:\PhD\ECDH\kv_openssl\crypto\biob_print.c */
static void fmtint     (char **, char **, size_t *, size_t *,
			LLONG, int, int, int, int);
static void fmtfp      (char **, char **, size_t *, size_t *,
			LDOUBLE, int, int, int);
static void doapr_outch (char **, char **, size_t *, size_t *, int);
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
/* file: fmtfp : D:\PhD\ECDH\kv_openssl\crypto\biob_print.c */
static void fmtfp      (char **, char **, size_t *, size_t *,
			LDOUBLE, int, int, int);
static void doapr_outch (char **, char **, size_t *, size_t *, int);
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
/* file: fmtstr : D:\PhD\ECDH\kv_openssl\crypto\biob_print.c */
static void fmtstr     (char **, char **, size_t *, size_t *,
			const char *, int, int, int);
static void fmtint     (char **, char **, size_t *, size_t *,
			LLONG, int, int, int, int);
static void fmtfp      (char **, char **, size_t *, size_t *,
			LDOUBLE, int, int, int);
static void doapr_outch (char **, char **, size_t *, size_t *, int);
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
/* file: ASN1_STRING_set : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_lib.c */
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
/* file: ASN1_STRING_free : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_lib.c */
void ASN1_STRING_free(ASN1_STRING *a)
	{
	if (a == NULL) return;
	if (a->data && !(a->flags & ASN1_STRING_FLAG_NDEF))
		OPENSSL_free(a->data);
	OPENSSL_free(a);
	}
/* file: ASN1_mbstring_copy : D:\PhD\ECDH\kv_openssl\crypto\asn1a_mbstr.c */
int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
					int inform, unsigned long mask)
{
	return ASN1_mbstring_ncopy(out, in, len, inform, mask, 0, 0);
}
/* file: OBJ_obj2nid : D:\PhD\ECDH\kv_openssl\crypto\objectsobj_dat.c */
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
/* file: ASN1_PRINTABLE_type : D:\PhD\ECDH\kv_openssl\crypto\asn1a_print.c */
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
/* file: X509_NAME_add_entry : D:\PhD\ECDH\kv_openssl\crypto\x509x509name.c */
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
/* file: sk_insert : D:\PhD\ECDH\kv_openssl\crypto\stackstack.c */
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
/* file: X509V3_section_free : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_conf.c */
void X509V3_section_free(X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section)
	{
	if (!section) return;
	if (ctx->db_meth->free_section)
			ctx->db_meth->free_section(ctx->db, section);
	}
/* file: do_othername : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_alt.c */
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
/* file: ASN1_generate_v3 : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_gen.c */
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
/* file: asn1_multi : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_gen.c */
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
/* file: sk_push : D:\PhD\ECDH\kv_openssl\crypto\stackstack.c */
int sk_push(_STACK *st, void *data)
	{
	return(sk_insert(st,data,st->num));
	}
/* file: asn1_str2type : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_gen.c */
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
/* file: X509V3_get_value_bool : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_utl.c */
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
/* file: BN_hex2bn : D:\PhD\ECDH\kv_openssl\crypto\bnbn_print.c */
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
/* file: BN_dec2bn : D:\PhD\ECDH\kv_openssl\crypto\bnbn_print.c */
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
/* file: BN_to_ASN1_INTEGER : D:\PhD\ECDH\kv_openssl\crypto\asn1a_int.c */
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
/* file: BN_bn2bin : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lib.c */
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
/* file: ASN1_TIME_check : D:\PhD\ECDH\kv_openssl\crypto\asn1a_time.c */
int ASN1_TIME_check(ASN1_TIME *t)
	{
	if (t->type == V_ASN1_GENERALIZEDTIME)
		return ASN1_GENERALIZEDTIME_check(t);
	else if (t->type == V_ASN1_UTCTIME)
		return ASN1_UTCTIME_check(t);
	return 0;
	}
/* file: ASN1_GENERALIZEDTIME_check : D:\PhD\ECDH\kv_openssl\crypto\asn1a_gentm.c */
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
/* file: ASN1_UTCTIME_check : D:\PhD\ECDH\kv_openssl\crypto\asn1a_utctm.c */
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
/* file: ASN1_tag2bit : D:\PhD\ECDH\kv_openssl\crypto\asn1tasn_dec.c */
unsigned long ASN1_tag2bit(int tag)
	{
	if ((tag < 0) || (tag > 30)) return 0;
	return tag2bit[tag];
	}
/* file: string_to_hex : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_utl.c */
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
/* file: CRYPTO_get_dynlock_value : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
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
/* file: OpenSSLDie : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
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
/* file: OPENSSL_showfatal : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
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
/* file: OPENSSL_showfatal : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
void OPENSSL_showfatal (const char *fmta,...)
{ va_list ap;

    va_start (ap,fmta);
    vfprintf (stderr,fmta,ap);
    va_end (ap);
}
#endif
/* file: OPENSSL_isservice : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
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
/* file: OPENSSL_isservice : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
int OPENSSL_isservice(void) { return 0; }
#endif
#else
/* file: OPENSSL_isservice : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
int OPENSSL_isservice (void) { return 0; }
#endif
/* file: CRYPTO_destroy_dynlockid : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
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
/* file: EC_GROUP_new_by_curve_name : D:\PhD\ECDH\kv_openssl\crypto\ecec_curve.c */
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
/* file: BN_CTX_new : D:\PhD\ECDH\kv_openssl\crypto\bnbn_ctx.c */
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
/* file: BN_POOL_init : D:\PhD\ECDH\kv_openssl\crypto\bnbn_ctx.c */
static void BN_POOL_init(BN_POOL *p)
	{
	p->head = p->current = p->tail = NULL;
	p->used = p->size = 0;
	}
/* file: BN_STACK_init : D:\PhD\ECDH\kv_openssl\crypto\bnbn_ctx.c */
static void BN_STACK_init(BN_STACK *st)
	{
	st->indexes = NULL;
	st->depth = st->size = 0;
	}
/* file: BN_bin2bn : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lib.c */
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
/* file: EC_GROUP_new : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
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
/* file: BN_init : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lib.c */
void BN_init(BIGNUM *a)
	{
	memset(a,0,sizeof(BIGNUM));
	bn_check_top(a);
	}
/* file: EC_GROUP_new_curve_GFp : D:\PhD\ECDH\kv_openssl\crypto\ecec_cvt.c */
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
/* file: EC_GFp_mont_method : D:\PhD\ECDH\kv_openssl\crypto\ececp_mont.c */
const EC_METHOD *EC_GFp_mont_method(void)
	{
#ifdef OPENSSL_FIPS
	return fips_ec_gfp_mont_method();
#else
	static const EC_METHOD ret = {
		EC_FLAGS_DEFAULT_OCT,
		NID_X9_62_prime_field,
		ec_GFp_mont_group_init,
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
		ec_GFp_simple_points_make_affine,
		0 /* mul */,
		0 /* precompute_mult */,
		0 /* have_precompute_mult */,	
		ec_GFp_mont_field_mul,
		ec_GFp_mont_field_sqr,
		0 /* field_div */,
		ec_GFp_mont_field_encode,
		ec_GFp_mont_field_decode,
		ec_GFp_mont_field_set_to_one };

	return &ret;
#endif
	}
/* file: EC_GFp_nist_method : D:\PhD\ECDH\kv_openssl\crypto\ececp_nist.c */
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
/* file: EC_GROUP_set_curve_GFp : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	if (group->meth->group_set_curve == 0)
		{
		ECerr(EC_F_EC_GROUP_SET_CURVE_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
		}
	return group->meth->group_set_curve(group, p, a, b, ctx);
	}
/* file: ERR_peek_last_error : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
unsigned long ERR_peek_last_error(void)
	{ return(get_error_values(0,1,NULL,NULL,NULL,NULL)); }
/* file: EC_GROUP_clear_free : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
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
/* file: EC_EX_DATA_clear_free_all_data : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
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
/* file: EC_POINT_clear_free : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
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
/* file: OPENSSL_cleanse : D:\PhD\ECDH\kv_openssl\cryptomem_clr.c */
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
/* file: BN_clear_free : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lib.c */
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
/* file: ERR_clear_error : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
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
/* file: EC_GROUP_new_curve_GF2m : D:\PhD\ECDH\kv_openssl\crypto\ecec_cvt.c */
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
/* file: EC_GF2m_simple_method : D:\PhD\ECDH\kv_openssl\crypto\ecec2_smpl.c */
#ifndef OPENSSL_NO_EC2M
const EC_METHOD *EC_GF2m_simple_method(void)
	{
#ifdef OPENSSL_FIPS
	return fips_ec_gf2m_simple_method();
#else
	static const EC_METHOD ret = {
		EC_FLAGS_DEFAULT_OCT,
		NID_X9_62_characteristic_two_field,
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
		ec_GF2m_simple_point_set_to_infinity,
		0 /* set_Jprojective_coordinates_GFp */,
		0 /* get_Jprojective_coordinates_GFp */,
		ec_GF2m_simple_point_set_affine_coordinates,
		ec_GF2m_simple_point_get_affine_coordinates,
		0,0,0,
		ec_GF2m_simple_add,
		ec_GF2m_simple_dbl,
		ec_GF2m_simple_invert,
		ec_GF2m_simple_is_at_infinity,
		ec_GF2m_simple_is_on_curve,
		ec_GF2m_simple_cmp,
		ec_GF2m_simple_make_affine,
		ec_GF2m_simple_points_make_affine,

		/* the following three method functions are defined in ec2_mult.c */
		ec_GF2m_simple_mul,
		ec_GF2m_precompute_mult,
		ec_GF2m_have_precompute_mult,

		ec_GF2m_simple_field_mul,
		ec_GF2m_simple_field_sqr,
		ec_GF2m_simple_field_div,
		0 /* field_encode */,
		0 /* field_decode */,
		0 /* field_set_to_one */ };

	return &ret;
#endif
	}
#endif
/* file: EC_GROUP_set_curve_GF2m : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
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
/* file: EC_POINT_new : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
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
/* file: EC_POINT_set_affine_coordinates_GFp : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
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
/* file: EC_GROUP_set_generator : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
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
/* file: EC_POINT_copy : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
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
/* file: BN_copy : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lib.c */
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
/* file: EC_GROUP_set_seed : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
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
/* file: EC_GROUP_free : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
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
/* file: EC_EX_DATA_free_all_data : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
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
/* file: EC_POINT_free : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
void EC_POINT_free(EC_POINT *point)
	{
	if (!point) return;

	if (point->meth->point_finish != 0)
		point->meth->point_finish(point);
	OPENSSL_free(point);
	}
/* file: BN_CTX_free : D:\PhD\ECDH\kv_openssl\crypto\bnbn_ctx.c */
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
/* file: BN_STACK_finish : D:\PhD\ECDH\kv_openssl\crypto\bnbn_ctx.c */
static void BN_STACK_finish(BN_STACK *st)
	{
	if(st->size) OPENSSL_free(st->indexes);
	}
/* file: BN_POOL_finish : D:\PhD\ECDH\kv_openssl\crypto\bnbn_ctx.c */
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
/* file: EC_GROUP_set_curve_name : D:\PhD\ECDH\kv_openssl\crypto\ecec_lib.c */
void EC_GROUP_set_curve_name(EC_GROUP *group, int nid)
	{
	group->curve_name = nid;
	}
/* file: EC_KEY_free : D:\PhD\ECDH\kv_openssl\crypto\ecec_key.c */
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
