#include <stddef.h>
#include <memory.h>
#include <time.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STACK_OF(type) struct stack_st_##type
#define LHASH_OF(type) struct lhash_st_##type
#define ERR_NUM_ERRORS	16
#define BN_CTX_POOL_SIZE	16
#define KEYSIZB 1024 /* should hit tty line limit first :-) */
#define CRYPTO_MEM_CHECK_OFF	0x0	/* an enume */
#define CRYPTO_NUM_LOCKS		41
#define SHA_DIGEST_LENGTH 20
#define MD_DIGEST_LENGTH	SHA_DIGEST_LENGTH
#define V_ASN1_OCTET_STRING		4
#define TYPE    unsigned int
#define NID_X9_62_prime_field		406
#define STATE_SIZE	1023
#define SSL_MAX_KEY_ARG_LENGTH			8
#define SSL_MAX_MASTER_KEY_LENGTH		48
#define SSL_MAX_SSL_SESSION_ID_LENGTH		32
#define SSL_MAX_SID_CTX_LENGTH			32
#define SSL_MAX_KRB5_PRINCIPAL_LENGTH  256

#define MS_FAR /* FIXME */

#ifdef THIRTY_TWO_BIT
#ifdef BN_LLONG
# if defined(_WIN32) && !defined(__GNUC__)
#  define BN_ULLONG	unsigned __int64
# else
#  define BN_ULLONG	unsigned long long
# endif
#endif
#define BN_ULONG	unsigned int
#define BN_BITS		64
#define BN_BYTES	4
#define BN_BITS2	32
#define BN_BITS4	16
#define BN_MASK2	(0xffffffffL)
#define BN_MASK2l	(0xffff)
#define BN_MASK2h	(0xffff0000L)
#define BN_DEC_CONV	(1000000000L)
#define BN_DEC_NUM	9
#endif

#ifdef SIXTY_FOUR_BIT
#define BN_ULONG	unsigned long long
#define BN_BITS		128
#define BN_BYTES	8
#define BN_BITS2	64
#define BN_BITS4	32
#define BN_MASK2	(0xffffffffffffffffLL)
#define BN_MASK2l	(0xffffffffL)
#define BN_MASK2h	(0xffffffff00000000LL)
#define BN_DEC_CONV	(10000000000000000000ULL)
#define BN_DEC_NUM	19
#endif

#ifdef SIXTY_FOUR_BIT_LONG
#define BN_ULLONG	unsigned long long
#define BN_ULONG	unsigned long
#define BN_BITS		128
#define BN_BYTES	8
#define BN_BITS2	64
#define BN_BITS4	32
#define BN_MASK2	(0xffffffffffffffffL)
#define BN_MASK2l	(0xffffffffL)
#define BN_MASK2h	(0xffffffff00000000L)
#define BN_DEC_CONV	(10000000000000000000UL)
#define BN_DEC_NUM	19
#endif

#define BN_ULONG	unsigned int

#ifdef __GNUC__
#  define __bio_h__attr__ __attribute__
#endif

/* file: OPENSSL_malloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define OPENSSL_malloc(num)	CRYPTO_malloc((int)num,__FILE__,__LINE__)

/* file: is_MemCheck_on : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define is_MemCheck_on() CRYPTO_is_mem_check_on()

/* file: CRYPTO_r_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_r_lock(type)	\
	CRYPTO_lock(CRYPTO_LOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#endif
#else
/* file: CRYPTO_r_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define CRYPTO_r_lock(a)
#endif

/* file: sk_OPENSSL_STRING_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_OPENSSL_STRING_num(st) SKM_sk_num(OPENSSL_STRING, st)

/* file: SKM_sk_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define SKM_sk_num(type, st) \
	sk_num(CHECKED_STACK_OF(type, st))

/* file: CHECKED_STACK_OF : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define CHECKED_STACK_OF(type, p) \
    ((_STACK*) (1 ? p : (STACK_OF(type)*)0))

/* file: sk_GENERAL_NAMES_new_null : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_GENERAL_NAMES_new_null() SKM_sk_new_null(GENERAL_NAMES)

/* file: sk_OPENSSL_STRING_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_OPENSSL_STRING_value(st, i) ((OPENSSL_STRING)sk_value(CHECKED_STACK_OF(OPENSSL_STRING, st), i))

/* file: X509V3err : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define X509V3err(f,r) ERR_PUT_error(ERR_LIB_X509V3,(f),(r),__FILE__,__LINE__)

/* file: ERR_PUT_error : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef OPENSSL_NO_ERR
#define ERR_PUT_error(a,b,c,d,e)	ERR_put_error(a,b,c,d,e)

#else
/* file: ERR_PUT_error : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define ERR_PUT_error(a,b,c,d,e)	ERR_put_error(a,b,c,NULL,0)

#endif
/* file: strlen : /Volumes/work/Phd/ECDH/kv_openssl/e_os.h */
#if (defined(WINDOWS) || defined(MSDOS))
#  ifdef WINDOWS
#    ifdef _WIN64
#      define strlen(s) _strlen31(s)

#    endif
#  endif
#else /* The non-microsoft world */
#  endif
/* file: CRYPTO_w_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_w_lock(type)	\
	CRYPTO_lock(CRYPTO_LOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)

#endif
#else
/* file: CRYPTO_w_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define CRYPTO_w_lock(a)

#endif
/* file: CRYPTO_w_unlock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_w_unlock(type)	\
	CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)

#endif
#else
/* file: CRYPTO_w_unlock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define CRYPTO_w_unlock(a)

#endif
/* file: ERRFN : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
#define ERRFN(a) err_fns->cb_##a

/* file: err_clear_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
#define err_clear_data(p,i) \
	do { \
	if (((p)->err_data[i] != NULL) && \
		(p)->err_data_flags[i] & ERR_TXT_MALLOCED) \
		{  \
		OPENSSL_free((p)->err_data[i]); \
		(p)->err_data[i]=NULL; \
		} \
	(p)->err_data_flags[i]=0; \
	} while(0)

/* file: OPENSSL_free : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define OPENSSL_free(addr)	CRYPTO_free(addr)

/* file: MemCheck_off : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define MemCheck_off()	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE)

/* file: lh_MEM_delete : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define lh_MEM_delete(lh,inst) LHM_lh_delete(MEM,lh,inst)

/* file: MemCheck_on : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define MemCheck_on()	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE)

/* file: ERR_PACK : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define ERR_PACK(l,f,r)		(((((unsigned long)l)&0xffL)*0x1000000)| \
				((((unsigned long)f)&0xfffL)*0x1000)| \
				((((unsigned long)r)&0xfffL)))

/* file: lh_ADDED_OBJ_retrieve : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define lh_ADDED_OBJ_retrieve(lh,inst) LHM_lh_retrieve(ADDED_OBJ,lh,inst)

/* file: OBJerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define OBJerr(f,r)  ERR_PUT_error(ERR_LIB_OBJ,(f),(r),__FILE__,__LINE__)

/* file: ASN1err : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define ASN1err(f,r) ERR_PUT_error(ERR_LIB_ASN1,(f),(r),__FILE__,__LINE__)

/* file: BNerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define BNerr(f,r)   ERR_PUT_error(ERR_LIB_BN,(f),(r),__FILE__,__LINE__)

/* file: bn_check_top : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifdef BN_DEBUG
#define bn_check_top(a) \
	do { \
		const BIGNUM *_bnum2 = (a); \
		if (_bnum2 != NULL) { \
			assert((_bnum2->top == 0) || \
				(_bnum2->d[_bnum2->top - 1] != 0)); \
			bn_pollute(_bnum2); \
		} \
	} while(0)

/* file: bn_pollute : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifdef BN_DEBUG
#ifdef BN_DEBUG_RAND
#define bn_pollute(a) \
	do { \
		const BIGNUM *_bnum1 = (a); \
		if(_bnum1->top < _bnum1->dmax) { \
			unsigned char _tmp_char; \
			/* We cast away const without the compiler knowing, any \
			 * *genuinely* constant variables that aren't mutable \
			 * wouldn't be constructed with top!=dmax. */ \
			BN_ULONG *_not_const; \
			memcpy(&_not_const, &_bnum1->d, sizeof(BN_ULONG*)); \
			RAND_pseudo_bytes(&_tmp_char, 1); \
			memset((unsigned char *)(_not_const + _bnum1->top), _tmp_char, \
				(_bnum1->dmax - _bnum1->top) * sizeof(BN_ULONG)); \
		} \
	} while(0)

#else
/* file: bn_pollute : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define bn_pollute(a)

#endif
/* file: engine_table_select : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
#define engine_table_select(t,n) engine_table_select_tmp(t,n,__FILE__,__LINE__)

#endif
/* file: lh_FUNCTION_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define lh_FUNCTION_new() LHM_lh_new(FUNCTION,function)

/* file: lh_FUNCTION_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define lh_FUNCTION_insert(lh,inst) LHM_lh_insert(FUNCTION,lh,inst)

/* file: lh_ENGINE_PILE_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define lh_ENGINE_PILE_new() LHM_lh_new(ENGINE_PILE,engine_pile)

/* file: lh_ENGINE_PILE_retrieve : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define lh_ENGINE_PILE_retrieve(lh,inst) LHM_lh_retrieve(ENGINE_PILE,lh,inst)

/* file: engine_ref_debug : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
#ifdef ENGINE_REF_COUNT_DEBUG
#define engine_ref_debug(e, isfunct, diff) \
	fprintf(stderr, "engine: %08x %s from %d to %d (%s:%d)\n", \
		(unsigned int)(e), (isfunct ? "funct" : "struct"), \
		((isfunct) ? ((e)->funct_ref - (diff)) : ((e)->struct_ref - (diff))), \
		((isfunct) ? (e)->funct_ref : (e)->struct_ref), \
		(__FILE__), (__LINE__));

#else
/* file: engine_ref_debug : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
#define engine_ref_debug(e, isfunct, diff)

#endif
/* file: sk_ENGINE_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_ENGINE_value(st, i) SKM_sk_value(ENGINE, (st), (i))

/* file: SKM_sk_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define SKM_sk_value(type, st,i) \
	((type *)sk_value(CHECKED_STACK_OF(type, st), i))

/* file: ENGINEerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define ENGINEerr(f,r) ERR_PUT_error(ERR_LIB_ENGINE,(f),(r),__FILE__,__LINE__)

/* file: CRYPTO_add : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_add(addr,amount,type)	\
	CRYPTO_add_lock(addr,amount,type,__FILE__,__LINE__)

#endif
#else
/* file: CRYPTO_add : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define CRYPTO_add(a,b,c)	((*(a))+=(b))

#endif
/* file: EX_IMPL : /Volumes/work/Phd/ECDH/kv_openssl/cryptoex_data.c */
#define EX_IMPL(a) impl->cb_##a

/* file: err_clear : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
#define err_clear(p,i) \
	do { \
	(p)->err_flags[i]=0; \
	(p)->err_buffer[i]=0; \
	err_clear_data(p,i); \
	(p)->err_file[i]=NULL; \
	(p)->err_line[i]= -1; \
	} while(0)

/* file: bn_expand : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define bn_expand(a,bits) ((((((bits+BN_BITS2-1))/BN_BITS2)) <= (a)->dmax)?\
	(a):bn_expand2((a),(bits+BN_BITS2-1)/BN_BITS2))

/* file: BN_get_flags : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_get_flags(b,n)	((b)->flags&(n))

/* file: BN_zero : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifdef OPENSSL_NO_DEPRECATED
#define BN_zero(a)	BN_zero_ex(a)

#else
/* file: BN_zero : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_zero(a)	(BN_set_word((a),0))

#endif
/* file: BN_zero_ex : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_zero_ex(a) \
	do { \
		BIGNUM *_tmp_bn = (a); \
		_tmp_bn->top = 0; \
		_tmp_bn->neg = 0; \
	} while(0)

/* file: mul : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifdef BN_LLONG
#define mul(r,a,w,c) { \
	BN_ULLONG t; \
	t=(BN_ULLONG)w * (a) + (c); \
	(r)= Lw(t); \
	(c)= Hw(t); \
	}

#endif
/* file: Lw : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#define Lw(t)    (((BN_ULONG)(t))&BN_MASK2)

/* file: Hw : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#define Hw(t)    (((BN_ULONG)((t)>>BN_BITS2))&BN_MASK2)

/* file: LBITS : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifdef BN_LLONG
#define LBITS(a)	((a)&BN_MASK2l)

#endif /* !BN_LLONG */
/* file: HBITS : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifdef BN_LLONG
#define HBITS(a)	(((a)>>BN_BITS4)&BN_MASK2l)

#endif /* !BN_LLONG */
/* file: bn_wexpand : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define bn_wexpand(a,words) (((words) <= (a)->dmax)?(a):bn_expand2((a),(words)))

/* file: bn_correct_top : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define bn_correct_top(a) \
        { \
        BN_ULONG *ftl; \
	int tmp_top = (a)->top; \
	if (tmp_top > 0) \
		{ \
		for (ftl= &((a)->d[tmp_top-1]); tmp_top > 0; tmp_top--) \
			if (*(ftl--)) break; \
		(a)->top = tmp_top; \
		} \
	bn_pollute(a); \
	}

/* file: OPENSSL_realloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define OPENSSL_realloc(addr,num) \
	CRYPTO_realloc((char *)addr,(int)num,__FILE__,__LINE__)

/* file: lh_MEM_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define lh_MEM_insert(lh,inst) LHM_lh_insert(MEM,lh,inst)

/* file: BUFerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define BUFerr(f,r)  ERR_PUT_error(ERR_LIB_BUF,(f),(r),__FILE__,__LINE__)

/* file: CONFerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define CONFerr(f,r) ERR_PUT_error(ERR_LIB_CONF,(f),(r),__FILE__,__LINE__)

/* file: sk_CONF_VALUE_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_CONF_VALUE_num(st) SKM_sk_num(CONF_VALUE, (st))

/* file: sk_CONF_VALUE_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_CONF_VALUE_value(st, i) SKM_sk_value(CONF_VALUE, (st), (i))

/* file: X509err : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define X509err(f,r) ERR_PUT_error(ERR_LIB_X509,(f),(r),__FILE__,__LINE__)

/* file: sk_ASN1_STRING_TABLE_find : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_ASN1_STRING_TABLE_find(st, val) SKM_sk_find(ASN1_STRING_TABLE, (st), (val))

/* file: SKM_sk_find : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define SKM_sk_find(type, st, val) \
	sk_find(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val))

/* file: CHECKED_PTR_OF : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef CHECKED_PTR_OF
#define CHECKED_PTR_OF(type, p) \
    ((void*) (1 ? p : (type*)0))

#endif
/* file: sk_ASN1_STRING_TABLE_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_ASN1_STRING_TABLE_value(st, i) SKM_sk_value(ASN1_STRING_TABLE, (st), (i))

/* file: char_to_int : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
#define char_to_int(p) (p - '0')

/* file: sk_X509_NAME_ENTRY_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_X509_NAME_ENTRY_num(st) SKM_sk_num(X509_NAME_ENTRY, (st))

/* file: sk_X509_NAME_ENTRY_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_X509_NAME_ENTRY_value(st, i) SKM_sk_value(X509_NAME_ENTRY, (st), (i))

/* file: sk_X509_NAME_ENTRY_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_X509_NAME_ENTRY_insert(st, val, i) SKM_sk_insert(X509_NAME_ENTRY, (st), (val), (i))

/* file: SKM_sk_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define SKM_sk_insert(type, st,val, i) \
	sk_insert(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val), i)

/* file: memmove : /Volumes/work/Phd/ECDH/kv_openssl/e_os.h */
#if defined(sun) && !defined(__svr4__) && !defined(__SVR4)
# define memmove(s1,s2,n) bcopy((s2),(s1),(n))

#endif
#endif
/* file: sk_ASN1_TYPE_new_null : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_ASN1_TYPE_new_null() SKM_sk_new_null(ASN1_TYPE)

/* file: sk_ASN1_TYPE_push : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_ASN1_TYPE_push(st, val) SKM_sk_push(ASN1_TYPE, (st), (val))

/* file: SKM_sk_push : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define SKM_sk_push(type, st, val) \
	sk_push(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val))

/* file: sk_ASN1_TYPE_pop_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_ASN1_TYPE_pop_free(st, free_func) SKM_sk_pop_free(ASN1_TYPE, (st), (free_func))

/* file: SKM_sk_pop_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define SKM_sk_pop_free(type, st, free_func) \
	sk_pop_free(CHECKED_STACK_OF(type, st), CHECKED_SK_FREE_FUNC(type, free_func))

/* file: CHECKED_SK_FREE_FUNC : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define CHECKED_SK_FREE_FUNC(type, p) \
    ((void (*)(void *)) ((1 ? p : (void (*)(type *))0)))

/* file: X509V3_conf_err : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
#define X509V3_conf_err(val) ERR_add_error_data(6, "section:", val->section, \
",name:", val->name, ",value:", val->value);

/* file: M_ASN1_INTEGER_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#define M_ASN1_INTEGER_new()	(ASN1_INTEGER *)\
		ASN1_STRING_type_new(V_ASN1_INTEGER)

/* file: BN_is_negative : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_is_negative(a) ((a)->neg != 0)

/* file: BN_num_bytes : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_num_bytes(a)	((BN_num_bits(a)+7)/8)

/* file: M_ASN1_INTEGER_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#define M_ASN1_INTEGER_free(a)		ASN1_STRING_free((ASN1_STRING *)a)

/* file: M_ASN1_IA5STRING_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#define M_ASN1_IA5STRING_new()	(ASN1_IA5STRING *)\
		ASN1_STRING_type_new(V_ASN1_IA5STRING)

/* file: sk_GENERAL_NAME_push : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_GENERAL_NAME_push(st, val) SKM_sk_push(GENERAL_NAME, (st), (val))

/* file: sk_GENERAL_NAMES_push : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_GENERAL_NAMES_push(st, val) SKM_sk_push(GENERAL_NAMES, (st), (val))

/* file: sk_GENERAL_NAMES_pop_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_GENERAL_NAMES_pop_free(st, free_func) SKM_sk_pop_free(GENERAL_NAMES, (st), (free_func))

/* file: sk_CRYPTO_dynlock_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_CRYPTO_dynlock_num(st) SKM_sk_num(CRYPTO_dynlock, (st))

/* file: sk_CRYPTO_dynlock_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_CRYPTO_dynlock_value(st, i) SKM_sk_value(CRYPTO_dynlock, (st), (i))

/* file: OPENSSL_assert : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define OPENSSL_assert(e)       (void)((e) ? 0 : (OpenSSLDie(__FILE__, __LINE__, #e),1))

/* file: alloca : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_exp.c */
#ifdef _WIN32
# ifndef alloca
#  define alloca(s) __builtin_alloca((s))

# endif
#endif
/* file: sk_CRYPTO_dynlock_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_CRYPTO_dynlock_set(st, i, val) SKM_sk_set(CRYPTO_dynlock, (st), (i), (val))

/* file: CRYPTO_r_unlock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_r_unlock(type)	\
	CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_READ,type,__FILE__,__LINE__)

#endif
#else
/* file: CRYPTO_r_unlock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define CRYPTO_r_unlock(a)

#endif
/* file: lh_MEM_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define lh_MEM_new() LHM_lh_new(MEM,mem)

/* file: lh_APP_INFO_retrieve : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define lh_APP_INFO_retrieve(lh,inst) LHM_lh_retrieve(APP_INFO,lh,inst)

/* file: ECerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define ECerr(f,r)   ERR_PUT_error(ERR_LIB_EC,(f),(r),__FILE__,__LINE__)

/* file: ERR_GET_REASON : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define ERR_GET_REASON(l)	(int)((l)&0xfffL)

/* file: REF_PRINT : /Volumes/work/Phd/ECDH/kv_openssl/e_os.h */
#ifdef REF_PRINT
#define REF_PRINT(a,b)	fprintf(stderr,"%08X:%4d:%s\n",(int)b,b->references,a)

#endif
/* file: RANDerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define RANDerr(f,r) ERR_PUT_error(ERR_LIB_RAND,(f),(r),__FILE__,__LINE__)

/* file: EC_window_bits_for_scalar_size : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_mult.c */
#define EC_window_bits_for_scalar_size(b) \
		((size_t) \
		 ((b) >= 2000 ? 6 : \
		  (b) >=  800 ? 5 : \
		  (b) >=  300 ? 4 : \
		  (b) >=   70 ? 3 : \
		  (b) >=   20 ? 2 : \
		  1))

/* file: ECDHerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define ECDHerr(f,r)  ERR_PUT_error(ERR_LIB_ECDH,(f),(r),__FILE__,__LINE__)

/* file: DHerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define DHerr(f,r)   ERR_PUT_error(ERR_LIB_DH,(f),(r),__FILE__,__LINE__)

/* file: CTXDBG_ENTRY : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
#ifdef BN_CTX_DEBUG
#define CTXDBG_ENTRY(str, ctx)	do { \
				ctxdbg_cur = (str); \
				fprintf(stderr,"Starting %s\n", ctxdbg_cur); \
				ctxdbg(ctx); \
				} while(0)
#endif /* FIXME */

/* file: CTXDBG_EXIT : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
#ifdef BN_CTX_DEBUG
#define CTXDBG_EXIT(ctx)

#endif
/* file: CTXDBG_RET : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
#ifdef BN_CTX_DEBUG
#define CTXDBG_RET(ctx,ret)

#endif
/* file: BN_one : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_one(a)	(BN_set_word((a),1))

/* file: BN_mod : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_mod(rem,m,d,ctx) BN_div(NULL,(rem),(m),(d),(ctx))

/* file: bn_clear_top2max : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifdef BN_DEBUG_RAND
#define bn_clear_top2max(a) \
	{ \
	int      ind = (a)->dmax - (a)->top; \
	BN_ULONG *ftl = &(a)->d[(a)->top-1]; \
	for (; ind != 0; ind--) \
		*(++ftl) = 0x0; \
	}

#else
/* file: bn_clear_top2max : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#define bn_clear_top2max(a)

#endif
/* file: BN_UMULT_LOHI : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#if !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM) && !defined(PEDANTIC)
# if defined(__alpha) && (defined(SIXTY_FOUR_BIT_LONG) || defined(SIXTY_FOUR_BIT))
#  if defined(__GNUC__) && __GNUC__>=2
#   define BN_UMULT_LOHI(low,high,a,b)	\
	asm ("mulq	%3"		\
		: "=a"(low),"=d"(high)	\
		: "a"(a),"g"(b)		\
		: "cc");

#  endif
/* file: BN_UMULT_LOHI : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
# elif (defined(_M_AMD64) || defined(_M_X64)) && defined(SIXTY_FOUR_BIT)
#   define BN_UMULT_LOHI(low,high,a,b)	((low)=_umul128((a),(b),&(high)))

/* file: BN_UMULT_LOHI : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
# elif defined(__mips) && (defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG))
#     define BN_UMULT_LOHI(low,high,a,b) ({	\
	__uint128_t ret=(__uint128_t)(a)*(b);	\
	(high)=ret>>64; (low)=ret;	 })

/* file: BN_UMULT_HIGH : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
# if defined(__alpha) && (defined(SIXTY_FOUR_BIT_LONG) || defined(SIXTY_FOUR_BIT))
#  if defined(__DECC)
#   include <c_asm.h>
#   define BN_UMULT_HIGH(a,b)	(BN_ULONG)asm("umulh %a0,%a1,%v0",(a),(b))
#  elif defined(__GNUC__) && __GNUC__>=2
#   define BN_UMULT_HIGH(a,b)	({	\
register BN_ULONG ret;		\
asm ("umulh	%1,%2,%0"	\
: "=r"(ret)		\
: "r"(a), "r"(b));		\
ret;			})
#  endif	/* compiler */
# elif defined(_ARCH_PPC) && defined(__64BIT__) && defined(SIXTY_FOUR_BIT_LONG)
#  if defined(__GNUC__) && __GNUC__>=2
#   define BN_UMULT_HIGH(a,b)	({	\
register BN_ULONG ret;		\
asm ("mulhdu	%0,%1,%2"	\
: "=r"(ret)		\
: "r"(a), "r"(b));		\
ret;			})
#  endif	/* compiler */
# elif (defined(__x86_64) || defined(__x86_64__)) && \
(defined(SIXTY_FOUR_BIT_LONG) || defined(SIXTY_FOUR_BIT))
#  if defined(__GNUC__) && __GNUC__>=2
#   define BN_UMULT_HIGH(a,b)	({	\
register BN_ULONG ret,discard;	\
asm ("mulq	%3"		\
: "=a"(discard),"=d"(ret)	\
: "a"(a), "g"(b)		\
: "cc");			\
ret;			})
#   define BN_UMULT_LOHI(low,high,a,b)	\
asm ("mulq	%3"		\
: "=a"(low),"=d"(high)	\
: "a"(a),"g"(b)		\
: "cc");
#  endif
# elif (defined(_M_AMD64) || defined(_M_X64)) && defined(SIXTY_FOUR_BIT)
#  if defined(_MSC_VER) && _MSC_VER>=1400
unsigned __int64 __umulh	(unsigned __int64 a,unsigned __int64 b);
unsigned __int64 _umul128	(unsigned __int64 a,unsigned __int64 b,
							 unsigned __int64 *h);
#   pragma intrinsic(__umulh,_umul128)
#   define BN_UMULT_HIGH(a,b)		__umulh((a),(b))
#   define BN_UMULT_LOHI(low,high,a,b)	((low)=_umul128((a),(b),&(high)))
#  endif
# elif defined(__mips) && (defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG))
#  if defined(__GNUC__) && __GNUC__>=2
#   if __GNUC__>=4 && __GNUC_MINOR__>=4 /* "h" constraint is no more since 4.4 */
#     define BN_UMULT_HIGH(a,b)		 (((__uint128_t)(a)*(b))>>64)
#     define BN_UMULT_LOHI(low,high,a,b) ({	\
__uint128_t ret=(__uint128_t)(a)*(b);	\
(high)=ret>>64; (low)=ret;	 })
#   else
#     define BN_UMULT_HIGH(a,b)	({	\
register BN_ULONG ret;		\
asm ("dmultu	%1,%2"		\
: "=h"(ret)		\
: "r"(a), "r"(b) : "l");	\
ret;			})
#     define BN_UMULT_LOHI(low,high,a,b)\
asm ("dmultu	%2,%3"		\
: "=l"(low),"=h"(high)	\
: "r"(a), "r"(b));
#    endif
#  endif
# endif		/* cpu */
#endif		/* OPENSSL_NO_ASM */
#endif

/* file: mul64 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifdef BN_LLONG
#define mul64(l,h,bl,bh) \
	{ \
	BN_ULONG m,m1,lt,ht; \
 \
	lt=l; \
	ht=h; \
	m =(bh)*(lt); \
	lt=(bl)*(lt); \
	m1=(bl)*(ht); \
	ht =(bh)*(ht); \
	m=(m+m1)&BN_MASK2; if (m < m1) ht+=L2HBITS((BN_ULONG)1); \
	ht+=HBITS(m); \
	m1=L2HBITS(m); \
	lt=(lt+m1)&BN_MASK2; if (lt < m1) ht++; \
	(l)=lt; \
	(h)=ht; \
	}

#endif /* !BN_LLONG */
/* file: L2HBITS : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifdef BN_LLONG
#define	L2HBITS(a)	(((a)<<BN_BITS4)&BN_MASK2)

#endif /* !BN_LLONG */
/* file: BN_is_odd : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_is_odd(a)	    (((a)->top > 0) && ((a)->d[0] & 1))

/* file: BN_is_one : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_is_one(a)        (BN_abs_is_word((a),1) && !(a)->neg)

/* file: BN_abs_is_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_abs_is_word(a,w) ((((a)->top == 1) && ((a)->d[0] == (BN_ULONG)(w))) || \
				(((w) == 0) && ((a)->top == 0)))

/* file: BN_is_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_is_word(a,w)     (BN_abs_is_word((a),(w)) && (!(w) || !(a)->neg))

/* file: mul_add_c : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
#if defined(BN_MUL_COMBA) && !defined(OPENSSL_SMALL_FOOTPRINT)
#ifdef BN_LLONG
#define mul_add_c(a,b,c0,c1,c2) \
	t=(BN_ULLONG)a*b; \
	t1=(BN_ULONG)Lw(t); \
	t2=(BN_ULONG)Hw(t); \
	c0=(c0+t1)&BN_MASK2; if ((c0) < t1) t2++; \
	c1=(c1+t2)&BN_MASK2; if ((c1) < t2) c2++;

/* file: mul_add_c : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_asm.c */
#elif defined(BN_UMULT_LOHI)
#define mul_add_c(a,b,c0,c1,c2)	{	\
	BN_ULONG ta=(a),tb=(b);		\
	BN_UMULT_LOHI(t1,t2,ta,tb);	\
	c0 += t1; t2 += (c0<t1)?1:0;	\
	c1 += t2; c2 += (c1<t2)?1:0;	\
	}

/* file: mul_add : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifdef BN_LLONG
#define mul_add(r,a,w,c) { \
	BN_ULLONG t; \
	t=(BN_ULLONG)w * (a) + (r) + (c); \
	(r)= Lw(t); \
	(c)= Hw(t); \
	}

#endif
#endif
#endif
/* file: BN_set_flags : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_set_flags(b,n)	((b)->flags|=(n))

/********** Global Variabls and Structures **********/ 

	struct crypto_ex_data_st
	{
		STACK_OF(void) *sk;
	};
	
	typedef struct {
		int type;
		const char *name;
	} FUNCTION;
	
	typedef struct asn1_object_st
	{
		const char *sn,*ln;
		int nid;
		int length;
		const unsigned char *data;	/* data remains const after init */
		int flags;	/* Should we free this one */
	} ASN1_OBJECT;
	
#ifndef EVP_MD
	struct env_md_st
	{
		int type;
		int pkey_type;
		int md_size;
		unsigned long flags;
		
		/* FIXME: prototype these some day */
		int required_pkey_type[5]; /*EVP_PKEY_xxx */
		int block_size;
		int ctx_size; /* how big does the ctx->md_data need to be */
		/* control function */
	} /* EVP_MD */;
	
	typedef struct env_md_st EVP_MD;
	
#define EVP_MD_FLAG_ONESHOT	0x0001 
#define EVP_PKEY_NULL_method	NULL,NULL,{0,0,0,0}
#endif /* !EVP_MD */
	
	static int krb5_loaded = 0;     /* only attempt to initialize func ptrs once */
	
#ifdef OPENSSL_FIPS
#ifndef OPENSSL_DRBG_DEFAULT_TYPE
#define OPENSSL_DRBG_DEFAULT_TYPE	NID_aes_256_ctr
#endif
#ifndef OPENSSL_DRBG_DEFAULT_FLAGS
#define OPENSSL_DRBG_DEFAULT_FLAGS	DRBG_FLAG_CTR_USE_DF
#endif 
#endif
	
	struct st_ERR_FNS
	{
		/* Works on the "error_hash" string table */
		/* Works on the "thread_hash" error-state table */
		/* Returns the next available error "library" numbers */
	};
	
	typedef struct st_ERR_FNS ERR_FNS;
	
#ifdef HAVE_CRYPTODEV
	struct dev_crypto_state {
		struct session_op d_sess;
		int d_fd;
		
#ifdef USE_CRYPTODEV_DIGESTS
		char dummy_mac_key[HASH_MAX_LEN];
		
		unsigned char digest_res[HASH_MAX_LEN];
		char *mac_data;
		int mac_len;
#endif
	};
#endif

	typedef struct ssl3_enc_method
	{
		int finish_mac_length;
		const char *client_finished_label;
		int client_finished_label_len;
		const char *server_finished_label;
		int server_finished_label_len;
	} SSL3_ENC_METHOD;
	
	
#ifndef OPENSSL_NO_SSL_INTERN
	struct ssl_cipher_st
	{
		int valid;
		const char *name;		/* text name */
		unsigned long id;		/* id, 4 bytes, first is version */
		
		/* changed in 0.9.9: these four used to be portions of a single value 'algorithms' */
		unsigned long algorithm_mkey;	/* key exchange algorithm */
		unsigned long algorithm_auth;	/* server authentication */
		unsigned long algorithm_enc;	/* symmetric encryption */
		unsigned long algorithm_mac;	/* symmetric authentication */
		unsigned long algorithm_ssl;	/* (major) protocol version */
		
		unsigned long algo_strength;	/* strength and export flags */
		unsigned long algorithm2;	/* Extra flags */
		int strength_bits;		/* Number of bits really used */
		int alg_bits;			/* Number of bits for algorithm */
	};
	struct ssl_method_st
	{
		int version;
		struct ssl3_enc_method *ssl3_enc; /* Extra SSLv3/TLS stuff */
	};
	
	typedef struct ssl_cipher_st SSL_CIPHER;
	typedef struct ssl_method_st SSL_METHOD;
#endif

#ifdef NO_ASN1_TYPEDEFS
#define ASN1_NULL		int
#else
	typedef int ASN1_NULL;
#endif
	
#ifndef OPENSSL_NO_KRB5
#define	KSSL_ERR_MAX	255
#endif	/* OPENSSL_NO_KRB5	*/
	
	typedef struct ASN1_ENCODING_st
	{
		unsigned char *enc;	/* DER encoding */
		long len;		/* Length of encoding */
		int modified;		 /* set to 1 if 'enc' is invalid */
	} ASN1_ENCODING;
	
#if defined(USE_MD5_RAND)
#define MD_DIGEST_LENGTH	MD5_DIGEST_LENGTH
#elif defined(USE_SHA1_RAND)
#define MD_DIGEST_LENGTH	SHA_DIGEST_LENGTH
#elif defined(USE_MDC2_RAND)
#define MD_DIGEST_LENGTH	MDC2_DIGEST_LENGTH
#elif defined(USE_MD2_RAND)
#define MD_DIGEST_LENGTH	MD2_DIGEST_LENGTH
#endif

	struct buf_mem_st
	{
		size_t length;	/* current number of bytes */
		char *data;
		size_t max;	/* size of buffer */
	};
	
	typedef struct buf_mem_st BUF_MEM;
	
	struct x509_crl_method_st
	{
		int flags;
	};
	
	typedef struct x509_crl_method_st X509_CRL_METHOD;
	
#ifdef OPENSSL_NO_CAST
#else
/*#if 0
	char *text="Hello to all people out there";
#endif*/
#endif
	
	typedef struct X
	{
		STACK_OF(X509_EXTENSION) *ext;
	} X;

	
	static const char *engine_sureware_id = "sureware";
	static const char *engine_sureware_name = "SureWare hardware engine support";

	typedef struct {
		/* Temporary store for IPV6 output */
		unsigned char tmp[16];
		/* Total number of bytes in tmp */
		int total;
		/* The position of a zero (corresponding to '::') */
		int zero_pos;
		/* Number of zeroes */
		int zero_cnt;
	} IPV6_STAT;
	
	
/*#ifdef STRICT_ALIGNMENT
#  if defined(ROTATE)
#    define N	1
#  else
#    define N	8
#  endif
#else
#  define N	2
#endif*/
	
	
	static char *cipher=NULL;
	
	
#ifdef OPENSSL_SYS_NETWARE
#if !defined __int64
#  define __int64 long long
#endif   
#endif
	
#ifdef OPENSSL_NO_RC4
#else
	static unsigned char data[7][30]={
		{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xff},
		{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff},
		{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff},
		{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0xff},
		{0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,
			0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,
			0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,
			0x12,0x34,0x56,0x78,0xff},
		{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff},
		{0},
	};
#endif
	
#ifdef OPENSSL_FIPS
	static int fips_drbg_type = OPENSSL_DRBG_DEFAULT_TYPE;
	static int fips_drbg_flags = OPENSSL_DRBG_DEFAULT_FLAGS;
#endif

#ifdef OPENSSL_NO_OBJECT
	static const unsigned int sn_objs[1];
	static const unsigned int ln_objs[1];
	static const unsigned int obj_objs[1];
#endif

#ifndef OPENSSL_NO_MD4
	static char *ret[]={
		"31d6cfe0d16ae931b73c59d7e0c089c0",
		"bde52cb31de33e46245e05fbdbd6fb24",
		"a448017aaf21d8525fc10ae87aa6729d",
		"d9130a8164549fe818874806e1c7014b",
		"d79e1c308aa5bbcdeea8ed63df412da9",
		"043f8582f241db351ce627e153e7f0e4",
		"e33b4ddc9c38f2199c3e7b164fcc0536",
	};
#endif

	static const int dummy_nid = 1;
	
	static unsigned int table_flags = 0;
	
#ifdef _OSD_POSIX
#ifndef CHARSET_EBCDIC
#define CHARSET_EBCDIC 1
#endif
#endif
	
#ifdef OPENSSL_NO_CAST
#else
	static unsigned char in[8]={ 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
	static unsigned char out[80];
#endif
	
#ifdef BN_CTX_DEBUG
	static const char *ctxdbg_cur = NULL;
#endif

#ifdef HAVE_LONG_LONG
# if defined(_WIN32) && !defined(__GNUC__)
# define LLONG __int64
# else
# define LLONG long long
# endif
#endif /* FIXME */
	
#define ASN1_FLAG_EXP_MAX	20
	
	typedef struct
	{
		int exp_tag;
		int exp_class;
		int exp_constructed;
		int exp_pad;
		long exp_len;
	} tag_exp_type;
	
	typedef struct
	{
		int imp_tag;
		int imp_class;
		int utype;
		int format;
		const char *str;
		tag_exp_type exp_list[ASN1_FLAG_EXP_MAX];
		int exp_count;
	} tag_exp_arg;
	
	
	
	static unsigned long global_mask = 0xFFFFFFFFL;
	
	
#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
	typedef unsigned __int64 u64;
#elif defined(__arch64__)
	typedef unsigned long u64;
#else
	typedef unsigned long long u64;
#endif
	
	
	static unsigned long break_order_num=0;
	
	typedef struct crypto_threadid_st
	{
		void *ptr;
		unsigned long val;
	} CRYPTO_THREADID;
	
	static int mh_mode=CRYPTO_MEM_CHECK_OFF;
	
	
	unsigned char cleanse_ctr = 0;
	
	
#if defined(_WIN32) && !defined(__CYGWIN__)
#ifdef _MSC_VER
#define alloca _alloca
#endif
#endif
	
	
	static const unsigned char hash_coeffs[] = { 3, 5, 7, 11, 13, 17, 19, 23 };
	
	
	
	static const char* const lock_names[CRYPTO_NUM_LOCKS] =
	{
		"<<ERROR>>",
		"err",
		"ex_data",
		"x509",
		"x509_info",
		"x509_pkey",
		"x509_crl",
		"x509_req",
		"dsa",
		"rsa",
		"evp_pkey",
		"x509_store",
		"ssl_ctx",
		"ssl_cert",
		"ssl_session",
		"ssl_sess_cert",
		"ssl",
		"ssl_method",
		"rand",
		"rand2",
		"debug_malloc",
		"BIO",
		"gethostbyname",
		"getservbyname",
		"readdir",
		"RSA_blinding",
		"dh",
		"debug_malloc2",
		"dso",
		"dynlock",
		"engine",
		"ui",
		"ecdsa",
		"ec",
		"ecdh",
		"bn",
		"ec_pre_comp",
		"store",
		"comp",
		"fips",
		"fips2",
#if CRYPTO_NUM_LOCKS != 41
# error "Inconsistency between crypto.h and cryptlib.c"
#endif
	};
	
	
	static unsigned long a[4]={0x01234567,0x89ABCDEF,0xFEDCBA98,0x76543210};
	
	TYPE b;
	
	static int allow_customize = 1;      /* we provide flexible functions for */
	
	static int allow_customize_debug = 1;
	
	static unsigned long order = 0; /* number of memory requests */
	
	typedef struct bignum_ctx_stack
	{
		/* Array of indexes into the bignum stack */
		unsigned int *indexes;
		/* Number of stack frames, and the size of the allocated array */
		unsigned int depth, size;
	} BN_STACK;
	
	char key[KEYSIZB+1];
	
	struct sockaddr_in addr;
	
	struct sockaddr_in addr;
	
	
	struct dh_method
	{
		const char *name;
		/* Methods here */
		
		int flags;
		char *app_data;
		/* If this is non-NULL, it will be used to generate parameters */
	};
	
	typedef struct dh_method DH_METHOD;
	
	struct dsa_method
	{
		const char *name;
		int flags;
		char *app_data;
		/* If this is non-NULL, it is used to generate DSA parameters */
		/* If this is non-NULL, it is used to generate DSA keys */
	};
	
	typedef struct dsa_method DSA_METHOD;
	
	struct ecdsa_method 
	{
		const char *name;
		int flags;
		char *app_data;
	};
	
	typedef struct ecdsa_method ECDSA_METHOD;
	
	/* Store functions take a type code for the type of data they should store
	 or fetch */
	typedef enum STORE_object_types
	{
		STORE_OBJECT_TYPE_X509_CERTIFICATE=	0x01, /* X509 * */
		STORE_OBJECT_TYPE_X509_CRL=		0x02, /* X509_CRL * */
		STORE_OBJECT_TYPE_PRIVATE_KEY=		0x03, /* EVP_PKEY * */
		STORE_OBJECT_TYPE_PUBLIC_KEY=		0x04, /* EVP_PKEY * */
		STORE_OBJECT_TYPE_NUMBER=		0x05, /* BIGNUM * */
		STORE_OBJECT_TYPE_ARBITRARY=		0x06, /* BUF_MEM * */
		STORE_OBJECT_TYPE_NUM=			0x06  /* The amount of known
											   object types */
	} STORE_OBJECT_TYPES;
	
	typedef struct openssl_item_st
	{
		int code;
		void *value;		/* Not used for flag attributes */
		size_t value_size;	/* Max size of value for output, length for input */
		size_t *value_length;	/* Returned length of value for output */
	} OPENSSL_ITEM;
	
	typedef enum STORE_certificate_status
	{
		STORE_X509_VALID=			0x00,
		STORE_X509_EXPIRED=			0x01,
		STORE_X509_SUSPENDED=			0x02,
		STORE_X509_REVOKED=			0x03
	} STORE_CERTIFICATE_STATUS;
	
	struct rsa_meth_st
	{
		const char *name;
		int flags;			/* RSA_METHOD_FLAG_* things */
		char *app_data;			/* may be needed! */
		/* New sign and verify functions: some libraries don't allow arbitrary data
		 * to be signed/verified: this allows them to be used. Note: for this to work
		 * the RSA_public_decrypt() and RSA_private_encrypt() should *NOT* be used
		 * RSA_sign(), RSA_verify() should be used instead. Note: for backwards
		 * compatibility this functionality is only enabled if the RSA_FLAG_SIGN_VER
		 * option is set in 'flags'.
		 */
		/* If this callback is NULL, the builtin software RSA key-gen will be used. This
		 * is for behavioural compatibility whilst the code gets rewired, but one day
		 * it would be nice to assume there are no such things as "builtin software"
		 * implementations. */
	};
	
	typedef struct rsa_meth_st RSA_METHOD;
	
#ifdef NO_ASN1_TYPEDEFS
#define ASN1_ENUMERATED		ASN1_STRING
#define ASN1_BIT_STRING		ASN1_STRING
#define ASN1_PRINTABLESTRING	ASN1_STRING
#define ASN1_T61STRING		ASN1_STRING
#define ASN1_GENERALSTRING	ASN1_STRING
#define ASN1_UNIVERSALSTRING	ASN1_STRING
#define ASN1_BMPSTRING		ASN1_STRING
#define ASN1_VISIBLESTRING	ASN1_STRING
#define ASN1_UTF8STRING		ASN1_STRING
#define ASN1_BOOLEAN		int
#endif

	typedef enum {
		/** the point is encoded as z||x, where the octet z specifies 
		 *  which solution of the quadratic equation y is  */
		POINT_CONVERSION_COMPRESSED = 2,
		/** the point is encoded as z||x||y, where z is the octet 0x02  */
		POINT_CONVERSION_UNCOMPRESSED = 4,
		/** the point is encoded as z||x||y, where the octet z specifies
		 *  which solution of the quadratic equation y is  */
		POINT_CONVERSION_HYBRID = 6
	} point_conversion_form_t;
	
	typedef struct stack_st
	{
		int num;
		char **data;
		int sorted;
		
		int num_alloc;
	} _STACK;  /* Use STACK_OF(...) instead */
	
	
	typedef char *OPENSSL_STRING;
	
	struct rand_meth_st
	{
	};
	
	struct evp_pkey_method_st
	{
		int pkey_id;
		int flags;
		
	} /* EVP_PKEY_METHOD */;
	
	typedef struct ENGINE_CMD_DEFN_st
	{
		unsigned int cmd_num; /* The command number */
		const char *cmd_name; /* The command name itself */
		const char *cmd_desc; /* A short description of the command */
		unsigned int cmd_flags; /* The input the command expects */
	} ENGINE_CMD_DEFN;
	
	struct ecdh_method 
	{
		const char *name;
#if 0
#endif
		int flags;
		char *app_data;
	};

	struct ec_method_st {
		/* Various method flags */
		int flags;
		/* used by EC_METHOD_get_field_type: */
		int field_type; /* a NID */
		
	} /* EC_METHOD */;
	
	struct evp_pkey_asn1_method_st
	{
		int pkey_id;
		int pkey_base_id;
		unsigned long pkey_flags;
		
		char *pem_str;
		char *info;
		
		/* Legacy functions for old PEM */
		
		/* Custom ASN1 signature verification */
		
	} /* EVP_PKEY_ASN1_METHOD */;
	
	typedef struct ec_extra_data_st {
		struct ec_extra_data_st *next;
		void *data;
	} EC_EXTRA_DATA; /* used in EC_GROUP */
	
	typedef struct ecdh_method ECDH_METHOD;
	typedef struct rand_meth_st RAND_METHOD;
	typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
	typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
	typedef struct ec_method_st EC_METHOD;
	
#ifndef OPENSSL_DH_MAX_MODULUS_BITS
# define OPENSSL_DH_MAX_MODULUS_BITS	10000
#endif
	
	typedef struct
	{
		char *section;
		char *name;
		char *value;
	} CONF_VALUE;
	
	typedef struct asn1_string_table_st {
		int nid;
		long minsize;
		long maxsize;
		unsigned long mask;
		unsigned long flags;
	} ASN1_STRING_TABLE;
	
	struct asn1_string_st
	{
		int length;
		int type;
		unsigned char *data;
		/* The value of the following field depends on the type being
		 * held.  It is mostly being used for BIT_STRING so if the
		 * input data has a non-zero 'unused bits' value, it will be
		 * handled correctly */
		long flags;
	};
	
#ifdef NO_ASN1_TYPEDEFS
#define ASN1_ENUMERATED		ASN1_STRING
#define ASN1_BIT_STRING		ASN1_STRING
#define ASN1_PRINTABLESTRING	ASN1_STRING
#define ASN1_T61STRING		ASN1_STRING
#define ASN1_GENERALSTRING	ASN1_STRING
#define ASN1_UNIVERSALSTRING	ASN1_STRING
#define ASN1_BMPSTRING		ASN1_STRING
#define ASN1_VISIBLESTRING	ASN1_STRING
#define ASN1_UTF8STRING		ASN1_STRING
#define ASN1_BOOLEAN		int
#define ASN1_INTEGER		ASN1_STRING
#define ASN1_OCTET_STRING	ASN1_STRING
#define ASN1_IA5STRING		ASN1_STRING
#define ASN1_UTCTIME		ASN1_STRING
#define ASN1_GENERALIZEDTIME	ASN1_STRING
#define ASN1_TIME		ASN1_STRING
#else
	typedef struct asn1_string_st ASN1_INTEGER;
	typedef struct asn1_string_st ASN1_ENUMERATED;
	typedef struct asn1_string_st ASN1_BIT_STRING;
	typedef struct asn1_string_st ASN1_OCTET_STRING;
	typedef struct asn1_string_st ASN1_PRINTABLESTRING;
	typedef struct asn1_string_st ASN1_T61STRING;
	typedef struct asn1_string_st ASN1_IA5STRING;
	typedef struct asn1_string_st ASN1_GENERALSTRING;
	typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
	typedef struct asn1_string_st ASN1_BMPSTRING;
	typedef struct asn1_string_st ASN1_UTCTIME;
	typedef struct asn1_string_st ASN1_TIME;
	typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
	typedef struct asn1_string_st ASN1_VISIBLESTRING;
	typedef struct asn1_string_st ASN1_UTF8STRING;
	typedef struct asn1_string_st ASN1_STRING;
	typedef int ASN1_BOOLEAN;
	typedef int ASN1_NULL;
#endif

#ifdef OPENSSL_SYS_VMS
#define EC_POINT_set_affine_coordinates_GFp     EC_POINT_set_affine_coords_GFp
#define ec_GF2m_simple_group_clear_finish	ec_GF2m_simple_grp_clr_finish
#define ec_GF2m_simple_group_check_discriminant	ec_GF2m_simple_grp_chk_discrim
#define ec_GF2m_simple_point_clear_finish	ec_GF2m_simple_pt_clr_finish
#define ec_GF2m_simple_point_set_to_infinity	ec_GF2m_simple_pt_set_to_inf
#define ec_GF2m_simple_points_make_affine	ec_GF2m_simple_pts_make_affine
#define ec_GFp_simple_group_clear_finish	ec_GFp_simple_grp_clear_finish
#define ec_GFp_simple_point_clear_finish	ec_GFp_simple_pt_clear_finish
#define ec_GFp_simple_point_set_to_infinity     ec_GFp_simple_pt_set_to_inf
#define ec_GFp_simple_points_make_affine	ec_GFp_simple_pts_make_affine
#define ec_GFp_simple_group_check_discriminant	ec_GFp_simple_grp_chk_discrim
#endif /* defined OPENSSL_SYS_VMS */

	extern const unsigned char os_toebcdic[256];
	extern const unsigned char os_toascii[256];
	
#if (defined(WINDOWS) || defined(MSDOS))
#  ifdef WINDOWS
#    if !defined(_WIN32_WCE) && !defined(_WIN32_WINNT)
#      define _WIN32_WINNT 0x0400
#    endif
#  endif
#  endif

	typedef struct
	{
		int references;
		struct CRYPTO_dynlock_value *data;
	} CRYPTO_dynlock;
	
	typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
	
	typedef struct NOTICEREF_st {
		ASN1_STRING *organization;
		STACK_OF(ASN1_INTEGER) *noticenos;
	} NOTICEREF;
	
	typedef struct USERNOTICE_st {
		NOTICEREF *noticeref;
		ASN1_STRING *exptext;
	} USERNOTICE;
	
	typedef struct ASN1_VALUE_st ASN1_VALUE;
	
	typedef struct asn1_type_st
	{
		int type;
		union	{
			char *ptr;
			ASN1_BOOLEAN		boolean;
			ASN1_STRING *		asn1_string;
			ASN1_OBJECT *		object;
			ASN1_INTEGER *		integer;
			ASN1_ENUMERATED *	enumerated;
			ASN1_BIT_STRING *	bit_string;
			ASN1_OCTET_STRING *	octet_string;
			ASN1_PRINTABLESTRING *	printablestring;
			ASN1_T61STRING *	t61string;
			ASN1_IA5STRING *	ia5string;
			ASN1_GENERALSTRING *	generalstring;
			ASN1_BMPSTRING *	bmpstring;
			ASN1_UNIVERSALSTRING *	universalstring;
			ASN1_UTCTIME *		utctime;
			ASN1_GENERALIZEDTIME *	generalizedtime;
			ASN1_VISIBLESTRING *	visiblestring;
			ASN1_UTF8STRING *	utf8string;
			/* set and sequence are left complete and still
			 * contain the set or sequence bytes */
			ASN1_STRING *		set;
			ASN1_STRING *		sequence;
			ASN1_VALUE *		asn1_value;
		} value;
	} ASN1_TYPE;
	
	typedef struct POLICYQUALINFO_st {
		ASN1_OBJECT *pqualid;
		union {
			ASN1_IA5STRING *cpsuri;
			USERNOTICE *usernotice;
			ASN1_TYPE *other;
		} d;
	} POLICYQUALINFO;
	
	struct X509_POLICY_DATA_st
	{
		unsigned int flags;
		/* Policy OID and qualifiers for this data */
		ASN1_OBJECT *valid_policy;
		STACK_OF(POLICYQUALINFO) *qualifier_set;
		STACK_OF(ASN1_OBJECT) *expected_policy_set;
	};
	
	typedef struct X509_POLICY_DATA_st X509_POLICY_DATA;
	
	struct X509_name_st
	{
		STACK_OF(X509_NAME_ENTRY) *entries;
		int modified;	/* true if 'bytes' needs to be built */
#ifndef OPENSSL_NO_BUFFER
		BUF_MEM *bytes;
#else
		char *bytes;
#endif
		/*	unsigned long hash; Keep the hash around for lookups */
		unsigned char *canon_enc;
		int canon_enclen;
	} /* X509_NAME */;
	
	typedef struct X509_name_st X509_NAME;
	
	struct bignum_st
	{
		BN_ULONG *d;	/* Pointer to an array of 'BN_BITS2' bit chunks. */
		int top;	/* Index of last used d +1. */
		/* The next are internal book keeping for bn_expand. */
		int dmax;	/* Size of the d array. */
		int neg;	/* one if the number is negative */
		int flags;
	};
	
	typedef struct bignum_st BIGNUM;
	
	typedef struct bignum_pool_item
	{
		/* The bignum values */
		BIGNUM vals[BN_CTX_POOL_SIZE];
		/* Linked-list admin */
		struct bignum_pool_item *prev, *next;
	} BN_POOL_ITEM;
	
	typedef struct bignum_pool
	{
		/* Linked-list admin */
		BN_POOL_ITEM *head, *current, *tail;
		/* Stack depth and allocation size */
		unsigned used, size;
	} BN_POOL;
	
	struct bignum_ctx
	{
		/* The bignum bundles */
		BN_POOL pool;
		/* The "stack frames", if you will */
		BN_STACK stack;
		/* The number of bignums currently assigned */
		unsigned int used;
		/* Depth of stack overflow */
		int err_stack;
		/* Block "gets" until an "end" (compatibility behaviour) */
		int too_many;
	};
	
	typedef struct bignum_ctx BN_CTX;
	
	struct ec_point_st {
		const EC_METHOD *meth;
		
		/* All members except 'meth' are handled by the method functions,
		 * even if they appear generic */
		
		BIGNUM X;
		BIGNUM Y;
		BIGNUM Z; /* Jacobian projective coordinates:
				   * (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
		int Z_is_one; /* enable optimized point arithmetics for special case */
	} /* EC_POINT */;
	
	typedef struct ec_point_st EC_POINT;
	
	struct bn_mont_ctx_st
	{
		int ri;        /* number of bits in R */
		BIGNUM RR;     /* used to convert to montgomery form */
		BIGNUM N;      /* The modulus */
		BIGNUM Ni;     /* R*(1/R mod N) - N*Ni = 1
						* (Ni is only stored for bignum algorithm) */
		BN_ULONG n0[2];/* least significant word(s) of Ni;
						(type changed with 0.9.9, was "BN_ULONG n0;" before) */
		int flags;
	};
	
	typedef struct bn_mont_ctx_st BN_MONT_CTX;
	
	typedef struct X509_name_entry_st
	{
		ASN1_OBJECT *object;
		ASN1_STRING *value;
		int set;
		int size; 	/* temp variable */
	} X509_NAME_ENTRY;
	
	struct ec_group_st {
		const EC_METHOD *meth;
		
		EC_POINT *generator; /* optional */
		BIGNUM order, cofactor;
		
		int curve_name;/* optional NID for named curve */
		int asn1_flag; /* flag to control the asn1 encoding */
		point_conversion_form_t asn1_form;
		
		size_t seed_len;
		
		EC_EXTRA_DATA *extra_data; /* linked list */
		
		/* The following members are handled by the method functions,
		 * even if they appear generic */
		
		BIGNUM field; /* Field specification.
					   * For curves over GF(p), this is the modulus;
					   * for curves over GF(2^m), this is the 
					   * irreducible polynomial defining the field.
					   */
		
		int poly[6]; /* Field specification for curves over GF(2^m).
					  * The irreducible f(t) is then of the form:
					  *     t^poly[0] + t^poly[1] + ... + t^poly[k]
					  * where m = poly[0] > poly[1] > ... > poly[k] = 0.
					  * The array is terminated with poly[k+1]=-1.
					  * All elliptic curve irreducibles have at most 5
					  * non-zero terms.
					  */
		
		BIGNUM a, b; /* Curve coefficients.
					  * (Here the assumption is that BIGNUMs can be used
					  * or abused for all kinds of fields, not just GF(p).)
					  * For characteristic  > 3,  the curve is defined
					  * by a Weierstrass equation of the form
					  *     y^2 = x^3 + a*x + b.
					  * For characteristic  2,  the curve is defined by
					  * an equation of the form
					  *     y^2 + x*y = x^3 + a*x^2 + b.
					  */
		
		int a_is_minus3; /* enable optimized point arithmetics for special case */
		
		void *field_data1; /* method-specific (e.g., Montgomery structure) */
		void *field_data2; /* method-specific */
	} /* EC_GROUP */;
	
	typedef struct ec_group_st
	/*
	 EC_METHOD *meth;
	 -- field definition
	 -- curve coefficients
	 -- optional generator with associated information (order, cofactor)
	 -- optional extra data (precomputed table for fast computation of multiples of generator)
	 -- ASN1 stuff
	 */
	EC_GROUP;
	
	struct ec_key_st {
		int version;
		
		EC_GROUP *group;
		
		EC_POINT *pub_key;
		BIGNUM	 *priv_key;
		
		unsigned int enc_flag;
		point_conversion_form_t conv_form;
		
		int 	references;
		int	flags;
		
		EC_EXTRA_DATA *method_data;
	} /* EC_KEY */;
	
	typedef struct ec_key_st EC_KEY;
	
	typedef struct X509_extension_st
	{
		ASN1_OBJECT *object;
		ASN1_BOOLEAN critical;
		ASN1_OCTET_STRING *value;
	} X509_EXTENSION;
	
	typedef struct EDIPartyName_st {
		ASN1_STRING *nameAssigner;
		ASN1_STRING *partyName;
	} EDIPARTYNAME;
	
	typedef struct otherName_st {
		ASN1_OBJECT *type_id;
		ASN1_TYPE *value;
	} OTHERNAME;
	
	typedef struct X509V3_CONF_METHOD_st {
	} X509V3_CONF_METHOD;
	
	
	typedef struct app_mem_info_st
	/* For application-defined information (static C-string `info')
	 * to be displayed in memory leak list.
	 * Each thread has its own stack.  For applications, there is
	 *   CRYPTO_push_info("...")     to push an entry,
	 *   CRYPTO_pop_info()           to pop an entry,
	 *   CRYPTO_remove_all_info()    to pop all entries.
	 */
	{
		CRYPTO_THREADID threadid;
		const char *file;
		int line;
		const char *info;
		struct app_mem_info_st *next; /* tail of thread's stack */
		int references;
	} APP_INFO;
	
	typedef struct mem_st
	/* memory-block description */
	{
		void *addr;
		int num;
		const char *file;
		int line;
		CRYPTO_THREADID threadid;
		unsigned long order;
		time_t time;
		APP_INFO *app_info;
	} MEM;
	
	static CRYPTO_THREADID disabling_threadid;
		
	static unsigned int num_disable = 0; 
	
	static long options =             /* extra information to be recorded */
#if defined(CRYPTO_MDEBUG_TIME) || defined(CRYPTO_MDEBUG_ALL)
	V_CRYPTO_MDEBUG_TIME |
#endif
#if defined(CRYPTO_MDEBUG_THREAD) || defined(CRYPTO_MDEBUG_ALL)
	V_CRYPTO_MDEBUG_THREAD |
#endif
	0;
	
	typedef struct {
		int	field_type,	/* either NID_X9_62_prime_field or
						 * NID_X9_62_characteristic_two_field */
		seed_len,
		param_len;
		unsigned int cofactor;	/* promoted to BN_ULONG */
	} EC_CURVE_DATA;
	
	typedef struct _ec_list_element_st {
		int	nid;
		const EC_CURVE_DATA *data;
		const char *comment;
	} ec_list_element;
	
#ifndef OPENSSL_NO_EC2M
	static const struct { EC_CURVE_DATA h; unsigned char data[20+15*6]; }
	_EC_NIST_PRIME_192 = {
		{ NID_X9_62_prime_field,20,24,1 },
		{ 0x30,0x45,0xAE,0x6F,0xC8,0x42,0x2F,0x64,0xED,0x57,	/* seed */
			0x95,0x28,0xD3,0x81,0x20,0xEA,0xE1,0x21,0x96,0xD5,
			
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* a */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFC,
			0x64,0x21,0x05,0x19,0xE5,0x9C,0x80,0xE7,0x0F,0xA7,	/* b */
			0xE9,0xAB,0x72,0x24,0x30,0x49,0xFE,0xB8,0xDE,0xEC,
			0xC1,0x46,0xB9,0xB1,
			0x18,0x8D,0xA8,0x0E,0xB0,0x30,0x90,0xF6,0x7C,0xBF,	/* x */
			0x20,0xEB,0x43,0xA1,0x88,0x00,0xF4,0xFF,0x0A,0xFD,
			0x82,0xFF,0x10,0x12,
			0x07,0x19,0x2b,0x95,0xff,0xc8,0xda,0x78,0x63,0x10,	/* y */
			0x11,0xed,0x6b,0x24,0xcd,0xd5,0x73,0xf9,0x77,0xa1,
			0x1e,0x79,0x48,0x11,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0x99,0xDE,0xF8,0x36,0x14,0x6B,0xC9,0xB1,
			0xB4,0xD2,0x28,0x31 }
	};
	/* Fixme ec/ec_curve.c - copy */
#endif

	typedef struct ec_pre_comp_st {
		const EC_GROUP *group; /* parent EC_GROUP object */
		size_t blocksize;      /* block size for wNAF splitting */
		size_t numblocks;      /* max. number of blocks for which we have precomputation */
		size_t w;              /* window size */
		EC_POINT **points;     /* array with pre-calculated multiples of generator:
								* 'num' pointers to EC_POINT objects followed by a NULL */
		size_t num;            /* numblocks * 2^(w-1) */
		int references;
	} EC_PRE_COMP;
	
	static unsigned char state[STATE_SIZE+MD_DIGEST_LENGTH];
	
	typedef struct added_obj_st
	{
		int type;
		ASN1_OBJECT *obj;
	} ADDED_OBJ;
	
#ifdef OPENSSL_NO_OBJECT
	static const ASN1_OBJECT nid_objs[1];
#endif

	static const RAND_METHOD *default_RAND_meth = NULL;
	
	
#ifndef OPENSSL_NO_DSA
	/* FIXME */
	/*static DSA_METHOD surewarehk_dsa =
	{
		"SureWare DSA method", 
		surewarehk_dsa_do_sign,
		NULL,/*sign setup*
		NULL,/*verify,*
		surewarehk_dsa_mod_exp,/*mod exp*
		NULL,/*bn mod exp*
		NULL, /*init*
		NULL,/*finish*
		0,
		NULL,
		NULL,
		NULL
	};*/
#endif
	
	typedef struct err_state_st
	{
		CRYPTO_THREADID tid;
		int err_flags[ERR_NUM_ERRORS];
		unsigned long err_buffer[ERR_NUM_ERRORS];
		char *err_data[ERR_NUM_ERRORS];
		int err_data_flags[ERR_NUM_ERRORS];
		const char *err_file[ERR_NUM_ERRORS];
		int err_line[ERR_NUM_ERRORS];
		int top,bottom;
	} ERR_STATE;
	
	typedef struct GENERAL_NAME_st {
		
#define GEN_OTHERNAME	0
#define GEN_EMAIL	1
#define GEN_DNS		2
#define GEN_X400	3
#define GEN_DIRNAME	4
#define GEN_EDIPARTY	5
#define GEN_URI		6
#define GEN_IPADD	7
#define GEN_RID		8
		
		int type;
		union {
			char *ptr;
			OTHERNAME *otherName; /* otherName */
			ASN1_IA5STRING *rfc822Name;
			ASN1_IA5STRING *dNSName;
			ASN1_TYPE *x400Address;
			X509_NAME *directoryName;
			EDIPARTYNAME *ediPartyName;
			ASN1_IA5STRING *uniformResourceIdentifier;
			ASN1_OCTET_STRING *iPAddress;
			ASN1_OBJECT *registeredID;
			
			/* Old names */
			ASN1_OCTET_STRING *ip; /* iPAddress */
			X509_NAME *dirn;		/* dirn */
			ASN1_IA5STRING *ia5;/* rfc822Name, dNSName, uniformResourceIdentifier */
			ASN1_OBJECT *rid; /* registeredID */
			ASN1_TYPE *other; /* x400Address */
		} d;
	} GENERAL_NAME;
	
	typedef STACK_OF(GENERAL_NAME) GENERAL_NAMES;
	
	typedef struct DIST_POINT_NAME_st {
		int type;
		union {
			GENERAL_NAMES *fullname;
			STACK_OF(X509_NAME_ENTRY) *relativename;
		} name;
		/* If relativename then this contains the full distribution point name */
		X509_NAME *dpname;
	} DIST_POINT_NAME;
	
	struct AUTHORITY_KEYID_st {
		ASN1_OCTET_STRING *keyid;
		GENERAL_NAMES *issuer;
		ASN1_INTEGER *serial;
	};
	
	typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;
	
#ifndef OPENSSL_NO_RFC3779
	
	typedef struct ASRange_st {
		ASN1_INTEGER *min, *max;
	} ASRange;
	
#define	ASIdOrRange_id		0
#define	ASIdOrRange_range	1
	
	typedef struct ASIdOrRange_st {
		int type;
		union {
			ASN1_INTEGER *id;
			ASRange      *range;
		} u;
	} ASIdOrRange;
	
	typedef STACK_OF(ASIdOrRange) ASIdOrRanges;
	
#define	ASIdentifierChoice_inherit			0
#define	ASIdentifierChoice_asIdsOrRanges	1
	
	typedef struct ASIdentifierChoice_st {
		int type;
		union {
			ASN1_NULL    *inherit;
			ASIdOrRanges *asIdsOrRanges;
		} u;
	} ASIdentifierChoice;
	
#endif

	typedef struct X509_val_st
	{
		ASN1_TIME *notBefore;
		ASN1_TIME *notAfter;
	} X509_VAL;
		
	typedef struct GENERAL_SUBTREE_st {
		GENERAL_NAME *base;
		ASN1_INTEGER *minimum;
		ASN1_INTEGER *maximum;
	} GENERAL_SUBTREE;
		
	struct x509_revoked_st
	{
		ASN1_INTEGER *serialNumber;
		ASN1_TIME *revocationDate;
		STACK_OF(X509_EXTENSION) /* optional */ *extensions;
		/* Set up if indirect CRL */
		STACK_OF(GENERAL_NAME) *issuer;
		/* Revocation reason */
		int reason;
		int sequence; /* load sequence */
	};
	
	typedef struct x509_revoked_st X509_REVOKED;
	
	typedef struct { u64 hi,lo; } u128;
	
	struct ISSUING_DIST_POINT_st
	{
		DIST_POINT_NAME *distpoint;
		int onlyuser;
		int onlyCA;
		ASN1_BIT_STRING *onlysomereasons;
		int indirectCRL;
		int onlyattr;
	};
	
	struct DIST_POINT_st {
		DIST_POINT_NAME	*distpoint;
		ASN1_BIT_STRING *reasons;
		GENERAL_NAMES *CRLissuer;
		int dp_reasons;
	};
	
	typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;
	typedef struct DIST_POINT_st DIST_POINT;
	
	struct ASN1_TEMPLATE_st {
		unsigned long flags;		/* Various flags */
		long tag;			/* tag, not used if no tagging */
		unsigned long offset;		/* Offset of this field in structure */
#ifndef NO_ASN1_FIELD_NAMES
		const char *field_name;		/* Field name */
#endif
		struct ASN1_ITEM_EXP *item;		/* Relevant ASN1_ITEM or ASN1_ADB */
	};
	
	typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;
	
	struct ASN1_ITEM_st {
		char itype;			/* The item type, primitive, SEQUENCE, CHOICE or extern */
		long utype;			/* underlying type */
		const ASN1_TEMPLATE *templates;	/* If SEQUENCE or CHOICE this contains the contents */
		long tcount;			/* Number of templates if SEQUENCE or CHOICE */
		const void *funcs;		/* functions that handle this type */
#ifndef NO_ASN1_FIELD_NAMES
		const char *sname;		/* Structure name */
#endif
	};
	
	typedef struct ASN1_ITEM_st ASN1_ITEM;
	
#ifndef OPENSSL_EXPORT_VAR_AS_FUNCTION
	typedef const ASN1_ITEM ASN1_ITEM_EXP;
#else
	typedef const ASN1_ITEM * ASN1_ITEM_EXP(void);
#endif

	struct st_CRYPTO_EX_DATA_IMPL
	{
		/*********************/
		/* GLOBAL OPERATIONS */
		/* Return a new class index */
		/* Cleanup all state used by the implementation */
		/************************/
		/* PER-CLASS OPERATIONS */
		/* Get a new method index within a class */
		/* Initialise a new CRYPTO_EX_DATA of a given class */
		/* Duplicate a CRYPTO_EX_DATA of a given class onto a copy */
		/* Cleanup a CRYPTO_EX_DATA of a given class */
	};
	
	typedef struct st_CRYPTO_EX_DATA_IMPL	CRYPTO_EX_DATA_IMPL;
	
	static const CRYPTO_EX_DATA_IMPL *impl = NULL;
	
	typedef struct IPAddressRange_st {
		ASN1_BIT_STRING	*min, *max;
	} IPAddressRange;
	
#define	IPAddressOrRange_addressPrefix	0
#define	IPAddressOrRange_addressRange	1
	
	typedef struct IPAddressOrRange_st {
		int type;
		union {
			ASN1_BIT_STRING	*addressPrefix;
			IPAddressRange	*addressRange;
		} u;
	} IPAddressOrRange;
	
	typedef STACK_OF(IPAddressOrRange) IPAddressOrRanges;
	//DECLARE_STACK_OF(IPAddressOrRange)
	
#define	IPAddressChoice_inherit			0
#define	IPAddressChoice_addressesOrRanges	1
	
	typedef struct IPAddressChoice_st {
		int type;
		union {
			ASN1_NULL		*inherit;
			IPAddressOrRanges	*addressesOrRanges;
		} u;
	} IPAddressChoice;
	
	
	typedef struct x509_attributes_st
	{
		ASN1_OBJECT *object;
		union	{
			char		*ptr;
			/* 0 */		STACK_OF(ASN1_TYPE) *set;
			/* 1 */		ASN1_TYPE	*single;
		} value;
	} X509_ATTRIBUTE;
	
	struct X509_POLICY_CACHE_st {
		/* anyPolicy data or NULL if no anyPolicy */
		X509_POLICY_DATA *anyPolicy;
		/* other policy data */
		STACK_OF(X509_POLICY_DATA) *data;
		/* If InhibitAnyPolicy present this is its value or -1 if absent. */
		long any_skip;
		/* If policyConstraints and requireExplicitPolicy present this is its
		 * value or -1 if absent.
		 */
		long explicit_skip;
		/* If policyConstraints and policyMapping present this is its
		 * value or -1 if absent.
		 */
		long map_skip;
	};
	
	typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;
	
	struct X509_algor_st
	{
		ASN1_OBJECT *algorithm;
		ASN1_TYPE *parameter;
	} /* X509_ALGOR */;
	
	typedef struct X509_algor_st X509_ALGOR;
	
	typedef struct X509_crl_info_st
	{
		ASN1_INTEGER *version;
		X509_ALGOR *sig_alg;
		X509_NAME *issuer;
		ASN1_TIME *lastUpdate;
		ASN1_TIME *nextUpdate;
		STACK_OF(X509_REVOKED) *revoked;
		STACK_OF(X509_EXTENSION) /* [0] */ *extensions;
		ASN1_ENCODING enc;
	} X509_CRL_INFO;
	
	typedef struct x509_cert_aux_st
	{
		STACK_OF(ASN1_OBJECT) *trust;		/* trusted uses */
		STACK_OF(ASN1_OBJECT) *reject;		/* rejected uses */
		ASN1_UTF8STRING *alias;			/* "friendly name" */
		ASN1_OCTET_STRING *keyid;		/* key id of private key */
		STACK_OF(X509_ALGOR) *other;		/* other unspecified info */
	} X509_CERT_AUX;
	
	struct X509_crl_st
	{
		/* actual signature */
		X509_CRL_INFO *crl;
		X509_ALGOR *sig_alg;
		ASN1_BIT_STRING *signature;
		int references;
		int flags;
		/* Copies of various extensions */
		AUTHORITY_KEYID *akid;
		ISSUING_DIST_POINT *idp;
		/* Convenient breakdown of IDP */
		int idp_flags;
		int idp_reasons;
		/* CRL and base CRL numbers for delta processing */
		ASN1_INTEGER *crl_number;
		ASN1_INTEGER *base_crl_number;
#ifndef OPENSSL_NO_SHA
		unsigned char sha1_hash[SHA_DIGEST_LENGTH];
#endif
		STACK_OF(GENERAL_NAMES) *issuers;
		const X509_CRL_METHOD *meth;
		void *meth_data;
	} /* X509_CRL */;
	
	struct NAME_CONSTRAINTS_st {
		STACK_OF(GENERAL_SUBTREE) *permittedSubtrees;
		STACK_OF(GENERAL_SUBTREE) *excludedSubtrees;
	};
	
	typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;
	typedef struct X509_crl_st X509_CRL;
	
	struct evp_cipher_st
	{
		int nid;
		int block_size;
		int key_len;		/* Default value for variable length ciphers */
		int iv_len;
		unsigned long flags;	/* Various flags */
		int ctx_size;		/* how big ctx->cipher_data needs to be */
		void *app_data;		/* Application data */
	} /* EVP_CIPHER */;
	
	typedef struct evp_cipher_st EVP_CIPHER;
	
#if !defined(OPENSSL_NO_DES) && !defined(OPENSSL_NO_SHA1)
	const EVP_CIPHER *enc;
#endif

	typedef struct store_st STORE;
	typedef struct STORE_OBJECT_st STORE_OBJECT;
	typedef struct store_method_st STORE_METHOD;
	typedef struct engine_st ENGINE;
	typedef struct evp_pkey_st EVP_PKEY;
	typedef struct x509_st X509;
	typedef struct x509_cinf_st X509_CINF;
	typedef struct X509_pubkey_st X509_PUBKEY;
	typedef struct ui_method_st UI_METHOD;
	typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
	typedef struct bio_st BIO;
	typedef struct ASIdentifiers_st ASIdentifiers;

	typedef int (*STORE_INITIALISE_FUNC_PTR)(STORE *);
	typedef void (*STORE_CLEANUP_FUNC_PTR)(STORE *);
	typedef STORE_OBJECT *(*STORE_GENERATE_OBJECT_FUNC_PTR)(STORE *, STORE_OBJECT_TYPES type, OPENSSL_ITEM attributes[], OPENSSL_ITEM parameters[]);
	typedef STORE_OBJECT *(*STORE_GET_OBJECT_FUNC_PTR)(STORE *, STORE_OBJECT_TYPES type, OPENSSL_ITEM attributes[], OPENSSL_ITEM parameters[]);
	typedef void *(*STORE_START_OBJECT_FUNC_PTR)(STORE *, STORE_OBJECT_TYPES type, OPENSSL_ITEM attributes[], OPENSSL_ITEM parameters[]);
	typedef STORE_OBJECT *(*STORE_NEXT_OBJECT_FUNC_PTR)(STORE *, void *handle);
	typedef int (*STORE_END_OBJECT_FUNC_PTR)(STORE *, void *handle);
	typedef int (*STORE_HANDLE_OBJECT_FUNC_PTR)(STORE *, STORE_OBJECT_TYPES type, OPENSSL_ITEM attributes[], OPENSSL_ITEM parameters[]);
	typedef int (*STORE_STORE_OBJECT_FUNC_PTR)(STORE *, STORE_OBJECT_TYPES type, STORE_OBJECT *data, OPENSSL_ITEM attributes[], OPENSSL_ITEM parameters[]);
	typedef int (*STORE_MODIFY_OBJECT_FUNC_PTR)(STORE *, STORE_OBJECT_TYPES type, OPENSSL_ITEM search_attributes[], OPENSSL_ITEM add_attributes[], OPENSSL_ITEM modify_attributes[], OPENSSL_ITEM delete_attributes[], OPENSSL_ITEM parameters[]);
	typedef int (*STORE_GENERIC_FUNC_PTR)(STORE *, OPENSSL_ITEM attributes[], OPENSSL_ITEM parameters[]);
	typedef int (*STORE_CTRL_FUNC_PTR)(STORE *, int cmd, long l, void *p, void (*f)(void));
	
	typedef int (*ENGINE_CIPHERS_PTR)(ENGINE *, const EVP_CIPHER **, const int **, int);
	typedef int (*ENGINE_DIGESTS_PTR)(ENGINE *, const EVP_MD **, const int **, int);
	typedef int (*ENGINE_PKEY_METHS_PTR)(ENGINE *, EVP_PKEY_METHOD **, const int **, int);
	typedef int (*ENGINE_PKEY_ASN1_METHS_PTR)(ENGINE *, EVP_PKEY_ASN1_METHOD **, const int **, int);
	typedef int (*ENGINE_GEN_INT_FUNC_PTR)(ENGINE *);
	typedef int (*ENGINE_CTRL_FUNC_PTR)(ENGINE *, int, long, void *, void (*f)(void));
	/* Generic load_key function pointer */
	typedef EVP_PKEY * (*ENGINE_LOAD_KEY_PTR)(ENGINE *, const char *,
											  UI_METHOD *ui_method, void *callback_data);
/*	typedef int (*ENGINE_SSL_CLIENT_CERT_PTR)(ENGINE *, SSL *ssl,
											  STACK_OF(X509_NAME) *ca_dn, X509 **pcert, EVP_PKEY **pkey,
											  STACK_OF(X509) **pother, UI_METHOD *ui_method, void *callback_data);
	
	FixMe */
	typedef int EVP_PKEY_gen_cb(EVP_PKEY_CTX *ctx);
	typedef void * (*X509V3_EXT_NEW)(void);
	typedef void (*X509V3_EXT_FREE)(void *);
	typedef void * (*X509V3_EXT_D2I)(void *, const unsigned char ** , long);
	typedef int (*X509V3_EXT_I2D)(void *, unsigned char **);
	typedef STACK_OF(CONF_VALUE) *
	(*X509V3_EXT_I2V)(const struct v3_ext_method *method, void *ext,
					  STACK_OF(CONF_VALUE) *extlist);
	typedef void * (*X509V3_EXT_V2I)(const struct v3_ext_method *method,
									 struct v3_ext_ctx *ctx,
									 STACK_OF(CONF_VALUE) *values);
	typedef char * (*X509V3_EXT_I2S)(const struct v3_ext_method *method, void *ext);
	typedef void * (*X509V3_EXT_S2I)(const struct v3_ext_method *method,
									 struct v3_ext_ctx *ctx, const char *str);
	typedef int (*X509V3_EXT_I2R)(const struct v3_ext_method *method, void *ext,
								  BIO *out, int indent);
	typedef void * (*X509V3_EXT_R2I)(const struct v3_ext_method *method,
									 struct v3_ext_ctx *ctx, const char *str);
	typedef void bio_info_cb(struct bio_st *, int, const char *, int, long, long);
	
	struct store_method_st
	{
		char *name;
		
		/* All the functions return a positive integer or non-NULL for success
		 and 0, a negative integer or NULL for failure */
		
		/* Initialise the STORE with private data */
		STORE_INITIALISE_FUNC_PTR init;
		/* Initialise the STORE with private data */
		STORE_CLEANUP_FUNC_PTR clean;
		/* Generate an object of a given type */
		STORE_GENERATE_OBJECT_FUNC_PTR generate_object;
		/* Get an object of a given type.  This function isn't really very
		 useful since the listing functions (below) can be used for the
		 same purpose and are much more general. */
		STORE_GET_OBJECT_FUNC_PTR get_object;
		/* Store an object of a given type. */
		STORE_STORE_OBJECT_FUNC_PTR store_object;
		/* Modify the attributes bound to an object of a given type. */
		STORE_MODIFY_OBJECT_FUNC_PTR modify_object;
		/* Revoke an object of a given type. */
		STORE_HANDLE_OBJECT_FUNC_PTR revoke_object;
		/* Delete an object of a given type. */
		STORE_HANDLE_OBJECT_FUNC_PTR delete_object;
		/* List a bunch of objects of a given type and with the associated
		 attributes. */
		STORE_START_OBJECT_FUNC_PTR list_object_start;
		STORE_NEXT_OBJECT_FUNC_PTR list_object_next;
		STORE_END_OBJECT_FUNC_PTR list_object_end;
		STORE_END_OBJECT_FUNC_PTR list_object_endp;
		/* Store-level function to make any necessary update operations. */
		STORE_GENERIC_FUNC_PTR update_store;
		/* Store-level function to get exclusive access to the store. */
		STORE_GENERIC_FUNC_PTR lock_store;
		/* Store-level function to release exclusive access to the store. */
		STORE_GENERIC_FUNC_PTR unlock_store;
		
		/* Generic control function */
		STORE_CTRL_FUNC_PTR ctrl;
	};
	
	struct engine_st
	{
		const char *id;
		const char *name;
		const RSA_METHOD *rsa_meth;
		const DSA_METHOD *dsa_meth;
		const DH_METHOD *dh_meth;
		const ECDH_METHOD *ecdh_meth;
		const ECDSA_METHOD *ecdsa_meth;
		const RAND_METHOD *rand_meth;
		const STORE_METHOD *store_meth;
		/* Cipher handling is via this callback */
		ENGINE_CIPHERS_PTR ciphers;
		/* Digest handling is via this callback */
		ENGINE_DIGESTS_PTR digests;
		/* Public key handling via this callback */
		ENGINE_PKEY_METHS_PTR pkey_meths;
		/* ASN1 public key handling via this callback */
		ENGINE_PKEY_ASN1_METHS_PTR pkey_asn1_meths;
		
		ENGINE_GEN_INT_FUNC_PTR	destroy;
		
		ENGINE_GEN_INT_FUNC_PTR init;
		ENGINE_GEN_INT_FUNC_PTR finish;
		ENGINE_CTRL_FUNC_PTR ctrl;
		ENGINE_LOAD_KEY_PTR load_privkey;
		ENGINE_LOAD_KEY_PTR load_pubkey;
		
		//ENGINE_SSL_CLIENT_CERT_PTR load_ssl_client_cert;
		
		const ENGINE_CMD_DEFN *cmd_defns;
		int flags;
		/* reference count on the structure itself */
		int struct_ref;
		/* reference count on usability of the engine type. NB: This
		 * controls the loading and initialisation of any functionlity
		 * required by this engine, whereas the previous count is
		 * simply to cope with (de)allocation of this structure. Hence,
		 * running_ref <= struct_ref at all times. */
		int funct_ref;
		/* A place to store per-ENGINE data */
		CRYPTO_EX_DATA ex_data;
		/* Used to maintain the linked-list of engines. */
		struct engine_st *prev;
		struct engine_st *next;
	};
	
	struct evp_pkey_st
	{
		int type;
		int save_type;
		int references;
		const EVP_PKEY_ASN1_METHOD *ameth;
		ENGINE *engine;
		union	{
			char *ptr;
#ifndef OPENSSL_NO_RSA
			struct rsa_st *rsa;	/* RSA */
#endif
#ifndef OPENSSL_NO_DSA
			struct dsa_st *dsa;	/* DSA */
#endif
#ifndef OPENSSL_NO_DH
			struct dh_st *dh;	/* DH */
#endif
#ifndef OPENSSL_NO_EC
			struct ec_key_st *ec;	/* ECC */
#endif
		} pkey;
		int save_parameters;
		STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
	} /* EVP_PKEY */;
	
	typedef struct STORE_OBJECT_st
	{
		STORE_OBJECT_TYPES type;
		union
		{
			struct
			{
				STORE_CERTIFICATE_STATUS status;
				X509 *certificate;
			} x509;
			struct X509_CRL *crl;
			EVP_PKEY *key;
			BIGNUM *number;
			struct BUF_MEM *arbitrary;
		} data;
	} STORE_OBJECT;
	
	struct store_st
	{
		const struct STORE_METHOD *meth;
		/* functional reference if 'meth' is ENGINE-provided */
		struct ENGINE *engine;
		
		CRYPTO_EX_DATA ex_data;
		int references;
	};
	
	struct x509_st
	{
		X509_CINF *cert_info;
		X509_ALGOR *sig_alg;
		ASN1_BIT_STRING *signature;
		int valid;
		int references;
		char *name;
		CRYPTO_EX_DATA ex_data;
		/* These contain copies of various extension values */
		long ex_pathlen;
		long ex_pcpathlen;
		unsigned long ex_flags;
		unsigned long ex_kusage;
		unsigned long ex_xkusage;
		unsigned long ex_nscert;
		ASN1_OCTET_STRING *skid;
		AUTHORITY_KEYID *akid;
		X509_POLICY_CACHE *policy_cache;
		STACK_OF(DIST_POINT) *crldp;
		STACK_OF(GENERAL_NAME) *altname;
		NAME_CONSTRAINTS *nc;
#ifndef OPENSSL_NO_RFC3779
		STACK_OF(IPAddressFamily) *rfc3779_addr;
		ASIdentifiers *rfc3779_asid;
#endif
#ifndef OPENSSL_NO_SHA
		unsigned char sha1_hash[SHA_DIGEST_LENGTH];
#endif
		X509_CERT_AUX *aux;
	} /* X509 */;
	
	typedef struct x509_cinf_st
	{
		ASN1_INTEGER *version;		/* [ 0 ] default of v1 */
		ASN1_INTEGER *serialNumber;
		X509_ALGOR *signature;
		X509_NAME *issuer;
		X509_VAL *validity;
		X509_NAME *subject;
		X509_PUBKEY *key;
		ASN1_BIT_STRING *issuerUID;		/* [ 1 ] optional in v2 */
		ASN1_BIT_STRING *subjectUID;		/* [ 2 ] optional in v2 */
		STACK_OF(X509_EXTENSION) *extensions;	/* [ 3 ] optional in v3 */
		ASN1_ENCODING enc;
	};
	
	struct X509_pubkey_st
	{
		X509_ALGOR *algor;
		ASN1_BIT_STRING *public_key;
		EVP_PKEY *pkey;
	};
	
	struct ui_method_st
	{
		char *name;
		
		/* All the functions return 1 or non-NULL for success and 0 or NULL
		 for failure */
		
		/* Open whatever channel for this, be it the console, an X window
		 or whatever.
		 This function should use the ex_data structure to save
		 intermediate data. */
		
		
		/* Flush the output.  If a GUI dialog box is used, this function can
		 be used to actually display it. */
		
		
		
		/* Construct a prompt in a user-defined manner.  object_desc is a
		 textual short description of the object, for example "pass phrase",
		 and object_name is the name of the object (might be a card name or
		 a file name.
		 The returned string shall always be allocated on the heap with*/
	};
	
#ifndef OPENSSL_NO_SSL_INTERN
	struct ssl_session_st
	{
		int ssl_version;	/* what ssl version session info is
							 * being kept in here? */
		
		/* only really used in SSLv2 */
		unsigned int key_arg_length;
		unsigned char key_arg[SSL_MAX_KEY_ARG_LENGTH];
		int master_key_length;
		unsigned char master_key[SSL_MAX_MASTER_KEY_LENGTH];
		/* session_id - valid? */
		unsigned int session_id_length;
		unsigned char session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
		/* this is used to determine whether the session is being reused in
		 * the appropriate context. It is up to the application to set this,
		 * via SSL_new */
		unsigned int sid_ctx_length;
		unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
		
#ifndef OPENSSL_NO_KRB5
		unsigned int krb5_client_princ_len;
		unsigned char krb5_client_princ[SSL_MAX_KRB5_PRINCIPAL_LENGTH];
#endif /* OPENSSL_NO_KRB5 */
#ifndef OPENSSL_NO_PSK
		char *psk_identity_hint;
		char *psk_identity;
#endif
		/* Used to indicate that session resumption is not allowed.
		 * Applications can also set this bit for a new session via
		 * not_resumable_session_cb to disable session caching and tickets. */
		int not_resumable;
		
		/* The cert is the certificate used to establish this connection */
		struct sess_cert_st /* SESS_CERT */ *sess_cert;
		
		/* This is the cert for the other end.
		 * On clients, it will be the same as sess_cert->peer_key->x509
		 * (the latter is not enough as sess_cert is not retained
		 * in the external representation of sessions, see ssl_asn1.c). */
		X509 *peer;
		/* when app_verify_callback accepts a session where the peer's certificate
		 * is not ok, we must remember the error for session reuse: */
		long verify_result; /* only for servers */
		
		int references;
		long timeout;
		long time;
		
		unsigned int compress_meth;	/* Need to lookup the method */
		
		const SSL_CIPHER *cipher;
		unsigned long cipher_id;	/* when ASN.1 loaded, this
									 * needs to be used to load
									 * the 'cipher' structure */
		
		STACK_OF(SSL_CIPHER) *ciphers; /* shared ciphers? */
		
		CRYPTO_EX_DATA ex_data; /* application specific data */
		
		/* These are used to make removal of session-ids more
		 * efficient and to implement a maximum cache size. */
		struct ssl_session_st *prev,*next;
#ifndef OPENSSL_NO_TLSEXT
		char *tlsext_hostname;
#ifndef OPENSSL_NO_EC
		size_t tlsext_ecpointformatlist_length;
		unsigned char *tlsext_ecpointformatlist; /* peer's list */
		size_t tlsext_ellipticcurvelist_length;
		unsigned char *tlsext_ellipticcurvelist; /* peer's list */
#endif /* OPENSSL_NO_EC */
		/* RFC4507 info */
		unsigned char *tlsext_tick;	/* Session ticket */
		size_t tlsext_ticklen;		/* Session ticket length */
		long tlsext_tick_lifetime_hint;	/* Session lifetime hint in seconds */
#endif
#ifndef OPENSSL_NO_SRP
		char *srp_username;
#endif
	};
#endif
	
	typedef struct ssl_session_st SSL_SESSION;
	
	typedef struct X509_req_info_st
	{
		ASN1_ENCODING enc;
		ASN1_INTEGER *version;
		X509_NAME *subject;
		X509_PUBKEY *pubkey;
		/*  d=2 hl=2 l=  0 cons: cont: 00 */
		STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
	} X509_REQ_INFO;
	
#ifndef OPENSSL_NO_ENGINE
	static ENGINE *funct_ref =NULL;
#endif

	typedef struct st_engine_pile
	{
		/* The 'nid' of this algorithm/mode */
		int nid;
		/* ENGINEs that implement this algorithm/mode. */
		STACK_OF(ENGINE) *sk;
		/* The default ENGINE to perform this algorithm/mode. */
		ENGINE *funct;
		/* Zero if 'sk' is newer than the cached 'funct', non-zero otherwise */
		int uptodate;
	} ENGINE_PILE;
	
	typedef struct X509_req_st
	{
		X509_REQ_INFO *req_info;
		X509_ALGOR *sig_alg;
		ASN1_BIT_STRING *signature;
		int references;
	} X509_REQ;
	
	struct v3_ext_ctx {
#define CTX_TEST 0x1
		int flags;
		X509 *issuer_cert;
		X509 *subject_cert;
		X509_REQ *subject_req;
		X509_CRL *crl;
		X509V3_CONF_METHOD *db_meth;
		void *db;
		/* Maybe more here */
	};
	
	typedef struct v3_ext_ctx X509V3_CTX;
	
	struct evp_pkey_ctx_st
	{
		/* Method associated with this operation */
		const EVP_PKEY_METHOD *pmeth;
		/* Engine that implements this method or NULL if builtin */
		ENGINE *engine;
		/* Key: may be NULL */
		EVP_PKEY *pkey;
		/* Peer key for key agreement, may be NULL */
		EVP_PKEY *peerkey;
		/* Actual operation */
		int operation;
		/* Algorithm specific data */
		void *data;
		/* Application specific data */
		void *app_data;
		/* Keygen callback */
		EVP_PKEY_gen_cb *pkey_gencb;
		/* implementation specific keygen data */
		int *keygen_info;
		int keygen_info_count;
	} /* EVP_PKEY_CTX */;
	
	struct dh_st
	{
		/* This first argument is used to pick up errors when
		 * a DH is passed instead of a EVP_PKEY */
		int pad;
		int version;
		BIGNUM *p;
		BIGNUM *g;
		long length; /* optional */
		BIGNUM *pub_key;	/* g^x */
		BIGNUM *priv_key;	/* x */
		
		int flags;
		BN_MONT_CTX *method_mont_p;
		/* Place holders if we want to do X9.42 DH */
		BIGNUM *q;
		BIGNUM *j;
		unsigned char *seed;
		int seedlen;
		BIGNUM *counter;
		
		int references;
		CRYPTO_EX_DATA ex_data;
		const DH_METHOD *meth;
		ENGINE *engine;
	};
	
	typedef struct dh_st DH;
	
	typedef struct ecdh_data_st {
		/* EC_KEY_METH_DATA part */
		/* method specific part */
		ENGINE	*engine;
		int	flags;
		const ECDH_METHOD *meth;
		CRYPTO_EX_DATA ex_data;
	} ECDH_DATA;
	
	struct v3_ext_method {
		int ext_nid;
		int ext_flags;	/* If this is set the following four fields are ignored */
		ASN1_ITEM_EXP *it;
		/* Old style ASN1 calls */
		X509V3_EXT_NEW ext_new;
		X509V3_EXT_FREE ext_free;
		X509V3_EXT_D2I d2i;
		X509V3_EXT_I2D i2d;
		
		/* The following pair is used for string extensions */
		X509V3_EXT_I2S i2s;
		X509V3_EXT_S2I s2i;
		
		/* The following pair is used for multi-valued extensions */
		X509V3_EXT_I2V i2v;
		X509V3_EXT_V2I v2i;
		
		/* The following are used for raw extensions */
		X509V3_EXT_I2R i2r;
		X509V3_EXT_R2I r2i;
		
		void *usr_data;	/* Any extension specific data */
	};
	
	typedef struct v3_ext_method X509V3_EXT_METHOD;
	
	typedef struct bio_method_st
	{
		int type;
		const char *name;
		int (*bwrite)(BIO *, const char *, int);
		int (*bread)(BIO *, char *, int);
		int (*bputs)(BIO *, const char *);
		int (*bgets)(BIO *, char *, int);
		long (*ctrl)(BIO *, int, long, void *);
		int (*create)(BIO *);
		int (*destroy)(BIO *);
        long (*callback_ctrl)(BIO *, int, bio_info_cb *);
	} BIO_METHOD;
	
	struct bio_st
	{
		BIO_METHOD *method;
		/* bio, mode, argp, argi, argl, ret */
		long (*callback)(struct bio_st *,int,const char *,int, long,long);
		char *cb_arg; /* first argument for the callback */
		
		int init;
		int shutdown;
		int flags;	/* extra storage */
		int retry_reason;
		int num;
		void *ptr;
		struct bio_st *next_bio;	/* used by filter BIOs */
		struct bio_st *prev_bio;	/* used by filter BIOs */
		int references;
		unsigned long num_read;
		unsigned long num_write;
		
		CRYPTO_EX_DATA ex_data;
	};
	
#ifndef OPENSSL_NO_KRB5
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)
#ifndef NO_DEF_KRB5_CCACHE
	typedef struct _krb5_ccache
	{
		krb5_magic magic;
		struct _krb5_cc_ops FAR *ops;
		krb5_pointer data;
	} *krb5_ccache;
	typedef struct _krb5_cc_ops
	{
		krb5_magic magic;
		char  *prefix;
		krb5_error_code (KRB5_CALLCONV *resolve)
		(krb5_context, krb5_ccache  *, const char  *);
		krb5_error_code (KRB5_CALLCONV *gen_new)
		(krb5_context, krb5_ccache  *);
		krb5_error_code (KRB5_CALLCONV *init)
		(krb5_context, krb5_ccache, krb5_principal);
		krb5_error_code (KRB5_CALLCONV *destroy)
		(krb5_context, krb5_ccache);
		krb5_error_code (KRB5_CALLCONV *close)
		(krb5_context, krb5_ccache);
		krb5_error_code (KRB5_CALLCONV *store)
		(krb5_context, krb5_ccache, krb5_creds  *);
		krb5_error_code (KRB5_CALLCONV *retrieve)
		(krb5_context, krb5_ccache,
		 krb5_flags, krb5_creds  *, krb5_creds  *);
		krb5_error_code (KRB5_CALLCONV *get_princ)
		(krb5_context, krb5_ccache, krb5_principal  *);
		krb5_error_code (KRB5_CALLCONV *get_first)
		(krb5_context, krb5_ccache, krb5_cc_cursor  *);
		krb5_error_code (KRB5_CALLCONV *get_next)
		(krb5_context, krb5_ccache,
		 krb5_cc_cursor  *, krb5_creds  *);
		krb5_error_code (KRB5_CALLCONV *end_get)
		(krb5_context, krb5_ccache, krb5_cc_cursor  *);
		krb5_error_code (KRB5_CALLCONV *remove_cred)
		(krb5_context, krb5_ccache,
		 krb5_flags, krb5_creds  *);
		krb5_error_code (KRB5_CALLCONV *set_flags)
		(krb5_context, krb5_ccache, krb5_flags);
	} krb5_cc_ops;
#endif /* NO_DEF_KRB5_CCACHE */
#endif  /* OPENSSL_SYS_WINDOWS || OPENSSL_SYS_WIN32 */
#endif	/* !OPENSSL_NO_KRB5	*/

	typedef struct ASIdentifiers_st {
		ASIdentifierChoice *asnum, *rdi;
	};
	
	typedef struct IPAddressFamily_st {
		ASN1_OCTET_STRING	*addressFamily;
		IPAddressChoice	*ipAddressChoice;
	} IPAddressFamily;
	

	/********** Headers **********/ 
	
	ASN1_STRING *	ASN1_STRING_type_new(int type );
	ASN1_STRING *	ASN1_STRING_new(void);
	ASN1_OBJECT *	d2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
									long length);
	ASN1_OBJECT *	c2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
									long length);
	ASN1_OBJECT *	ASN1_OBJECT_new(void );
	
	static BIGNUM *		BN_POOL_get(BN_POOL *);
	
	ASN1_OBJECT *	OBJ_txt2obj(const char *s, int no_name);
	ASN1_OBJECT *	OBJ_nid2obj(int n);
	ASN1_OBJECT *	OBJ_dup(const ASN1_OBJECT *o);
	
	static void *default_malloc_ex(size_t num, const char *file, int line);
	
	/* file: CRYPTO_malloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void *CRYPTO_malloc(int num, const char *file, int line);
	
	/* file: CRYPTO_dbg_malloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void CRYPTO_dbg_malloc(void *addr,int num,const char *file,int line,int before_p);
	
	/* file: CRYPTO_is_mem_check_on : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	int CRYPTO_is_mem_check_on(void);
	
	/* file: malloc_debug_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
#ifdef CRYPTO_MDEBUG
	static void (*malloc_debug_func)(void *,int,const char *,int,int)
	= CRYPTO_dbg_malloc;
#else
	/* file: malloc_debug_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
	static void (*malloc_debug_func)(void *,int,const char *,int,int) = NULL;
#endif

	/* file: CRYPTO_THREADID_set_numeric : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id, unsigned long val);
	
	/* file: CRYPTO_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void CRYPTO_lock(int mode, int type,const char *file,int line);
	
	/* file: CRYPTO_THREADID_set_pointer : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void CRYPTO_THREADID_set_pointer(CRYPTO_THREADID *id, void *ptr);
	
	/* file: CRYPTO_THREADID_hash : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	unsigned long CRYPTO_THREADID_hash(const CRYPTO_THREADID *id);
	
	/* file: CRYPTO_get_lock_name : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	const char *CRYPTO_get_lock_name(int type);
	
	/* file: sk_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.h */
	int sk_num(const _STACK *);
	
	/* file: STACK_OF : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
	typedef STACK_OF(ASN1_TYPE) ASN1_SEQUENCE_ANY;
	
	/* file: sk_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.h */
	void *sk_value(const _STACK *, int);
	
	/* file: ERR_put_error : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
	void ERR_put_error(int lib, int func,int reason,const char *file,int line);
	
	/* file: CRYPTO_THREADID_cpy : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest, const CRYPTO_THREADID *src);
	
	/* file: CRYPTO_free : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void CRYPTO_free(void *ptr);
	
	/* file: CRYPTO_dbg_free : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void CRYPTO_dbg_free(void *addr,int before_p);
	
	/* file: CRYPTO_mem_ctrl : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	int CRYPTO_mem_ctrl(int mode);
	
	/* file: CRYPTO_THREADID_cmp : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	int CRYPTO_THREADID_cmp(const CRYPTO_THREADID *a, const CRYPTO_THREADID *b);
	
	/* file: free_debug_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
#ifdef CRYPTO_MDEBUG
	static void (*free_debug_func)(void *,int) = CRYPTO_dbg_free;
#else
	/* file: free_debug_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
	static void (*free_debug_func)(void *,int) = NULL;
#endif

	/* file: OBJ_sn2nid : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobjects.h */
	int		OBJ_sn2nid(const char *s);	
	
	/* file: OBJ_ln2nid : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobjects.h */
	int		OBJ_ln2nid(const char *s);
	
	/* file: a2d_ASN1_OBJECT : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
	int a2d_ASN1_OBJECT(unsigned char *out,int olen, const char *buf, int num);
		
	/* file: RAND_pseudo_bytes : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifdef BN_DEBUG
#ifdef BN_DEBUG_RAND
#ifndef RAND_pseudo_bytes
	int RAND_pseudo_bytes(unsigned char *buf,int num);
#endif
#endif
#endif
	
	/* file: ERR_set_mark : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
	int ERR_set_mark(void);
	
	/* file: CRYPTO_add_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	int CRYPTO_add_lock(int *pointer,int amount,int type, const char *file,
						int line);
	
	/* file: add_lock_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
	static int (MS_FAR *add_lock_callback)(int *pointer,int amount,
										   int type,const char *file,int line)=0;
										   
	/* file: ERR_pop_to_mark : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
	int ERR_pop_to_mark(void);
	
	/* file: ASN1_object_size : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
	int ASN1_object_size(int constructed, int length, int tag);
	
	/* file: ASN1_put_object : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
	void ASN1_put_object(unsigned char **pp, int constructed, int length,
						 int tag, int xclass);
	
	/* file: asn1_put_length : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_lib.c */
	static void asn1_put_length(unsigned char **pp, int length);
	
	/* file: ASN1_get_object : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
	int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
						int *pclass, long omax);
	
	/* file: asn1_get_length : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_lib.c */
	static int asn1_get_length(const unsigned char **pp,int *inf,long *rl,int max);
	
	/* file: CRYPTO_realloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void *CRYPTO_realloc(void *addr,int num, const char *file, int line);
	
	/* file: realloc_debug_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
#ifdef CRYPTO_MDEBUG
	static void (*realloc_debug_func)(void *,void *,int,const char *,int,int)
	= CRYPTO_dbg_realloc;
#else
	/* file: realloc_debug_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
	static void (*realloc_debug_func)(void *,void *,int,const char *,int,int)
	= NULL;
#endif

	/* file: CRYPTO_dbg_realloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void CRYPTO_dbg_realloc(void *addr1,void *addr2,int num,const char *file,int line,int before_p);
	
	/* file: default_realloc_ex : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
	static void *default_realloc_ex(void *str, size_t num, const char *file, int line);
	
	/* file: realloc_ex_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
	static void *(*realloc_ex_func)(void *, size_t, const char *file, int line)
	= default_realloc_ex;
	
	/* file: BUF_strlcat : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bufferbuffer.h */
	size_t BUF_strlcat(char *dst,const char *src,size_t siz);
	
	/* file: BUF_strlcpy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bufferbuffer.h */
	size_t BUF_strlcpy(char *dst,const char *src,size_t siz);
	
	/* file: ERR_set_error_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
	void ERR_set_error_data(char *data,int flags);
	
	
	/* file: a2i_ipadd : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
	int a2i_ipadd(unsigned char *ipout, const char *ipasc);
	
	/* file: ipv6_from_asc : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
	static int ipv6_from_asc(unsigned char *v6, const char *in);
	
	/* file: CONF_parse_list : /Volumes/work/Phd/ECDH/kv_openssl/crypto/confconf.h */
	int CONF_parse_list(const char *list, int sep, int nospc,
						int (*list_cb)(const char *elem, int len, void *usr), void *arg);
	
	/* file: ipv4_from_asc : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
	static int ipv4_from_asc(unsigned char *v4, const char *in);
	
	/* file: traverse_string : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_mbstr.c */
	static int traverse_string(const unsigned char *p, int len, int inform,
							   int (*rfunc)(unsigned long value, void *in), void *arg);
	
	/* file: BIO_snprintf : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biobio.h */
	int BIO_snprintf(char *buf, size_t n, const char *format, ...)
	__bio_h__attr__((__format__(__printf__,3,4)));
	
	/* file: BIO_vsnprintf : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biobio.h */
	int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
	__bio_h__attr__((__format__(__printf__,3,0)));
	
	/* file: _dopr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
	static void _dopr(char **sbuffer, char **buffer,
					  size_t *maxlen, size_t *retlen, int *truncated,
					  const char *format, va_list args);
	
	/* file: doapr_outch : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
	static void doapr_outch (char **, char **, size_t *, size_t *, int);
	
	
	/* file: fmtint : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
	static void fmtint     (char **, char **, size_t *, size_t *,
							LLONG, int, int, int, int);
	
	/* file: fmtfp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
	static void fmtfp      (char **, char **, size_t *, size_t *,
							LDOUBLE, int, int, int);
	
	/* file: fmtstr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
	static void fmtstr     (char **, char **, size_t *, size_t *,
							const char *, int, int, int);
							
	/* file: OBJ_obj2nid : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobjects.h */
	int		OBJ_obj2nid(const ASN1_OBJECT *o);
	
	/* file: ASN1_PRINTABLE_type : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
	int ASN1_PRINTABLE_type(const unsigned char *s, int max);
	
	/* file: ASN1_tag2bit : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
	unsigned long ASN1_tag2bit(int tag);
	
	/* file: string_to_hex : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
	unsigned char *string_to_hex(const char *str, long *len);
	
	/* file: OpenSSLDie : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void OpenSSLDie(const char *file,int line,const char *assertion);
	
	/* file: OPENSSL_showfatal : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.h */
	void OPENSSL_showfatal(const char *fmta,...);
	
	/* file: OPENSSL_isservice : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	int OPENSSL_isservice(void);
	
	/* file: dynlock_lock_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
	static void (MS_FAR *dynlock_lock_callback)(int mode, struct CRYPTO_dynlock_value *l, const char *file,int line)=0;
	
	/* file: CRYPTO_destroy_dynlockid : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void CRYPTO_destroy_dynlockid(int i);
	
	
	/* file: dynlock_destroy_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
	static void (MS_FAR *dynlock_destroy_callback)(struct CRYPTO_dynlock_value *l,
												   const char *file,int line)=0;
	
	/* file: locking_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
	static void (MS_FAR *locking_callback)(int mode,int type,
										   const char *file,int line)=0;
	
	/* file: malloc_ex_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
	static void *(*malloc_ex_func)(size_t, const char *file, int line)
	= default_malloc_ex;
	
	/* file: malloc_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
	static void *(*malloc_func)(size_t)         = malloc;
	
	/* file: OPENSSL_cleanse : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void OPENSSL_cleanse(void *ptr, size_t len);
	
	
	/* file: FIPS_mode : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	int FIPS_mode(void);
	
	/* file: OPENSSL_init : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void OPENSSL_init(void);
	
	/* file: RAND_init_fips : /Volumes/work/Phd/ECDH/kv_openssl/crypto/randrand.h */
#ifdef OPENSSL_FIPS
	int RAND_init_fips(void);
#endif

	/* file: ecdh_data_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhech_lib.c */
	static void  ecdh_data_free(void *);
	
	char *	BUF_strndup(const char *str, size_t siz);
	char *	BUF_strdup(const char *str);
	
#ifdef __cplusplus
}
#endif	
