#include <stddef.h>
#include <memory.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STACK_OF(type) struct stack_st_##type
#define ERR_NUM_ERRORS	16
#define BN_CTX_POOL_SIZE	16
#define KEYSIZB 1024 /* should hit tty line limit first :-) */
#define CRYPTO_MEM_CHECK_OFF	0x0	/* an enume */
#define CRYPTO_NUM_LOCKS		41
#define SHA_DIGEST_LENGTH 20
#define MD_DIGEST_LENGTH	SHA_DIGEST_LENGTH
#define V_ASN1_OCTET_STRING		4
#define TYPE    unsigned int

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
/* file: BN_set_flags : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_set_flags(b,n)	((b)->flags|=(n))

/********** Global Variabls and Structures **********/ 

struct crypto_ex_data_st
{
	STACK_OF(void) *sk;
};

typedef struct
{
	int references;
	struct CRYPTO_dynlock_value *data;
} CRYPTO_dynlock;

typedef struct crypto_ex_data_st CRYPTO_EX_DATA;

typedef struct {
	int type;
	const char *name;
} FUNCTION;


typedef struct NOTICEREF_st {
	ASN1_STRING *organization;
	STACK_OF(ASN1_INTEGER) *noticenos;
} NOTICEREF;


typedef struct USERNOTICE_st {
	NOTICEREF *noticeref;
	ASN1_STRING *exptext;
} USERNOTICE;

typedef struct x509_store_st X509_STORE;

struct ASN1_TEMPLATE_st {
unsigned long flags;		/* Various flags */
long tag;			/* tag, not used if no tagging */
unsigned long offset;		/* Offset of this field in structure */
#ifndef NO_ASN1_FIELD_NAMES
const char *field_name;		/* Field name */
#endif
ASN1_ITEM_EXP *item;		/* Relevant ASN1_ITEM or ASN1_ADB */
};

typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;

typedef struct asn1_object_st
{
	const char *sn,*ln;
	int nid;
	int length;
	const unsigned char *data;	/* data remains const after init */
	int flags;	/* Should we free this one */
} ASN1_OBJECT;

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
#define EVP_MD_FLAG_ONESHOT	0x0001 
#define EVP_PKEY_NULL_method	NULL,NULL,{0,0,0,0}
#endif /* !EVP_MD */


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


typedef struct env_md_st EVP_MD;

static int krb5_loaded = 0;     /* only attempt to initialize func ptrs once */
EVP_PKEY *pkey;


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
#ifdef USE_CRYPTODEV_DIGESTS
const EVP_MD cryptodev_sha1 = {
	NID_sha1,
	NID_undef, 
	SHA_DIGEST_LENGTH, 
	EVP_MD_FLAG_ONESHOT,
	cryptodev_digest_init,
	cryptodev_digest_update,
	cryptodev_digest_final,
	cryptodev_digest_copy,
	cryptodev_digest_cleanup,
	EVP_PKEY_NULL_method,
	SHA_CBLOCK,
	sizeof(struct dev_crypto_state),
};
const EVP_MD cryptodev_md5 = {
	NID_md5,
	NID_undef, 
	16 /* MD5_DIGEST_LENGTH */, 
	EVP_MD_FLAG_ONESHOT,
	cryptodev_digest_init,
	cryptodev_digest_update,
	cryptodev_digest_final,
	cryptodev_digest_copy,
	cryptodev_digest_cleanup,
	EVP_PKEY_NULL_method,
	64 /* MD5_CBLOCK */,
	sizeof(struct dev_crypto_state),
};
#endif /* USE_CRYPTODEV_DIGESTS */
#endif /* HAVE_CRYPTODEV */

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

static const CRYPTO_EX_DATA_IMPL *impl = NULL;

typedef struct st_CRYPTO_EX_DATA_IMPL	CRYPTO_EX_DATA_IMPL;

#if !defined(OPENSSL_NO_DES) && !defined(OPENSSL_NO_SHA1)
const EVP_CIPHER *enc;
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


typedef struct ssl_cipher_st SSL_CIPHER;


typedef struct ssl_method_st SSL_METHOD;


typedef struct GENERAL_SUBTREE_st {
	GENERAL_NAME *base;
	ASN1_INTEGER *minimum;
	ASN1_INTEGER *maximum;
} GENERAL_SUBTREE;


typedef struct DIST_POINT_NAME_st {
int type;
union {
	GENERAL_NAMES *fullname;
	STACK_OF(X509_NAME_ENTRY) *relativename;
} name;
/* If relativename then this contains the full distribution point name */
X509_NAME *dpname;
} DIST_POINT_NAME;



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


struct X509_pubkey_st
	{
	X509_ALGOR *algor;
	ASN1_BIT_STRING *public_key;
	EVP_PKEY *pkey;
	};


typedef struct X509_val_st
	{
	ASN1_TIME *notBefore;
	ASN1_TIME *notAfter;
	} X509_VAL;


#ifndef OPENSSL_NO_SSL_INTERN
struct ssl_ctx_st
	{
	const SSL_METHOD *method;

	STACK_OF(SSL_CIPHER) *cipher_list;
	/* same as above but sorted for lookup */
	STACK_OF(SSL_CIPHER) *cipher_list_by_id;

	struct x509_store_st /* X509_STORE */ *cert_store;
	LHASH_OF(SSL_SESSION) *sessions;
	/* Most session-ids that will be cached, default is
	 * SSL_SESSION_CACHE_MAX_SIZE_DEFAULT. 0 is unlimited. */
	unsigned long session_cache_size;
	struct ssl_session_st *session_cache_head;
	struct ssl_session_st *session_cache_tail;

	/* This can have one of 2 values, ored together,
	 * SSL_SESS_CACHE_CLIENT,
	 * SSL_SESS_CACHE_SERVER,
	 * Default is SSL_SESSION_CACHE_SERVER, which means only
	 * SSL_accept which cache SSL_SESSIONS. */
	int session_cache_mode;

	/* If timeout is not 0, it is the default timeout value set
	 * when SSL_new() is called.  This has been put in to make
	 * life easier to set things up */
	long session_timeout;

	/* If this callback is not null, it will be called each
	 * time a session id is added to the cache.  If this function
	 * returns 1, it means that the callback will do a
	 * SSL_SESSION_free() when it has finished using it.  Otherwise,
	 * on 0, it means the callback has finished with it.
	 * If remove_session_cb is not null, it will be called when
	 * a session-id is removed from the cache.  After the call,
	 * OpenSSL will SSL_SESSION_free() it. */

	struct
		{
		int sess_connect;	/* SSL new conn - started */
		int sess_connect_renegotiate;/* SSL reneg - requested */
		int sess_connect_good;	/* SSL new conne/reneg - finished */
		int sess_accept;	/* SSL new accept - started */
		int sess_accept_renegotiate;/* SSL reneg - requested */
		int sess_accept_good;	/* SSL accept/reneg - finished */
		int sess_miss;		/* session lookup misses  */
		int sess_timeout;	/* reuse attempt on timeouted session */
		int sess_cache_full;	/* session removed due to full cache */
		int sess_hit;		/* session reuse actually done */
		int sess_cb_hit;	/* session-id that was not
					 * in the cache was
					 * passed back via the callback.  This
					 * indicates that the application is
					 * supplying session-id's from other
					 * processes - spooky :-) */
		} stats;

	int references;

	/* if defined, these override the X509_verify_cert() calls */
	void *app_verify_arg;
	/* before OpenSSL 0.9.7, 'app_verify_arg' was ignored
	 * ('app_verify_callback' was called with just one argument) */

	/* Default password callback. */
	pem_password_cb *default_passwd_callback;

	/* Default password callback user data. */
	void *default_passwd_callback_userdata;

	/* get client cert callback */

    /* cookie generate callback */

    /* verify cookie callback */

	CRYPTO_EX_DATA ex_data;

	const EVP_MD *rsa_md5;/* For SSLv2 - name is 'ssl2-md5' */
	const EVP_MD *md5;	/* For SSLv3/TLSv1 'ssl3-md5' */
	const EVP_MD *sha1;   /* For SSLv3/TLSv1 'ssl3->sha1' */

	STACK_OF(X509) *extra_certs;
	STACK_OF(SSL_COMP) *comp_methods; /* stack of SSL_COMP, SSLv3/TLSv1 */


	/* Default values used when no per-SSL value is defined follow */


	/* what we put in client cert requests */
	STACK_OF(X509_NAME) *client_CA;


	/* Default values to use in SSL structures follow (these are copied by SSL_new) */

	unsigned long options;
	unsigned long mode;
	long max_cert_list;

	struct cert_st /* CERT */ *cert;
	int read_ahead;

	/* callback that allows applications to peek at protocol messages */
	void *msg_callback_arg;

	int verify_mode;
	unsigned int sid_ctx_length;
	unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];

	/* Default generate session ID callback. */
	GEN_SESSION_CB generate_session_id;

	X509_VERIFY_PARAM *param;

#if 0
	int purpose;		/* Purpose setting */
	int trust;		/* Trust setting */
#endif

	int quiet_shutdown;

	/* Maximum amount of data to send in one fragment.
	 * actual record size can be more than this due to
	 * padding and MAC overheads.
	 */
	unsigned int max_send_fragment;

#ifndef OPENSSL_ENGINE
	/* Engine to pass requests for client certs to
	 */
	ENGINE *client_cert_engine;
#endif

#ifndef OPENSSL_NO_TLSEXT
	/* TLS extensions servername callback */
	void *tlsext_servername_arg;
	/* RFC 4507 session ticket keys */
	unsigned char tlsext_tick_key_name[16];
	unsigned char tlsext_tick_hmac_key[16];
	unsigned char tlsext_tick_aes_key[16];
	/* Callback to support customisation of ticket key setting */

	/* certificate status request info */
	/* Callback for status request */
	void *tlsext_status_arg;

	/* draft-rescorla-tls-opaque-prf-input-00.txt information */
	void *tlsext_opaque_prf_input_callback_arg;
#endif

#ifndef OPENSSL_NO_PSK
	char *psk_identity_hint;
#endif

#ifndef OPENSSL_NO_BUF_FREELISTS
#define SSL_MAX_BUF_FREELIST_LEN_DEFAULT 32
	unsigned int freelist_max_len;
	struct ssl3_buf_freelist_st *wbuf_freelist;
	struct ssl3_buf_freelist_st *rbuf_freelist;
#endif
#ifndef OPENSSL_NO_SRP
	SRP_CTX srp_ctx; /* ctx for SRP authentication */
#endif

#ifndef OPENSSL_NO_TLSEXT

# ifndef OPENSSL_NO_NEXTPROTONEG
	/* Next protocol negotiation information */
	/* (for experimental NPN extension). */

	/* For a server, this contains a callback function by which the set of
	 * advertised protocols can be provided. */
	void *next_protos_advertised_cb_arg;
	/* For a client, this contains a callback function that selects the
	 * next protocol from the list provided by the server. */
	void *next_proto_select_cb_arg;
# endif
        /* SRTP profiles we are willing to do from RFC 5764 */
        STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;  
#endif
	};
#endif

typedef struct X509_pubkey_st X509_PUBKEY;


typedef struct x509_revoked_st X509_REVOKED;



typedef struct ASN1_ITEM_st ASN1_ITEM;


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


typedef struct IPAddressChoice_st {
  int type;
  union {
    ASN1_NULL		*inherit;
    IPAddressOrRanges	*addressesOrRanges;
  } u;
} IPAddressChoice;


typedef struct ASIdentifierChoice_st {
  int type;
  union {
    ASN1_NULL    *inherit;
    ASIdOrRanges *asIdsOrRanges;
  } u;
} ASIdentifierChoice;


struct ISSUING_DIST_POINT_st
	{
	DIST_POINT_NAME *distpoint;
	int onlyuser;
	int onlyCA;
	ASN1_BIT_STRING *onlysomereasons;
	int indirectCRL;
	int onlyattr;
	};


struct NAME_CONSTRAINTS_st {
	STACK_OF(GENERAL_SUBTREE) *permittedSubtrees;
	STACK_OF(GENERAL_SUBTREE) *excludedSubtrees;
};


struct AUTHORITY_KEYID_st {
ASN1_OCTET_STRING *keyid;
GENERAL_NAMES *issuer;
ASN1_INTEGER *serial;
};


struct DIST_POINT_st {
DIST_POINT_NAME	*distpoint;
ASN1_BIT_STRING *reasons;
GENERAL_NAMES *CRLissuer;
int dp_reasons;
};


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
	} X509_CINF;


typedef struct X509_req_info_st
	{
	ASN1_ENCODING enc;
	ASN1_INTEGER *version;
	X509_NAME *subject;
	X509_PUBKEY *pubkey;
	/*  d=2 hl=2 l=  0 cons: cont: 00 */
	STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
	} X509_REQ_INFO;


typedef struct x509_attributes_st
	{
	ASN1_OBJECT *object;
	union	{
		char		*ptr;
/* 0 */		STACK_OF(ASN1_TYPE) *set;
/* 1 */		ASN1_TYPE	*single;
		} value;
	} X509_ATTRIBUTE;



#if defined(USE_MD5_RAND)
#define MD_DIGEST_LENGTH	MD5_DIGEST_LENGTH
#elif defined(USE_SHA1_RAND)
#define MD_DIGEST_LENGTH	SHA_DIGEST_LENGTH
#elif defined(USE_MDC2_RAND)
#define MD_DIGEST_LENGTH	MDC2_DIGEST_LENGTH
#elif defined(USE_MD2_RAND)
#define MD_DIGEST_LENGTH	MD2_DIGEST_LENGTH
#endif

#ifndef OPENSSL_NO_DSA
struct dsa_st;
#endif

#ifndef OPENSSL_NO_RSA
struct rsa_st;
#endif


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




struct buf_mem_st
	{
	size_t length;	/* current number of bytes */
	char *data;
	size_t max;	/* size of buffer */
	};


struct x509_crl_method_st
	{
	int flags;
	};


#ifndef OPENSSL_EXPORT_VAR_AS_FUNCTION
typedef const ASN1_ITEM ASN1_ITEM_EXP;
#else
typedef const ASN1_ITEM * ASN1_ITEM_EXP(void);
#endif

struct X509_algor_st;


typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;


typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;


typedef struct DIST_POINT_st DIST_POINT;


typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;


typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;


typedef struct ssl_ctx_st SSL_CTX;

static SSL_CTX *ctx=NULL;

typedef struct st_ERR_FNS ERR_FNS;


typedef struct x509_crl_method_st X509_CRL_METHOD;


typedef struct X509_algor_st X509_ALGOR;


#ifdef OPENSSL_NO_CAST
#else
#if 0
char *text="Hello to all people out there";
#endif
#endif

typedef struct X
    {
    STACK_OF(X509_EXTENSION) *ext;
    } X;


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


 Our internal RSA_METHOD that we provide pointers to */
static RSA_METHOD surewarehk_rsa =
	{
	"SureWare RSA method",
	NULL, /* pub_enc*/
	NULL, /* pub_dec*/
	surewarehk_rsa_sign, /* our rsa_sign is OpenSSL priv_enc*/
	surewarehk_rsa_priv_dec, /* priv_dec*/
	NULL, /*mod_exp*/
	surewarehk_mod_exp_mont, /*mod_exp_mongomery*/
	NULL, /* init*/
	NULL, /* finish*/
	0,	/* RSA flag*/
	NULL, 
	NULL, /* OpenSSL sign*/
	NULL, /* OpenSSL verify*/
	NULL  /* keygen */
	};
#endif

#ifndef OPENSSL_NO_DH


static DH_METHOD surewarehk_dh =
	{
	"SureWare DH method",
	NULL,/*gen_key*/
	NULL,/*agree,*/
	surewarehk_modexp_dh, /*dh mod exp*/
	NULL, /* init*/
	NULL, /* finish*/
	0,    /* flags*/
	NULL,
	NULL
	};
#endif

static RAND_METHOD surewarehk_rand =
	{
	/* "SureWare RAND method", */
	surewarehk_rand_seed,
	surewarehk_rand_bytes,
	NULL,/*cleanup*/
	surewarehk_rand_add,
	surewarehk_rand_bytes,
	NULL,/*rand_status*/
	};


/* DSA stuff */
static	DSA_SIG * surewarehk_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa);

#ifndef OPENSSL_NO_DSA
static DSA_METHOD surewarehk_dsa =
	{
	 "SureWare DSA method", 
	surewarehk_dsa_do_sign,
	NULL,/*sign setup*/
	NULL,/*verify,*/
	surewarehk_dsa_mod_exp,/*mod exp*/
	NULL,/*bn mod exp*/
	NULL, /*init*/
	NULL,/*finish*/
	0,
	NULL,
	NULL,
	NULL
	};
#endif

static const char *engine_sureware_id = "sureware";
static const char *engine_sureware_name = "SureWare hardware engine support";

/* Now, to our own code */

/* As this is only ever called once, there's no need for locking


extern int errno;


int type;


int bits;


int n;


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


#ifdef STRICT_ALIGNMENT
#  if defined(ROTATE)
#    define N	1
#  else
#    define N	8
#  endif
#else
#  define N	2
#endif


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


static const RAND_METHOD *default_RAND_meth = NULL;


#ifndef OPENSSL_NO_ENGINE
static ENGINE *funct_ref =NULL;
#endif


static unsigned char state[STATE_SIZE+MD_DIGEST_LENGTH];


typedef struct added_obj_st
	{
	int type;
	ASN1_OBJECT *obj;
	} ADDED_OBJ;


#ifndef OPENSSL_NO_OBJECT
#else
static const ASN1_OBJECT nid_objs[1];
static const unsigned int sn_objs[1];
static const unsigned int ln_objs[1];
static const unsigned int obj_objs[1];
#endif

#ifdef OPENSSL_NO_MD4
#else
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

#if 0
#ifdef OPENSSL_OPENBSD_DEV_CRYPTO
typedef struct session_op session_op;
#endif
#endif


static const ERR_FNS *err_fns = NULL;


static const ERR_FNS err_defaults =
	{
	int_err_get,
	int_err_del,
	int_err_get_item,
	int_err_set_item,
	int_err_del_item,
	int_thread_get,
	int_thread_release,
	int_thread_get_item,
	int_thread_set_item,
	int_thread_del_item,
	int_err_get_next_lib
	};


static ENGINE_TABLE *rand_table = NULL;


static ENGINE_TABLE *ecdh_table = NULL;


static const int dummy_nid = 1;


static unsigned int table_flags = 0;


struct st_engine_table
	{
	LHASH_OF(ENGINE_PILE) piles;
	}; /* ENGINE_TABLE */


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

static const ECDH_METHOD *default_ECDH_method = NULL;


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


typedef struct _ec_list_element_st {
	int	nid;
	const EC_CURVE_DATA *data;
	const char *comment;
	} ec_list_element;


#ifndef OPENSSL_NO_EC2M
static const struct { EC_CURVE_DATA h; unsigned char data[20+15*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+15*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+17*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+17*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+21*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+21*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+21*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+25*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+25*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+30*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+30*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+30*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+36*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+36*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+52*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+52*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+72*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+72*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+21*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+21*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+21*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+23*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+24*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+24*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+24*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+27*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+30*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+30*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+30*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+35*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+39*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[20+45*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+47*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+54*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+15*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+20*6]; }
static const struct { EC_CURVE_DATA h; unsigned char data[0+24*6]; }
#endif

static const struct { EC_CURVE_DATA h; unsigned char data[0+28*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[0+21*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[0+15*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[0+32*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[0+29*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[0+24*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+21*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+21*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[0+21*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+16*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+16*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+14*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+14*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+32*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+30*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+30*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+30*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+24*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+24*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+66*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+48*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+28*6]; }


static const struct { EC_CURVE_DATA h; unsigned char data[20+24*6]; }


typedef struct {
	int	field_type,	/* either NID_X9_62_prime_field or
				 * NID_X9_62_characteristic_two_field */
		seed_len,
		param_len;
	unsigned int cofactor;	/* promoted to BN_ULONG */
} EC_CURVE_DATA;


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


static BIGNUM *		BN_POOL_get(BN_POOL *);



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

typedef struct bignum_ctx_stack
{
	/* Array of indexes into the bignum stack */
	unsigned int *indexes;
	/* Number of stack frames, and the size of the allocated array */
	unsigned int depth, size;
} BN_STACK;

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


struct dsa_method
	{
	const char *name;
	int flags;
	char *app_data;
	/* If this is non-NULL, it is used to generate DSA parameters */
	/* If this is non-NULL, it is used to generate DSA keys */
	};


struct ecdsa_method 
	{
	const char *name;
	int flags;
	char *app_data;
	};

struct store_st
{
	const struct STORE_METHOD *meth;
	/* functional reference if 'meth' is ENGINE-provided */
	struct ENGINE *engine;
	
	struct CRYPTO_EX_DATA ex_data;
	int references;
};


typedef struct store_st STORE;

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


/********** Headers **********/ 
/* file: STORE_INITIALISE_FUNC_PTR : /Volumes/work/Phd/ECDH/kv_openssl/crypto/storestore.h */
/* These callback types are use for store handlers */
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

int STORE_method_set_initialise_function(struct STORE_METHOD *sm, STORE_INITIALISE_FUNC_PTR init_f);
int STORE_method_set_cleanup_function(struct STORE_METHOD *sm, STORE_CLEANUP_FUNC_PTR clean_f);
int STORE_method_set_generate_function(struct STORE_METHOD *sm, STORE_GENERATE_OBJECT_FUNC_PTR generate_f);
int STORE_method_set_get_function(struct STORE_METHOD *sm, STORE_GET_OBJECT_FUNC_PTR get_f);
int STORE_method_set_store_function(struct STORE_METHOD *sm, STORE_STORE_OBJECT_FUNC_PTR store_f);
int STORE_method_set_modify_function(struct STORE_METHOD *sm, STORE_MODIFY_OBJECT_FUNC_PTR store_f);
int STORE_method_set_revoke_function(struct STORE_METHOD *sm, STORE_HANDLE_OBJECT_FUNC_PTR revoke_f);
int STORE_method_set_delete_function(struct STORE_METHOD *sm, STORE_HANDLE_OBJECT_FUNC_PTR delete_f);
int STORE_method_set_list_start_function(struct STORE_METHOD *sm, STORE_START_OBJECT_FUNC_PTR list_start_f);
int STORE_method_set_list_next_function(struct STORE_METHOD *sm, STORE_NEXT_OBJECT_FUNC_PTR list_next_f);
int STORE_method_set_list_end_function(struct STORE_METHOD *sm, STORE_END_OBJECT_FUNC_PTR list_end_f);
int STORE_method_set_update_store_function(struct STORE_METHOD *sm, STORE_GENERIC_FUNC_PTR);
int STORE_method_set_lock_store_function(struct STORE_METHOD *sm, STORE_GENERIC_FUNC_PTR);
int STORE_method_set_unlock_store_function(struct STORE_METHOD *sm, STORE_GENERIC_FUNC_PTR);
int STORE_method_set_ctrl_function(struct STORE_METHOD *sm, STORE_CTRL_FUNC_PTR ctrl_f);

STORE_INITIALISE_FUNC_PTR STORE_method_get_initialise_function(struct STORE_METHOD *sm);
STORE_CLEANUP_FUNC_PTR STORE_method_get_cleanup_function(struct STORE_METHOD *sm);
STORE_GENERATE_OBJECT_FUNC_PTR STORE_method_get_generate_function(struct STORE_METHOD *sm);
STORE_GET_OBJECT_FUNC_PTR STORE_method_get_get_function(struct STORE_METHOD *sm);
STORE_STORE_OBJECT_FUNC_PTR STORE_method_get_store_function(struct STORE_METHOD *sm);
STORE_MODIFY_OBJECT_FUNC_PTR STORE_method_get_modify_function(struct STORE_METHOD *sm);
STORE_HANDLE_OBJECT_FUNC_PTR STORE_method_get_revoke_function(struct STORE_METHOD *sm);
STORE_HANDLE_OBJECT_FUNC_PTR STORE_method_get_delete_function(struct STORE_METHOD *sm);
STORE_START_OBJECT_FUNC_PTR STORE_method_get_list_start_function(struct STORE_METHOD *sm);
STORE_NEXT_OBJECT_FUNC_PTR STORE_method_get_list_next_function(struct STORE_METHOD *sm);
STORE_END_OBJECT_FUNC_PTR STORE_method_get_list_end_function(struct STORE_METHOD *sm);
STORE_GENERIC_FUNC_PTR STORE_method_get_update_store_function(struct STORE_METHOD *sm);
STORE_GENERIC_FUNC_PTR STORE_method_get_lock_store_function(struct STORE_METHOD *sm);
STORE_GENERIC_FUNC_PTR STORE_method_get_unlock_store_function(struct STORE_METHOD *sm);
STORE_CTRL_FUNC_PTR STORE_method_get_ctrl_function(struct STORE_METHOD *sm);

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

typedef struct IPAddressFamily_st {
  ASN1_OCTET_STRING	*addressFamily;
  IPAddressChoice	*ipAddressChoice;
} IPAddressFamily;


typedef struct ASIdentifiers_st {
  ASIdentifierChoice *asnum, *rdi;
} ASIdentifiers;


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


struct v3_ext_method {
int ext_nid;
int ext_flags;
/* If this is set the following four fields are ignored */
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


struct v3_ext_method;



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
	struct ASIdentifiers_st *rfc3779_asid;
#endif
#ifndef OPENSSL_NO_SHA
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
#endif
	X509_CERT_AUX *aux;
	} /* X509 */;


typedef struct X509_req_st
	{
	X509_REQ_INFO *req_info;
	X509_ALGOR *sig_alg;
	ASN1_BIT_STRING *signature;
	int references;
	} X509_REQ;


typedef struct X509_extension_st
	{
	ASN1_OBJECT *object;
	ASN1_BOOLEAN critical;
	ASN1_OCTET_STRING *value;
	} X509_EXTENSION;



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


typedef struct store_method_st STORE_METHOD;


typedef struct X509_crl_st X509_CRL;


typedef struct x509_st X509;


typedef struct ecdsa_method ECDSA_METHOD;


typedef struct rsa_meth_st RSA_METHOD;


typedef struct dsa_method DSA_METHOD;


typedef struct dh_method DH_METHOD;


typedef struct evp_pkey_st EVP_PKEY;


typedef struct buf_mem_st BUF_MEM;


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
#else
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
typedef struct asn1_string_st ASN1_BMPSTRING;
typedef struct asn1_string_st ASN1_VISIBLESTRING;
typedef struct asn1_string_st ASN1_UTF8STRING;
typedef int ASN1_BOOLEAN;
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


typedef struct v3_ext_method X509V3_EXT_METHOD;


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


struct v3_ext_ctx;

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


typedef struct X509_name_entry_st
	{
	ASN1_OBJECT *object;
	ASN1_STRING *value;
	int set;
	int size; 	/* temp variable */
	} X509_NAME_ENTRY;



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

#define _DECLARE_OBJ_BSEARCH_CMP_FN(scope, type1, type2, nm)	\


ASN1_OBJECT *	OBJ_txt2obj(const char *s, int no_name);


ASN1_OBJECT *	OBJ_nid2obj(int n);


ASN1_OBJECT *	OBJ_dup(const ASN1_OBJECT *o);


typedef struct { u64 hi,lo; } u128;

struct evp_pkey_method_st
	{
	int pkey_id;
	int flags;

	} /* EVP_PKEY_METHOD */;


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

typedef struct ENGINE_CMD_DEFN_st
	{
	unsigned int cmd_num; /* The command number */
	const char *cmd_name; /* The command name itself */
	const char *cmd_desc; /* A short description of the command */
	unsigned int cmd_flags; /* The input the command expects */
	} ENGINE_CMD_DEFN;



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

	ENGINE_SSL_CLIENT_CERT_PTR load_ssl_client_cert;

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



typedef struct st_engine_table ENGINE_TABLE;



typedef struct ecdh_data_st {
	/* EC_KEY_METH_DATA part */
	/* method specific part */
	ENGINE	*engine;
	int	flags;
	const ECDH_METHOD *meth;
	CRYPTO_EX_DATA ex_data;
} ECDH_DATA;


struct ecdh_method 
	{
	const char *name;
#if 0
#endif
	int flags;
	char *app_data;
	};




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


typedef struct ec_extra_data_st {
	struct ec_extra_data_st *next;
	void *data;
} EC_EXTRA_DATA; /* used in EC_GROUP */


struct ec_method_st {
	/* Various method flags */
	int flags;
	/* used by EC_METHOD_get_field_type: */
	int field_type; /* a NID */

	/* used by EC_GROUP_new, EC_GROUP_free, EC_GROUP_clear_free, EC_GROUP_copy: */

	/* used by EC_GROUP_set_curve_GFp, EC_GROUP_get_curve_GFp, */
	/* EC_GROUP_set_curve_GF2m, and EC_GROUP_get_curve_GF2m: */

	/* used by EC_GROUP_get_degree: */

	/* used by EC_GROUP_check: */

	/* used by EC_POINT_new, EC_POINT_free, EC_POINT_clear_free, EC_POINT_copy: */

	/* used by EC_POINT_set_to_infinity,
	 * EC_POINT_set_Jprojective_coordinates_GFp,
	 * EC_POINT_get_Jprojective_coordinates_GFp,
	 * EC_POINT_set_affine_coordinates_GFp,     ..._GF2m,
	 * EC_POINT_get_affine_coordinates_GFp,     ..._GF2m,
	 * EC_POINT_set_compressed_coordinates_GFp, ..._GF2m:
	 */

	/* used by EC_POINT_point2oct, EC_POINT_oct2point: */

	/* used by EC_POINT_add, EC_POINT_dbl, ECP_POINT_invert: */

	/* used by EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_cmp: */

	/* used by EC_POINT_make_affine, EC_POINTs_make_affine: */

	/* used by EC_POINTs_mul, EC_POINT_mul, EC_POINT_precompute_mult, EC_POINT_have_precompute_mult
	 * (default implementations are used if the 'mul' pointer is 0): */


	/* internal functions */

	/* 'field_mul', 'field_sqr', and 'field_div' can be used by 'add' and 'dbl' so that
	 * the same implementations of point operations can be used with different
	 * optimized implementations of expensive field operations: */

} /* EC_METHOD */;




typedef struct ec_key_st EC_KEY;



typedef struct ec_point_st EC_POINT;


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


typedef struct ec_method_st EC_METHOD;




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



#ifndef OPENSSL_DH_MAX_MODULUS_BITS
# define OPENSSL_DH_MAX_MODULUS_BITS	10000
#endif

typedef struct
	{
	char *section;
	char *name;
	char *value;
	} CONF_VALUE;

char *	BUF_strndup(const char *str, size_t siz);

char *	BUF_strdup(const char *str);

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

#ifndef OPENSSL_NO_BIO
#endif /* FIXME */

ASN1_STRING *	ASN1_STRING_type_new(int type );

ASN1_STRING *	ASN1_STRING_new(void);

ASN1_OBJECT *	d2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
			long length);

ASN1_OBJECT *	c2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
			long length);
			
ASN1_OBJECT *	ASN1_OBJECT_new(void );

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

typedef struct engine_st ENGINE;


typedef struct v3_ext_ctx X509V3_CTX;


typedef struct X509_name_st X509_NAME;


typedef struct ecdh_method ECDH_METHOD;


typedef struct rand_meth_st RAND_METHOD;


typedef struct dh_st DH;


typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;


typedef struct evp_pkey_method_st EVP_PKEY_METHOD;


typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;


typedef struct bn_mont_ctx_st BN_MONT_CTX;


typedef struct bignum_ctx BN_CTX;


#ifdef NO_ASN1_TYPEDEFS
#define ASN1_INTEGER		ASN1_STRING
#define ASN1_OCTET_STRING	ASN1_STRING
#define ASN1_IA5STRING		ASN1_STRING
#define ASN1_UTCTIME		ASN1_STRING
#define ASN1_GENERALIZEDTIME	ASN1_STRING
#define ASN1_TIME		ASN1_STRING
#else
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_STRING;
#endif

extern const unsigned char os_toebcdic[256];


extern const unsigned char os_toascii[256];



#if (defined(WINDOWS) || defined(MSDOS))
#  ifdef WINDOWS
#    if !defined(_WIN32_WCE) && !defined(_WIN32_WINNT)
#      define _WIN32_WINNT 0x0400
#    endif
#  endif
#  endif

/********** Headers **********/ 
static void *default_malloc_ex(size_t num, const char *file, int line);

/* file: EC_KEY_new_by_curve_name : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
EC_KEY *EC_KEY_new_by_curve_name(int nid);

/* file: EC_KEY_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
EC_KEY *EC_KEY_new(void);

/* file: CRYPTO_malloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
void *CRYPTO_malloc(int num, const char *file, int line);

/* file: malloc_debug_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
#ifdef CRYPTO_MDEBUG
static void (*malloc_debug_func)(void *,int,const char *,int,int)
	= CRYPTO_dbg_malloc;
#else
/* file: malloc_debug_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
static void (*malloc_debug_func)(void *,int,const char *,int,int) = NULL;
#endif
/* file: CRYPTO_dbg_malloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
void CRYPTO_dbg_malloc(void *addr,int num,const char *file,int line,int before_p);

/* file: CRYPTO_is_mem_check_on : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
int CRYPTO_is_mem_check_on(void);

/* file: CRYPTO_THREADID_current : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
void CRYPTO_THREADID_current(CRYPTO_THREADID *id);

/* file: threadid_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
static void (MS_FAR *threadid_callback)(CRYPTO_THREADID *)=0;

/* file: CRYPTO_THREADID_set_numeric : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id, unsigned long val);

/* file: id_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
#ifndef OPENSSL_NO_DEPRECATED
static unsigned long (MS_FAR *id_callback)(void)=0;
#endif

/* file: CRYPTO_THREADID_set_pointer : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
void CRYPTO_THREADID_set_pointer(CRYPTO_THREADID *id, void *ptr);

/* file: CRYPTO_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
void CRYPTO_lock(int mode, int type,const char *file,int line);

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


/* file: a2i_GENERAL_NAME : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
GENERAL_NAME *a2i_GENERAL_NAME(GENERAL_NAME *out,
			       const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
			       int gen_type, char *value, int is_nc);

/* file: ERR_put_error : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
void ERR_put_error(int lib, int func,int reason,const char *file,int line);


/* file: ERR_get_state : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
ERR_STATE *ERR_get_state(void);


/* file: CRYPTO_THREADID_cpy : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
void CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest, const CRYPTO_THREADID *src);


/* file: ERR_STATE_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
static void ERR_STATE_free(ERR_STATE *s);

/* file: CRYPTO_free : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
void CRYPTO_free(void *ptr);

/* file: free_debug_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
#ifdef CRYPTO_MDEBUG
static void (*free_debug_func)(void *,int) = CRYPTO_dbg_free;
#else
/* file: free_debug_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
static void (*free_debug_func)(void *,int) = NULL;
#endif
/* file: CRYPTO_dbg_free : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
void CRYPTO_dbg_free(void *addr,int before_p);

/* file: CRYPTO_mem_ctrl : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
int CRYPTO_mem_ctrl(int mode);

/* file: CRYPTO_THREADID_cmp : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
int CRYPTO_THREADID_cmp(const CRYPTO_THREADID *a, const CRYPTO_THREADID *b);

/* file: app_info_free : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem_dbg.c */
static void app_info_free(APP_INFO *);

/* file: free_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
int CRYPTO_set_locked_mem_functions(void *(*m)(size_t), void (*free_func)(void *));

/* file: OBJ_sn2nid : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobjects.h */
int		OBJ_sn2nid(const char *s);


/* file: OBJ_ln2nid : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobjects.h */
int		OBJ_ln2nid(const char *s);

/* file: a2d_ASN1_OBJECT : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
int a2d_ASN1_OBJECT(unsigned char *out,int olen, const char *buf, int num);


/* file: BN_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BIGNUM *BN_new(void);


/* file: RAND_pseudo_bytes : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifdef BN_DEBUG
#ifdef BN_DEBUG_RAND
#ifndef RAND_pseudo_bytes
int RAND_pseudo_bytes(unsigned char *buf,int num);
#endif
#else
#endif

/* file: RAND_get_rand_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/randrand.h */
const RAND_METHOD *RAND_get_rand_method(void);

/* file: ENGINE_get_default_RAND : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineengine.h */
ENGINE *ENGINE_get_default_RAND(void);

/* file: engine_table_select : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
#ifndef ENGINE_TABLE_DEBUG
ENGINE *engine_table_select(ENGINE_TABLE **table, int nid);
#else
/* file: engine_table_select_tmp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
#ifndef ENGINE_TABLE_DEBUG
ENGINE *engine_table_select_tmp(ENGINE_TABLE **table, int nid, const char *f, int l);
#endif
#endif

/* file: ERR_set_mark : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
int ERR_set_mark(void);

/* file: int_table_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_table.c */
static int int_table_check(ENGINE_TABLE **t, int create) 	{
 LHASH_OF(ENGINE_PILE) *lh; 
 if(*t) return 1;  if(!create) return 0;  if((lh = lh_ENGINE_PILE_new()) == NULL) 		return 0;
 *t = (ENGINE_TABLE *)lh; 	return 1;
	}
/* file: LHASH_OF : /Volumes/work/Phd/ECDH/kv_openssl/appsopenssl.c */
static LHASH_OF(FUNCTION) *prog_init(void );

/* file: engine_unlocked_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
int engine_unlocked_init(ENGINE *e);

/* file: init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/evpevp.h */
	int (*init)(EVP_PKEY_CTX *ctx));

/* file: engine_unlocked_finish : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
int engine_unlocked_finish(ENGINE *e, int unlock_for_handlers);

/* file: engine_free_util : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
int engine_free_util(ENGINE *e, int locked);


/* file: CRYPTO_add_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
int CRYPTO_add_lock(int *pointer,int amount,int type, const char *file,
		    int line);

/* file: add_lock_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
static int (MS_FAR *add_lock_callback)(int *pointer,int amount,
	int type,const char *file,int line)=0;


/* file: engine_pkey_meths_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
void engine_pkey_meths_free(ENGINE *e);

/* file: EVP_PKEY_meth_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/evpevp.h */
void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth);

/* file: engine_pkey_asn1_meths_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
void engine_pkey_asn1_meths_free(ENGINE *e);

/* file: EVP_PKEY_asn1_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/evpevp.h */
void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth);

/* file: CRYPTO_free_ex_data : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);


/* file: ERR_pop_to_mark : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
int ERR_pop_to_mark(void);



/* file: ENGINE_get_RAND : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineengine.h */
const RAND_METHOD *ENGINE_get_RAND(const ENGINE *e);

/* file: ENGINE_finish : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineengine.h */
int ENGINE_finish(ENGINE *e);

/* file: RAND_SSLeay : /Volumes/work/Phd/ECDH/kv_openssl/crypto/randrand.h */
RAND_METHOD *RAND_SSLeay(void);

/* file: BN_set_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_set_word(BIGNUM *a, BN_ULONG w);

/* file: bn_expand2 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BIGNUM *bn_expand2(BIGNUM *a, int words);

/* file: BN_mul_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_mul_word(BIGNUM *a, BN_ULONG w);

/* file: bn_mul_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);

/* file: BN_add_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_add_word(BIGNUM *a, BN_ULONG w);

/* file: BN_sub_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_sub_word(BIGNUM *a, BN_ULONG w);

/* file: BN_set_negative : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
void	BN_set_negative(BIGNUM *b, int n);

/* file: BN_num_bits : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_num_bits(const BIGNUM *a);

/* file: BN_num_bits_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_num_bits_word(BN_ULONG);

/* file: BN_div_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);

/* file: BN_lshift : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_lshift(BIGNUM *r, const BIGNUM *a, int n);

/* file: bn_div_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d);

/* file: BN_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
void	BN_free(BIGNUM *a);

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

/* file: ASN1_OBJECT_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
void		ASN1_OBJECT_free(ASN1_OBJECT *a);

/* file: ERR_add_error_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
void ERR_add_error_data(int num, ...);

/* file: ERR_add_error_vdata : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
void ERR_add_error_vdata(int num, va_list args);

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

/* file: realloc_ex_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
static void *(*realloc_ex_func)(void *, size_t, const char *file, int line)
        = default_realloc_ex;
/* file: default_realloc_ex : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
static void *default_realloc_ex(void *str, size_t num,         const char *file, int line)
 { return realloc_func(str,num); } /* file: realloc_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
static void *(*realloc_func)(void *, size_t)= realloc;

/* file: BUF_strlcat : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bufferbuffer.h */
size_t BUF_strlcat(char *dst,const char *src,size_t siz);

/* file: BUF_strlcpy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bufferbuffer.h */
size_t BUF_strlcpy(char *dst,const char *src,size_t siz);

/* file: ERR_set_error_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
void ERR_set_error_data(char *data,int flags);

/* file: a2i_IPADDRESS_NC : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
ASN1_OCTET_STRING *a2i_IPADDRESS_NC(const char *ipasc);

/* file: a2i_ipadd : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
int a2i_ipadd(unsigned char *ipout, const char *ipasc);

/* file: ipv6_from_asc : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
static int ipv6_from_asc(unsigned char *v6, const char *in);

/* file: CONF_parse_list : /Volumes/work/Phd/ECDH/kv_openssl/crypto/confconf.h */
int CONF_parse_list(const char *list, int sep, int nospc,
	int (*list_cb)(const char *elem, int len, void *usr), void *arg);

/* file: list_cb : /Volumes/work/Phd/ECDH/kv_openssl/crypto/confconf.h */
	int (*list_cb)(const char *elem, int len, void *usr), void *arg);

/* file: ipv4_from_asc : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
static int ipv4_from_asc(unsigned char *v4, const char *in);

/* file: ASN1_OCTET_STRING_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
int 	ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data, int len);

/* file: a2i_IPADDRESS : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
ASN1_OCTET_STRING *a2i_IPADDRESS(const char *ipasc);

/* file: do_dirname : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_alt.c */
static int do_dirname(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx);

/* file: X509V3_NAME_from_section : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
int X509V3_NAME_from_section(X509_NAME *nm, STACK_OF(CONF_VALUE)*dn_sk,
						unsigned long chtype);

/* file: X509_NAME_add_entry_by_txt : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type,
			const unsigned char *bytes, int len, int loc, int set);

/* file: X509_NAME_ENTRY_create_by_txt : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne,
		const char *field, int type, const unsigned char *bytes, int len);


/* file: X509_NAME_ENTRY_create_by_OBJ : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_OBJ(X509_NAME_ENTRY **ne,
			ASN1_OBJECT *obj, int type,const unsigned char *bytes,
			int len);

/* file: X509_NAME_ENTRY_set_object : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
int 		X509_NAME_ENTRY_set_object(X509_NAME_ENTRY *ne,
			ASN1_OBJECT *obj);

/* file: X509_NAME_ENTRY_set_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
int 		X509_NAME_ENTRY_set_data(X509_NAME_ENTRY *ne, int type,
			const unsigned char *bytes, int len);

/* file: ASN1_STRING_set_by_NID : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out, 
		const unsigned char *in, int inlen, int inform, int nid);

/* file: ASN1_STRING_TABLE_get : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid);

/* file: sk_find : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.h */
int sk_find(_STACK *st, void *data);

/* file: sk_sort : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.h */
void sk_sort(_STACK *st);

/* file: ASN1_mbstring_ncopy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
					int inform, unsigned long mask, 
					long minsize, long maxsize);

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

/* file: ASN1_STRING_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
int 		ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);

/* file: ASN1_STRING_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
void		ASN1_STRING_free(ASN1_STRING *a);

/* file: ASN1_mbstring_copy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
					int inform, unsigned long mask);

/* file: OBJ_obj2nid : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobjects.h */
int		OBJ_obj2nid(const ASN1_OBJECT *o);

/* file: ASN1_PRINTABLE_type : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
int ASN1_PRINTABLE_type(const unsigned char *s, int max);

/* file: X509_NAME_add_entry : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
int 		X509_NAME_add_entry(X509_NAME *name,X509_NAME_ENTRY *ne,
			int loc, int set);

/* file: X509_NAME_ENTRY_dup : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
X509_NAME_ENTRY *X509_NAME_ENTRY_dup(X509_NAME_ENTRY *ne);

/* file: sk_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.h */
int sk_insert(_STACK *sk, void *data, int where);

/* file: X509V3_section_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
void X509V3_section_free( X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section);
#endif

/* file: do_othername : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_alt.c */
static int do_othername(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx);

/* file: ASN1_generate_v3 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
ASN1_TYPE *ASN1_generate_v3(char *str, X509V3_CTX *cnf);

/* file: asn1_multi : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_gen.c */
static ASN1_TYPE *asn1_multi(int utype, const char *section, X509V3_CTX *cnf);

/* file: sk_push : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.h */
int sk_push(_STACK *st, void *data);

/* file: asn1_str2type : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_gen.c */
static ASN1_TYPE *asn1_str2type(const char *str, int format, int utype);

/* file: X509V3_get_value_bool : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
int X509V3_get_value_bool(CONF_VALUE *value, int *asn1_bool);

/* file: BN_hex2bn : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int 	BN_hex2bn(BIGNUM **a, const char *str);

/* file: BN_dec2bn : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int 	BN_dec2bn(BIGNUM **a, const char *str);

/* file: BN_to_ASN1_INTEGER : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);

/* file: BN_bn2bin : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_bn2bin(const BIGNUM *a, unsigned char *to);

/* file: ASN1_STRING_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_lib.c */
ASN1_STRING *ASN1_STRING_new(void) 	{
 return(ASN1_STRING_type_new(V_ASN1_OCTET_STRING)); 	}

/* file: ASN1_TIME_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
int ASN1_TIME_check(ASN1_TIME *t);

/* file: ASN1_GENERALIZEDTIME_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
int ASN1_GENERALIZEDTIME_check(ASN1_GENERALIZEDTIME *a);

/* file: ASN1_UTCTIME_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
int ASN1_UTCTIME_check(ASN1_UTCTIME *a);

/* file: ASN1_tag2bit : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
unsigned long ASN1_tag2bit(int tag);

/* file: string_to_hex : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
unsigned char *string_to_hex(const char *str, long *len);

/* file: CRYPTO_get_dynlock_value : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
struct CRYPTO_dynlock_value *CRYPTO_get_dynlock_value(int i);

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

/* file: EC_GROUP_new_by_curve_name : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
EC_GROUP *EC_GROUP_new_by_curve_name(int nid);

/* file: BN_CTX_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BN_CTX *BN_CTX_new(void);

/* file: BN_POOL_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void		BN_POOL_init(BN_POOL *);

/* file: BN_STACK_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void		BN_STACK_init(BN_STACK *);

/* file: BN_bin2bn : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BIGNUM *BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret);

/* file: EC_GROUP_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
EC_GROUP *EC_GROUP_new(const EC_METHOD *meth);

/* file: BN_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
void	BN_init(BIGNUM *);

/* file: EC_GROUP_new_curve_GFp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);

/* file: EC_GFp_mont_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
const EC_METHOD *EC_GFp_mont_method(void);

/* file: EC_GFp_nist_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
const EC_METHOD *EC_GFp_nist_method(void);

/* file: EC_GROUP_set_curve_GFp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);

/* file: ERR_peek_last_error : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
unsigned long ERR_peek_last_error(void);


/* file: EC_GROUP_clear_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
void EC_GROUP_clear_free(EC_GROUP *group);

/* file: EC_EX_DATA_clear_free_all_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lcl.h */
void EC_EX_DATA_clear_free_all_data(EC_EXTRA_DATA **);

/* file: clear_free_func : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
void *EC_KEY_get_key_method_data(EC_KEY *key, 
								 void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));

void *EC_KEY_insert_key_method_data(EC_KEY *key, void *data,
									void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));


/* file: EC_POINT_clear_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
void EC_POINT_clear_free(EC_POINT *point);

/* file: OPENSSL_cleanse : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
void OPENSSL_cleanse(void *ptr, size_t len);

/* file: BN_clear_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
void	BN_clear_free(BIGNUM *a);

/* file: ERR_clear_error : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
void ERR_clear_error(void );

/* file: EC_GROUP_new_curve_GF2m : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef OPENSSL_NO_EC2M
EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
#endif

/* file: EC_GF2m_simple_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef OPENSSL_NO_EC2M
const EC_METHOD *EC_GF2m_simple_method(void);
#endif

/* file: EC_GROUP_set_curve_GF2m : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef OPENSSL_NO_EC2M
int EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
#endif

/* file: EC_POINT_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
EC_POINT *EC_POINT_new(const EC_GROUP *group);

/* file: EC_POINT_set_affine_coordinates_GFp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
	const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);

/* file: EC_GROUP_set_generator : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);

/* file: EC_POINT_copy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_POINT_copy(EC_POINT *dst, const EC_POINT *src);

/* file: BN_copy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);

/* file: EC_GROUP_set_seed : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);

/* file: EC_GROUP_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
void EC_GROUP_free(EC_GROUP *group);

/* file: EC_EX_DATA_free_all_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lcl.h */
void EC_EX_DATA_free_all_data(EC_EXTRA_DATA **);

/* file: EC_POINT_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
void EC_POINT_free(EC_POINT *point);

/* file: BN_CTX_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
void	BN_CTX_free(BN_CTX *c);

/* file: BN_STACK_finish : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void		BN_STACK_finish(BN_STACK *);

/* file: BN_POOL_finish : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void		BN_POOL_finish(BN_POOL *);


/* file: EC_GROUP_set_curve_name : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
void EC_GROUP_set_curve_name(EC_GROUP *group, int nid);

/* file: EC_KEY_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
void EC_KEY_free(EC_KEY *key);


/* file: EC_KEY_generate_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_KEY_generate_key(EC_KEY *key);

/* file: FIPS_mode : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
int FIPS_mode(void);

/* file: OPENSSL_init : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
void OPENSSL_init(void);

/* file: RAND_init_fips : /Volumes/work/Phd/ECDH/kv_openssl/crypto/randrand.h */
#ifdef OPENSSL_FIPS
int RAND_init_fips(void);
#endif


/* file: drbg_get_adin : /Volumes/work/Phd/ECDH/kv_openssl/crypto/randrand_lib.c */
#ifdef OPENSSL_FIPS
static size_t drbg_get_adin(DRBG_CTX *ctx, unsigned char **pout)     	{
	/* Use of static variables is OK as this happens under a lock */
	static unsigned char buf[16];
	static unsigned long counter;
 FIPS_get_timevec(buf, &counter); 	*pout = buf;
 return sizeof(buf); 	}
#endif

/* file: EC_GROUP_get_order : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx);

/* file: BN_rand_range : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_rand_range(BIGNUM *rnd, const BIGNUM *range);

/* file: BN_is_bit_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_is_bit_set(const BIGNUM *a, int n);

/* file: BN_cmp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_cmp(const BIGNUM *a, const BIGNUM *b);

/* file: BN_sub : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

/* file: BN_uadd : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

/* file: bn_add_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BN_ULONG bn_add_words(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,int num);

/* file: BN_ucmp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_ucmp(const BIGNUM *a, const BIGNUM *b);

/* file: BN_usub : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

/* file: bn_sub_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BN_ULONG bn_sub_words(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,int num);


/* file: EC_POINT_mul : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);

/* file: EC_POINTs_mul : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, size_t num, const EC_POINT *p[], const BIGNUM *m[], BN_CTX *ctx);

/* file: ec_wNAF_mul : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lcl.h */
int ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
	size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *);

/* file: EC_POINT_set_to_infinity : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point);

/* file: EC_GROUP_get0_generator : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group);

/* file: EC_EX_DATA_get_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lcl.h */
void *EC_EX_DATA_get_data(const EC_EXTRA_DATA *,
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));

/* file: EC_POINT_cmp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);

/* file: EC_POINT_dbl : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx);

/* file: EC_POINT_add : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);

/* file: EC_POINTs_make_affine : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_POINTs_make_affine(const EC_GROUP *group, size_t num, EC_POINT *points[], BN_CTX *ctx);

/* file: EC_POINT_invert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx);

/* file: EC_GROUP_get_degree : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_GROUP_get_degree(const EC_GROUP *group);

/* file: EC_KEY_get0_group : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);

/* file: ECDH_compute_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhecdh.h */
int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key, EC_KEY *ecdh,
                     void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));

/* file: ecdh_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhech_locl.h */
ECDH_DATA *ecdh_check(EC_KEY *);

/* file: EC_KEY_get_key_method_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
void *EC_KEY_get_key_method_data(EC_KEY *key, 
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));

/* file: ecdh_data_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhech_lib.c */
static void *ecdh_data_new(void);

/* file: ECDH_get_default_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhecdh.h */
const ECDH_METHOD *ECDH_get_default_method(void);

/* file: ECDH_OpenSSL : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhecdh.h */
const ECDH_METHOD *ECDH_OpenSSL(void);

/* file: ENGINE_get_default_ECDH : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineengine.h */
ENGINE *ENGINE_get_default_ECDH(void);

/* file: ENGINE_get_ECDH : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineengine.h */
const ECDH_METHOD *ENGINE_get_ECDH(const ENGINE *e);

/* file: CRYPTO_new_ex_data : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
int CRYPTO_new_ex_data(int class_index, void *obj, struct CRYPTO_EX_DATA *ad);


/* file: EC_KEY_insert_key_method_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
void *EC_KEY_insert_key_method_data(EC_KEY *key, void *data,
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));

/* file: EC_EX_DATA_set_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lcl.h */
int EC_EX_DATA_set_data(EC_EXTRA_DATA **, void *data,
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));

/* file: ecdh_data_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhech_lib.c */
static void  ecdh_data_free(void *);

/* file: EC_KEY_get_flags : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
int EC_KEY_get_flags(const EC_KEY *key);

/* file: compute_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/dhdh_key.c */
static int compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);


/* file: BN_CTX_start : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
void	BN_CTX_start(BN_CTX *ctx);


/* file: BN_STACK_push : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static int		BN_STACK_push(BN_STACK *, unsigned int);


/* file: BN_CTX_get : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BIGNUM *BN_CTX_get(BN_CTX *ctx);


/* file: BN_MONT_CTX_set_locked : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, int lock,
					const BIGNUM *mod, BN_CTX *ctx);

/* file: BN_MONT_CTX_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BN_MONT_CTX *BN_MONT_CTX_new(void );

/* file: BN_MONT_CTX_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
void BN_MONT_CTX_init(BN_MONT_CTX *ctx);

/* file: BN_MONT_CTX_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int BN_MONT_CTX_set(BN_MONT_CTX *mont,const BIGNUM *mod,BN_CTX *ctx);

/* file: BN_set_bit : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_set_bit(BIGNUM *a, int n);

/* file: BN_mod_inverse : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BIGNUM *BN_mod_inverse(BIGNUM *ret,
	const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);

/* file: BN_mod_inverse_no_branch : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_gcd.c */
static BIGNUM *BN_mod_inverse_no_branch(BIGNUM *in,
        const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);


/* file: BN_nnmod : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);

/* file: BN_div : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
	BN_CTX *ctx);

/* file: BN_lshift1 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_lshift1(BIGNUM *r, const BIGNUM *a);

/* file: BN_rshift1 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_rshift1(BIGNUM *r, const BIGNUM *a);

/* file: BN_CTX_end : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
void	BN_CTX_end(BN_CTX *ctx);

/* file: BN_STACK_pop : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static unsigned int	BN_STACK_pop(BN_STACK *);

/* file: BN_POOL_release : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void		BN_POOL_release(BN_POOL *, unsigned int);

/* file: BN_rshift : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_rshift(BIGNUM *r, const BIGNUM *a, int n);

/* file: BN_add : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

/* file: BN_mul : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
int	BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);

/* file: bn_mul_comba4 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
void bn_mul_comba4(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b);


/* file: bn_mul_add_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);


/* file: bn_mul_comba8 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
void bn_mul_comba8(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b);

/* file: bn_mul_part_recursive : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
void bn_mul_part_recursive(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b,
	int n,int tna,int tnb,BN_ULONG *t);

/* file: bn_mul_normal : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
void bn_mul_normal(BN_ULONG *r,BN_ULONG *a,int na,BN_ULONG *b,int nb);

/* file: bn_cmp_part_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
int bn_cmp_part_words(const BN_ULONG *a, const BN_ULONG *b,
	int cl, int dl);

/* file: bn_cmp_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
int bn_cmp_words(const BN_ULONG *a,const BN_ULONG *b,int n);

/* file: bn_sub_part_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
BN_ULONG bn_sub_part_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
	int cl, int dl);

/* file: bn_mul_recursive : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
void bn_mul_recursive(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b,int n2,
	int dna,int dnb,BN_ULONG *t);

/* file: BN_MONT_CTX_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
void BN_MONT_CTX_free(BN_MONT_CTX *mont);


/* file: DH_check_pub_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/dhdh.h */
int	DH_check_pub_key(const DH *dh,const BIGNUM *pub_key, int *codes);

/* file: bn_mod_exp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
	int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

/* file: EC_KEY_get0_public_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key);

#ifdef __cplusplus
}
#endif
