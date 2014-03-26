#ifndef HEADER_E_OS_H
#if defined(WINDOWS)
#elif defined(__DJGPP__)
#elif defined(MAC_OS_pre_X)
#elif defined(OPENSSL_SYS_VMS)
#elif defined(OPENSSL_SYS_VXWORKS)
#if (defined(WINDOWS) || defined(MSDOS))
#  ifdef WINDOWS
#    if !defined(_WIN32_WCE) && !defined(_WIN32_WINNT)
#      define _WIN32_WINNT 0x0400
#    endif
#endif
#ifdef USE_SOCKETS
#  if defined(WINDOWS) || defined(MSDOS)
#if defined(OPENSSL_SYS_WINDOWS)
#elif defined(OPENSSL_SYS_VMS)
#ifndef HEADER_E_OS2_H
   macro to be used. */
#ifdef OPENSSL_SYS_WINDOWS
# ifndef OPENSSL_OPT_WINDLL
#  if defined(_WINDLL) /* This is used when building OpenSSL to indicate that
                          DLL linkage should be used */
#   define OPENSSL_OPT_WINDLL
#  endif
# endif
#endif

/* -------------------------------- OpenVMS -------------------------------- */
#if defined(__VMS) || defined(VMS) || defined(OPENSSL_SYSNAME_VMS)
# undef OPENSSL_SYS_UNIX
# define OPENSSL_SYS_VMS
# if defined(__DECC)
#  define OPENSSL_SYS_VMS_DECC
# elif defined(__DECCXX)
#  define OPENSSL_SYS_VMS_DECC
#  define OPENSSL_SYS_VMS_DECCXX
# else
#  define OPENSSL_SYS_VMS_NODECC
# endif
#endif

/* --------------------------------- OS/2 ---------------------------------- */
#if defined(__EMX__) || defined(__OS2__)
# undef OPENSSL_SYS_UNIX
# define OPENSSL_SYS_OS2
#endif

/* --------------------------------- Unix ---------------------------------- */
#ifdef OPENSSL_SYS_UNIX
# if defined(linux) || defined(__linux__) || defined(OPENSSL_SYSNAME_LINUX)
#  define OPENSSL_SYS_LINUX
# endif
# ifdef OPENSSL_SYSNAME_MPE
#  define OPENSSL_SYS_MPE
# endif
# ifdef OPENSSL_SYSNAME_SNI
#  define OPENSSL_SYS_SNI
# endif
# ifdef OPENSSL_SYSNAME_ULTRASPARC
#  define OPENSSL_SYS_ULTRASPARC
# endif
# ifdef OPENSSL_SYSNAME_NEWS4
#  define OPENSSL_SYS_NEWS4
# endif
# ifdef OPENSSL_SYSNAME_MACOSX
#  define OPENSSL_SYS_MACOSX
# endif
# ifdef OPENSSL_SYSNAME_MACOSX_RHAPSODY
#  define OPENSSL_SYS_MACOSX_RHAPSODY
#  define OPENSSL_SYS_MACOSX
# endif
# ifdef OPENSSL_SYSNAME_SUNOS
#  define OPENSSL_SYS_SUNOS
#endif
# if defined(_CRAY) || defined(OPENSSL_SYSNAME_CRAY)
#  define OPENSSL_SYS_CRAY
# endif
# if defined(_AIX) || defined(OPENSSL_SYSNAME_AIX)
#  define OPENSSL_SYS_AIX
# endif
#endif

/* --------------------------------- VOS ----------------------------------- */
#if defined(__VOS__) || defined(OPENSSL_SYSNAME_VOS)
# define OPENSSL_SYS_VOS
#ifdef __HPPA__
# define OPENSSL_SYS_VOS_HPPA
#endif
#ifdef __IA32__
# define OPENSSL_SYS_VOS_IA32
#endif
#endif

/* ------------------------------- VxWorks --------------------------------- */
#ifdef OPENSSL_SYSNAME_VXWORKS
# define OPENSSL_SYS_VXWORKS
#endif

/* --------------------------------- BeOS ---------------------------------- */
#if defined(__BEOS__)
# define OPENSSL_SYS_BEOS
# include <sys/socket.h>
# if defined(BONE_VERSION)
#  define OPENSSL_SYS_BEOS_BONE
# else
#  define OPENSSL_SYS_BEOS_R5
# endif
#endif

/**
 * That's it for OS-specific stuff
 *****************************************************************************/


/* Specials for I/O an exit */
#ifdef OPENSSL_SYS_MSDOS
# define OPENSSL_UNISTD_IO <io.h>
# define OPENSSL_DECLARE_EXIT extern void exit(int);
#endif
static char *section=NULL;
extern int errno;
#ifndef HEADER_CRYPTO_H
#if 0
typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
#endif
struct crypto_ex_data_st
	{
	STACK_OF(void) *sk;
	int dummy; /* gcc is screwing up this data structure :-( */
	};
#endif
#ifndef HEADER_OPENSSL_TYPES_H
#ifdef NO_ASN1_TYPEDEFS
#define ASN1_UTCTIME		ASN1_STRING
#define ASN1_GENERALIZEDTIME	ASN1_STRING
#define ASN1_TIME		ASN1_STRING
#else
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_STRING;
#endif
typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
typedef struct rand_meth_st RAND_METHOD;
typedef struct X509_name_st X509_NAME;
typedef struct v3_ext_ctx X509V3_CTX;
typedef struct engine_st ENGINE;
#endif /* def HEADER_OPENSSL_TYPES_H */
#ifdef HAVE_LONG_DOUBLE
#define LDOUBLE long double
#else
#define LDOUBLE double
#endif
#ifdef HAVE_LONG_LONG
# if defined(_WIN32) && !defined(__GNUC__)
# define LLONG __int64
# else
# define LLONG long long
# endif
#else
#define LLONG long
#endif
static LDOUBLE
abs_val(LDOUBLE value)
{
    LDOUBLE result = value;
    if (value < 0)
        result = -value;
    return result;
}
static LDOUBLE
pow_10(int in_exp)
{
    LDOUBLE result = 1;
    while (in_exp) {
        result *= 10;
        in_exp--;
    }
    return result;
}
#ifndef HEADER_ASN1_H
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
#endif
struct evp_pkey_asn1_method_st
	{
	int pkey_id;
	int pkey_base_id;
	unsigned long pkey_flags;

	char *pem_str;
	char *info;

	int (*pub_decode)(EVP_PKEY *pk, X509_PUBKEY *pub);
	int (*pub_encode)(X509_PUBKEY *pub, const EVP_PKEY *pk);
	int (*pub_cmp)(const EVP_PKEY *a, const EVP_PKEY *b);
	int (*pub_print)(BIO *out, const EVP_PKEY *pkey, int indent,
							ASN1_PCTX *pctx);

	int (*priv_decode)(EVP_PKEY *pk, PKCS8_PRIV_KEY_INFO *p8inf);
	int (*priv_encode)(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk);
	int (*priv_print)(BIO *out, const EVP_PKEY *pkey, int indent,
							ASN1_PCTX *pctx);

	int (*pkey_size)(const EVP_PKEY *pk);
	int (*pkey_bits)(const EVP_PKEY *pk);

	int (*param_decode)(EVP_PKEY *pkey,
				const unsigned char **pder, int derlen);
	int (*param_encode)(const EVP_PKEY *pkey, unsigned char **pder);
	int (*param_missing)(const EVP_PKEY *pk);
	int (*param_copy)(EVP_PKEY *to, const EVP_PKEY *from);
	int (*param_cmp)(const EVP_PKEY *a, const EVP_PKEY *b);
	int (*param_print)(BIO *out, const EVP_PKEY *pkey, int indent,
							ASN1_PCTX *pctx);
	int (*sig_print)(BIO *out,
			 const X509_ALGOR *sigalg, const ASN1_STRING *sig,
					 int indent, ASN1_PCTX *pctx);


	void (*pkey_free)(EVP_PKEY *pkey);
	int (*pkey_ctrl)(EVP_PKEY *pkey, int op, long arg1, void *arg2);

	/* Legacy functions for old PEM */

	int (*old_priv_decode)(EVP_PKEY *pkey,
				const unsigned char **pder, int derlen);
	int (*old_priv_encode)(const EVP_PKEY *pkey, unsigned char **pder);
	/* Custom ASN1 signature verification */
	int (*item_verify)(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
				X509_ALGOR *a, ASN1_BIT_STRING *sig,
				EVP_PKEY *pkey);
	int (*item_sign)(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
				X509_ALGOR *alg1, X509_ALGOR *alg2, 
				ASN1_BIT_STRING *sig);

	} /* EVP_PKEY_ASN1_METHOD */;
    const char *value,
    int flags,
    int min,
    int max)
{
    int padlen, strln;
    int cnt = 0;

    if (value == 0)
        value = "<NULL>";
    for (strln = 0; value[strln]; ++strln)
        ;
    padlen = min - strln;
    if (padlen < 0)
        padlen = 0;
    if (flags & DP_F_MINUS)
        padlen = -padlen;

    while ((padlen > 0) && (cnt < max)) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
        --padlen;
        ++cnt;
    }
    while (*value && (cnt < max)) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, *value++);
        ++cnt;
    }
    while ((padlen < 0) && (cnt < max)) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
        ++padlen;
        ++cnt;
    }
}
    LLONG value,
    int base,
    int min,
    int max,
    int flags)
{
    int signvalue = 0;
    const char *prefix = "";
    unsigned LLONG uvalue;
    char convert[DECIMAL_SIZE(value)+3];
    int place = 0;
    int spadlen = 0;
    int zpadlen = 0;
    int caps = 0;

    if (max < 0)
        max = 0;
    uvalue = value;
    if (!(flags & DP_F_UNSIGNED)) {
        if (value < 0) {
            signvalue = '-';
            uvalue = -value;
        } else if (flags & DP_F_PLUS)
            signvalue = '+';
        else if (flags & DP_F_SPACE)
            signvalue = ' ';
    }
    if (flags & DP_F_NUM) {
	if (base == 8) prefix = "0";
	if (base == 16) prefix = "0x";
    }
    if (flags & DP_F_UP)
        caps = 1;
    do {
        convert[place++] =
            (caps ? "0123456789ABCDEF" : "0123456789abcdef")
            [uvalue % (unsigned) base];
        uvalue = (uvalue / (unsigned) base);
    } while (uvalue && (place < (int)sizeof(convert)));
    if (place == sizeof(convert))
        place--;
    convert[place] = 0;

    zpadlen = max - place;
    spadlen = min - OSSL_MAX(max, place) - (signvalue ? 1 : 0) - strlen(prefix);
    if (zpadlen < 0)
        zpadlen = 0;
    if (spadlen < 0)
        spadlen = 0;
    if (flags & DP_F_ZERO) {
        zpadlen = OSSL_MAX(zpadlen, spadlen);
        spadlen = 0;
    }
    if (flags & DP_F_MINUS)
        spadlen = -spadlen;

    /* spaces */
    while (spadlen > 0) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
        --spadlen;
    }

    /* sign */
    if (signvalue)
        doapr_outch(sbuffer, buffer, currlen, maxlen, signvalue);

    /* prefix */
    while (*prefix) {
	doapr_outch(sbuffer, buffer, currlen, maxlen, *prefix);
	prefix++;
    }

    /* zeros */
    if (zpadlen > 0) {
        while (zpadlen > 0) {
            doapr_outch(sbuffer, buffer, currlen, maxlen, '0');
            --zpadlen;
        }
    }
    /* digits */
    while (place > 0)
        doapr_outch(sbuffer, buffer, currlen, maxlen, convert[--place]);

    /* left justified spaces */
    while (spadlen < 0) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
        ++spadlen;
    }
    return;
}
   it really be this way?  -- Richard Levitte */
/* NB: The prototypes have been typedef'd to CRYPTO_MEM_LEAK_CB inside crypto.h
 * If this code is restructured, remove the callback type if it is no longer
 * needed. -- Geoff Thorpe */

/* Can't pass CRYPTO_MEM_LEAK_CB directly to lh_MEM_doall_arg because it
 * is a function pointer and conversion to void * is prohibited. Instead
 * pass its address
 */

typedef CRYPTO_MEM_LEAK_CB *PCRYPTO_MEM_LEAK_CB;
#ifndef HEADER_CRYPTO_H
	struct CRYPTO_dynlock_value *data;
#endif
#if !(defined(__GNUC__) && __GNUC__>=2)
#else
#ifdef _WIN64
#define BN_ULONG unsigned long long
#else
#define BN_ULONG unsigned long
#endif
#endif
#ifdef OPENSSL_NO_CAST
#else
static unsigned char in[8]={ 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
#endif
#ifndef HEADER_BN_H
#ifdef SIXTY_FOUR_BIT_LONG
#define BN_ULLONG	unsigned long long
#endif
#ifdef THIRTY_TWO_BIT
#ifdef BN_LLONG
# if defined(_WIN32) && !defined(__GNUC__)
#  define BN_ULLONG	unsigned __int64
# else
#  define BN_ULLONG	unsigned long long
# endif
#endif
#endif
			     based on the size of the number */

/* number of Miller-Rabin iterations for an error rate  of less than 2^-80
 * for random 'b'-bit input, b >= 100 (taken from table 4.4 in the Handbook
 * of Applied Cryptography [Menezes, van Oorschot, Vanstone; CRC Press 1996];
#endif
   by the "CONF classic" functions, for consistency.  */

CONF *NCONF_new(CONF_METHOD *meth)
	{
	CONF *ret;

	if (meth == NULL)
		meth = NCONF_default();

	ret = meth->create(meth);
	if (ret == NULL)
		{
		CONFerr(CONF_F_NCONF_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}

	return ret;
	}
#ifndef HEADER_EC_H
#ifdef  __cplusplus
typedef struct ec_method_st EC_METHOD;
typedef struct ec_point_st EC_POINT;
#endif
struct ec_method_st {
	/* Various method flags */
	int flags;
	/* used by EC_METHOD_get_field_type: */
	int field_type; /* a NID */

	/* used by EC_GROUP_new, EC_GROUP_free, EC_GROUP_clear_free, EC_GROUP_copy: */
	int (*group_copy)(EC_GROUP *, const EC_GROUP *);

	/* used by EC_GROUP_set_curve_GFp, EC_GROUP_get_curve_GFp, */
	/* EC_GROUP_set_curve_GF2m, and EC_GROUP_get_curve_GF2m: */
	int (*group_get_curve)(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);

	/* used by EC_GROUP_get_degree: */
	int (*group_get_degree)(const EC_GROUP *);

	/* used by EC_GROUP_check: */
	int (*group_check_discriminant)(const EC_GROUP *, BN_CTX *);

	/* used by EC_POINT_new, EC_POINT_free, EC_POINT_clear_free, EC_POINT_copy: */

	/* used by EC_POINT_set_to_infinity,
	 * EC_POINT_set_Jprojective_coordinates_GFp,
	 * EC_POINT_get_Jprojective_coordinates_GFp,
	 * EC_POINT_set_affine_coordinates_GFp,     ..._GF2m,
	 * EC_POINT_get_affine_coordinates_GFp,     ..._GF2m,
	 * EC_POINT_set_compressed_coordinates_GFp, ..._GF2m:
	 */
	int (*point_set_to_infinity)(const EC_GROUP *, EC_POINT *);
	int (*point_set_Jprojective_coordinates_GFp)(const EC_GROUP *, EC_POINT *,
		const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *);
	int (*point_get_Jprojective_coordinates_GFp)(const EC_GROUP *, const EC_POINT *,
		BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *);
		const BIGNUM *x, const BIGNUM *y, BN_CTX *);
	int (*point_get_affine_coordinates)(const EC_GROUP *, const EC_POINT *,
		BIGNUM *x, BIGNUM *y, BN_CTX *);
	int (*point_set_compressed_coordinates)(const EC_GROUP *, EC_POINT *,
		const BIGNUM *x, int y_bit, BN_CTX *);

	/* used by EC_POINT_point2oct, EC_POINT_oct2point: */
	size_t (*point2oct)(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
	        unsigned char *buf, size_t len, BN_CTX *);
	int (*oct2point)(const EC_GROUP *, EC_POINT *,
	        const unsigned char *buf, size_t len, BN_CTX *);

	/* used by EC_POINT_add, EC_POINT_dbl, ECP_POINT_invert: */
	int (*add)(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
	int (*dbl)(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
	int (*invert)(const EC_GROUP *, EC_POINT *, BN_CTX *);

	/* used by EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_cmp: */
	int (*is_at_infinity)(const EC_GROUP *, const EC_POINT *);
	int (*is_on_curve)(const EC_GROUP *, const EC_POINT *, BN_CTX *);
	int (*point_cmp)(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);

	/* used by EC_POINT_make_affine, EC_POINTs_make_affine: */
	int (*make_affine)(const EC_GROUP *, EC_POINT *, BN_CTX *);
	int (*points_make_affine)(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);

	/* used by EC_POINTs_mul, EC_POINT_mul, EC_POINT_precompute_mult, EC_POINT_have_precompute_mult
	 * (default implementations are used if the 'mul' pointer is 0): */
		size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *);
	int (*precompute_mult)(EC_GROUP *group, BN_CTX *);
	int (*have_precompute_mult)(const EC_GROUP *group);


	/* internal functions */

	/* 'field_mul', 'field_sqr', and 'field_div' can be used by 'add' and 'dbl' so that
	 * the same implementations of point operations can be used with different
	 * optimized implementations of expensive field operations: */
	int (*field_mul)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
	int (*field_sqr)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
	int (*field_div)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);

	int (*field_encode)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *); /* e.g. to Montgomery */
	int (*field_decode)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *); /* e.g. from Montgomery */
	int (*field_set_to_one)(const EC_GROUP *, BIGNUM *r, BN_CTX *);
} /* EC_METHOD */;
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
#ifdef OPENSSL_SYS_NETWARE
#if !defined __int64
#  define __int64 long long
#endif   
#endif
			     const X509V3_EXT_METHOD *, ext);
#ifndef HEADER_OPENSSL_TYPES_H
typedef struct bignum_st BIGNUM;
#endif /* def HEADER_OPENSSL_TYPES_H */
 normalise pubkey and parameters in case of */
		dsatmp->pub_key->top=el/sizeof(BN_ULONG);
#ifndef HEADER_BN_H
struct bignum_st
	{
	BN_ULONG *d;	/* Pointer to an array of 'BN_BITS2' bit chunks. */
	int top;	/* Index of last used d +1. */
	/* The next are internal book keeping for bn_expand. */
	int dmax;	/* Size of the d array. */
	int neg;	/* one if the number is negative */
	int flags;
	};
#endif
#ifndef HEADER_BN_H
#ifdef SIXTY_FOUR_BIT_LONG
#define BN_ULONG	unsigned long
#endif
#ifdef SIXTY_FOUR_BIT
#define BN_ULONG	unsigned long long
#endif
#ifdef THIRTY_TWO_BIT
#define BN_ULONG	unsigned int
#endif
#endif
#ifndef HEADER_ENGINE_INT_H
typedef struct st_engine_table ENGINE_TABLE;
#endif /* HEADER_ENGINE_INT_H */
struct st_engine_table
	{
	LHASH_OF(ENGINE_PILE) piles;
	}; /* ENGINE_TABLE */
/********** Headers **********/ 
/* file: EC_KEY_new_by_curve_name : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
EC_KEY *EC_KEY_new_by_curve_name(int nid);
#endif

/* file: EC_KEY_new : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
EC_KEY *EC_KEY_new(void);
#endif

/* file: OPENSSL_malloc : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#define OPENSSL_malloc(num)	CRYPTO_malloc((int)num,__FILE__,__LINE__)
#endif
/* file: CRYPTO_malloc : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void *CRYPTO_malloc(int num, const char *file, int line);
#endif

/* file: malloc_debug_func : D:\PhD\ECDH\kv_openssl\cryptomem.c */
#ifdef CRYPTO_MDEBUG
static void (*malloc_debug_func)(void *,int,const char *,int,int)
	= CRYPTO_dbg_malloc;
#else
/* file: malloc_debug_func : D:\PhD\ECDH\kv_openssl\cryptomem.c */
static void (*malloc_debug_func)(void *,int,const char *,int,int) = NULL;
#endif
/* file: CRYPTO_dbg_malloc : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_dbg_malloc(void *addr,int num,const char *file,int line,int before_p);
#endif

/* file: is_MemCheck_on : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#define is_MemCheck_on() CRYPTO_is_mem_check_on()
#endif
/* file: CRYPTO_is_mem_check_on : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
int CRYPTO_is_mem_check_on(void);
#endif

/* file: CRYPTO_THREADID_current : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_THREADID_current(CRYPTO_THREADID *id);
#endif

/* file: threadid_callback : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
static void (MS_FAR *threadid_callback)(CRYPTO_THREADID *)=0;

/* file: CRYPTO_THREADID_set_numeric : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id, unsigned long val);
#endif

/* file: id_callback : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
#ifndef OPENSSL_NO_DEPRECATED
static unsigned long (MS_FAR *id_callback)(void)=0;
#endif

/* file: CRYPTO_THREADID_set_pointer : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_THREADID_set_pointer(CRYPTO_THREADID *id, void *ptr);
#endif

/* file: CRYPTO_r_lock : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_r_lock(type)	\
	CRYPTO_lock(CRYPTO_LOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#endif
#else
/* file: CRYPTO_r_lock : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#define CRYPTO_r_lock(a)
#endif
#endif
/* file: CRYPTO_lock : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_lock(int mode, int type,const char *file,int line);
#endif

/* file: CRYPTO_THREADID_hash : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
unsigned long CRYPTO_THREADID_hash(const CRYPTO_THREADID *id);
#endif

/* file: CRYPTO_get_lock_name : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
const char *CRYPTO_get_lock_name(int type);
#endif

/* file: sk_OPENSSL_STRING_num : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_OPENSSL_STRING_num(st) SKM_sk_num(OPENSSL_STRING, st)
#endif /* !defined HEADER_SAFESTACK_H */
/* file: SKM_sk_num : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define SKM_sk_num(type, st) \
	sk_num(CHECKED_STACK_OF(type, st))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: sk_num : D:\PhD\ECDH\kv_openssl\crypto\stackstack.h */
#ifndef HEADER_STACK_H
int sk_num(const _STACK *);
#endif

/* file: CHECKED_STACK_OF : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define CHECKED_STACK_OF(type, p) \
    ((_STACK*) (1 ? p : (STACK_OF(type)*)0))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: STACK_OF : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
typedef STACK_OF(ASN1_TYPE) ASN1_SEQUENCE_ANY;
#endif

/* file: sk_GENERAL_NAMES_new_null : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_GENERAL_NAMES_new_null() SKM_sk_new_null(GENERAL_NAMES)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: sk_OPENSSL_STRING_value : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_OPENSSL_STRING_value(st, i) ((OPENSSL_STRING)sk_value(CHECKED_STACK_OF(OPENSSL_STRING, st), i))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: sk_value : D:\PhD\ECDH\kv_openssl\crypto\stackstack.h */
#ifndef HEADER_STACK_H
void *sk_value(const _STACK *, int);
#endif


/* file: a2i_GENERAL_NAME : D:\PhD\ECDH\kv_openssl\crypto\x509v3x509v3.h */
#ifndef HEADER_X509V3_H
GENERAL_NAME *a2i_GENERAL_NAME(GENERAL_NAME *out,
			       const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
			       int gen_type, char *value, int is_nc);
#endif

/* file: X509V3err : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
#define X509V3err(f,r) ERR_PUT_error(ERR_LIB_X509V3,(f),(r),__FILE__,__LINE__)
#endif
/* file: ERR_PUT_error : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
#ifndef OPENSSL_NO_ERR
#define ERR_PUT_error(a,b,c,d,e)	ERR_put_error(a,b,c,d,e)
#else
/* file: ERR_PUT_error : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#define ERR_PUT_error(a,b,c,d,e)	ERR_put_error(a,b,c,NULL,0)
#endif
#endif
/* file: ERR_put_error : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
void ERR_put_error(int lib, int func,int reason,const char *file,int line);
#endif

/* file: strlen : D:\PhD\ECDH\kv_openssl\e_os.h */
#ifndef HEADER_E_OS_H
#if (defined(WINDOWS) || defined(MSDOS))
#  ifdef WINDOWS
#    ifdef _WIN64
#      define strlen(s) _strlen31(s)
#    endif
#  endif
#else /* The non-microsoft world */
#endif
#endif
/* file: _strlen31 : D:\PhD\ECDH\kv_openssl\e_os.h */
#ifndef HEADER_E_OS_H
#if (defined(WINDOWS) || defined(MSDOS))
#  ifdef WINDOWS
#    ifdef _WIN64
static unsigned int _strlen31(const char *str)
	{
	unsigned int len=0;
	while (*str && len<0x80000000U) str++, len++;
	return len&0x7FFFFFFF;
	}
#    endif
#  endif
#else /* The non-microsoft world */
#endif
#endif


/* file: ERR_get_state : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
ERR_STATE *ERR_get_state(void);
#endif

/* file: err_fns_check : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
static void err_fns_check(void) 	{
 if (err_fns) return; 	
 CRYPTO_w_lock(CRYPTO_LOCK_ERR);  if (!err_fns) 		err_fns = &err_defaults;
 CRYPTO_w_unlock(CRYPTO_LOCK_ERR); 	}
/* file: CRYPTO_w_lock : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_w_lock(type)	\
	CRYPTO_lock(CRYPTO_LOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#endif
#else
/* file: CRYPTO_w_lock : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#define CRYPTO_w_lock(a)
#endif
#endif

/* file: CRYPTO_w_unlock : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_w_unlock(type)	\
	CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#endif
#else
/* file: CRYPTO_w_unlock : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#define CRYPTO_w_unlock(a)
#endif
#endif


/* file: CRYPTO_THREADID_cpy : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest, const CRYPTO_THREADID *src);
#endif

/* file: ERRFN : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
#define ERRFN(a) err_fns->cb_##a

/* file: ERR_STATE_free : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
static void ERR_STATE_free(ERR_STATE *s);

/* file: err_clear_data : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
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
/* file: OPENSSL_free : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#define OPENSSL_free(addr)	CRYPTO_free(addr)
#endif
/* file: CRYPTO_free : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_free(void *ptr);
#endif

/* file: free_debug_func : D:\PhD\ECDH\kv_openssl\cryptomem.c */
#ifdef CRYPTO_MDEBUG
static void (*free_debug_func)(void *,int) = CRYPTO_dbg_free;
#else
/* file: free_debug_func : D:\PhD\ECDH\kv_openssl\cryptomem.c */
static void (*free_debug_func)(void *,int) = NULL;
#endif
/* file: CRYPTO_dbg_free : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_dbg_free(void *addr,int before_p);
#endif

/* file: MemCheck_off : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#define MemCheck_off()	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE)
#endif
/* file: CRYPTO_mem_ctrl : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
int CRYPTO_mem_ctrl(int mode);
#endif

/* file: CRYPTO_THREADID_cmp : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
int CRYPTO_THREADID_cmp(const CRYPTO_THREADID *a, const CRYPTO_THREADID *b);
#endif


/* file: lh_MEM_delete : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_MEM_delete(lh,inst) LHM_lh_delete(MEM,lh,inst)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: app_info_free : D:\PhD\ECDH\kv_openssl\cryptomem_dbg.c */
static void app_info_free(APP_INFO *);

/* file: MemCheck_on : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#define MemCheck_on()	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE)
#endif


/* file: free_func : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
int CRYPTO_set_locked_mem_functions(void *(*m)(size_t), void (*free_func)(void *));
#endif



/* file: ERR_PACK : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
#define ERR_PACK(l,f,r)		(((((unsigned long)l)&0xffL)*0x1000000)| \
				((((unsigned long)f)&0xfffL)*0x1000)| \
				((((unsigned long)r)&0xfffL)))
#endif



/* file: OBJ_txt2obj : D:\PhD\ECDH\kv_openssl\crypto\objectsobj_dat.c */
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
/* file: OBJ_sn2nid : D:\PhD\ECDH\kv_openssl\crypto\objectsobjects.h */
#ifndef HEADER_OBJECTS_H
int		OBJ_sn2nid(const char *s);
#endif

/* file: lh_ADDED_OBJ_retrieve : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_ADDED_OBJ_retrieve(lh,inst) LHM_lh_retrieve(ADDED_OBJ,lh,inst)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: OBJ_ln2nid : D:\PhD\ECDH\kv_openssl\crypto\objectsobjects.h */
#ifndef HEADER_OBJECTS_H
int		OBJ_ln2nid(const char *s);
#endif

/* file: OBJ_nid2obj : D:\PhD\ECDH\kv_openssl\crypto\objectsobj_dat.c */
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
/* file: OBJerr : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
#define OBJerr(f,r)  ERR_PUT_error(ERR_LIB_OBJ,(f),(r),__FILE__,__LINE__)
#endif


/* file: a2d_ASN1_OBJECT : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
int a2d_ASN1_OBJECT(unsigned char *out,int olen, const char *buf, int num);
#endif

/* file: ASN1err : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
#define ASN1err(f,r) ERR_PUT_error(ERR_LIB_ASN1,(f),(r),__FILE__,__LINE__)
#endif

/* file: BN_new : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
BIGNUM *BN_new(void);
#endif

/* file: BNerr : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
#define BNerr(f,r)   ERR_PUT_error(ERR_LIB_BN,(f),(r),__FILE__,__LINE__)
#endif

/* file: bn_check_top : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
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
#else /* !BN_DEBUG */
/* file: bn_check_top : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#define bn_check_top(a)
#endif
#endif
/* file: bn_pollute : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
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
/* file: bn_pollute : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#define bn_pollute(a)
#endif
#else /* !BN_DEBUG */
/* file: bn_pollute : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#define bn_pollute(a)
#endif
#endif
/* file: RAND_pseudo_bytes : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
#ifdef BN_DEBUG
#ifdef BN_DEBUG_RAND
#ifndef RAND_pseudo_bytes
int RAND_pseudo_bytes(unsigned char *buf,int num);
#endif
#else
#endif
#else /* !BN_DEBUG */
#endif
#endif

/* file: RAND_get_rand_method : D:\PhD\ECDH\kv_openssl\crypto\randrand.h */
#ifndef HEADER_RAND_H
const RAND_METHOD *RAND_get_rand_method(void);
#endif

/* file: ENGINE_get_default_RAND : D:\PhD\ECDH\kv_openssl\crypto\engineengine.h */
#ifndef HEADER_ENGINE_H
ENGINE *ENGINE_get_default_RAND(void);
#endif

/* file: engine_table_select : D:\PhD\ECDH\kv_openssl\crypto\engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
#ifndef ENGINE_TABLE_DEBUG
ENGINE *engine_table_select(ENGINE_TABLE **table, int nid);
#else
/* file: engine_table_select : D:\PhD\ECDH\kv_openssl\crypto\engineeng_int.h */
#define engine_table_select(t,n) engine_table_select_tmp(t,n,__FILE__,__LINE__)
#endif
#endif /* HEADER_ENGINE_INT_H */
/* file: engine_table_select_tmp : D:\PhD\ECDH\kv_openssl\crypto\engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
#ifndef ENGINE_TABLE_DEBUG
ENGINE *engine_table_select_tmp(ENGINE_TABLE **table, int nid, const char *f, int l);
#endif
#endif /* HEADER_ENGINE_INT_H */

/* file: ERR_set_mark : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
int ERR_set_mark(void);
#endif

/* file: int_table_check : D:\PhD\ECDH\kv_openssl\crypto\engineeng_table.c */
static int int_table_check(ENGINE_TABLE **t, int create) 	{
 LHASH_OF(ENGINE_PILE) *lh; 
 if(*t) return 1;  if(!create) return 0;  if((lh = lh_ENGINE_PILE_new()) == NULL) 		return 0;
 *t = (ENGINE_TABLE *)lh; 	return 1;
	}
/* file: LHASH_OF : D:\PhD\ECDH\kv_openssl\appsopenssl.c */
static LHASH_OF(FUNCTION) *prog_init(void );

/* file: lh_FUNCTION_new : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_FUNCTION_new() LHM_lh_new(FUNCTION,function)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: lh_FUNCTION_insert : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_FUNCTION_insert(lh,inst) LHM_lh_insert(FUNCTION,lh,inst)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: lh_ENGINE_PILE_new : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_ENGINE_PILE_new() LHM_lh_new(ENGINE_PILE,engine_pile)
#endif /* !defined HEADER_SAFESTACK_H */


/* file: lh_ENGINE_PILE_retrieve : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_ENGINE_PILE_retrieve(lh,inst) LHM_lh_retrieve(ENGINE_PILE,lh,inst)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: engine_unlocked_init : D:\PhD\ECDH\kv_openssl\crypto\engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
int engine_unlocked_init(ENGINE *e);
#endif /* HEADER_ENGINE_INT_H */

/* file: init : D:\PhD\ECDH\kv_openssl\crypto\evpevp.h */
#ifndef HEADER_ENVELOPE_H
	int (*init)(EVP_PKEY_CTX *ctx));
#endif

/* file: engine_ref_debug : D:\PhD\ECDH\kv_openssl\crypto\engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
#ifdef ENGINE_REF_COUNT_DEBUG
#define engine_ref_debug(e, isfunct, diff) \
	fprintf(stderr, "engine: %08x %s from %d to %d (%s:%d)\n", \
		(unsigned int)(e), (isfunct ? "funct" : "struct"), \
		((isfunct) ? ((e)->funct_ref - (diff)) : ((e)->struct_ref - (diff))), \
		((isfunct) ? (e)->funct_ref : (e)->struct_ref), \
		(__FILE__), (__LINE__));
#else
/* file: engine_ref_debug : D:\PhD\ECDH\kv_openssl\crypto\engineeng_int.h */
#define engine_ref_debug(e, isfunct, diff)
#endif
#endif /* HEADER_ENGINE_INT_H */

/* file: sk_ENGINE_value : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_ENGINE_value(st, i) SKM_sk_value(ENGINE, (st), (i))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: SKM_sk_value : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define SKM_sk_value(type, st,i) \
	((type *)sk_value(CHECKED_STACK_OF(type, st), i))
#endif /* !defined HEADER_SAFESTACK_H */


/* file: engine_unlocked_finish : D:\PhD\ECDH\kv_openssl\crypto\engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
int engine_unlocked_finish(ENGINE *e, int unlock_for_handlers);
#endif /* HEADER_ENGINE_INT_H */

/* file: engine_free_util : D:\PhD\ECDH\kv_openssl\crypto\engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
int engine_free_util(ENGINE *e, int locked);
#endif /* HEADER_ENGINE_INT_H */

/* file: ENGINEerr : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
#define ENGINEerr(f,r) ERR_PUT_error(ERR_LIB_ENGINE,(f),(r),__FILE__,__LINE__)
#endif

/* file: CRYPTO_add : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_add(addr,amount,type)	\
	CRYPTO_add_lock(addr,amount,type,__FILE__,__LINE__)
#endif
#else
/* file: CRYPTO_add : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#define CRYPTO_add(a,b,c)	((*(a))+=(b))
#endif
#endif
/* file: CRYPTO_add_lock : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
int CRYPTO_add_lock(int *pointer,int amount,int type, const char *file,
		    int line);
#endif

/* file: add_lock_callback : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
static int (MS_FAR *add_lock_callback)(int *pointer,int amount,
	int type,const char *file,int line)=0;


/* file: engine_pkey_meths_free : D:\PhD\ECDH\kv_openssl\crypto\engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
void engine_pkey_meths_free(ENGINE *e);
#endif /* HEADER_ENGINE_INT_H */

/* file: EVP_PKEY_meth_free : D:\PhD\ECDH\kv_openssl\crypto\evpevp.h */
#ifndef HEADER_ENVELOPE_H
void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth);
#endif

/* file: engine_pkey_asn1_meths_free : D:\PhD\ECDH\kv_openssl\crypto\engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
void engine_pkey_asn1_meths_free(ENGINE *e);
#endif /* HEADER_ENGINE_INT_H */

/* file: EVP_PKEY_asn1_free : D:\PhD\ECDH\kv_openssl\crypto\evpevp.h */
#ifndef HEADER_ENVELOPE_H
void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth);
#endif

/* file: CRYPTO_free_ex_data : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
#endif

/* file: EX_IMPL : D:\PhD\ECDH\kv_openssl\cryptoex_data.c */
#define EX_IMPL(a) impl->cb_##a

/* file: ERR_pop_to_mark : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
int ERR_pop_to_mark(void);
#endif

/* file: err_clear : D:\PhD\ECDH\kv_openssl\crypto\errerr.c */
#define err_clear(p,i) \
	do { \
	(p)->err_flags[i]=0; \
	(p)->err_buffer[i]=0; \
	err_clear_data(p,i); \
	(p)->err_file[i]=NULL; \
	(p)->err_line[i]= -1; \
	} while(0)


/* file: ENGINE_get_RAND : D:\PhD\ECDH\kv_openssl\crypto\engineengine.h */
#ifndef HEADER_ENGINE_H
const RAND_METHOD *ENGINE_get_RAND(const ENGINE *e);
#endif

/* file: ENGINE_finish : D:\PhD\ECDH\kv_openssl\crypto\engineengine.h */
#ifndef HEADER_ENGINE_H
int ENGINE_finish(ENGINE *e);
#endif

/* file: RAND_SSLeay : D:\PhD\ECDH\kv_openssl\crypto\randrand.h */
#ifndef HEADER_RAND_H
RAND_METHOD *RAND_SSLeay(void);
#endif



/* file: BN_set_word : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
int	BN_set_word(BIGNUM *a, BN_ULONG w);
#endif

/* file: bn_expand : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
#define bn_expand(a,bits) ((((((bits+BN_BITS2-1))/BN_BITS2)) <= (a)->dmax)?\
	(a):bn_expand2((a),(bits+BN_BITS2-1)/BN_BITS2))
#endif
/* file: bn_expand2 : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
BIGNUM *bn_expand2(BIGNUM *a, int words);
#endif

/* file: bn_expand_internal : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lib.c */
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
 memset(A,0,sizeof(BN_ULONG)*words);  memcpy(A,b->d,sizeof(b->d[0])*b->top); #endif
		
 return(a); 	}
/* file: BN_get_flags : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
#define BN_get_flags(b,n)	((b)->flags&(n))
#endif



/* file: BN_mul_word : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
int	BN_mul_word(BIGNUM *a, BN_ULONG w);
#endif

/* file: BN_zero : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
#ifdef OPENSSL_NO_DEPRECATED
#define BN_zero(a)	BN_zero_ex(a)
#else
/* file: BN_zero : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#define BN_zero(a)	(BN_set_word((a),0))
#endif
#endif
/* file: BN_zero_ex : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
#define BN_zero_ex(a) \
	do { \
		BIGNUM *_tmp_bn = (a); \
		_tmp_bn->top = 0; \
		_tmp_bn->neg = 0; \
	} while(0)
#endif


/* file: bn_mul_words : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);
#endif

/* file: mul : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
#ifdef BN_LLONG
#define mul(r,a,w,c) { \
	BN_ULLONG t; \
	t=(BN_ULLONG)w * (a) + (c); \
	(r)= Lw(t); \
	(c)= Hw(t); \
	}
#endif
#endif
/* file: Lw : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
#define Lw(t)    (((BN_ULONG)(t))&BN_MASK2)
#endif

/* file: Hw : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
#define Hw(t)    (((BN_ULONG)((t)>>BN_BITS2))&BN_MASK2)
#endif


/* file: LBITS : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
#ifdef BN_LLONG
#define LBITS(a)	((a)&BN_MASK2l)
#endif /* !BN_LLONG */
#endif

/* file: HBITS : D:\PhD\ECDH\kv_openssl\crypto\bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
#ifdef BN_LLONG
#define HBITS(a)	(((a)>>BN_BITS4)&BN_MASK2l)
#endif /* !BN_LLONG */
#endif

/* file: bn_wexpand : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
#define bn_wexpand(a,words) (((words) <= (a)->dmax)?(a):bn_expand2((a),(words)))
#endif

/* file: BN_add_word : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
int	BN_add_word(BIGNUM *a, BN_ULONG w);
#endif

/* file: BN_sub_word : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
int	BN_sub_word(BIGNUM *a, BN_ULONG w);
#endif

/* file: BN_set_negative : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
void	BN_set_negative(BIGNUM *b, int n);
#endif

/* file: BN_num_bits : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
int	BN_num_bits(const BIGNUM *a);
#endif

/* file: BN_num_bits_word : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
int	BN_num_bits_word(BN_ULONG);
#endif

/* file: BN_div_word : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);
#endif

/* file: BN_lshift : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
int	BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
#endif

/* file: bn_correct_top : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
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
#endif

/* file: bn_div_words : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d);
#endif

/* file: BN_free : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
void	BN_free(BIGNUM *a);
#endif

/* file: ASN1_object_size : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_object_size(int constructed, int length, int tag);
#endif

/* file: ASN1_put_object : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
void ASN1_put_object(unsigned char **pp, int constructed, int length,
	int tag, int xclass);
#endif

/* file: asn1_put_length : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_lib.c */
static void asn1_put_length(unsigned char **pp, int length);

/* file: d2i_ASN1_OBJECT : D:\PhD\ECDH\kv_openssl\crypto\asn1a_object.c */
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
/* file: ASN1_get_object : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
	int *pclass, long omax);
#endif

/* file: asn1_get_length : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_lib.c */
static int asn1_get_length(const unsigned char **pp,int *inf,long *rl,int max);

/* file: c2i_ASN1_OBJECT : D:\PhD\ECDH\kv_openssl\crypto\asn1a_object.c */
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
/* file: ASN1_OBJECT_new : D:\PhD\ECDH\kv_openssl\crypto\asn1a_object.c */
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

/* file: ASN1_OBJECT_free : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
void		ASN1_OBJECT_free(ASN1_OBJECT *a);
#endif




/* file: ERR_add_error_data : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
void ERR_add_error_data(int num, ...);
#endif

/* file: ERR_add_error_vdata : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
void ERR_add_error_vdata(int num, va_list args);
#endif

/* file: OPENSSL_realloc : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#define OPENSSL_realloc(addr,num) \
	CRYPTO_realloc((char *)addr,(int)num,__FILE__,__LINE__)
#endif
/* file: CRYPTO_realloc : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void *CRYPTO_realloc(void *addr,int num, const char *file, int line);
#endif

/* file: realloc_debug_func : D:\PhD\ECDH\kv_openssl\cryptomem.c */
#ifdef CRYPTO_MDEBUG
static void (*realloc_debug_func)(void *,void *,int,const char *,int,int)
	= CRYPTO_dbg_realloc;
#else
/* file: realloc_debug_func : D:\PhD\ECDH\kv_openssl\cryptomem.c */
static void (*realloc_debug_func)(void *,void *,int,const char *,int,int)
	= NULL;
#endif
/* file: CRYPTO_dbg_realloc : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_dbg_realloc(void *addr1,void *addr2,int num,const char *file,int line,int before_p);
#endif

/* file: lh_MEM_insert : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_MEM_insert(lh,inst) LHM_lh_insert(MEM,lh,inst)
#endif /* !defined HEADER_SAFESTACK_H */


/* file: realloc_ex_func : D:\PhD\ECDH\kv_openssl\cryptomem.c */
static void *(*realloc_ex_func)(void *, size_t, const char *file, int line)
        = default_realloc_ex;
/* file: default_realloc_ex : D:\PhD\ECDH\kv_openssl\cryptomem.c */
static void *default_realloc_ex(void *str, size_t num,         const char *file, int line)
 { return realloc_func(str,num); } /* file: realloc_func : D:\PhD\ECDH\kv_openssl\cryptomem.c */
static void *(*realloc_func)(void *, size_t)= realloc;




/* file: BUF_strlcat : D:\PhD\ECDH\kv_openssl\crypto\bufferbuffer.h */
#ifndef HEADER_BUFFER_H
size_t BUF_strlcat(char *dst,const char *src,size_t siz);
#endif

/* file: BUF_strlcpy : D:\PhD\ECDH\kv_openssl\crypto\bufferbuffer.h */
#ifndef HEADER_BUFFER_H
size_t BUF_strlcpy(char *dst,const char *src,size_t siz);
#endif

/* file: ERR_set_error_data : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
void ERR_set_error_data(char *data,int flags);
#endif

/* file: a2i_IPADDRESS_NC : D:\PhD\ECDH\kv_openssl\crypto\x509v3x509v3.h */
#ifndef HEADER_X509V3_H
ASN1_OCTET_STRING *a2i_IPADDRESS_NC(const char *ipasc);
#endif

/* file: BUF_strdup : D:\PhD\ECDH\kv_openssl\crypto\bufferbuf_str.c */
char *BUF_strdup(const char *str)
	{
	if (str == NULL) return(NULL);
	return BUF_strndup(str, strlen(str));
	}

/* file: a2i_ipadd : D:\PhD\ECDH\kv_openssl\crypto\x509v3x509v3.h */
#ifndef HEADER_X509V3_H
int a2i_ipadd(unsigned char *ipout, const char *ipasc);
#endif

/* file: ipv6_from_asc : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_utl.c */
static int ipv6_from_asc(unsigned char *v6, const char *in);

/* file: CONF_parse_list : D:\PhD\ECDH\kv_openssl\crypto\confconf.h */
int CONF_parse_list(const char *list, int sep, int nospc,
	int (*list_cb)(const char *elem, int len, void *usr), void *arg);

/* file: CONFerr : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
#define CONFerr(f,r) ERR_PUT_error(ERR_LIB_CONF,(f),(r),__FILE__,__LINE__)
#endif

/* file: list_cb : D:\PhD\ECDH\kv_openssl\crypto\confconf.h */
	int (*list_cb)(const char *elem, int len, void *usr), void *arg);

/* file: ipv4_from_asc : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_utl.c */
static int ipv4_from_asc(unsigned char *v4, const char *in);

/* file: ASN1_OCTET_STRING_set : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
int 	ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data, int len);
#endif

/* file: a2i_IPADDRESS : D:\PhD\ECDH\kv_openssl\crypto\x509v3x509v3.h */
#ifndef HEADER_X509V3_H
ASN1_OCTET_STRING *a2i_IPADDRESS(const char *ipasc);
#endif

/* file: do_dirname : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_alt.c */
static int do_dirname(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx);

/* file: X509V3_NAME_from_section : D:\PhD\ECDH\kv_openssl\crypto\x509v3x509v3.h */
#ifndef HEADER_X509V3_H
int X509V3_NAME_from_section(X509_NAME *nm, STACK_OF(CONF_VALUE)*dn_sk,
						unsigned long chtype);
#endif

/* file: sk_CONF_VALUE_num : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_CONF_VALUE_num(st) SKM_sk_num(CONF_VALUE, (st))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: sk_CONF_VALUE_value : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_CONF_VALUE_value(st, i) SKM_sk_value(CONF_VALUE, (st), (i))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: X509_NAME_add_entry_by_txt : D:\PhD\ECDH\kv_openssl\crypto\x509x509.h */
#ifndef HEADER_X509_H
int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type,
			const unsigned char *bytes, int len, int loc, int set);
#endif

/* file: X509_NAME_ENTRY_create_by_txt : D:\PhD\ECDH\kv_openssl\crypto\x509x509.h */
#ifndef HEADER_X509_H
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne,
		const char *field, int type, const unsigned char *bytes, int len);
#endif

/* file: X509err : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
#define X509err(f,r) ERR_PUT_error(ERR_LIB_X509,(f),(r),__FILE__,__LINE__)
#endif

/* file: X509_NAME_ENTRY_create_by_OBJ : D:\PhD\ECDH\kv_openssl\crypto\x509x509.h */
#ifndef HEADER_X509_H
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_OBJ(X509_NAME_ENTRY **ne,
			ASN1_OBJECT *obj, int type,const unsigned char *bytes,
			int len);
#endif

/* file: X509_NAME_ENTRY_set_object : D:\PhD\ECDH\kv_openssl\crypto\x509x509.h */
#ifndef HEADER_X509_H
int 		X509_NAME_ENTRY_set_object(X509_NAME_ENTRY *ne,
			ASN1_OBJECT *obj);
#endif

/* file: OBJ_dup : D:\PhD\ECDH\kv_openssl\crypto\objectsobj_lib.c */
ASN1_OBJECT *OBJ_dup(const ASN1_OBJECT *o)
	{
	ASN1_OBJECT *r;
	int i;
	char *ln=NULL,*sn=NULL;
	unsigned char *data=NULL;

	if (o == NULL) return(NULL);
	if (!(o->flags & ASN1_OBJECT_FLAG_DYNAMIC))
		return((ASN1_OBJECT *)o); /* XXX: ugh! Why? What kind of
					     duplication is this??? */

	r=ASN1_OBJECT_new();
	if (r == NULL)
		{
		OBJerr(OBJ_F_OBJ_DUP,ERR_R_ASN1_LIB);
		return(NULL);
		}
	data=OPENSSL_malloc(o->length);
	if (data == NULL)
		goto err;
	if (o->data != NULL)
		memcpy(data,o->data,o->length);
	/* once data attached to object it remains const */
	r->data = data;
	r->length=o->length;
	r->nid=o->nid;
	r->ln=r->sn=NULL;
	if (o->ln != NULL)
		{
		i=strlen(o->ln)+1;
		ln=OPENSSL_malloc(i);
		if (ln == NULL) goto err;
		memcpy(ln,o->ln,i);
		r->ln=ln;
		}

	if (o->sn != NULL)
		{
		i=strlen(o->sn)+1;
		sn=OPENSSL_malloc(i);
		if (sn == NULL) goto err;
		memcpy(sn,o->sn,i);
		r->sn=sn;
		}
	r->flags=o->flags|(ASN1_OBJECT_FLAG_DYNAMIC|
		ASN1_OBJECT_FLAG_DYNAMIC_STRINGS|ASN1_OBJECT_FLAG_DYNAMIC_DATA);
	return(r);
err:
	OBJerr(OBJ_F_OBJ_DUP,ERR_R_MALLOC_FAILURE);
	if (ln != NULL)		OPENSSL_free(ln);
	if (sn != NULL)		OPENSSL_free(sn);
	if (data != NULL)	OPENSSL_free(data);
	if (r != NULL)		OPENSSL_free(r);
	return(NULL);
	}

/* file: X509_NAME_ENTRY_set_data : D:\PhD\ECDH\kv_openssl\crypto\x509x509.h */
#ifndef HEADER_X509_H
int 		X509_NAME_ENTRY_set_data(X509_NAME_ENTRY *ne, int type,
			const unsigned char *bytes, int len);
#endif

/* file: ASN1_STRING_set_by_NID : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out, 
		const unsigned char *in, int inlen, int inform, int nid);
#endif

/* file: ASN1_STRING_TABLE_get : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid);
#endif

/* file: sk_ASN1_STRING_TABLE_find : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_ASN1_STRING_TABLE_find(st, val) SKM_sk_find(ASN1_STRING_TABLE, (st), (val))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: SKM_sk_find : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define SKM_sk_find(type, st, val) \
	sk_find(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: sk_find : D:\PhD\ECDH\kv_openssl\crypto\stackstack.h */
#ifndef HEADER_STACK_H
int sk_find(_STACK *st, void *data);
#endif

/* file: internal_find : D:\PhD\ECDH\kv_openssl\crypto\stackstack.c */
static int internal_find(_STACK *st, void *data, int ret_val_options) 	{
	const void * const *r;
	int i;

 if(st == NULL) return -1; 
 if (st->comp == NULL) 		{
  for (i=0; i<st->num; i++)    if (st->data[i] == data)     return(i);   return(-1); 		}
 sk_sort(st);  if (data == NULL) return(-1);  r=OBJ_bsearch_ex_(&data,st->data,st->num,sizeof(void *),st->comp, 			  ret_val_options);
 if (r == NULL) return(-1);  return (int)((char **)r-st->data); 	}
/* file: sk_sort : D:\PhD\ECDH\kv_openssl\crypto\stackstack.h */
#ifndef HEADER_STACK_H
void sk_sort(_STACK *st);
#endif

/* file: OBJ_bsearch_ex_ : D:\PhD\ECDH\kv_openssl\crypto\objectsobj_dat.c */
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


/* file: CHECKED_PTR_OF : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#ifndef CHECKED_PTR_OF
#define CHECKED_PTR_OF(type, p) \
    ((void*) (1 ? p : (type*)0))
#endif
#endif /* !defined HEADER_SAFESTACK_H */



/* file: sk_ASN1_STRING_TABLE_value : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_ASN1_STRING_TABLE_value(st, i) SKM_sk_value(ASN1_STRING_TABLE, (st), (i))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: ASN1_mbstring_ncopy : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
					int inform, unsigned long mask, 
					long minsize, long maxsize);
#endif

/* file: traverse_string : D:\PhD\ECDH\kv_openssl\crypto\asn1a_mbstr.c */
static int traverse_string(const unsigned char *p, int len, int inform,
		 int (*rfunc)(unsigned long value, void *in), void *arg);

/* file: BIO_snprintf : D:\PhD\ECDH\kv_openssl\crypto\biobio.h */
#ifndef HEADER_BIO_H
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
	__bio_h__attr__((__format__(__printf__,3,4)));
#endif

/* file: BIO_vsnprintf : D:\PhD\ECDH\kv_openssl\crypto\biobio.h */
#ifndef HEADER_BIO_H
int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
	__bio_h__attr__((__format__(__printf__,3,0)));
#endif

/* file: _dopr : D:\PhD\ECDH\kv_openssl\crypto\biob_print.c */
static void _dopr(char **sbuffer, char **buffer,
		  size_t *maxlen, size_t *retlen, int *truncated,
		  const char *format, va_list args);

/* file: doapr_outch : D:\PhD\ECDH\kv_openssl\crypto\biob_print.c */
static void doapr_outch (char **, char **, size_t *, size_t *, int);

/* file: char_to_int : D:\PhD\ECDH\kv_openssl\crypto\biob_print.c */
#define char_to_int(p) (p - '0')

/* file: fmtint : D:\PhD\ECDH\kv_openssl\crypto\biob_print.c */
static void fmtint     (char **, char **, size_t *, size_t *,
			LLONG, int, int, int, int);

/* file: fmtfp : D:\PhD\ECDH\kv_openssl\crypto\biob_print.c */
static void fmtfp      (char **, char **, size_t *, size_t *,
			LDOUBLE, int, int, int);

/* file: fmtstr : D:\PhD\ECDH\kv_openssl\crypto\biob_print.c */
static void fmtstr     (char **, char **, size_t *, size_t *,
			const char *, int, int, int);

/* file: ASN1_STRING_type_new : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_lib.c */
ASN1_STRING *ASN1_STRING_type_new(int type) 	{
	ASN1_STRING *ret;

 ret=(ASN1_STRING *)OPENSSL_malloc(sizeof(ASN1_STRING));  if (ret == NULL) 		{
  ASN1err(ASN1_F_ASN1_STRING_TYPE_NEW,ERR_R_MALLOC_FAILURE);   return(NULL); 		}
	ret->length=0;
	ret->type=type;
	ret->data=NULL;
	ret->flags=0;
 return(ret); 	}

/* file: ASN1_STRING_set : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
int 		ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);
#endif

/* file: ASN1_STRING_free : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
void		ASN1_STRING_free(ASN1_STRING *a);
#endif

/* file: ASN1_mbstring_copy : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
					int inform, unsigned long mask);
#endif

/* file: OBJ_obj2nid : D:\PhD\ECDH\kv_openssl\crypto\objectsobjects.h */
#ifndef HEADER_OBJECTS_H
int		OBJ_obj2nid(const ASN1_OBJECT *o);
#endif

/* file: ASN1_PRINTABLE_type : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_PRINTABLE_type(const unsigned char *s, int max);
#endif

/* file: X509_NAME_add_entry : D:\PhD\ECDH\kv_openssl\crypto\x509x509.h */
#ifndef HEADER_X509_H
int 		X509_NAME_add_entry(X509_NAME *name,X509_NAME_ENTRY *ne,
			int loc, int set);
#endif

/* file: sk_X509_NAME_ENTRY_num : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_X509_NAME_ENTRY_num(st) SKM_sk_num(X509_NAME_ENTRY, (st))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: sk_X509_NAME_ENTRY_value : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_X509_NAME_ENTRY_value(st, i) SKM_sk_value(X509_NAME_ENTRY, (st), (i))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: X509_NAME_ENTRY_dup : D:\PhD\ECDH\kv_openssl\crypto\x509x509.h */
#ifndef HEADER_X509_H
X509_NAME_ENTRY *X509_NAME_ENTRY_dup(X509_NAME_ENTRY *ne);
#endif

/* file: sk_X509_NAME_ENTRY_insert : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_X509_NAME_ENTRY_insert(st, val, i) SKM_sk_insert(X509_NAME_ENTRY, (st), (val), (i))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: SKM_sk_insert : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define SKM_sk_insert(type, st,val, i) \
	sk_insert(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val), i)
#endif /* !defined HEADER_SAFESTACK_H */
/* file: sk_insert : D:\PhD\ECDH\kv_openssl\crypto\stackstack.h */
#ifndef HEADER_STACK_H
int sk_insert(_STACK *sk, void *data, int where);
#endif

/* file: memmove : D:\PhD\ECDH\kv_openssl\e_os.h */
#ifndef HEADER_E_OS_H
#if defined(sun) && !defined(__svr4__) && !defined(__SVR4)
# define memmove(s1,s2,n) bcopy((s2),(s1),(n))
#endif
#endif



/* file: X509V3_section_free : D:\PhD\ECDH\kv_openssl\crypto\x509v3x509v3.h */
#ifndef HEADER_X509V3_H
void X509V3_section_free( X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section);
#endif

/* file: do_othername : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_alt.c */
static int do_othername(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx);

/* file: ASN1_generate_v3 : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
ASN1_TYPE *ASN1_generate_v3(char *str, X509V3_CTX *cnf);
#endif

/* file: asn1_multi : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_gen.c */
static ASN1_TYPE *asn1_multi(int utype, const char *section, X509V3_CTX *cnf);

/* file: sk_ASN1_TYPE_new_null : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_ASN1_TYPE_new_null() SKM_sk_new_null(ASN1_TYPE)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: sk_ASN1_TYPE_push : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_ASN1_TYPE_push(st, val) SKM_sk_push(ASN1_TYPE, (st), (val))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: SKM_sk_push : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define SKM_sk_push(type, st, val) \
	sk_push(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: sk_push : D:\PhD\ECDH\kv_openssl\crypto\stackstack.h */
#ifndef HEADER_STACK_H
int sk_push(_STACK *st, void *data);
#endif



/* file: sk_ASN1_TYPE_pop_free : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_ASN1_TYPE_pop_free(st, free_func) SKM_sk_pop_free(ASN1_TYPE, (st), (free_func))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: SKM_sk_pop_free : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define SKM_sk_pop_free(type, st, free_func) \
	sk_pop_free(CHECKED_STACK_OF(type, st), CHECKED_SK_FREE_FUNC(type, free_func))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: CHECKED_SK_FREE_FUNC : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define CHECKED_SK_FREE_FUNC(type, p) \
    ((void (*)(void *)) ((1 ? p : (void (*)(type *))0)))
#endif /* !defined HEADER_SAFESTACK_H */



/* file: asn1_str2type : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_gen.c */
static ASN1_TYPE *asn1_str2type(const char *str, int format, int utype);

/* file: X509V3_get_value_bool : D:\PhD\ECDH\kv_openssl\crypto\x509v3x509v3.h */
#ifndef HEADER_X509V3_H
#ifdef HEADER_CONF_H
int X509V3_get_value_bool(CONF_VALUE *value, int *asn1_bool);
#endif
#endif

/* file: X509V3_conf_err : D:\PhD\ECDH\kv_openssl\crypto\x509v3x509v3.h */
#ifndef HEADER_X509V3_H
#define X509V3_conf_err(val) ERR_add_error_data(6, "section:", val->section, \
",name:", val->name, ",value:", val->value);
#endif

/* file: s2i_ASN1_INTEGER : D:\PhD\ECDH\kv_openssl\crypto\x509v3v3_utl.c */
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
/* file: BN_hex2bn : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
int 	BN_hex2bn(BIGNUM **a, const char *str);
#endif

/* file: BN_dec2bn : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
int 	BN_dec2bn(BIGNUM **a, const char *str);
#endif

/* file: BN_to_ASN1_INTEGER : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
#endif

/* file: M_ASN1_INTEGER_new : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
#define M_ASN1_INTEGER_new()	(ASN1_INTEGER *)\
		ASN1_STRING_type_new(V_ASN1_INTEGER)
#endif

/* file: BN_is_negative : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
#define BN_is_negative(a) ((a)->neg != 0)
#endif

/* file: BN_bn2bin : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
int	BN_bn2bin(const BIGNUM *a, unsigned char *to);
#endif

/* file: BN_num_bytes : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
#define BN_num_bytes(a)	((BN_num_bits(a)+7)/8)
#endif

/* file: M_ASN1_INTEGER_free : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
#define M_ASN1_INTEGER_free(a)		ASN1_STRING_free((ASN1_STRING *)a)
#endif


/* file: ASN1_STRING_new : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1_lib.c */
ASN1_STRING *ASN1_STRING_new(void) 	{
 return(ASN1_STRING_type_new(V_ASN1_OCTET_STRING)); 	}

/* file: ASN1_TIME_check : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_TIME_check(ASN1_TIME *t);
#endif

/* file: ASN1_GENERALIZEDTIME_check : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_GENERALIZEDTIME_check(ASN1_GENERALIZEDTIME *a);
#endif

/* file: ASN1_UTCTIME_check : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_UTCTIME_check(ASN1_UTCTIME *a);
#endif

/* file: ASN1_tag2bit : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
unsigned long ASN1_tag2bit(int tag);
#endif

/* file: string_to_hex : D:\PhD\ECDH\kv_openssl\crypto\x509v3x509v3.h */
#ifndef HEADER_X509V3_H
unsigned char *string_to_hex(const char *str, long *len);
#endif

/* file: M_ASN1_IA5STRING_new : D:\PhD\ECDH\kv_openssl\crypto\asn1asn1.h */
#ifndef HEADER_ASN1_H
#define M_ASN1_IA5STRING_new()	(ASN1_IA5STRING *)\
		ASN1_STRING_type_new(V_ASN1_IA5STRING)
#endif

/* file: sk_GENERAL_NAME_push : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_GENERAL_NAME_push(st, val) SKM_sk_push(GENERAL_NAME, (st), (val))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: sk_GENERAL_NAMES_push : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_GENERAL_NAMES_push(st, val) SKM_sk_push(GENERAL_NAMES, (st), (val))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: sk_GENERAL_NAMES_pop_free : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_GENERAL_NAMES_pop_free(st, free_func) SKM_sk_pop_free(GENERAL_NAMES, (st), (free_func))
#endif /* !defined HEADER_SAFESTACK_H */




/* file: CRYPTO_get_dynlock_value : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
struct CRYPTO_dynlock_value *CRYPTO_get_dynlock_value(int i);
#endif

/* file: sk_CRYPTO_dynlock_num : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_CRYPTO_dynlock_num(st) SKM_sk_num(CRYPTO_dynlock, (st))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: sk_CRYPTO_dynlock_value : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_CRYPTO_dynlock_value(st, i) SKM_sk_value(CRYPTO_dynlock, (st), (i))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: OPENSSL_assert : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#define OPENSSL_assert(e)       (void)((e) ? 0 : (OpenSSLDie(__FILE__, __LINE__, #e),1))
#endif
/* file: OpenSSLDie : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void OpenSSLDie(const char *file,int line,const char *assertion);
#endif

/* file: OPENSSL_showfatal : D:\PhD\ECDH\kv_openssl\cryptocryptlib.h */
#ifndef HEADER_CRYPTLIB_H
void OPENSSL_showfatal(const char *fmta,...);
#endif

/* file: alloca : D:\PhD\ECDH\kv_openssl\crypto\bnbn_exp.c */
#ifdef _WIN32
# ifndef alloca
#  define alloca(s) __builtin_alloca((s))
# endif
#endif

/* file: OPENSSL_isservice : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
int OPENSSL_isservice(void);
#endif


/* file: dynlock_lock_callback : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
static void (MS_FAR *dynlock_lock_callback)(int mode,
	struct CRYPTO_dynlock_value *l, const char *file,int line)=0;

/* file: CRYPTO_destroy_dynlockid : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_destroy_dynlockid(int i);
#endif

/* file: sk_CRYPTO_dynlock_set : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_CRYPTO_dynlock_set(st, i, val) SKM_sk_set(CRYPTO_dynlock, (st), (i), (val))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: dynlock_destroy_callback : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
static void (MS_FAR *dynlock_destroy_callback)(struct CRYPTO_dynlock_value *l,
	const char *file,int line)=0;

/* file: locking_callback : D:\PhD\ECDH\kv_openssl\cryptocryptlib.c */
static void (MS_FAR *locking_callback)(int mode,int type,
	const char *file,int line)=0;


/* file: CRYPTO_r_unlock : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_r_unlock(type)	\
	CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#endif
#else
/* file: CRYPTO_r_unlock : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#define CRYPTO_r_unlock(a)
#endif
#endif


/* file: lh_MEM_new : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_MEM_new() LHM_lh_new(MEM,mem)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: lh_APP_INFO_retrieve : D:\PhD\ECDH\kv_openssl\crypto\stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_APP_INFO_retrieve(lh,inst) LHM_lh_retrieve(APP_INFO,lh,inst)
#endif /* !defined HEADER_SAFESTACK_H */


/* file: malloc_ex_func : D:\PhD\ECDH\kv_openssl\cryptomem.c */
static void *(*malloc_ex_func)(size_t, const char *file, int line)
        = default_malloc_ex;
/* file: default_malloc_ex : D:\PhD\ECDH\kv_openssl\cryptomem.c */
static void *default_malloc_ex(size_t num, const char *file, int line)
	{ return malloc_func(num); }



/* file: ECerr : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
#define ECerr(f,r)   ERR_PUT_error(ERR_LIB_EC,(f),(r),__FILE__,__LINE__)
#endif

/* file: EC_GROUP_new_by_curve_name : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
#endif

/* file: ec_group_new_from_data : D:\PhD\ECDH\kv_openssl\crypto\ecec_curve.c */
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
/* file: BN_CTX_new : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
BN_CTX *BN_CTX_new(void);
#endif

/* file: BN_POOL_init : D:\PhD\ECDH\kv_openssl\crypto\bnbn_ctx.c */
static void		BN_POOL_init(BN_POOL *);

/* file: BN_STACK_init : D:\PhD\ECDH\kv_openssl\crypto\bnbn_ctx.c */
static void		BN_STACK_init(BN_STACK *);

/* file: BN_bin2bn : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
BIGNUM *BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret);
#endif

/* file: EC_GROUP_new : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
EC_GROUP *EC_GROUP_new(const EC_METHOD *meth);
#endif

/* file: BN_init : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
void	BN_init(BIGNUM *);
#endif

/* file: EC_GROUP_new_curve_GFp : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
#endif

/* file: EC_GFp_mont_method : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
const EC_METHOD *EC_GFp_mont_method(void);
#endif

/* file: EC_GFp_nist_method : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
const EC_METHOD *EC_GFp_nist_method(void);
#endif

/* file: EC_GROUP_set_curve_GFp : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
#endif

/* file: ERR_peek_last_error : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
unsigned long ERR_peek_last_error(void);
#endif

/* file: ERR_GET_REASON : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
#define ERR_GET_REASON(l)	(int)((l)&0xfffL)
#endif

/* file: EC_GROUP_clear_free : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
void EC_GROUP_clear_free(EC_GROUP *group);
#endif

/* file: EC_EX_DATA_clear_free_all_data : D:\PhD\ECDH\kv_openssl\crypto\ecec_lcl.h */
void EC_EX_DATA_clear_free_all_data(EC_EXTRA_DATA **);

/* file: clear_free_func : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));
/* file: clear_free_func : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));
#endif

/* file: EC_POINT_clear_free : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
void EC_POINT_clear_free(EC_POINT *point);
#endif

/* file: OPENSSL_cleanse : D:\PhD\ECDH\kv_openssl\cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void OPENSSL_cleanse(void *ptr, size_t len);
#endif

/* file: BN_clear_free : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
void	BN_clear_free(BIGNUM *a);
#endif

/* file: ERR_clear_error : D:\PhD\ECDH\kv_openssl\crypto\errerr.h */
#ifndef HEADER_ERR_H
void ERR_clear_error(void );
#endif

/* file: EC_GROUP_new_curve_GF2m : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
#ifndef OPENSSL_NO_EC2M
EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
#endif
#endif

/* file: EC_GF2m_simple_method : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
#ifndef OPENSSL_NO_EC2M
const EC_METHOD *EC_GF2m_simple_method(void);
#endif
#endif

/* file: EC_GROUP_set_curve_GF2m : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
#ifndef OPENSSL_NO_EC2M
int EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
#endif
#endif

/* file: EC_POINT_new : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
EC_POINT *EC_POINT_new(const EC_GROUP *group);
#endif

/* file: EC_POINT_set_affine_coordinates_GFp : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
	const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
#endif

/* file: EC_GROUP_set_generator : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);
#endif

/* file: EC_POINT_copy : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
int EC_POINT_copy(EC_POINT *dst, const EC_POINT *src);
#endif

/* file: BN_copy : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
#endif

/* file: EC_GROUP_set_seed : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);
#endif

/* file: EC_GROUP_free : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
void EC_GROUP_free(EC_GROUP *group);
#endif

/* file: EC_EX_DATA_free_all_data : D:\PhD\ECDH\kv_openssl\crypto\ecec_lcl.h */
void EC_EX_DATA_free_all_data(EC_EXTRA_DATA **);

/* file: EC_POINT_free : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
void EC_POINT_free(EC_POINT *point);
#endif

/* file: BN_CTX_free : D:\PhD\ECDH\kv_openssl\crypto\bnbn.h */
#ifndef HEADER_BN_H
void	BN_CTX_free(BN_CTX *c);
#endif

/* file: BN_STACK_finish : D:\PhD\ECDH\kv_openssl\crypto\bnbn_ctx.c */
static void		BN_STACK_finish(BN_STACK *);

/* file: BN_POOL_finish : D:\PhD\ECDH\kv_openssl\crypto\bnbn_ctx.c */
static void		BN_POOL_finish(BN_POOL *);


/* file: EC_GROUP_set_curve_name : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
void EC_GROUP_set_curve_name(EC_GROUP *group, int nid);
#endif

/* file: EC_KEY_free : D:\PhD\ECDH\kv_openssl\crypto\ecec.h */
#ifndef HEADER_EC_H
void EC_KEY_free(EC_KEY *key);
#endif

/* file: REF_PRINT : D:\PhD\ECDH\kv_openssl\e_os.h */
#ifndef HEADER_E_OS_H
#ifdef REF_PRINT
#define REF_PRINT(a,b)	fprintf(stderr,"%08X:%4d:%s\n",(int)b,b->references,a)
#endif
#endif

