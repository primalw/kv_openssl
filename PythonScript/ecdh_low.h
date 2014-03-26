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
#endif
static SSL_CTX *ctx=NULL;
#ifndef OPENSSL_NO_TLSEXT
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
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
typedef struct dh_st DH;
typedef struct rand_meth_st RAND_METHOD;
typedef struct X509_name_st X509_NAME;
typedef struct v3_ext_ctx X509V3_CTX;
typedef struct engine_st ENGINE;
typedef struct ssl_ctx_st SSL_CTX;
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

	/* used by EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_cmp: */
	int (*is_at_infinity)(const EC_GROUP *, const EC_POINT *);
	int (*is_on_curve)(const EC_GROUP *, const EC_POINT *, BN_CTX *);

	/* used by EC_POINT_make_affine, EC_POINTs_make_affine: */
	int (*make_affine)(const EC_GROUP *, EC_POINT *, BN_CTX *);

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
/* file: ecdh_low : /Volumes/work/Phd/ECDH/kv_openssl/PythonScriptecdh_low.h */
#ifndef HEADER_EC_H
unsigned char *ecdh_low(size_t *secret_len) {
	EC_KEY *key, *peerkey;
	int field_size;
	unsigned char *secret;
	
	/* Create an Elliptic Curve Key object and set it up to use the ANSI X9.62 Prime 256v1 curve */
 if(NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) handleErrors(); 	
	/* Generate the private and public key */
 if(1 != EC_KEY_generate_key(key)) handleErrors(); 	
	/* Get the peer's public key, and provide the peer with our public key -
	 * how this is done will be specific to your circumstances */
 peerkey = get_peerkey_low(key); 	
	/* Calculate the size of the buffer for the shared secret */
 field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));  *secret_len = (field_size+7)/8; 	
	/* Allocate the memory for the shared secret */
 if(NULL == (secret = OPENSSL_malloc(*secret_len))) handleErrors(); 	
	/* Derive the shared secret */
 *secret_len = ECDH_compute_key(secret, *secret_len, EC_KEY_get0_public_key(peerkey), 								   key, NULL);
	
	/* Clean up */
 EC_KEY_free(key);  EC_KEY_free(peerkey); 	
 if(*secret_len <= 0) 	{
  OPENSSL_free(secret); 		return NULL;
	}
	
	return secret;
}
/* file: EC_KEY_new_by_curve_name : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
EC_KEY *EC_KEY_new_by_curve_name(int nid);
#endif

/* file: EC_KEY_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
EC_KEY *EC_KEY_new(void);
#endif

/* file: OPENSSL_malloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#define OPENSSL_malloc(num)	CRYPTO_malloc((int)num,__FILE__,__LINE__)
#endif
/* file: CRYPTO_malloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void *CRYPTO_malloc(int num, const char *file, int line);
#endif

/* file: malloc_debug_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
#ifdef CRYPTO_MDEBUG
static void (*malloc_debug_func)(void *,int,const char *,int,int)
	= CRYPTO_dbg_malloc;
#else
/* file: malloc_debug_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
static void (*malloc_debug_func)(void *,int,const char *,int,int) = NULL;
#endif
/* file: CRYPTO_dbg_malloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_dbg_malloc(void *addr,int num,const char *file,int line,int before_p);
#endif

/* file: is_MemCheck_on : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#define is_MemCheck_on() CRYPTO_is_mem_check_on()
#endif
/* file: CRYPTO_is_mem_check_on : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
int CRYPTO_is_mem_check_on(void);
#endif

/* file: CRYPTO_THREADID_current : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_THREADID_current(CRYPTO_THREADID *id);
#endif

/* file: threadid_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
static void (MS_FAR *threadid_callback)(CRYPTO_THREADID *)=0;

/* file: CRYPTO_THREADID_set_numeric : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id, unsigned long val);
#endif

/* file: id_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
#ifndef OPENSSL_NO_DEPRECATED
static unsigned long (MS_FAR *id_callback)(void)=0;
#endif

/* file: CRYPTO_THREADID_set_pointer : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_THREADID_set_pointer(CRYPTO_THREADID *id, void *ptr);
#endif

/* file: CRYPTO_r_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_r_lock(type)	\
	CRYPTO_lock(CRYPTO_LOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#endif
#else
/* file: CRYPTO_r_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define CRYPTO_r_lock(a)
#endif
#endif
/* file: CRYPTO_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_lock(int mode, int type,const char *file,int line);
#endif

/* file: CRYPTO_THREADID_hash : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
unsigned long CRYPTO_THREADID_hash(const CRYPTO_THREADID *id);
#endif

/* file: CRYPTO_get_lock_name : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
const char *CRYPTO_get_lock_name(int type);
#endif

/* file: sk_OPENSSL_STRING_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_OPENSSL_STRING_num(st) SKM_sk_num(OPENSSL_STRING, st)
#endif /* !defined HEADER_SAFESTACK_H */
/* file: SKM_sk_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define SKM_sk_num(type, st) \
	sk_num(CHECKED_STACK_OF(type, st))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: sk_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.h */
#ifndef HEADER_STACK_H
int sk_num(const _STACK *);
#endif

/* file: CHECKED_STACK_OF : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define CHECKED_STACK_OF(type, p) \
    ((_STACK*) (1 ? p : (STACK_OF(type)*)0))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: STACK_OF : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
typedef STACK_OF(ASN1_TYPE) ASN1_SEQUENCE_ANY;
#endif

/* file: sk_GENERAL_NAMES_new_null : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_GENERAL_NAMES_new_null() SKM_sk_new_null(GENERAL_NAMES)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: sk_OPENSSL_STRING_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_OPENSSL_STRING_value(st, i) ((OPENSSL_STRING)sk_value(CHECKED_STACK_OF(OPENSSL_STRING, st), i))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: sk_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.h */
#ifndef HEADER_STACK_H
void *sk_value(const _STACK *, int);
#endif


/* file: a2i_GENERAL_NAME : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
#ifndef HEADER_X509V3_H
GENERAL_NAME *a2i_GENERAL_NAME(GENERAL_NAME *out,
			       const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
			       int gen_type, char *value, int is_nc);
#endif

/* file: X509V3err : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
#define X509V3err(f,r) ERR_PUT_error(ERR_LIB_X509V3,(f),(r),__FILE__,__LINE__)
#endif
/* file: ERR_PUT_error : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
#ifndef OPENSSL_NO_ERR
#define ERR_PUT_error(a,b,c,d,e)	ERR_put_error(a,b,c,d,e)
#else
/* file: ERR_PUT_error : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define ERR_PUT_error(a,b,c,d,e)	ERR_put_error(a,b,c,NULL,0)
#endif
#endif
/* file: ERR_put_error : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
void ERR_put_error(int lib, int func,int reason,const char *file,int line);
#endif

/* file: strlen : /Volumes/work/Phd/ECDH/kv_openssl/e_os.h */
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
/* file: _strlen31 : /Volumes/work/Phd/ECDH/kv_openssl/e_os.h */
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


/* file: ERR_get_state : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
ERR_STATE *ERR_get_state(void);
#endif

/* file: err_fns_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
static void err_fns_check(void) 	{
 if (err_fns) return; 	
 CRYPTO_w_lock(CRYPTO_LOCK_ERR);  if (!err_fns) 		err_fns = &err_defaults;
 CRYPTO_w_unlock(CRYPTO_LOCK_ERR); 	}
/* file: CRYPTO_w_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_w_lock(type)	\
	CRYPTO_lock(CRYPTO_LOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#endif
#else
/* file: CRYPTO_w_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define CRYPTO_w_lock(a)
#endif
#endif

/* file: CRYPTO_w_unlock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_w_unlock(type)	\
	CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#endif
#else
/* file: CRYPTO_w_unlock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define CRYPTO_w_unlock(a)
#endif
#endif


/* file: CRYPTO_THREADID_cpy : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest, const CRYPTO_THREADID *src);
#endif

/* file: ERRFN : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
#define ERRFN(a) err_fns->cb_##a

/* file: ERR_STATE_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
static void ERR_STATE_free(ERR_STATE *s);

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
#ifndef HEADER_CRYPTO_H
#define OPENSSL_free(addr)	CRYPTO_free(addr)
#endif
/* file: CRYPTO_free : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_free(void *ptr);
#endif

/* file: free_debug_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
#ifdef CRYPTO_MDEBUG
static void (*free_debug_func)(void *,int) = CRYPTO_dbg_free;
#else
/* file: free_debug_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
static void (*free_debug_func)(void *,int) = NULL;
#endif
/* file: CRYPTO_dbg_free : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_dbg_free(void *addr,int before_p);
#endif

/* file: MemCheck_off : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#define MemCheck_off()	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE)
#endif
/* file: CRYPTO_mem_ctrl : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
int CRYPTO_mem_ctrl(int mode);
#endif

/* file: CRYPTO_THREADID_cmp : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
int CRYPTO_THREADID_cmp(const CRYPTO_THREADID *a, const CRYPTO_THREADID *b);
#endif


/* file: lh_MEM_delete : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_MEM_delete(lh,inst) LHM_lh_delete(MEM,lh,inst)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: app_info_free : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem_dbg.c */
static void app_info_free(APP_INFO *);

/* file: MemCheck_on : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#define MemCheck_on()	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE)
#endif


/* file: free_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
int CRYPTO_set_locked_mem_functions(void *(*m)(size_t), void (*free_func)(void *));
#endif



/* file: ERR_PACK : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
#define ERR_PACK(l,f,r)		(((((unsigned long)l)&0xffL)*0x1000000)| \
				((((unsigned long)f)&0xfffL)*0x1000)| \
				((((unsigned long)r)&0xfffL)))
#endif



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
/* file: OBJ_sn2nid : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobjects.h */
#ifndef HEADER_OBJECTS_H
int		OBJ_sn2nid(const char *s);
#endif

/* file: lh_ADDED_OBJ_retrieve : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_ADDED_OBJ_retrieve(lh,inst) LHM_lh_retrieve(ADDED_OBJ,lh,inst)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: OBJ_ln2nid : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobjects.h */
#ifndef HEADER_OBJECTS_H
int		OBJ_ln2nid(const char *s);
#endif

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
/* file: OBJerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
#define OBJerr(f,r)  ERR_PUT_error(ERR_LIB_OBJ,(f),(r),__FILE__,__LINE__)
#endif


/* file: a2d_ASN1_OBJECT : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
int a2d_ASN1_OBJECT(unsigned char *out,int olen, const char *buf, int num);
#endif

/* file: ASN1err : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
#define ASN1err(f,r) ERR_PUT_error(ERR_LIB_ASN1,(f),(r),__FILE__,__LINE__)
#endif

/* file: BN_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BIGNUM *BN_new(void);
#endif

/* file: BNerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
#define BNerr(f,r)   ERR_PUT_error(ERR_LIB_BN,(f),(r),__FILE__,__LINE__)
#endif

/* file: bn_check_top : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
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
/* file: bn_check_top : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define bn_check_top(a)
#endif
#endif
/* file: bn_pollute : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
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
/* file: bn_pollute : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define bn_pollute(a)
#endif
#else /* !BN_DEBUG */
/* file: bn_pollute : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define bn_pollute(a)
#endif
#endif
/* file: RAND_pseudo_bytes : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
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

/* file: RAND_get_rand_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/randrand.h */
#ifndef HEADER_RAND_H
const RAND_METHOD *RAND_get_rand_method(void);
#endif

/* file: ENGINE_get_default_RAND : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineengine.h */
#ifndef HEADER_ENGINE_H
ENGINE *ENGINE_get_default_RAND(void);
#endif

/* file: engine_table_select : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
#ifndef ENGINE_TABLE_DEBUG
ENGINE *engine_table_select(ENGINE_TABLE **table, int nid);
#else
/* file: engine_table_select : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
#define engine_table_select(t,n) engine_table_select_tmp(t,n,__FILE__,__LINE__)
#endif
#endif /* HEADER_ENGINE_INT_H */
/* file: engine_table_select_tmp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
#ifndef ENGINE_TABLE_DEBUG
ENGINE *engine_table_select_tmp(ENGINE_TABLE **table, int nid, const char *f, int l);
#endif
#endif /* HEADER_ENGINE_INT_H */

/* file: ERR_set_mark : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
int ERR_set_mark(void);
#endif

/* file: int_table_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_table.c */
static int int_table_check(ENGINE_TABLE **t, int create) 	{
 LHASH_OF(ENGINE_PILE) *lh; 
 if(*t) return 1;  if(!create) return 0;  if((lh = lh_ENGINE_PILE_new()) == NULL) 		return 0;
 *t = (ENGINE_TABLE *)lh; 	return 1;
	}
/* file: LHASH_OF : /Volumes/work/Phd/ECDH/kv_openssl/appsopenssl.c */
static LHASH_OF(FUNCTION) *prog_init(void );

/* file: lh_FUNCTION_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_FUNCTION_new() LHM_lh_new(FUNCTION,function)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: lh_FUNCTION_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_FUNCTION_insert(lh,inst) LHM_lh_insert(FUNCTION,lh,inst)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: lh_ENGINE_PILE_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_ENGINE_PILE_new() LHM_lh_new(ENGINE_PILE,engine_pile)
#endif /* !defined HEADER_SAFESTACK_H */


/* file: lh_ENGINE_PILE_retrieve : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_ENGINE_PILE_retrieve(lh,inst) LHM_lh_retrieve(ENGINE_PILE,lh,inst)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: engine_unlocked_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
int engine_unlocked_init(ENGINE *e);
#endif /* HEADER_ENGINE_INT_H */

/* file: init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/evpevp.h */
#ifndef HEADER_ENVELOPE_H
	int (*init)(EVP_PKEY_CTX *ctx));
#endif

/* file: engine_ref_debug : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
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
#endif /* HEADER_ENGINE_INT_H */

/* file: sk_ENGINE_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_ENGINE_value(st, i) SKM_sk_value(ENGINE, (st), (i))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: SKM_sk_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define SKM_sk_value(type, st,i) \
	((type *)sk_value(CHECKED_STACK_OF(type, st), i))
#endif /* !defined HEADER_SAFESTACK_H */


/* file: engine_unlocked_finish : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
int engine_unlocked_finish(ENGINE *e, int unlock_for_handlers);
#endif /* HEADER_ENGINE_INT_H */

/* file: engine_free_util : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
int engine_free_util(ENGINE *e, int locked);
#endif /* HEADER_ENGINE_INT_H */

/* file: ENGINEerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
#define ENGINEerr(f,r) ERR_PUT_error(ERR_LIB_ENGINE,(f),(r),__FILE__,__LINE__)
#endif

/* file: CRYPTO_add : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_add(addr,amount,type)	\
	CRYPTO_add_lock(addr,amount,type,__FILE__,__LINE__)
#endif
#else
/* file: CRYPTO_add : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define CRYPTO_add(a,b,c)	((*(a))+=(b))
#endif
#endif
/* file: CRYPTO_add_lock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
int CRYPTO_add_lock(int *pointer,int amount,int type, const char *file,
		    int line);
#endif

/* file: add_lock_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
static int (MS_FAR *add_lock_callback)(int *pointer,int amount,
	int type,const char *file,int line)=0;


/* file: engine_pkey_meths_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
void engine_pkey_meths_free(ENGINE *e);
#endif /* HEADER_ENGINE_INT_H */

/* file: EVP_PKEY_meth_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/evpevp.h */
#ifndef HEADER_ENVELOPE_H
void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth);
#endif

/* file: engine_pkey_asn1_meths_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
#ifndef HEADER_ENGINE_INT_H
void engine_pkey_asn1_meths_free(ENGINE *e);
#endif /* HEADER_ENGINE_INT_H */

/* file: EVP_PKEY_asn1_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/evpevp.h */
#ifndef HEADER_ENVELOPE_H
void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth);
#endif

/* file: CRYPTO_free_ex_data : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
#endif

/* file: EX_IMPL : /Volumes/work/Phd/ECDH/kv_openssl/cryptoex_data.c */
#define EX_IMPL(a) impl->cb_##a

/* file: ERR_pop_to_mark : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
int ERR_pop_to_mark(void);
#endif

/* file: err_clear : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
#define err_clear(p,i) \
	do { \
	(p)->err_flags[i]=0; \
	(p)->err_buffer[i]=0; \
	err_clear_data(p,i); \
	(p)->err_file[i]=NULL; \
	(p)->err_line[i]= -1; \
	} while(0)


/* file: ENGINE_get_RAND : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineengine.h */
#ifndef HEADER_ENGINE_H
const RAND_METHOD *ENGINE_get_RAND(const ENGINE *e);
#endif

/* file: ENGINE_finish : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineengine.h */
#ifndef HEADER_ENGINE_H
int ENGINE_finish(ENGINE *e);
#endif

/* file: RAND_SSLeay : /Volumes/work/Phd/ECDH/kv_openssl/crypto/randrand.h */
#ifndef HEADER_RAND_H
RAND_METHOD *RAND_SSLeay(void);
#endif



/* file: BN_set_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_set_word(BIGNUM *a, BN_ULONG w);
#endif

/* file: bn_expand : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
#define bn_expand(a,bits) ((((((bits+BN_BITS2-1))/BN_BITS2)) <= (a)->dmax)?\
	(a):bn_expand2((a),(bits+BN_BITS2-1)/BN_BITS2))
#endif
/* file: bn_expand2 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BIGNUM *bn_expand2(BIGNUM *a, int words);
#endif

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
 memset(A,0,sizeof(BN_ULONG)*words);  memcpy(A,b->d,sizeof(b->d[0])*b->top); #endif
		
 return(a); 	}
/* file: BN_get_flags : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
#define BN_get_flags(b,n)	((b)->flags&(n))
#endif



/* file: BN_mul_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_mul_word(BIGNUM *a, BN_ULONG w);
#endif

/* file: BN_zero : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
#ifdef OPENSSL_NO_DEPRECATED
#define BN_zero(a)	BN_zero_ex(a)
#else
/* file: BN_zero : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_zero(a)	(BN_set_word((a),0))
#endif
#endif
/* file: BN_zero_ex : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
#define BN_zero_ex(a) \
	do { \
		BIGNUM *_tmp_bn = (a); \
		_tmp_bn->top = 0; \
		_tmp_bn->neg = 0; \
	} while(0)
#endif


/* file: bn_mul_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);
#endif

/* file: mul : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
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
/* file: Lw : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
#define Lw(t)    (((BN_ULONG)(t))&BN_MASK2)
#endif

/* file: Hw : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
#define Hw(t)    (((BN_ULONG)((t)>>BN_BITS2))&BN_MASK2)
#endif


/* file: LBITS : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
#ifdef BN_LLONG
#define LBITS(a)	((a)&BN_MASK2l)
#endif /* !BN_LLONG */
#endif

/* file: HBITS : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
#ifdef BN_LLONG
#define HBITS(a)	(((a)>>BN_BITS4)&BN_MASK2l)
#endif /* !BN_LLONG */
#endif

/* file: bn_wexpand : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
#define bn_wexpand(a,words) (((words) <= (a)->dmax)?(a):bn_expand2((a),(words)))
#endif

/* file: BN_add_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_add_word(BIGNUM *a, BN_ULONG w);
#endif

/* file: BN_sub_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_sub_word(BIGNUM *a, BN_ULONG w);
#endif

/* file: BN_set_negative : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
void	BN_set_negative(BIGNUM *b, int n);
#endif

/* file: BN_num_bits : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_num_bits(const BIGNUM *a);
#endif

/* file: BN_num_bits_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_num_bits_word(BN_ULONG);
#endif

/* file: BN_div_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);
#endif

/* file: BN_lshift : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
#endif

/* file: bn_correct_top : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
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

/* file: bn_div_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d);
#endif

/* file: BN_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
void	BN_free(BIGNUM *a);
#endif

/* file: ASN1_object_size : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_object_size(int constructed, int length, int tag);
#endif

/* file: ASN1_put_object : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
void ASN1_put_object(unsigned char **pp, int constructed, int length,
	int tag, int xclass);
#endif

/* file: asn1_put_length : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_lib.c */
static void asn1_put_length(unsigned char **pp, int length);

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
/* file: ASN1_get_object : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
	int *pclass, long omax);
#endif

/* file: asn1_get_length : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_lib.c */
static int asn1_get_length(const unsigned char **pp,int *inf,long *rl,int max);

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

/* file: ASN1_OBJECT_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
void		ASN1_OBJECT_free(ASN1_OBJECT *a);
#endif




/* file: ERR_add_error_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
void ERR_add_error_data(int num, ...);
#endif

/* file: ERR_add_error_vdata : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
void ERR_add_error_vdata(int num, va_list args);
#endif

/* file: OPENSSL_realloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#define OPENSSL_realloc(addr,num) \
	CRYPTO_realloc((char *)addr,(int)num,__FILE__,__LINE__)
#endif
/* file: CRYPTO_realloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void *CRYPTO_realloc(void *addr,int num, const char *file, int line);
#endif

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
#ifndef HEADER_CRYPTO_H
void CRYPTO_dbg_realloc(void *addr1,void *addr2,int num,const char *file,int line,int before_p);
#endif

/* file: lh_MEM_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_MEM_insert(lh,inst) LHM_lh_insert(MEM,lh,inst)
#endif /* !defined HEADER_SAFESTACK_H */


/* file: realloc_ex_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
static void *(*realloc_ex_func)(void *, size_t, const char *file, int line)
        = default_realloc_ex;
/* file: default_realloc_ex : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
static void *default_realloc_ex(void *str, size_t num,         const char *file, int line)
 { return realloc_func(str,num); } /* file: realloc_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
static void *(*realloc_func)(void *, size_t)= realloc;




/* file: BUF_strlcat : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bufferbuffer.h */
#ifndef HEADER_BUFFER_H
size_t BUF_strlcat(char *dst,const char *src,size_t siz);
#endif

/* file: BUF_strlcpy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bufferbuffer.h */
#ifndef HEADER_BUFFER_H
size_t BUF_strlcpy(char *dst,const char *src,size_t siz);
#endif

/* file: ERR_set_error_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
void ERR_set_error_data(char *data,int flags);
#endif

/* file: a2i_IPADDRESS_NC : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
#ifndef HEADER_X509V3_H
ASN1_OCTET_STRING *a2i_IPADDRESS_NC(const char *ipasc);
#endif

/* file: BUF_strdup : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bufferbuf_str.c */
char *BUF_strdup(const char *str)
	{
	if (str == NULL) return(NULL);
	return BUF_strndup(str, strlen(str));
	}

/* file: a2i_ipadd : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
#ifndef HEADER_X509V3_H
int a2i_ipadd(unsigned char *ipout, const char *ipasc);
#endif

/* file: ipv6_from_asc : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
static int ipv6_from_asc(unsigned char *v6, const char *in);

/* file: CONF_parse_list : /Volumes/work/Phd/ECDH/kv_openssl/crypto/confconf.h */
int CONF_parse_list(const char *list, int sep, int nospc,
	int (*list_cb)(const char *elem, int len, void *usr), void *arg);

/* file: CONFerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
#define CONFerr(f,r) ERR_PUT_error(ERR_LIB_CONF,(f),(r),__FILE__,__LINE__)
#endif

/* file: list_cb : /Volumes/work/Phd/ECDH/kv_openssl/crypto/confconf.h */
	int (*list_cb)(const char *elem, int len, void *usr), void *arg);

/* file: ipv4_from_asc : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_utl.c */
static int ipv4_from_asc(unsigned char *v4, const char *in);

/* file: ASN1_OCTET_STRING_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
int 	ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data, int len);
#endif

/* file: a2i_IPADDRESS : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
#ifndef HEADER_X509V3_H
ASN1_OCTET_STRING *a2i_IPADDRESS(const char *ipasc);
#endif

/* file: do_dirname : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_alt.c */
static int do_dirname(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx);

/* file: X509V3_NAME_from_section : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
#ifndef HEADER_X509V3_H
int X509V3_NAME_from_section(X509_NAME *nm, STACK_OF(CONF_VALUE)*dn_sk,
						unsigned long chtype);
#endif

/* file: sk_CONF_VALUE_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_CONF_VALUE_num(st) SKM_sk_num(CONF_VALUE, (st))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: sk_CONF_VALUE_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_CONF_VALUE_value(st, i) SKM_sk_value(CONF_VALUE, (st), (i))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: X509_NAME_add_entry_by_txt : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
#ifndef HEADER_X509_H
int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type,
			const unsigned char *bytes, int len, int loc, int set);
#endif

/* file: X509_NAME_ENTRY_create_by_txt : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
#ifndef HEADER_X509_H
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne,
		const char *field, int type, const unsigned char *bytes, int len);
#endif

/* file: X509err : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
#define X509err(f,r) ERR_PUT_error(ERR_LIB_X509,(f),(r),__FILE__,__LINE__)
#endif

/* file: X509_NAME_ENTRY_create_by_OBJ : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
#ifndef HEADER_X509_H
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_OBJ(X509_NAME_ENTRY **ne,
			ASN1_OBJECT *obj, int type,const unsigned char *bytes,
			int len);
#endif

/* file: X509_NAME_ENTRY_set_object : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
#ifndef HEADER_X509_H
int 		X509_NAME_ENTRY_set_object(X509_NAME_ENTRY *ne,
			ASN1_OBJECT *obj);
#endif

/* file: OBJ_dup : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobj_lib.c */
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

/* file: X509_NAME_ENTRY_set_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
#ifndef HEADER_X509_H
int 		X509_NAME_ENTRY_set_data(X509_NAME_ENTRY *ne, int type,
			const unsigned char *bytes, int len);
#endif

/* file: ASN1_STRING_set_by_NID : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out, 
		const unsigned char *in, int inlen, int inform, int nid);
#endif

/* file: ASN1_STRING_TABLE_get : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid);
#endif

/* file: sk_ASN1_STRING_TABLE_find : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_ASN1_STRING_TABLE_find(st, val) SKM_sk_find(ASN1_STRING_TABLE, (st), (val))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: SKM_sk_find : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define SKM_sk_find(type, st, val) \
	sk_find(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: sk_find : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.h */
#ifndef HEADER_STACK_H
int sk_find(_STACK *st, void *data);
#endif

/* file: internal_find : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.c */
static int internal_find(_STACK *st, void *data, int ret_val_options) 	{
	const void * const *r;
	int i;

 if(st == NULL) return -1; 
 if (st->comp == NULL) 		{
  for (i=0; i<st->num; i++)    if (st->data[i] == data)     return(i);   return(-1); 		}
 sk_sort(st);  if (data == NULL) return(-1);  r=OBJ_bsearch_ex_(&data,st->data,st->num,sizeof(void *),st->comp, 			  ret_val_options);
 if (r == NULL) return(-1);  return (int)((char **)r-st->data); 	}
/* file: sk_sort : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.h */
#ifndef HEADER_STACK_H
void sk_sort(_STACK *st);
#endif

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


/* file: CHECKED_PTR_OF : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#ifndef CHECKED_PTR_OF
#define CHECKED_PTR_OF(type, p) \
    ((void*) (1 ? p : (type*)0))
#endif
#endif /* !defined HEADER_SAFESTACK_H */



/* file: sk_ASN1_STRING_TABLE_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_ASN1_STRING_TABLE_value(st, i) SKM_sk_value(ASN1_STRING_TABLE, (st), (i))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: ASN1_mbstring_ncopy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
					int inform, unsigned long mask, 
					long minsize, long maxsize);
#endif

/* file: traverse_string : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1a_mbstr.c */
static int traverse_string(const unsigned char *p, int len, int inform,
		 int (*rfunc)(unsigned long value, void *in), void *arg);

/* file: BIO_snprintf : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biobio.h */
#ifndef HEADER_BIO_H
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
	__bio_h__attr__((__format__(__printf__,3,4)));
#endif

/* file: BIO_vsnprintf : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biobio.h */
#ifndef HEADER_BIO_H
int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
	__bio_h__attr__((__format__(__printf__,3,0)));
#endif

/* file: _dopr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
static void _dopr(char **sbuffer, char **buffer,
		  size_t *maxlen, size_t *retlen, int *truncated,
		  const char *format, va_list args);

/* file: doapr_outch : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
static void doapr_outch (char **, char **, size_t *, size_t *, int);

/* file: char_to_int : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
#define char_to_int(p) (p - '0')

/* file: fmtint : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
static void fmtint     (char **, char **, size_t *, size_t *,
			LLONG, int, int, int, int);

/* file: fmtfp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
static void fmtfp      (char **, char **, size_t *, size_t *,
			LDOUBLE, int, int, int);

/* file: fmtstr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
static void fmtstr     (char **, char **, size_t *, size_t *,
			const char *, int, int, int);

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

/* file: ASN1_STRING_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
int 		ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);
#endif

/* file: ASN1_STRING_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
void		ASN1_STRING_free(ASN1_STRING *a);
#endif

/* file: ASN1_mbstring_copy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
					int inform, unsigned long mask);
#endif

/* file: OBJ_obj2nid : /Volumes/work/Phd/ECDH/kv_openssl/crypto/objectsobjects.h */
#ifndef HEADER_OBJECTS_H
int		OBJ_obj2nid(const ASN1_OBJECT *o);
#endif

/* file: ASN1_PRINTABLE_type : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_PRINTABLE_type(const unsigned char *s, int max);
#endif

/* file: X509_NAME_add_entry : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
#ifndef HEADER_X509_H
int 		X509_NAME_add_entry(X509_NAME *name,X509_NAME_ENTRY *ne,
			int loc, int set);
#endif

/* file: sk_X509_NAME_ENTRY_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_X509_NAME_ENTRY_num(st) SKM_sk_num(X509_NAME_ENTRY, (st))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: sk_X509_NAME_ENTRY_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_X509_NAME_ENTRY_value(st, i) SKM_sk_value(X509_NAME_ENTRY, (st), (i))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: X509_NAME_ENTRY_dup : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
#ifndef HEADER_X509_H
X509_NAME_ENTRY *X509_NAME_ENTRY_dup(X509_NAME_ENTRY *ne);
#endif

/* file: sk_X509_NAME_ENTRY_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_X509_NAME_ENTRY_insert(st, val, i) SKM_sk_insert(X509_NAME_ENTRY, (st), (val), (i))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: SKM_sk_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define SKM_sk_insert(type, st,val, i) \
	sk_insert(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val), i)
#endif /* !defined HEADER_SAFESTACK_H */
/* file: sk_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.h */
#ifndef HEADER_STACK_H
int sk_insert(_STACK *sk, void *data, int where);
#endif

/* file: memmove : /Volumes/work/Phd/ECDH/kv_openssl/e_os.h */
#ifndef HEADER_E_OS_H
#if defined(sun) && !defined(__svr4__) && !defined(__SVR4)
# define memmove(s1,s2,n) bcopy((s2),(s1),(n))
#endif
#endif



/* file: X509V3_section_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
#ifndef HEADER_X509V3_H
void X509V3_section_free( X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section);
#endif

/* file: do_othername : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3v3_alt.c */
static int do_othername(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx);

/* file: ASN1_generate_v3 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
ASN1_TYPE *ASN1_generate_v3(char *str, X509V3_CTX *cnf);
#endif

/* file: asn1_multi : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_gen.c */
static ASN1_TYPE *asn1_multi(int utype, const char *section, X509V3_CTX *cnf);

/* file: sk_ASN1_TYPE_new_null : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_ASN1_TYPE_new_null() SKM_sk_new_null(ASN1_TYPE)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: sk_ASN1_TYPE_push : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_ASN1_TYPE_push(st, val) SKM_sk_push(ASN1_TYPE, (st), (val))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: SKM_sk_push : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define SKM_sk_push(type, st, val) \
	sk_push(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: sk_push : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.h */
#ifndef HEADER_STACK_H
int sk_push(_STACK *st, void *data);
#endif



/* file: sk_ASN1_TYPE_pop_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_ASN1_TYPE_pop_free(st, free_func) SKM_sk_pop_free(ASN1_TYPE, (st), (free_func))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: SKM_sk_pop_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define SKM_sk_pop_free(type, st, free_func) \
	sk_pop_free(CHECKED_STACK_OF(type, st), CHECKED_SK_FREE_FUNC(type, free_func))
#endif /* !defined HEADER_SAFESTACK_H */
/* file: CHECKED_SK_FREE_FUNC : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define CHECKED_SK_FREE_FUNC(type, p) \
    ((void (*)(void *)) ((1 ? p : (void (*)(type *))0)))
#endif /* !defined HEADER_SAFESTACK_H */



/* file: asn1_str2type : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_gen.c */
static ASN1_TYPE *asn1_str2type(const char *str, int format, int utype);

/* file: X509V3_get_value_bool : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
#ifndef HEADER_X509V3_H
#ifdef HEADER_CONF_H
int X509V3_get_value_bool(CONF_VALUE *value, int *asn1_bool);
#endif
#endif

/* file: X509V3_conf_err : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
#ifndef HEADER_X509V3_H
#define X509V3_conf_err(val) ERR_add_error_data(6, "section:", val->section, \
",name:", val->name, ",value:", val->value);
#endif

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
/* file: BN_hex2bn : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int 	BN_hex2bn(BIGNUM **a, const char *str);
#endif

/* file: BN_dec2bn : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int 	BN_dec2bn(BIGNUM **a, const char *str);
#endif

/* file: BN_to_ASN1_INTEGER : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
#endif

/* file: M_ASN1_INTEGER_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
#define M_ASN1_INTEGER_new()	(ASN1_INTEGER *)\
		ASN1_STRING_type_new(V_ASN1_INTEGER)
#endif

/* file: BN_is_negative : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
#define BN_is_negative(a) ((a)->neg != 0)
#endif

/* file: BN_bn2bin : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_bn2bin(const BIGNUM *a, unsigned char *to);
#endif

/* file: BN_num_bytes : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
#define BN_num_bytes(a)	((BN_num_bits(a)+7)/8)
#endif

/* file: M_ASN1_INTEGER_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
#define M_ASN1_INTEGER_free(a)		ASN1_STRING_free((ASN1_STRING *)a)
#endif


/* file: ASN1_STRING_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1_lib.c */
ASN1_STRING *ASN1_STRING_new(void) 	{
 return(ASN1_STRING_type_new(V_ASN1_OCTET_STRING)); 	}

/* file: ASN1_TIME_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_TIME_check(ASN1_TIME *t);
#endif

/* file: ASN1_GENERALIZEDTIME_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_GENERALIZEDTIME_check(ASN1_GENERALIZEDTIME *a);
#endif

/* file: ASN1_UTCTIME_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
int ASN1_UTCTIME_check(ASN1_UTCTIME *a);
#endif

/* file: ASN1_tag2bit : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
unsigned long ASN1_tag2bit(int tag);
#endif

/* file: string_to_hex : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
#ifndef HEADER_X509V3_H
unsigned char *string_to_hex(const char *str, long *len);
#endif

/* file: M_ASN1_IA5STRING_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
#ifndef HEADER_ASN1_H
#define M_ASN1_IA5STRING_new()	(ASN1_IA5STRING *)\
		ASN1_STRING_type_new(V_ASN1_IA5STRING)
#endif

/* file: sk_GENERAL_NAME_push : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_GENERAL_NAME_push(st, val) SKM_sk_push(GENERAL_NAME, (st), (val))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: sk_GENERAL_NAMES_push : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_GENERAL_NAMES_push(st, val) SKM_sk_push(GENERAL_NAMES, (st), (val))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: sk_GENERAL_NAMES_pop_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_GENERAL_NAMES_pop_free(st, free_func) SKM_sk_pop_free(GENERAL_NAMES, (st), (free_func))
#endif /* !defined HEADER_SAFESTACK_H */




/* file: CRYPTO_get_dynlock_value : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
struct CRYPTO_dynlock_value *CRYPTO_get_dynlock_value(int i);
#endif

/* file: sk_CRYPTO_dynlock_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_CRYPTO_dynlock_num(st) SKM_sk_num(CRYPTO_dynlock, (st))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: sk_CRYPTO_dynlock_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_CRYPTO_dynlock_value(st, i) SKM_sk_value(CRYPTO_dynlock, (st), (i))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: OPENSSL_assert : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#define OPENSSL_assert(e)       (void)((e) ? 0 : (OpenSSLDie(__FILE__, __LINE__, #e),1))
#endif
/* file: OpenSSLDie : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void OpenSSLDie(const char *file,int line,const char *assertion);
#endif

/* file: OPENSSL_showfatal : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.h */
#ifndef HEADER_CRYPTLIB_H
void OPENSSL_showfatal(const char *fmta,...);
#endif

/* file: alloca : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_exp.c */
#ifdef _WIN32
# ifndef alloca
#  define alloca(s) __builtin_alloca((s))
# endif
#endif

/* file: OPENSSL_isservice : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
int OPENSSL_isservice(void);
#endif


/* file: dynlock_lock_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
static void (MS_FAR *dynlock_lock_callback)(int mode,
	struct CRYPTO_dynlock_value *l, const char *file,int line)=0;

/* file: CRYPTO_destroy_dynlockid : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void CRYPTO_destroy_dynlockid(int i);
#endif

/* file: sk_CRYPTO_dynlock_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define sk_CRYPTO_dynlock_set(st, i, val) SKM_sk_set(CRYPTO_dynlock, (st), (i), (val))
#endif /* !defined HEADER_SAFESTACK_H */

/* file: dynlock_destroy_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
static void (MS_FAR *dynlock_destroy_callback)(struct CRYPTO_dynlock_value *l,
	const char *file,int line)=0;

/* file: locking_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
static void (MS_FAR *locking_callback)(int mode,int type,
	const char *file,int line)=0;


/* file: CRYPTO_r_unlock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_r_unlock(type)	\
	CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#endif
#else
/* file: CRYPTO_r_unlock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define CRYPTO_r_unlock(a)
#endif
#endif


/* file: lh_MEM_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_MEM_new() LHM_lh_new(MEM,mem)
#endif /* !defined HEADER_SAFESTACK_H */

/* file: lh_APP_INFO_retrieve : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#ifndef HEADER_SAFESTACK_H
#define lh_APP_INFO_retrieve(lh,inst) LHM_lh_retrieve(APP_INFO,lh,inst)
#endif /* !defined HEADER_SAFESTACK_H */


/* file: malloc_ex_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
static void *(*malloc_ex_func)(size_t, const char *file, int line)
        = default_malloc_ex;
/* file: default_malloc_ex : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
static void *default_malloc_ex(size_t num, const char *file, int line)
	{ return malloc_func(num); }



/* file: ECerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
#define ECerr(f,r)   ERR_PUT_error(ERR_LIB_EC,(f),(r),__FILE__,__LINE__)
#endif

/* file: EC_GROUP_new_by_curve_name : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
#endif

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
/* file: BN_CTX_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BN_CTX *BN_CTX_new(void);
#endif

/* file: BN_POOL_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void		BN_POOL_init(BN_POOL *);

/* file: BN_STACK_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void		BN_STACK_init(BN_STACK *);

/* file: BN_bin2bn : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BIGNUM *BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret);
#endif

/* file: EC_GROUP_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
EC_GROUP *EC_GROUP_new(const EC_METHOD *meth);
#endif

/* file: BN_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
void	BN_init(BIGNUM *);
#endif

/* file: EC_GROUP_new_curve_GFp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
#endif

/* file: EC_GFp_mont_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
const EC_METHOD *EC_GFp_mont_method(void);
#endif

/* file: EC_GFp_nist_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
const EC_METHOD *EC_GFp_nist_method(void);
#endif

/* file: EC_GROUP_set_curve_GFp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
#endif

/* file: ERR_peek_last_error : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
unsigned long ERR_peek_last_error(void);
#endif

/* file: ERR_GET_REASON : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
#define ERR_GET_REASON(l)	(int)((l)&0xfffL)
#endif

/* file: EC_GROUP_clear_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
void EC_GROUP_clear_free(EC_GROUP *group);
#endif

/* file: EC_EX_DATA_clear_free_all_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lcl.h */
void EC_EX_DATA_clear_free_all_data(EC_EXTRA_DATA **);

/* file: clear_free_func : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));
/* file: clear_free_func : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));
#endif

/* file: EC_POINT_clear_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
void EC_POINT_clear_free(EC_POINT *point);
#endif

/* file: OPENSSL_cleanse : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void OPENSSL_cleanse(void *ptr, size_t len);
#endif

/* file: BN_clear_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
void	BN_clear_free(BIGNUM *a);
#endif

/* file: ERR_clear_error : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
void ERR_clear_error(void );
#endif

/* file: EC_GROUP_new_curve_GF2m : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
#ifndef OPENSSL_NO_EC2M
EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
#endif
#endif

/* file: EC_GF2m_simple_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
#ifndef OPENSSL_NO_EC2M
const EC_METHOD *EC_GF2m_simple_method(void);
#endif
#endif

/* file: EC_GROUP_set_curve_GF2m : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
#ifndef OPENSSL_NO_EC2M
int EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
#endif
#endif

/* file: EC_POINT_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
EC_POINT *EC_POINT_new(const EC_GROUP *group);
#endif

/* file: EC_POINT_set_affine_coordinates_GFp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
	const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
#endif

/* file: EC_GROUP_set_generator : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);
#endif

/* file: EC_POINT_copy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_POINT_copy(EC_POINT *dst, const EC_POINT *src);
#endif

/* file: BN_copy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
#endif

/* file: EC_GROUP_set_seed : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);
#endif

/* file: EC_GROUP_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
void EC_GROUP_free(EC_GROUP *group);
#endif

/* file: EC_EX_DATA_free_all_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lcl.h */
void EC_EX_DATA_free_all_data(EC_EXTRA_DATA **);

/* file: EC_POINT_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
void EC_POINT_free(EC_POINT *point);
#endif

/* file: BN_CTX_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
void	BN_CTX_free(BN_CTX *c);
#endif

/* file: BN_STACK_finish : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void		BN_STACK_finish(BN_STACK *);

/* file: BN_POOL_finish : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void		BN_POOL_finish(BN_POOL *);


/* file: EC_GROUP_set_curve_name : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
void EC_GROUP_set_curve_name(EC_GROUP *group, int nid);
#endif

/* file: EC_KEY_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
void EC_KEY_free(EC_KEY *key);
#endif

/* file: REF_PRINT : /Volumes/work/Phd/ECDH/kv_openssl/e_os.h */
#ifndef HEADER_E_OS_H
#ifdef REF_PRINT
#define REF_PRINT(a,b)	fprintf(stderr,"%08X:%4d:%s\n",(int)b,b->references,a)
#endif
#endif

/* file: EC_KEY_generate_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_KEY_generate_key(EC_KEY *key);
#endif

/* file: FIPS_mode : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
int FIPS_mode(void);
#endif

/* file: OPENSSL_init : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
void OPENSSL_init(void);
#endif

/* file: RAND_init_fips : /Volumes/work/Phd/ECDH/kv_openssl/crypto/randrand.h */
#ifndef HEADER_RAND_H
#ifdef OPENSSL_FIPS
int RAND_init_fips(void);
#endif
#endif

/* file: RANDerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
#define RANDerr(f,r) ERR_PUT_error(ERR_LIB_RAND,(f),(r),__FILE__,__LINE__)
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
#ifndef HEADER_EC_H
int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx);
#endif

/* file: BN_rand_range : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
#endif

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
/* file: BN_is_bit_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_is_bit_set(const BIGNUM *a, int n);
#endif

/* file: BN_cmp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_cmp(const BIGNUM *a, const BIGNUM *b);
#endif

/* file: BN_sub : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
#endif

/* file: BN_uadd : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
#endif

/* file: bn_add_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BN_ULONG bn_add_words(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,int num);
#endif

/* file: BN_ucmp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_ucmp(const BIGNUM *a, const BIGNUM *b);
#endif

/* file: BN_usub : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
#endif

/* file: bn_sub_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BN_ULONG bn_sub_words(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,int num);
#endif


/* file: EC_POINT_mul : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);
#endif

/* file: EC_POINTs_mul : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, size_t num, const EC_POINT *p[], const BIGNUM *m[], BN_CTX *ctx);
#endif

/* file: ec_wNAF_mul : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lcl.h */
int ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
	size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *);

/* file: EC_POINT_set_to_infinity : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point);
#endif

/* file: EC_GROUP_get0_generator : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group);
#endif

/* file: EC_EX_DATA_get_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lcl.h */
void *EC_EX_DATA_get_data(const EC_EXTRA_DATA *,
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));

/* file: EC_POINT_cmp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);
#endif

/* file: EC_window_bits_for_scalar_size : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_mult.c */
#define EC_window_bits_for_scalar_size(b) \
		((size_t) \
		 ((b) >= 2000 ? 6 : \
		  (b) >=  800 ? 5 : \
		  (b) >=  300 ? 4 : \
		  (b) >=   70 ? 3 : \
		  (b) >=   20 ? 2 : \
		  1))

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

/* file: EC_POINT_dbl : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx);
#endif

/* file: EC_POINT_add : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);
#endif

/* file: EC_POINTs_make_affine : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_POINTs_make_affine(const EC_GROUP *group, size_t num, EC_POINT *points[], BN_CTX *ctx);
#endif

/* file: EC_POINT_invert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx);
#endif

/* file: EC_GROUP_get_degree : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_GROUP_get_degree(const EC_GROUP *group);
#endif

/* file: EC_KEY_get0_group : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);
#endif

/* file: ECDH_compute_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhecdh.h */
#ifndef HEADER_ECDH_H
int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key, EC_KEY *ecdh,
                     void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
#endif

/* file: ecdh_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhech_locl.h */
#ifndef HEADER_ECH_LOCL_H
ECDH_DATA *ecdh_check(EC_KEY *);
#endif /* HEADER_ECH_LOCL_H */

/* file: EC_KEY_get_key_method_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
void *EC_KEY_get_key_method_data(EC_KEY *key, 
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));
#endif

/* file: ecdh_data_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhech_lib.c */
static void *ecdh_data_new(void);

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
#endif	
 return(ret); 	}
/* file: ECDHerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
#define ECDHerr(f,r)  ERR_PUT_error(ERR_LIB_ECDH,(f),(r),__FILE__,__LINE__)
#endif

/* file: ECDH_get_default_method : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhecdh.h */
#ifndef HEADER_ECDH_H
const ECDH_METHOD *ECDH_get_default_method(void);
#endif

/* file: ECDH_OpenSSL : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhecdh.h */
#ifndef HEADER_ECDH_H
const ECDH_METHOD *ECDH_OpenSSL(void);
#endif

/* file: ENGINE_get_default_ECDH : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineengine.h */
#ifndef HEADER_ENGINE_H
ENGINE *ENGINE_get_default_ECDH(void);
#endif

/* file: ENGINE_get_ECDH : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineengine.h */
#ifndef HEADER_ENGINE_H
const ECDH_METHOD *ENGINE_get_ECDH(const ENGINE *e);
#endif

/* file: CRYPTO_new_ex_data : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef HEADER_CRYPTO_H
int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
#endif


/* file: EC_KEY_insert_key_method_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
void *EC_KEY_insert_key_method_data(EC_KEY *key, void *data,
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));
#endif

/* file: EC_EX_DATA_set_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lcl.h */
int EC_EX_DATA_set_data(EC_EXTRA_DATA **, void *data,
	void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));

/* file: ecdh_data_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecdhech_lib.c */
static void  ecdh_data_free(void *);

/* file: EC_KEY_get_flags : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
int EC_KEY_get_flags(const EC_KEY *key);
#endif

/* file: compute_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/dhdh_key.c */
static int compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);

/* file: DHerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#ifndef HEADER_ERR_H
#define DHerr(f,r)   ERR_PUT_error(ERR_LIB_DH,(f),(r),__FILE__,__LINE__)
#endif

/* file: BN_CTX_start : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
void	BN_CTX_start(BN_CTX *ctx);
#endif

/* file: CTXDBG_ENTRY : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
#ifdef BN_CTX_DEBUG
#define CTXDBG_ENTRY(str, ctx)	do { \
				ctxdbg_cur = (str); \
				fprintf(stderr,"Starting %s\n", ctxdbg_cur); \
				ctxdbg(ctx); \
				} while(0)
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
#else
#endif


/* file: BN_STACK_push : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static int		BN_STACK_push(BN_STACK *, unsigned int);

/* file: CTXDBG_EXIT : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
#ifdef BN_CTX_DEBUG
#define CTXDBG_EXIT(ctx)
#endif

/* file: BN_CTX_get : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BIGNUM *BN_CTX_get(BN_CTX *ctx);
#endif

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

/* file: CTXDBG_RET : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
#ifdef BN_CTX_DEBUG
#define CTXDBG_RET(ctx,ret)
#endif

/* file: BN_MONT_CTX_set_locked : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, int lock,
					const BIGNUM *mod, BN_CTX *ctx);
#endif

/* file: BN_MONT_CTX_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BN_MONT_CTX *BN_MONT_CTX_new(void );
#endif

/* file: BN_MONT_CTX_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
void BN_MONT_CTX_init(BN_MONT_CTX *ctx);
#endif

/* file: BN_MONT_CTX_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int BN_MONT_CTX_set(BN_MONT_CTX *mont,const BIGNUM *mod,BN_CTX *ctx);
#endif

/* file: BN_set_bit : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_set_bit(BIGNUM *a, int n);
#endif

/* file: BN_mod_inverse : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BIGNUM *BN_mod_inverse(BIGNUM *ret,
	const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);
#endif

/* file: BN_mod_inverse_no_branch : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_gcd.c */
static BIGNUM *BN_mod_inverse_no_branch(BIGNUM *in,
        const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

/* file: BN_one : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
#define BN_one(a)	(BN_set_word((a),1))
#endif

/* file: BN_nnmod : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
#endif

/* file: BN_mod : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
#define BN_mod(rem,m,d,ctx) BN_div(NULL,(rem),(m),(d),(ctx))
#endif
/* file: BN_div : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
	BN_CTX *ctx);
#endif

/* file: BN_lshift1 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_lshift1(BIGNUM *r, const BIGNUM *a);
#endif

/* file: BN_rshift1 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_rshift1(BIGNUM *r, const BIGNUM *a);
#endif

/* file: BN_CTX_end : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
void	BN_CTX_end(BN_CTX *ctx);
#endif

/* file: BN_STACK_pop : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static unsigned int	BN_STACK_pop(BN_STACK *);

/* file: BN_POOL_release : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_ctx.c */
static void		BN_POOL_release(BN_POOL *, unsigned int);

/* file: bn_clear_top2max : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
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
#endif

/* file: BN_UMULT_LOHI : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
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
#ifndef HEADER_BN_LCL_H
#if !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM) && !defined(PEDANTIC)
# if defined(__alpha) && (defined(SIXTY_FOUR_BIT_LONG) || defined(SIXTY_FOUR_BIT))
#  if defined(__DECC)
#   define BN_UMULT_HIGH(a,b)	(BN_ULONG)asm("umulh %a0,%a1,%v0",(a),(b))
/* file: BN_UMULT_HIGH : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#  elif defined(__GNUC__) && __GNUC__>=2
#   define BN_UMULT_HIGH(a,b)	({	\
	register BN_ULONG ret;		\
	asm ("umulh	%1,%2,%0"	\
	     : "=r"(ret)		\
	     : "r"(a), "r"(b));		\
	ret;			})
/* file: BN_UMULT_HIGH : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#   define BN_UMULT_HIGH(a,b)	({	\
	register BN_ULONG ret;		\
	asm ("mulhdu	%0,%1,%2"	\
	     : "=r"(ret)		\
	     : "r"(a), "r"(b));		\
	ret;			})
/* file: BN_UMULT_HIGH : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#   define BN_UMULT_HIGH(a,b)	({	\
	register BN_ULONG ret,discard;	\
	asm ("mulq	%3"		\
	     : "=a"(discard),"=d"(ret)	\
	     : "a"(a), "g"(b)		\
	     : "cc");			\
	ret;			})

/* file: mul64 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
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
#endif
/* file: L2HBITS : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
#ifdef BN_LLONG
#define	L2HBITS(a)	(((a)<<BN_BITS4)&BN_MASK2)
#endif /* !BN_LLONG */
#endif


/* file: BN_rshift : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
#endif


/* file: BN_is_odd : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
#define BN_is_odd(a)	    (((a)->top > 0) && ((a)->d[0] & 1))
#endif

/* file: BN_add : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
#endif

/* file: BN_is_one : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
#define BN_is_one(a)        (BN_abs_is_word((a),1) && !(a)->neg)
#endif
/* file: BN_abs_is_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
#define BN_abs_is_word(a,w) ((((a)->top == 1) && ((a)->d[0] == (BN_ULONG)(w))) || \
				(((w) == 0) && ((a)->top == 0)))
#endif


/* file: BN_is_word : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
#define BN_is_word(a,w)     (BN_abs_is_word((a),(w)) && (!(w) || !(a)->neg))
#endif

/* file: BN_mul : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
int	BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
#endif

/* file: bn_mul_comba4 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
void bn_mul_comba4(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b);
#endif

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

/* file: bn_mul_add_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);
#endif

/* file: mul_add : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
#ifdef BN_LLONG
#define mul_add(r,a,w,c) { \
	BN_ULLONG t; \
	t=(BN_ULLONG)w * (a) + (r) + (c); \
	(r)= Lw(t); \
	(c)= Hw(t); \
	}
#endif
#endif

/* file: bn_mul_comba8 : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
void bn_mul_comba8(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b);
#endif

/* file: bn_mul_part_recursive : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
void bn_mul_part_recursive(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b,
	int n,int tna,int tnb,BN_ULONG *t);
#endif

/* file: bn_mul_normal : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
void bn_mul_normal(BN_ULONG *r,BN_ULONG *a,int na,BN_ULONG *b,int nb);
#endif

/* file: bn_cmp_part_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
int bn_cmp_part_words(const BN_ULONG *a, const BN_ULONG *b,
	int cl, int dl);
#endif

/* file: bn_cmp_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
int bn_cmp_words(const BN_ULONG *a,const BN_ULONG *b,int n);
#endif

/* file: bn_sub_part_words : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
BN_ULONG bn_sub_part_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
	int cl, int dl);
#endif

/* file: bn_mul_recursive : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn_lcl.h */
#ifndef HEADER_BN_LCL_H
void bn_mul_recursive(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b,int n2,
	int dna,int dnb,BN_ULONG *t);
#endif

/* file: BN_MONT_CTX_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
void BN_MONT_CTX_free(BN_MONT_CTX *mont);
#endif

/* file: BN_set_flags : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
#define BN_set_flags(b,n)	((b)->flags|=(n))
#endif

/* file: DH_check_pub_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/dhdh.h */
#ifndef HEADER_DH_H
int	DH_check_pub_key(const DH *dh,const BIGNUM *pub_key, int *codes);
#endif

/* file: bn_mod_exp : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#ifndef HEADER_BN_H
	int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
			  const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx),
	BN_MONT_CTX *m_ctx);
#endif

/* file: EC_KEY_get0_public_key : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
#ifndef HEADER_EC_H
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key);
#endif


