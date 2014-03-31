#include <stddef.h>
#include <memory.h>

#ifndef HEADER_X509V3_H
typedef struct NOTICEREF_st {
	ASN1_STRING *organization;
	STACK_OF(ASN1_INTEGER) *noticenos;
} NOTICEREF;
#endif

#ifndef HEADER_X509V3_H
typedef struct USERNOTICE_st {
	NOTICEREF *noticeref;
	ASN1_STRING *exptext;
} USERNOTICE;
#endif

#ifndef HEADER_X509_VFY_H
typedef struct x509_lookup_method_st
	{
	const char *name;
	} X509_LOOKUP_METHOD;
#endif

#ifndef HEADER_SSL_H 
#define SSL_MAX_SSL_SESSION_ID_LENGTH		32
#define SSL_MAX_KEY_ARG_LENGTH			8
#define SSL_MAX_MASTER_KEY_LENGTH		48
#endif

#ifndef HEADER_OPENSSL_TYPES_H
typedef struct x509_store_st X509_STORE;
#endif /* def HEADER_OPENSSL_TYPES_H */

#ifndef HEADER_BIO_H
typedef struct bio_method_st
	{
	int type;
	const char *name;
	} BIO_METHOD;
#endif

#ifndef HEADER_ASN1T_H
struct ASN1_TEMPLATE_st {
unsigned long flags;		/* Various flags */
long tag;			/* tag, not used if no tagging */
unsigned long offset;		/* Offset of this field in structure */
#ifndef NO_ASN1_FIELD_NAMES
const char *field_name;		/* Field name */
#endif
ASN1_ITEM_EXP *item;		/* Relevant ASN1_ITEM or ASN1_ADB */
};
#endif

#ifndef HEADER_ASN1_H
typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;
#endif

#ifndef HEADER_X509V3_H
typedef struct POLICYQUALINFO_st {
	ASN1_OBJECT *pqualid;
	union {
		ASN1_IA5STRING *cpsuri;
		USERNOTICE *usernotice;
		ASN1_TYPE *other;
	} d;
} POLICYQUALINFO;
#endif

struct X509_POLICY_DATA_st
	{
	unsigned int flags;
	/* Policy OID and qualifiers for this data */
	ASN1_OBJECT *valid_policy;
	STACK_OF(POLICYQUALINFO) *qualifier_set;
	STACK_OF(ASN1_OBJECT) *expected_policy_set;
	};

typedef struct X509_POLICY_DATA_st X509_POLICY_DATA;

#ifndef HEADER_X509_VFY_H
typedef struct x509_object_st
	{
	/* one of the above types */
	int type;
	union	{
		char *ptr;
		X509 *x509;
		X509_CRL *crl;
		EVP_PKEY *pkey;
		} data;
	} X509_OBJECT;
typedef struct x509_lookup_st X509_LOOKUP;
typedef struct X509_VERIFY_PARAM_st
	{
	char *name;
	time_t check_time;	/* Time to use */
	unsigned long inh_flags; /* Inheritance flags */
	unsigned long flags;	/* Various verify flags */
	int purpose;		/* purpose to check untrusted certificates */
	int trust;		/* trust setting to check */
	int depth;		/* Verify depth */
	STACK_OF(ASN1_OBJECT) *policies;	/* Permissible policies */
	} X509_VERIFY_PARAM;
struct x509_lookup_st
	{
	int init;			/* have we been started */
	int skip;			/* don't use us. */
	X509_LOOKUP_METHOD *method;	/* the functions */
	char *method_data;		/* method data */

	X509_STORE *store_ctx;	/* who owns us */
	} /* X509_LOOKUP */;
#endif

#define NID_aes_256_ctr		906

#ifndef HEADER_MD2_H
#define MD2_DIGEST_LENGTH	16
#endif

#ifndef HEADER_ENVELOPE_H
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
#define EVP_PKEY_NULL_method	NULL,NULL,{0,0,0,0}
#endif /* !EVP_MD */
#ifndef OPENSSL_NO_RSA
struct rsa_st;
#endif
EVP_PKEY *	EVP_PKEY_new(void);
#endif

#ifndef HEADER_BIO_H
typedef struct bio_st BIO;
struct bio_st
	{
	BIO_METHOD *method;
	/* bio, mode, argp, argi, argl, ret */
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
#endif

#ifndef HEADER_ASN1T_H
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
#endif

#ifndef HEADER_OPENSSL_TYPES_H
typedef struct env_md_st EVP_MD;
typedef struct rsa_st RSA;
#endif /* def HEADER_OPENSSL_TYPES_H */

#ifndef OPENSSL_NO_KRB5
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)
static int krb5_loaded = 0;     /* only attempt to initialize func ptrs once */
                          krb5_const krb5_flags F,
                          krb5_data  * pD1,
                          krb5_creds  * pC,
                          krb5_data  * pD2)
	{
	if (!krb5_loaded)
		load_krb5_dll();

	if ( p_krb5_mk_req_extended )
		return(p_krb5_mk_req_extended(CO,pACO,F,pD1,pC,pD2));
	else
		return KRB5KRB_ERR_GENERIC;
	}
                       krb5_auth_context  * pACO)
	{
	if (!krb5_loaded)
		load_krb5_dll();

	if ( p_krb5_auth_con_init )
		return(p_krb5_auth_con_init(CO,pACO));
	else
		return KRB5KRB_ERR_GENERIC;
	}
                         krb5_const krb5_flags F,
                         krb5_ccache CC,
                         krb5_creds  * pCR,
                         krb5_creds  ** ppCR)
	{
	if (!krb5_loaded)
		load_krb5_dll();

	if ( p_krb5_get_credentials )
		return(p_krb5_get_credentials(CO,F,CC,pCR,ppCR));
	else
		return KRB5KRB_ERR_GENERIC;
	}
                            krb5_const char  * pC1,
                            krb5_const char  * pC2,
                            krb5_int32 I,
                            krb5_principal  * pPR)
	{
	if (!krb5_loaded)
		load_krb5_dll();

	if ( p_krb5_sname_to_principal )
		return(p_krb5_sname_to_principal(CO,pC1,pC2,I,pPR));
	else
		return KRB5KRB_ERR_GENERIC;
	}
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

#ifdef OPENSSL_FIPS
#ifndef OPENSSL_DRBG_DEFAULT_TYPE
#define OPENSSL_DRBG_DEFAULT_TYPE	NID_aes_256_ctr
#endif
#ifndef OPENSSL_DRBG_DEFAULT_FLAGS
#define OPENSSL_DRBG_DEFAULT_FLAGS	DRBG_FLAG_CTR_USE_DF
#endif 
#endif


#define STATE_SIZE	1023


struct st_ERR_FNS
	{
	/* Works on the "error_hash" string table */
	/* Works on the "thread_hash" error-state table */
	/* Returns the next available error "library" numbers */
	};

#ifndef HAVE_CRYPTODEV
#else 
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

        --padlen;
        ++cnt;
    }
        ++cnt;
    }
        ++padlen;
        ++cnt;
    }
}

#define ASN1_FLAG_EXP_MAX	20

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

#define TYPE    unsigned int


#define ioctl ioctlsocket

#if !defined(OPENSSL_NO_DES) && !defined(OPENSSL_NO_SHA1)
const EVP_CIPHER *enc;
#endif

#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
static EVP_PKEY *
load_netscape_key(BIO *err, BIO *key, const char *file,
		const char *key_descrip, int format)
	{
	EVP_PKEY *pkey;
	BUF_MEM *buf;
	RSA	*rsa;
	const unsigned char *p;
	int size, i;

	buf=BUF_MEM_new();
	pkey = EVP_PKEY_new();
	size = 0;
	if (buf == NULL || pkey == NULL)
		goto error;
	for (;;)
		{
		if (!BUF_MEM_grow_clean(buf,size+1024*10))
			goto error;
		i = BIO_read(key, &(buf->data[size]), 1024*10);
		size += i;
		if (i == 0)
			break;
		if (i < 0)
			{
				BIO_printf(err, "Error reading %s %s",
					key_descrip, file);
				goto error;
			}
		}
	p=(unsigned char *)buf->data;
	rsa = d2i_RSA_NET(NULL,&p,(long)size,NULL,
		(format == FORMAT_IISSGC ? 1 : 0));
	if (rsa == NULL)
		goto error;
	BUF_MEM_free(buf);
	EVP_PKEY_set1_RSA(pkey, rsa);
	return pkey;
error:
	BUF_MEM_free(buf);
	EVP_PKEY_free(pkey);
	return NULL;
	}
#endif /* ndef OPENSSL_NO_RC4 */

#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
static EVP_PKEY *
load_netscape_key(BIO *err, BIO *key, const char *file,
		const char *key_descrip, int format);
#endif

#ifndef HEADER_SSL_LOCL_H
typedef struct ssl3_enc_method
	{
	int finish_mac_length;
	const char *client_finished_label;
	int client_finished_label_len;
	const char *server_finished_label;
	int server_finished_label_len;
	} SSL3_ENC_METHOD;
#endif

#ifndef HEADER_SSL_H 
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_cipher_st SSL_CIPHER;
typedef struct ssl_session_st SSL_SESSION;
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
#endif

#ifndef HEADER_X509V3_H
typedef struct DIST_POINT_NAME_st {
int type;
union {
	GENERAL_NAMES *fullname;
	STACK_OF(X509_NAME_ENTRY) *relativename;
} name;
/* If relativename then this contains the full distribution point name */
X509_NAME *dpname;
} DIST_POINT_NAME;
typedef struct GENERAL_SUBTREE_st {
	GENERAL_NAME *base;
	ASN1_INTEGER *minimum;
	ASN1_INTEGER *maximum;
} GENERAL_SUBTREE;
#endif

#ifndef HEADER_X509_VFY_H
struct x509_store_st
	{
	/* The following is a cache of trusted certs */
	int cache; 	/* if true, stash any hits */
	STACK_OF(X509_OBJECT) *objs;	/* Cache of all objects */

	/* These are external lookup methods */
	STACK_OF(X509_LOOKUP) *get_cert_methods;

	X509_VERIFY_PARAM *param;

	/* Callbacks for various operations */

	CRYPTO_EX_DATA ex_data;
	int references;
	} /* X509_STORE */;
#endif

#ifndef HEADER_X509_H
typedef struct X509_val_st
	{
	ASN1_TIME *notBefore;
	ASN1_TIME *notAfter;
	} X509_VAL;
struct X509_pubkey_st
	{
	X509_ALGOR *algor;
	ASN1_BIT_STRING *public_key;
	EVP_PKEY *pkey;
	};
typedef struct x509_attributes_st
	{
	ASN1_OBJECT *object;
	union	{
		char		*ptr;
/* 0 */		STACK_OF(ASN1_TYPE) *set;
/* 1 */		ASN1_TYPE	*single;
		} value;
	} X509_ATTRIBUTE;
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
#endif

#ifndef HEADER_SSL_H 
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
#define SSL_R_KRB5_S_RD_REQ				 292
#endif

#ifndef HEADER_OPENSSL_TYPES_H
#ifdef NO_ASN1_TYPEDEFS
#define ASN1_NULL		int
#else
typedef int ASN1_NULL;
#endif
typedef struct ASN1_ITEM_st ASN1_ITEM;
typedef struct x509_revoked_st X509_REVOKED;
typedef struct X509_pubkey_st X509_PUBKEY;
#endif /* def HEADER_OPENSSL_TYPES_H */

#ifndef HEADER_MDC2_H
#define MDC2_DIGEST_LENGTH      16
#endif

#ifndef HEADER_MD5_H
#define MD5_DIGEST_LENGTH 16
#endif

#ifndef	KSSL_H
#ifndef OPENSSL_NO_KRB5
#define	KSSL_ERR_MAX	255
#endif	/* OPENSSL_NO_KRB5	*/
#endif	/* KSSL_H 	*/

#ifndef HEADER_ASN1_H
typedef struct ASN1_ENCODING_st
	{
	unsigned char *enc;	/* DER encoding */
	long len;		/* Length of encoding */
	int modified;		 /* set to 1 if 'enc' is invalid */
	} ASN1_ENCODING;
#endif

#ifndef HEADER_X509V3_H
struct DIST_POINT_st {
DIST_POINT_NAME	*distpoint;
ASN1_BIT_STRING *reasons;
GENERAL_NAMES *CRLissuer;
int dp_reasons;
};
struct AUTHORITY_KEYID_st {
ASN1_OCTET_STRING *keyid;
GENERAL_NAMES *issuer;
ASN1_INTEGER *serial;
};
struct NAME_CONSTRAINTS_st {
	STACK_OF(GENERAL_SUBTREE) *permittedSubtrees;
	STACK_OF(GENERAL_SUBTREE) *excludedSubtrees;
};
struct ISSUING_DIST_POINT_st
	{
	DIST_POINT_NAME *distpoint;
	int onlyuser;
	int onlyCA;
	ASN1_BIT_STRING *onlysomereasons;
	int indirectCRL;
	int onlyattr;
	};
#ifndef OPENSSL_NO_RFC3779
typedef struct ASIdentifierChoice_st {
  int type;
  union {
    ASN1_NULL    *inherit;
    ASIdOrRanges *asIdsOrRanges;
  } u;
} ASIdentifierChoice;
typedef struct IPAddressChoice_st {
  int type;
  union {
    ASN1_NULL		*inherit;
    IPAddressOrRanges	*addressesOrRanges;
  } u;
} IPAddressChoice;
#endif /* OPENSSL_NO_RFC3779 */
#endif

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

#ifndef HEADER_X509_H
typedef struct X509_req_info_st
	{
	ASN1_ENCODING enc;
	ASN1_INTEGER *version;
	X509_NAME *subject;
	X509_PUBKEY *pubkey;
	/*  d=2 hl=2 l=  0 cons: cont: 00 */
	STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
	} X509_REQ_INFO;
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
typedef struct x509_cert_aux_st
	{
	STACK_OF(ASN1_OBJECT) *trust;		/* trusted uses */
	STACK_OF(ASN1_OBJECT) *reject;		/* rejected uses */
	ASN1_UTF8STRING *alias;			/* "friendly name" */
	ASN1_OCTET_STRING *keyid;		/* key id of private key */
	STACK_OF(X509_ALGOR) *other;		/* other unspecified info */
	} X509_CERT_AUX;
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
#endif

#ifndef HEADER_STORE_LOCL_H
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
#endif

#ifndef HEADER_SHA_H
#define SHA_DIGEST_LENGTH 20
#endif

#ifndef HEADER_RAND_LCL_H
#if defined(USE_MD5_RAND)
#define MD_DIGEST_LENGTH	MD5_DIGEST_LENGTH
#elif defined(USE_SHA1_RAND)
#define MD_DIGEST_LENGTH	SHA_DIGEST_LENGTH
#elif defined(USE_MDC2_RAND)
#define MD_DIGEST_LENGTH	MDC2_DIGEST_LENGTH
#elif defined(USE_MD2_RAND)
#define MD_DIGEST_LENGTH	MD2_DIGEST_LENGTH
#endif
#endif

#define NID_cast5_cbc		108
#define NID_md5		4
#define NID_rc4		5
#define NID_des_ede3_cbc		44
#define NID_bf_cbc		91
#define NID_des_cbc		31
#define NID_sha1		64
#define NID_aes_128_cbc		419
#define NID_aes_192_cbc		423
#define NID_aes_256_cbc		427










#ifndef HEADER_ENVELOPE_H
#define EVP_MAX_IV_LENGTH		16
#endif

#ifndef HEADER_ECS_LOCL_H
struct ecdsa_method 
	{
	const char *name;
#if 0
#endif
	int flags;
	char *app_data;
	};
#endif /* HEADER_ECS_LOCL_H */

#ifndef HEADER_DSA_H
struct dsa_method
	{
	const char *name;
	int flags;
	char *app_data;
	/* If this is non-NULL, it is used to generate DSA parameters */
	/* If this is non-NULL, it is used to generate DSA keys */
	};
#endif

#ifndef HEADER_DH_H
struct dh_method
	{
	const char *name;
	/* Methods here */

	int flags;
	char *app_data;
	/* If this is non-NULL, it will be used to generate parameters */
	};
#endif

#ifndef HEADER_BUFFER_H
struct buf_mem_st
	{
	size_t length;	/* current number of bytes */
	char *data;
	size_t max;	/* size of buffer */
	};
#endif

struct x509_crl_method_st
	{
	int flags;
	};

#ifndef HEADER_ASN1_H
struct X509_algor_st;
#ifndef OPENSSL_EXPORT_VAR_AS_FUNCTION
typedef const ASN1_ITEM ASN1_ITEM_EXP;
#else
typedef const ASN1_ITEM * ASN1_ITEM_EXP(void);
#endif
#endif

#ifndef HEADER_OPENSSL_TYPES_H
typedef struct X509_algor_st X509_ALGOR;
typedef struct x509_crl_method_st X509_CRL_METHOD;
typedef struct st_ERR_FNS ERR_FNS;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;
typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;
typedef struct DIST_POINT_st DIST_POINT;
typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;
typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;
#endif /* def HEADER_OPENSSL_TYPES_H */

#ifndef HEADER_CRYPTO_H
typedef struct st_CRYPTO_EX_DATA_IMPL	CRYPTO_EX_DATA_IMPL;
#endif

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
                         krb5_ccache CC,
                         krb5_creds  * pCR,
                         krb5_creds  ** ppCR)
	{
	if (!krb5_loaded)
		load_krb5_dll();

	if ( p_krb5_get_credentials )
		return(p_krb5_get_credentials(CO,F,CC,pCR,ppCR));
	else
		return KRB5KRB_ERR_GENERIC;
	}
                    krb5_const char * sz,
                    krb5_keytab * kt)
	{
	if (!krb5_loaded)
		load_krb5_dll();

	if ( p_krb5_kt_resolve )
		return(p_krb5_kt_resolve(con,sz,kt));
	else
		return KRB5KRB_ERR_GENERIC;
	}
                    krb5_keytab * kt)
	{
	if (!krb5_loaded)
		load_krb5_dll();

	if ( p_krb5_kt_default )
		return(p_krb5_kt_default(con,kt));
	else
		return KRB5KRB_ERR_GENERIC;
	}
                     krb5_ticket * kt)
	{
	if (!krb5_loaded)
		load_krb5_dll();

	if ( p_krb5_free_ticket )
		return(p_krb5_free_ticket(con,kt));
	else
		return KRB5KRB_ERR_GENERIC;
	}
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
	return 0;
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
/* Our internal DH_METHOD that we provide pointers to */
/* This function is aliased to mod_exp (with the dh and mont dropped). */
static int surewarehk_modexp_dh(const DH *dh, BIGNUM *r, const BIGNUM *a,
	const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
	return surewarehk_modexp(r, a, p, m, ctx);
}

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

#ifndef OPENSSL_NO_DSA
/* DSA stuff */
static	DSA_SIG * surewarehk_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa);
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

	    struct sockaddr_in addr;

	struct sockaddr_in addr;

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

#define ADDED_DATA	0
#define ADDED_SNAME	1
#define ADDED_LNAME	2
#define ADDED_NID	3




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

#ifndef HAVE_CRYPTODEV
#else 
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
	struct dev_crypto_state *state = ctx->cipher_data;
	struct session_op *sess = &state->d_sess;
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

#define curve_list_length (sizeof(curve_list)/sizeof(ec_list_element))

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

	return num;

#define KEYSIZB 1024 /* should hit tty line limit first :-) */

#ifdef OPENSSL_NO_CAST
#else
static unsigned char in[8]={ 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
static unsigned char out[80];
#endif

#ifdef BN_CTX_DEBUG
static const char *ctxdbg_cur = NULL;
#endif

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


typedef struct bignum_ctx_stack
	{
	/* Array of indexes into the bignum stack */
	unsigned int *indexes;
	/* Number of stack frames, and the size of the allocated array */
	unsigned int depth, size;
	} BN_STACK;

static BIGNUM *		BN_POOL_get(BN_POOL *);


typedef struct bignum_pool
	{
	/* Linked-list admin */
	BN_POOL_ITEM *head, *current, *tail;
	/* Stack depth and allocation size */
	unsigned used, size;
	} BN_POOL;

typedef struct bignum_pool_item
	{
	/* The bignum values */
	BIGNUM vals[BN_CTX_POOL_SIZE];
	/* Linked-list admin */
	struct bignum_pool_item *prev, *next;
	} BN_POOL_ITEM;

#define BN_CTX_POOL_SIZE	16
#define BN_CTX_START_FRAMES	32


    int flags)
{
    int signvalue = 0;
    LDOUBLE ufvalue;
    char iconvert[20];
    char fconvert[20];
    int iplace = 0;
    int fplace = 0;
    int padlen = 0;
    int zpadlen = 0;
    int caps = 0;
    long intpart;
    long fracpart;
    long max10;

    if (max < 0)
        max = 6;
    ufvalue = abs_val(fvalue);
    if (fvalue < 0)
        signvalue = '-';


    /* sorry, we only support 9 digits past the decimal because of our
       conversion method */
    if (max > 9)
        max = 9;

    /* we "cheat" by converting the fractional part to integer by
       multiplying by a factor of 10 */
    max10 = roundv(pow_10(max));
    fracpart = roundv(pow_10(max) * (ufvalue - intpart));

    if (fracpart >= max10) {
        intpart++;
        fracpart -= max10;
    }

    /* convert integer part */
    do {
        iconvert[iplace++] =
            (caps ? "0123456789ABCDEF"
              : "0123456789abcdef")[intpart % 10];
    } while (intpart && (iplace < (int)sizeof(iconvert)));
    if (iplace == sizeof iconvert)
        iplace--;
    iconvert[iplace] = 0;

    /* convert fractional part */
    do {
        fconvert[fplace++] =
            (caps ? "0123456789ABCDEF"
              : "0123456789abcdef")[fracpart % 10];
    } while (fplace < max);
    if (fplace == sizeof fconvert)
        fplace--;
    fconvert[fplace] = 0;

    /* -1 for decimal point, another -1 if we are printing a sign */
    zpadlen = max - fplace;
    if (zpadlen < 0)
        zpadlen = 0;
    if (padlen < 0)
        padlen = 0;
    if (flags & DP_F_MINUS)
        padlen = -padlen;

    if ((flags & DP_F_ZERO) && (padlen > 0)) {
        if (signvalue) {
            doapr_outch(sbuffer, buffer, currlen, maxlen, signvalue);
            --padlen;
            signvalue = 0;
        }
        while (padlen > 0) {
            doapr_outch(sbuffer, buffer, currlen, maxlen, '0');
            --padlen;
        }
    }
    while (padlen > 0) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
        --padlen;
    }
    if (signvalue)
        doapr_outch(sbuffer, buffer, currlen, maxlen, signvalue);

    while (iplace > 0)
        doapr_outch(sbuffer, buffer, currlen, maxlen, iconvert[--iplace]);

    /*
     * Decimal point. This should probably use locale to find the correct
     * char to print out.
     */

        while (fplace > 0)
            doapr_outch(sbuffer, buffer, currlen, maxlen, fconvert[--fplace]);
    }
    while (zpadlen > 0) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, '0');
        --zpadlen;
    }

    while (padlen < 0) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
        ++padlen;
    }
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

static LDOUBLE
abs_val(LDOUBLE value)
{
    LDOUBLE result = value;
    if (value < 0)
        result = -value;
    return result;
}

    int flags)
{
    int signvalue = 0;
    const char *prefix = "";
    unsigned LLONG uvalue;
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
                    break;
                case DP_C_LONG:
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, unsigned LLONG);
                    break;
                default:
                    break;
                }
                fmtint(sbuffer, buffer, &currlen, maxlen, value,
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

#define LDOUBLE long double
#define LDOUBLE double
# define LLONG __int64
# define LLONG long long
#define LLONG long
#define DP_S_DEFAULT    0
#define DP_S_FLAGS      1
#define DP_S_MIN        2
#define DP_S_DOT        3
#define DP_S_MAX        4
#define DP_S_MOD        5
#define DP_S_CONV       6
#define DP_S_DONE       7
#define DP_F_MINUS      (1 << 0)
#define DP_F_PLUS       (1 << 1)
#define DP_F_SPACE      (1 << 2)
#define DP_F_NUM        (1 << 3)
#define DP_F_ZERO       (1 << 4)
#define DP_F_UP         (1 << 5)
#define DP_F_UNSIGNED   (1 << 6)
#define DP_C_SHORT      1
#define DP_C_LONG       2
#define DP_C_LDOUBLE    3
#define DP_C_LLONG      4



















#ifdef HAVE_LONG_LONG
# if defined(_WIN32) && !defined(__GNUC__)
# define LLONG __int64
# else
# define LLONG long long
# endif
#else
#define LLONG long
#endif

#ifdef HAVE_LONG_DOUBLE
#define LDOUBLE long double
#else
#define LDOUBLE double
#endif

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

typedef struct
	{
	int exp_tag;
	int exp_class;
	int exp_constructed;
	int exp_pad;
	long exp_len;
	} tag_exp_type;

#define ASN1_GEN_FORMAT_ASCII	1
#define ASN1_GEN_FORMAT_UTF8	2
#define ASN1_GEN_FORMAT_HEX	3
#define ASN1_GEN_FORMAT_BITLIST	4





static unsigned long global_mask = 0xFFFFFFFFL;

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
typedef unsigned __int64 u64;
#elif defined(__arch64__)
typedef unsigned long u64;
#else
typedef unsigned long long u64;
#endif


static unsigned long break_order_num=0;

static CRYPTO_THREADID disabling_threadid;

static long options =             /* extra information to be recorded */
#if defined(CRYPTO_MDEBUG_TIME) || defined(CRYPTO_MDEBUG_ALL)
	V_CRYPTO_MDEBUG_TIME |
#endif
#if defined(CRYPTO_MDEBUG_THREAD) || defined(CRYPTO_MDEBUG_ALL)
	V_CRYPTO_MDEBUG_THREAD |
#endif
	0;

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

static unsigned long order = 0; /* number of memory requests */

static int mh_mode=CRYPTO_MEM_CHECK_OFF;

unsigned char cleanse_ctr = 0;


static int allow_customize = 1;      /* we provide flexible functions for */

#define IMPL_CHECK if(!impl) impl_check();

static const CRYPTO_EX_DATA_IMPL *impl = NULL;

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


static SSL_CTX *ctx=NULL;


char key[KEYSIZB+1];

#ifndef HEADER_X509V3_H
struct v3_ext_method;
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
typedef struct X509V3_CONF_METHOD_st {
} X509V3_CONF_METHOD;
typedef struct otherName_st {
ASN1_OBJECT *type_id;
ASN1_TYPE *value;
} OTHERNAME;
typedef struct EDIPartyName_st {
	ASN1_STRING *nameAssigner;
	ASN1_STRING *partyName;
} EDIPARTYNAME;
#ifndef OPENSSL_NO_RFC3779
typedef struct ASIdentifiers_st {
  ASIdentifierChoice *asnum, *rdi;
} ASIdentifiers;
typedef struct IPAddressFamily_st {
  ASN1_OCTET_STRING	*addressFamily;
  IPAddressChoice	*ipAddressChoice;
} IPAddressFamily;
#endif /* OPENSSL_NO_RFC3779 */
#endif

#ifndef HEADER_X509_H
typedef struct X509_extension_st
	{
	ASN1_OBJECT *object;
	ASN1_BOOLEAN critical;
	ASN1_OCTET_STRING *value;
	} X509_EXTENSION;
typedef struct X509_req_st
	{
	X509_REQ_INFO *req_info;
	X509_ALGOR *sig_alg;
	ASN1_BIT_STRING *signature;
	int references;
	} X509_REQ;
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
#endif

#ifndef HEADER_RSA_H
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
#endif

#ifndef HEADER_OPENSSL_TYPES_H
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
typedef struct buf_mem_st BUF_MEM;
typedef struct dh_method DH_METHOD;
typedef struct dsa_method DSA_METHOD;
typedef struct rsa_meth_st RSA_METHOD;
typedef struct ecdsa_method ECDSA_METHOD;
typedef struct x509_st X509;
typedef struct X509_crl_st X509_CRL;
typedef struct store_method_st STORE_METHOD;
#endif /* def HEADER_OPENSSL_TYPES_H */

#ifndef HEADER_ERR_H
#define ERR_R_FATAL				64
#endif

#ifndef HEADER_EC_H
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
#endif

#ifndef HEADER_X509V3_H
struct v3_ext_ctx;
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
typedef struct v3_ext_method X509V3_EXT_METHOD;
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
				ASN1_BIT_STRING *bits,
				STACK_OF(CONF_VALUE) *extlist);
ASN1_INTEGER * s2i_ASN1_INTEGER(X509V3_EXT_METHOD *meth, char *value);
#define X509V3_F_A2I_GENERAL_NAME			 164
#define X509V3_F_DO_DIRNAME				 144
#define X509V3_F_S2I_ASN1_INTEGER			 108
#define X509V3_F_STRING_TO_HEX				 113
#define X509V3_F_X509V3_GET_VALUE_BOOL			 110
#define X509V3_R_BAD_IP_ADDRESS				 118
#define X509V3_R_BAD_OBJECT				 119
#define X509V3_R_BN_DEC2BN_ERROR			 100
#define X509V3_R_BN_TO_ASN1_INTEGER_ERROR		 101
#define X509V3_R_DIRNAME_ERROR				 149
#define X509V3_R_ILLEGAL_HEX_DIGIT			 113
#define X509V3_R_INVALID_BOOLEAN_STRING			 104
#define X509V3_R_INVALID_NULL_ARGUMENT			 107
#define X509V3_R_INVALID_NULL_VALUE			 109
#define X509V3_R_MISSING_VALUE				 124
#define X509V3_R_ODD_NUMBER_OF_DIGITS			 112
#define X509V3_R_OTHERNAME_ERROR			 147
#define X509V3_R_SECTION_NOT_FOUND			 150
#define X509V3_R_UNSUPPORTED_TYPE			 167
#endif

#ifndef HEADER_X509_H
typedef struct X509_name_entry_st
	{
	ASN1_OBJECT *object;
	ASN1_STRING *value;
	int set;
	int size; 	/* temp variable */
	} X509_NAME_ENTRY;
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
					 X509_EXTENSION *ex, int loc);
#define X509_F_X509_NAME_ADD_ENTRY			 113
#define X509_F_X509_NAME_ENTRY_CREATE_BY_TXT		 131
#define X509_F_X509_NAME_ENTRY_SET_OBJECT		 115
#define X509_R_INVALID_FIELD_NAME			 119
#endif

#ifndef HEADER_STACK_H
typedef struct stack_st
	{
	int num;
	char **data;
	int sorted;

	int num_alloc;
	} _STACK;  /* Use STACK_OF(...) instead */
#endif

#ifndef HEADER_SAFESTACK_H
typedef char *OPENSSL_STRING;
#endif /* !defined HEADER_SAFESTACK_H */

#ifndef HEADER_RAND_H
struct rand_meth_st
	{
	};
#define RAND_F_RAND_INIT_FIPS				 102
#define RAND_R_DUAL_EC_DRBG_DISABLED			 104
#define RAND_R_ERROR_INITIALISING_DRBG			 102
#define RAND_R_ERROR_INSTANTIATING_DRBG			 103
#endif

#ifndef HEADER_PEM_H
		      pem_password_cb *cb, void *u);
	pem_password_cb *cb, void *u);
#endif

#ifndef HEADER_OBJECTS_H
#define OBJ_BSEARCH_VALUE_ON_NOMATCH		0x01
#define OBJ_BSEARCH_FIRST_VALUE_ON_MATCH	0x02
ASN1_OBJECT *	OBJ_dup(const ASN1_OBJECT *o);
ASN1_OBJECT *	OBJ_nid2obj(int n);
ASN1_OBJECT *	OBJ_txt2obj(const char *s, int no_name);
const void *	OBJ_bsearch_ex_(const void *key,const void *base,int num,
				int size,

#define _DECLARE_OBJ_BSEARCH_CMP_FN(scope, type1, type2, nm)	\
#define OBJ_F_OBJ_DUP					 101
#define OBJ_F_OBJ_NID2OBJ				 103
#define OBJ_R_UNKNOWN_NID				 101
#endif

#define NID_undef			0
#define NID_X9_62_prime_field		406
#define NID_X9_62_characteristic_two_field		407
#define NID_X9_62_prime256v1		415




#define NUM_NID 920
#define NUM_SN 913
#define NUM_LN 913
#define NUM_OBJ 857





typedef struct { u64 hi,lo; } u128;


struct evp_pkey_method_st
	{
	int pkey_id;
	int flags;














	} /* EVP_PKEY_METHOD */;

#define EVP_PKEY_FLAG_DYNAMIC	1

#ifndef HEADER_ENVELOPE_H
			long length);
			long length);
			long length);
#define ASN1_PKEY_DYNAMIC	0x2
#endif

#ifndef HEADER_ERR_H
#define ERR_TXT_MALLOCED	0x01
#define ERR_TXT_STRING		0x02
#define ERR_FLAG_MARK		0x01
#define ERR_NUM_ERRORS	16
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
#define ERR_LIB_BN		3
#define ERR_LIB_DH		5
#define ERR_LIB_OBJ		8
#define ERR_LIB_X509		11
#define ERR_LIB_ASN1		13
#define ERR_LIB_CONF		14
#define ERR_LIB_EC		16
#define ERR_LIB_X509V3		34
#define ERR_LIB_RAND		36
#define ERR_LIB_ENGINE		38
#define ERR_LIB_ECDH		43
#define ERR_R_BN_LIB	ERR_LIB_BN        /* 3 */
#define ERR_R_ASN1_LIB	ERR_LIB_ASN1     /* 13 */
#define ERR_R_EC_LIB	ERR_LIB_EC       /* 16 */
#define ERR_R_ENGINE_LIB ERR_LIB_ENGINE  /* 38 */
#define ERR_R_NESTED_ASN1_ERROR			58
#define	ERR_R_MALLOC_FAILURE			(1|ERR_R_FATAL)
#define	ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED	(2|ERR_R_FATAL)
#define	ERR_R_PASSED_NULL_PARAMETER		(3|ERR_R_FATAL)
#define	ERR_R_INTERNAL_ERROR			(4|ERR_R_FATAL)
#endif

#ifndef HEADER_ENGINE_H
#define ENGINE_TABLE_FLAG_NOINIT	(unsigned int)0x0001
typedef struct ENGINE_CMD_DEFN_st
	{
	unsigned int cmd_num; /* The command number */
	const char *cmd_name; /* The command name itself */
	const char *cmd_desc; /* A short description of the command */
	unsigned int cmd_flags; /* The input the command expects */
	} ENGINE_CMD_DEFN;
#define ENGINE_F_ENGINE_FINISH				 107
#define ENGINE_F_ENGINE_FREE_UTIL			 108
#define ENGINE_F_ENGINE_UNLOCKED_FINISH			 191
#define ENGINE_R_FINISH_FAILED				 106
#endif

#ifndef HEADER_ENGINE_INT_H
typedef struct st_engine_table ENGINE_TABLE;
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
#endif /* HEADER_ENGINE_INT_H */

#ifndef HEADER_ECH_LOCL_H
struct ecdh_method 
	{
	const char *name;
#if 0
#endif
	int flags;
	char *app_data;
	};
#define ECDH_FLAG_FIPS_METHOD	0x1
typedef struct ecdh_data_st {
	/* EC_KEY_METH_DATA part */
	/* method specific part */
	ENGINE	*engine;
	int	flags;
	const ECDH_METHOD *meth;
	CRYPTO_EX_DATA ex_data;
} ECDH_DATA;
#endif /* HEADER_ECH_LOCL_H */

#ifndef HEADER_ECDH_H
#define ECDH_F_ECDH_CHECK				 102
#define ECDH_F_ECDH_DATA_NEW_METHOD			 101
#define ECDH_R_NON_FIPS_METHOD				 103
#endif


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

#define EC_FLAGS_DEFAULT_OCT	0x1

#ifndef HEADER_EC_H
typedef struct ec_method_st EC_METHOD;
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
typedef struct ec_point_st EC_POINT;
typedef struct ec_key_st EC_KEY;
#define EC_F_COMPUTE_WNAF				 143
#define EC_F_EC_EX_DATA_SET_DATA			 211
#define EC_F_EC_GROUP_GET_DEGREE			 173
#define EC_F_EC_GROUP_NEW				 108
#define EC_F_EC_GROUP_NEW_BY_CURVE_NAME			 174
#define EC_F_EC_GROUP_NEW_FROM_DATA			 175
#define EC_F_EC_GROUP_SET_CURVE_GF2M			 176
#define EC_F_EC_GROUP_SET_CURVE_GFP			 109
#define EC_F_EC_GROUP_SET_GENERATOR			 111
#define EC_F_EC_KEY_GENERATE_KEY			 179
#define EC_F_EC_KEY_NEW					 182
#define EC_F_EC_POINTS_MAKE_AFFINE			 136
#define EC_F_EC_POINT_ADD				 112
#define EC_F_EC_POINT_CMP				 113
#define EC_F_EC_POINT_COPY				 114
#define EC_F_EC_POINT_DBL				 115
#define EC_F_EC_POINT_INVERT				 210
#define EC_F_EC_POINT_NEW				 121
#define EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP	 124
#define EC_F_EC_POINT_SET_TO_INFINITY			 127
#define EC_F_EC_WNAF_MUL				 187
#define EC_R_INCOMPATIBLE_OBJECTS			 101
#define EC_R_NOT_A_SUPPORTED_NIST_PRIME			 136
#define EC_R_SLOT_FULL					 108
#define EC_R_UNDEFINED_GENERATOR			 113
#define EC_R_UNKNOWN_GROUP				 129
#endif

#ifndef HEADER_DH_H
#ifndef OPENSSL_DH_MAX_MODULUS_BITS
# define OPENSSL_DH_MAX_MODULUS_BITS	10000
#endif
#define DH_FLAG_CACHE_MONT_P     0x01
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
#define DH_CHECK_PUBKEY_TOO_SMALL	0x01
#define DH_CHECK_PUBKEY_TOO_LARGE	0x02
#define DH_F_COMPUTE_KEY				 102
#define DH_R_INVALID_PUBKEY				 102
#define DH_R_MODULUS_TOO_LARGE				 103
#define DH_R_NO_PRIVATE_VALUE				 100
#endif


#define CONF_F_CONF_PARSE_LIST				 119
#define CONF_R_LIST_CANNOT_BE_NULL			 115


#ifndef  HEADER_CONF_H
typedef struct
	{
	char *section;
	char *name;
	char *value;
	} CONF_VALUE;
				       const char *section);
#endif

#ifndef HEADER_BUFFER_H
char *	BUF_strdup(const char *str);
char *	BUF_strndup(const char *str, size_t siz);
#endif

#ifndef HEADER_BN_LCL_H
#define BN_MULL_SIZE_NORMAL			(16) /* 32 */
#define BN_MUL_RECURSIVE_SIZE_NORMAL		(16) /* 32 less than */
#endif

#ifndef HEADER_BN_H
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
#define BN_FLG_MALLOCED		0x01
#define BN_FLG_STATIC_DATA	0x02
struct bignum_st
	{
	BN_ULONG *d;	/* Pointer to an array of 'BN_BITS2' bit chunks. */
	int top;	/* Index of last used d +1. */
	/* The next are internal book keeping for bn_expand. */
	int dmax;	/* Size of the d array. */
	int neg;	/* one if the number is negative */
	int flags;
	};
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
#define BN_F_BN_CTX_GET					 116
#define BN_F_BN_CTX_NEW					 106
#define BN_F_BN_CTX_START				 129
#define BN_F_BN_DIV					 107
#define BN_F_BN_EXPAND_INTERNAL				 120
#define BN_F_BN_MOD_INVERSE				 110
#define BN_F_BN_NEW					 113
#define BN_F_BN_RAND_RANGE				 122
#define BN_F_BN_USUB					 115
#define BN_R_ARG2_LT_ARG3				 100
#define BN_R_BIGNUM_TOO_LONG				 114
#define BN_R_DIV_BY_ZERO				 103
#define BN_R_EXPAND_ON_STATIC_BIGNUM_DATA		 105
#define BN_R_INVALID_RANGE				 115
#define BN_R_NOT_INITIALIZED				 107
#define BN_R_NO_INVERSE					 108
#define BN_R_TOO_MANY_ITERATIONS			 113
#define BN_R_TOO_MANY_TEMPORARY_VARIABLES		 109
#endif

#ifndef HEADER_BIO_H
#ifdef __GNUC__
#  define __bio_h__attr__ __attribute__
#endif
#endif

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


#define V_ASN1_UNIVERSAL		0x00
#define V_ASN1_PRIVATE			0xc0
#define V_ASN1_CONSTRUCTED		0x20
#define V_ASN1_PRIMITIVE_TAG		0x1f
#define V_ASN1_NEG			0x100	/* negative flag */
#define V_ASN1_BOOLEAN			1	/**/
#define V_ASN1_INTEGER			2
#define V_ASN1_NEG_INTEGER		(2 | V_ASN1_NEG)
#define V_ASN1_BIT_STRING		3
#define V_ASN1_OCTET_STRING		4
#define V_ASN1_NULL			5
#define V_ASN1_OBJECT			6
#define V_ASN1_ENUMERATED		10
#define V_ASN1_UTF8STRING		12
#define V_ASN1_SEQUENCE			16
#define V_ASN1_SET			17
#define V_ASN1_NUMERICSTRING		18	/**/
#define V_ASN1_PRINTABLESTRING		19
#define V_ASN1_T61STRING		20
#define V_ASN1_IA5STRING		22
#define V_ASN1_UTCTIME			23
#define V_ASN1_GENERALIZEDTIME		24	/**/
#define V_ASN1_VISIBLESTRING		26	/* alias */
#define V_ASN1_GENERALSTRING		27	/**/
#define V_ASN1_UNIVERSALSTRING		28	/**/
#define V_ASN1_BMPSTRING		30
#define B_ASN1_PRINTABLESTRING	0x0002
#define B_ASN1_T61STRING	0x0004
#define B_ASN1_IA5STRING	0x0010
#define B_ASN1_UNIVERSALSTRING	0x0100
#define B_ASN1_BMPSTRING	0x0800
#define MBSTRING_FLAG		0x1000
#define MBSTRING_UTF8		(MBSTRING_FLAG)
#define MBSTRING_ASC		(MBSTRING_FLAG|1)
#define MBSTRING_BMP		(MBSTRING_FLAG|2)
#define MBSTRING_UNIV		(MBSTRING_FLAG|4)
#define ASN1_OBJECT_FLAG_DYNAMIC	 0x01	/* internal use */
#define ASN1_OBJECT_FLAG_DYNAMIC_STRINGS 0x04	/* internal use */
#define ASN1_OBJECT_FLAG_DYNAMIC_DATA 	 0x08	/* internal use */
#define ASN1_STRING_FLAG_NDEF 0x010 
#define STABLE_NO_MASK		0x02
#define ASN1_F_A2D_ASN1_OBJECT				 100
#define ASN1_F_ASN1_GENERATE_V3				 178
#define ASN1_F_ASN1_GET_OBJECT				 114
#define ASN1_F_ASN1_MBSTRING_NCOPY			 122
#define ASN1_F_ASN1_OBJECT_NEW				 123
#define ASN1_F_ASN1_STR2TYPE				 179
#define ASN1_F_ASN1_STRING_SET				 186
#define ASN1_F_ASN1_STRING_TYPE_NEW			 130
#define ASN1_F_BN_TO_ASN1_INTEGER			 139
#define ASN1_F_C2I_ASN1_OBJECT				 196
#define ASN1_F_D2I_ASN1_OBJECT				 147
#define ASN1_R_BUFFER_TOO_SMALL				 107
#define ASN1_R_FIRST_NUM_TOO_LARGE			 122
#define ASN1_R_HEADER_TOO_LONG				 123
#define ASN1_R_ILLEGAL_BITSTRING_FORMAT			 175
#define ASN1_R_ILLEGAL_BOOLEAN				 176
#define ASN1_R_ILLEGAL_CHARACTERS			 124
#define ASN1_R_ILLEGAL_FORMAT				 177
#define ASN1_R_ILLEGAL_HEX				 178
#define ASN1_R_ILLEGAL_INTEGER				 180
#define ASN1_R_ILLEGAL_NULL_VALUE			 182
#define ASN1_R_ILLEGAL_OBJECT				 183
#define ASN1_R_ILLEGAL_TIME_VALUE			 184
#define ASN1_R_INTEGER_NOT_ASCII_FORMAT			 185
#define ASN1_R_INVALID_BMPSTRING_LENGTH			 129
#define ASN1_R_INVALID_DIGIT				 130
#define ASN1_R_INVALID_OBJECT_ENCODING			 216
#define ASN1_R_INVALID_SEPARATOR			 131
#define ASN1_R_INVALID_UNIVERSALSTRING_LENGTH		 133
#define ASN1_R_INVALID_UTF8STRING			 134
#define ASN1_R_LIST_ERROR				 188
#define ASN1_R_MISSING_SECOND_NUMBER			 138
#define ASN1_R_NOT_ASCII_FORMAT				 190
#define ASN1_R_OBJECT_NOT_ASCII_FORMAT			 191
#define ASN1_R_SECOND_NUMBER_TOO_LARGE			 147
#define ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG		 192
#define ASN1_R_STRING_TOO_LONG				 151
#define ASN1_R_STRING_TOO_SHORT				 152
#define ASN1_R_TIME_NOT_ASCII_FORMAT			 193
#define ASN1_R_TOO_LONG					 155
#define ASN1_R_UNKNOWN_FORMAT				 160
#define ASN1_R_UNSUPPORTED_TYPE				 196










































#ifndef HEADER_ASN1_H
#define V_ASN1_UNIVERSAL		0x00
#define V_ASN1_PRIVATE			0xc0
#define V_ASN1_CONSTRUCTED		0x20
#define V_ASN1_PRIMITIVE_TAG		0x1f
#define V_ASN1_NEG			0x100	/* negative flag */
#define V_ASN1_BOOLEAN			1	/**/
#define V_ASN1_INTEGER			2
#define V_ASN1_NEG_INTEGER		(2 | V_ASN1_NEG)
#define V_ASN1_BIT_STRING		3
#define V_ASN1_OCTET_STRING		4
#define V_ASN1_NULL			5
#define V_ASN1_OBJECT			6
#define V_ASN1_ENUMERATED		10
#define V_ASN1_UTF8STRING		12
#define V_ASN1_SEQUENCE			16
#define V_ASN1_SET			17
#define V_ASN1_NUMERICSTRING		18	/**/
#define V_ASN1_PRINTABLESTRING		19
#define V_ASN1_T61STRING		20
#define V_ASN1_IA5STRING		22
#define V_ASN1_UTCTIME			23
#define V_ASN1_GENERALIZEDTIME		24	/**/
#define V_ASN1_VISIBLESTRING		26	/* alias */
#define V_ASN1_GENERALSTRING		27	/**/
#define V_ASN1_UNIVERSALSTRING		28	/**/
#define V_ASN1_BMPSTRING		30
#define B_ASN1_PRINTABLESTRING	0x0002
#define B_ASN1_T61STRING	0x0004
#define B_ASN1_IA5STRING	0x0010
#define B_ASN1_UNIVERSALSTRING	0x0100
#define B_ASN1_BMPSTRING	0x0800
#define MBSTRING_FLAG		0x1000
#define MBSTRING_UTF8		(MBSTRING_FLAG)
#define MBSTRING_ASC		(MBSTRING_FLAG|1)
#define MBSTRING_BMP		(MBSTRING_FLAG|2)
#define MBSTRING_UNIV		(MBSTRING_FLAG|4)
#define ASN1_OBJECT_FLAG_DYNAMIC	 0x01	/* internal use */
#define ASN1_OBJECT_FLAG_DYNAMIC_STRINGS 0x04	/* internal use */
#define ASN1_OBJECT_FLAG_DYNAMIC_DATA 	 0x08	/* internal use */
typedef struct asn1_object_st
	{
	const char *sn,*ln;
	int nid;
	int length;
	const unsigned char *data;	/* data remains const after init */
	int flags;	/* Should we free this one */
	} ASN1_OBJECT;
#define ASN1_STRING_FLAG_NDEF 0x010 
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
#define STABLE_NO_MASK		0x02
typedef struct asn1_string_table_st {
	int nid;
	long minsize;
	long maxsize;
	unsigned long mask;
	unsigned long flags;
} ASN1_STRING_TABLE;
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
ASN1_OBJECT *	ASN1_OBJECT_new(void );
ASN1_OBJECT *	c2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
			long length);
ASN1_OBJECT *	d2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
			long length);
ASN1_STRING *	ASN1_STRING_new(void);
ASN1_STRING *	ASN1_STRING_type_new(int type );
			      const unsigned char **pp,
			      long length, d2i_of_void *d2i,


#ifndef HEADER_SYMHACKS_H
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
#endif /* ! defined HEADER_VMS_IDHACKS_H */

#ifndef HEADER_OPENSSL_TYPES_H
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
typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
typedef struct dh_st DH;
typedef struct rand_meth_st RAND_METHOD;
typedef struct ecdh_method ECDH_METHOD;
typedef struct X509_name_st X509_NAME;
typedef struct v3_ext_ctx X509V3_CTX;
typedef struct engine_st ENGINE;
#endif /* def HEADER_OPENSSL_TYPES_H */

#ifndef HEADER_EBCDIC_H
#define os_toascii   _openssl_os_toascii
#define os_toebcdic  _openssl_os_toebcdic
extern const unsigned char os_toascii[256];
extern const unsigned char os_toebcdic[256];
#endif

#ifndef HEADER_CRYPTO_H
#if 0
typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
#endif
#define	CRYPTO_LOCK_ERR			1
#define CRYPTO_LOCK_MALLOC		20
#define CRYPTO_LOCK_DH			26
#define CRYPTO_LOCK_MALLOC2		27
#define CRYPTO_LOCK_DYNLOCK		29
#define CRYPTO_LOCK_ENGINE		30
#define CRYPTO_LOCK_EC			33
#define CRYPTO_NUM_LOCKS		41
#define CRYPTO_LOCK		1
#define CRYPTO_UNLOCK		2
#define CRYPTO_READ		4
#define CRYPTO_WRITE		8
typedef struct
	{
	int references;
	struct CRYPTO_dynlock_value *data;
	} CRYPTO_dynlock;
#define CRYPTO_MEM_CHECK_OFF	0x0	/* an enume */
#define CRYPTO_MEM_CHECK_ON	0x1	/* a bit */
#define CRYPTO_MEM_CHECK_ENABLE	0x2	/* a bit */
#define CRYPTO_MEM_CHECK_DISABLE 0x3	/* an enume */
#define V_CRYPTO_MDEBUG_TIME	0x1 /* a bit */
#define V_CRYPTO_MDEBUG_THREAD	0x2 /* a bit */
struct crypto_ex_data_st
	{
	STACK_OF(void) *sk;
	};
#define CRYPTO_EX_INDEX_ENGINE		9
#define CRYPTO_EX_INDEX_ECDH		13
typedef struct crypto_threadid_st
	{
	void *ptr;
	unsigned long val;
	} CRYPTO_THREADID;
#endif

typedef struct {
	int type;
	const char *name;
	} FUNCTION;

#ifndef HEADER_E_OS_H
#if (defined(WINDOWS) || defined(MSDOS))
#  ifdef WINDOWS
#    if !defined(_WIN32_WCE) && !defined(_WIN32_WINNT)
#      define _WIN32_WINNT 0x0400
#    endif
#  endif
#endif
#endif

/********** Headers **********/ 
/* file: ecdh_low : /Volumes/work/Phd/ECDH/kv_openssl/PythonScriptecdh_low.h */
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
 memset(A,0,sizeof(BN_ULONG)*words); /* file: BN_get_flags : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
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
#endif
#endif

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


