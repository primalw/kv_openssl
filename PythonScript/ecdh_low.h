#include <stddef.h>
#include <memory.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include "obj_mac.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NID_X9_62_prime256v1		415
#define NID_X9_62_characteristic_two_field		407

#define ub_name				32768
#define ub_common_name			64
#define ub_locality_name		128
#define ub_state_name			128
#define ub_organization_name		64
#define ub_organization_unit_name	64
#define ub_title			64
#define ub_email_address		128
#define ub_serial_number		64

#define CRYPTO_LOCK_EC_PRE_COMP		36

//#define ec_GFp_simple_points_make_affine	ec_GFp_simple_pts_make_affine
#define STACK_OF(type) struct stack_st_##type
#define LHASH_OF(type) struct lhash_st_##type
#define DECLARE_LHASH_OF(type) LHASH_OF(type) { int dummy; }
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
#define BUF_F_BUF_STRNDUP				 104
#define CRYPTO_EX_INDEX_ECDH		13
#define ECDH_F_ECDH_DATA_NEW_METHOD			 101
#define EC_F_COMPUTE_WNAF				 143
#define SSL_R_KRB5_S_RD_REQ				 292
#define KRB5KRB_ERR_GENERIC 1
#define ENOMEM KRB5KRB_ERR_GENERIC
#define	CRYPTO_LOCK_ERR			1
#define EC_F_EC_GROUP_NEW_FROM_DATA			 175
#define NID_undef			0
#define OBJ_F_OBJ_NID2OBJ				 103
#define OBJ_R_UNKNOWN_NID				 101
#define ADDED_NID	3
#define OBJ_F_OBJ_DUP					 101

#ifdef OPENSSL_NO_OBJECT
#define NUM_NID 0
#else
#define NUM_NID 920
#endif

#define ERR_R_BN_LIB	ERR_LIB_BN        /* 3 */
#define ERR_R_EC_LIB	ERR_LIB_EC       /* 16 */

#ifdef OPENSSL_NO_OBJECT
#define NUM_NID 0
#define NUM_SN 0
#define NUM_LN 0
#define NUM_OBJ 0
#else
#define NUM_NID 920
#define NUM_SN 913
#define NUM_LN 913
#define NUM_OBJ 857
#endif

#define STABLE_FLAGS_MALLOC	0x01
#define STABLE_NO_MASK		0x02
#define DIRSTRING_TYPE	\
(B_ASN1_PRINTABLESTRING|B_ASN1_T61STRING|B_ASN1_BMPSTRING|B_ASN1_UTF8STRING)
#define PKCS9STRING_TYPE (DIRSTRING_TYPE|B_ASN1_IA5STRING)

#define ASN1_GEN_FORMAT_ASCII	1
#define ASN1_GEN_FORMAT_UTF8	2
#define ASN1_GEN_FORMAT_HEX	3
#define ASN1_GEN_FORMAT_BITLIST	4
#define ASN1_STRING_FLAG_BITS_LEFT 0x08 /* Set if 0x07 has bits left value */
#define X509_F_X509_NAME_ADD_ENTRY			 113
#define ASN1_STRING_FLAG_NDEF 0x010 
#define EVP_PKEY_FLAG_DYNAMIC	1
#define ASN1_PKEY_DYNAMIC	0x2
#define CONF_R_LIST_CANNOT_BE_NULL			 115
#define X509_R_INVALID_FIELD_NAME			 119

#define ERR_R_ENGINE_LIB ERR_LIB_ENGINE  /* 38 */

#define OBJ_BSEARCH_VALUE_ON_NOMATCH		0x01
#define OBJ_BSEARCH_FIRST_VALUE_ON_MATCH	0x02
#define DH_CHECK_PUBKEY_TOO_SMALL	0x01
#define DH_CHECK_PUBKEY_TOO_LARGE	0x02
#define BN_FLG_CONSTTIME	0x04 /* avoid leaking exponent information through timing, */
#define BN_CTX_START_FRAMES	32
#define BN_FLG_FREE		0x8000	/* used for debuging */

#define DH_F_COMPUTE_KEY				 102
#define DH_FLAG_NO_EXP_CONSTTIME 0x02 /* new with 0.9.7h; the built-in DH */
#define DH_FLAG_CACHE_MONT_P     0x01
#define DH_R_INVALID_PUBKEY				 102
#define DH_R_NO_PRIVATE_VALUE				 100
#define DH_R_MODULUS_TOO_LARGE				 103

#define ERR_LIB_EC		16
#define EC_F_EC_KEY_NEW					 182
#define V_CRYPTO_MDEBUG_THREAD	0x2 /* a bit */
#define V_CRYPTO_MDEBUG_TIME	0x1 /* a bit */
#define CRYPTO_WRITE		8
#define CRYPTO_EX_INDEX_ENGINE		9
#define CRYPTO_UNLOCK		2
#define CRYPTO_EX_INDEX_ENGINE		9

#define ADDED_DATA	0
#define ADDED_SNAME	1
#define ADDED_LNAME	2
#define BN_FLG_MALLOCED		0x01
#define ENGINE_TABLE_FLAG_NOINIT	(unsigned int)0x0001
#define ERR_TXT_STRING		0x02
#define ERR_FLAG_MARK		0x01
#define ERR_R_NESTED_ASN1_ERROR			58
#define CONF_F_CONF_PARSE_LIST				 119

#define X509_F_X509_NAME_ENTRY_CREATE_BY_TXT		 131
#define X509_F_X509_NAME_ENTRY_SET_OBJECT		 115

#define ENGINE_F_ENGINE_UNLOCKED_FINISH			 191
#define ENGINE_F_ENGINE_FREE_UTIL			 108
#define ENGINE_F_ENGINE_FINISH				 107
#define ENGINE_R_FINISH_FAILED				 106

#define CRYPTO_MEM_CHECK_OFF	0x0	/* an enume */
#define CRYPTO_MEM_CHECK_ON	0x1	/* a bit */
#define CRYPTO_MEM_CHECK_ENABLE	0x2	/* a bit */
#define CRYPTO_MEM_CHECK_DISABLE 0x3	/* an enume */

#define CRYPTO_LOCK		1
#define CRYPTO_LOCK_MALLOC		20
#define CRYPTO_LOCK_DH			26
#define CRYPTO_LOCK_MALLOC2		27
#define CRYPTO_LOCK_DYNLOCK		29
#define CRYPTO_LOCK_ENGINE		30
#define CRYPTO_LOCK_EC			33
#define CRYPTO_READ		4
#define ERR_LIB_X509V3		34
#define V_ASN1_IA5STRING		22
#define ERR_TXT_MALLOCED	0x01

#define ERR_LIB_ASN1		13
#undef BN_LLONG
#undef BN_ULLONG
#define BN_ULONG	unsigned long long
#define BN_LONG		long long
#define BN_BITS		128
#define BN_BYTES	8
#define BN_BITS2	64
#define BN_BITS4	32
#define BN_MASK2	(0xffffffffffffffffLL)
#define BN_MASK2l	(0xffffffffL)
#define BN_MASK2h	(0xffffffff00000000LL)
#define BN_MASK2h1	(0xffffffff80000000LL)
#define BN_TBIT		(0x8000000000000000LL)
#define BN_DEC_CONV	(10000000000000000000ULL)
#define BN_DEC_FMT1	"%llu"
#define BN_DEC_FMT2	"%019llu"
#define BN_DEC_NUM	19
#define BN_HEX_FMT1	"%llX"
#define BN_HEX_FMT2	"%016llX"

#define ASN1_OBJECT_FLAG_DYNAMIC	 0x01	/* internal use */
#define ASN1_OBJECT_FLAG_CRITICAL	 0x02	/* critical x509v3 object id */
#define ASN1_OBJECT_FLAG_DYNAMIC_STRINGS 0x04	/* internal use */
#define ASN1_OBJECT_FLAG_DYNAMIC_DATA 	 0x08	/* internal use */

#define ASN1_F_A2D_ASN1_OBJECT				 100
#define ASN1_F_A2I_ASN1_ENUMERATED			 101
#define ASN1_F_A2I_ASN1_INTEGER				 102
#define ASN1_F_A2I_ASN1_STRING				 103
#define ASN1_F_APPEND_EXP				 176
#define ASN1_F_ASN1_BIT_STRING_SET_BIT			 183
#define ASN1_F_ASN1_CB					 177
#define ASN1_F_ASN1_CHECK_TLEN				 104
#define ASN1_F_ASN1_COLLATE_PRIMITIVE			 105
#define ASN1_F_ASN1_COLLECT				 106
#define ASN1_F_ASN1_D2I_EX_PRIMITIVE			 108
#define ASN1_F_ASN1_D2I_FP				 109
#define ASN1_F_ASN1_D2I_READ_BIO			 107
#define ASN1_F_ASN1_DIGEST				 184
#define ASN1_F_ASN1_DO_ADB				 110
#define ASN1_F_ASN1_DUP					 111
#define ASN1_F_ASN1_ENUMERATED_SET			 112
#define ASN1_F_ASN1_ENUMERATED_TO_BN			 113
#define ASN1_F_ASN1_EX_C2I				 204
#define ASN1_F_ASN1_FIND_END				 190
#define ASN1_F_ASN1_GENERALIZEDTIME_ADJ			 216
#define ASN1_F_ASN1_GENERALIZEDTIME_SET			 185
#define ASN1_F_ASN1_GENERATE_V3				 178
#define ASN1_F_ASN1_GET_OBJECT				 114
#define ASN1_F_ASN1_HEADER_NEW				 115
#define ASN1_F_ASN1_I2D_BIO				 116
#define ASN1_F_ASN1_I2D_FP				 117
#define ASN1_F_ASN1_INTEGER_SET				 118
#define ASN1_F_ASN1_INTEGER_TO_BN			 119
#define ASN1_F_ASN1_ITEM_D2I_FP				 206
#define ASN1_F_ASN1_ITEM_DUP				 191
#define ASN1_F_ASN1_ITEM_EX_COMBINE_NEW			 121
#define ASN1_F_ASN1_ITEM_EX_D2I				 120
#define ASN1_F_ASN1_ITEM_I2D_BIO			 192
#define ASN1_F_ASN1_ITEM_I2D_FP				 193
#define ASN1_F_ASN1_ITEM_PACK				 198
#define ASN1_F_ASN1_ITEM_SIGN				 195
#define ASN1_F_ASN1_ITEM_SIGN_CTX			 220
#define ASN1_F_ASN1_ITEM_UNPACK				 199
#define ASN1_F_ASN1_ITEM_VERIFY				 197
#define ASN1_F_ASN1_MBSTRING_NCOPY			 122
#define ASN1_F_ASN1_OBJECT_NEW				 123
#define ASN1_F_ASN1_OUTPUT_DATA				 214
#define ASN1_F_ASN1_PACK_STRING				 124
#define ASN1_F_ASN1_PCTX_NEW				 205
#define ASN1_F_ASN1_PKCS5_PBE_SET			 125
#define ASN1_F_ASN1_SEQ_PACK				 126
#define ASN1_F_ASN1_SEQ_UNPACK				 127
#define ASN1_F_ASN1_SIGN				 128
#define ASN1_F_ASN1_STR2TYPE				 179
#define ASN1_F_ASN1_STRING_SET				 186
#define ASN1_F_ASN1_STRING_TABLE_ADD			 129
#define ASN1_F_ASN1_STRING_TYPE_NEW			 130
#define ASN1_F_ASN1_TEMPLATE_EX_D2I			 132
#define ASN1_F_ASN1_TEMPLATE_NEW			 133
#define ASN1_F_ASN1_TEMPLATE_NOEXP_D2I			 131
#define ASN1_F_ASN1_TIME_ADJ				 217
#define ASN1_F_ASN1_TIME_SET				 175
#define ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING		 134
#define ASN1_F_ASN1_TYPE_GET_OCTETSTRING		 135
#define ASN1_F_ASN1_UNPACK_STRING			 136
#define ASN1_F_ASN1_UTCTIME_ADJ				 218
#define ASN1_F_ASN1_UTCTIME_SET				 187
#define ASN1_F_ASN1_VERIFY				 137
#define ASN1_F_B64_READ_ASN1				 209
#define ASN1_F_B64_WRITE_ASN1				 210
#define ASN1_F_BIO_NEW_NDEF				 208
#define ASN1_F_BITSTR_CB				 180
#define ASN1_F_BN_TO_ASN1_ENUMERATED			 138
#define ASN1_F_BN_TO_ASN1_INTEGER			 139
#define ASN1_F_C2I_ASN1_BIT_STRING			 189
#define ASN1_F_C2I_ASN1_INTEGER				 194
#define ASN1_F_C2I_ASN1_OBJECT				 196
#define ASN1_F_COLLECT_DATA				 140
#define ASN1_F_D2I_ASN1_BIT_STRING			 141
#define ASN1_F_D2I_ASN1_BOOLEAN				 142
#define ASN1_F_D2I_ASN1_BYTES				 143
#define ASN1_F_D2I_ASN1_GENERALIZEDTIME			 144
#define ASN1_F_D2I_ASN1_HEADER				 145
#define ASN1_F_D2I_ASN1_INTEGER				 146
#define ASN1_F_D2I_ASN1_OBJECT				 147
#define ASN1_F_D2I_ASN1_SET				 148
#define ASN1_F_D2I_ASN1_TYPE_BYTES			 149
#define ASN1_F_D2I_ASN1_UINTEGER			 150
#define ASN1_F_D2I_ASN1_UTCTIME				 151
#define ASN1_F_D2I_AUTOPRIVATEKEY			 207
#define ASN1_F_D2I_NETSCAPE_RSA				 152
#define ASN1_F_D2I_NETSCAPE_RSA_2			 153
#define ASN1_F_D2I_PRIVATEKEY				 154
#define ASN1_F_D2I_PUBLICKEY				 155
#define ASN1_F_D2I_RSA_NET				 200
#define ASN1_F_D2I_RSA_NET_2				 201
#define ASN1_F_D2I_X509					 156
#define ASN1_F_D2I_X509_CINF				 157
#define ASN1_F_D2I_X509_PKEY				 159
#define ASN1_F_I2D_ASN1_BIO_STREAM			 211
#define ASN1_F_I2D_ASN1_SET				 188
#define ASN1_F_I2D_ASN1_TIME				 160
#define ASN1_F_I2D_DSA_PUBKEY				 161
#define ASN1_F_I2D_EC_PUBKEY				 181
#define ASN1_F_I2D_PRIVATEKEY				 163
#define ASN1_F_I2D_PUBLICKEY				 164
#define ASN1_F_I2D_RSA_NET				 162
#define ASN1_F_I2D_RSA_PUBKEY				 165
#define ASN1_F_LONG_C2I					 166
#define ASN1_F_OID_MODULE_INIT				 174
#define ASN1_F_PARSE_TAGGING				 182
#define ASN1_F_PKCS5_PBE2_SET_IV			 167
#define ASN1_F_PKCS5_PBE_SET				 202
#define ASN1_F_PKCS5_PBE_SET0_ALGOR			 215
#define ASN1_F_PKCS5_PBKDF2_SET				 219
#define ASN1_F_SMIME_READ_ASN1				 212
#define ASN1_F_SMIME_TEXT				 213
#define ASN1_F_X509_CINF_NEW				 168
#define ASN1_F_X509_CRL_ADD0_REVOKED			 169
#define ASN1_F_X509_INFO_NEW				 170
#define ASN1_F_X509_NAME_ENCODE				 203
#define ASN1_F_X509_NAME_EX_D2I				 158
#define ASN1_F_X509_NAME_EX_NEW				 171
#define ASN1_F_X509_NEW					 172
#define ASN1_F_X509_PKEY_NEW				 173
	
	/* Reason codes. */
#define ASN1_R_ADDING_OBJECT				 171
#define ASN1_R_ASN1_PARSE_ERROR				 203
#define ASN1_R_ASN1_SIG_PARSE_ERROR			 204
#define ASN1_R_AUX_ERROR				 100
#define ASN1_R_BAD_CLASS				 101
#define ASN1_R_BAD_OBJECT_HEADER			 102
#define ASN1_R_BAD_PASSWORD_READ			 103
#define ASN1_R_BAD_TAG					 104
#define ASN1_R_BMPSTRING_IS_WRONG_LENGTH		 214
#define ASN1_R_BN_LIB					 105
#define ASN1_R_BOOLEAN_IS_WRONG_LENGTH			 106
#define ASN1_R_BUFFER_TOO_SMALL				 107
#define ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER		 108
#define ASN1_R_CONTEXT_NOT_INITIALISED			 217
#define ASN1_R_DATA_IS_WRONG				 109
#define ASN1_R_DECODE_ERROR				 110
#define ASN1_R_DECODING_ERROR				 111
#define ASN1_R_DEPTH_EXCEEDED				 174
#define ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED	 198
#define ASN1_R_ENCODE_ERROR				 112
#define ASN1_R_ERROR_GETTING_TIME			 173
#define ASN1_R_ERROR_LOADING_SECTION			 172
#define ASN1_R_ERROR_PARSING_SET_ELEMENT		 113
#define ASN1_R_ERROR_SETTING_CIPHER_PARAMS		 114
#define ASN1_R_EXPECTING_AN_INTEGER			 115
#define ASN1_R_EXPECTING_AN_OBJECT			 116
#define ASN1_R_EXPECTING_A_BOOLEAN			 117
#define ASN1_R_EXPECTING_A_TIME				 118
#define ASN1_R_EXPLICIT_LENGTH_MISMATCH			 119
#define ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED		 120
#define ASN1_R_FIELD_MISSING				 121
#define ASN1_R_FIRST_NUM_TOO_LARGE			 122
#define ASN1_R_HEADER_TOO_LONG				 123
#define ASN1_R_ILLEGAL_BITSTRING_FORMAT			 175
#define ASN1_R_ILLEGAL_BOOLEAN				 176
#define ASN1_R_ILLEGAL_CHARACTERS			 124
#define ASN1_R_ILLEGAL_FORMAT				 177
#define ASN1_R_ILLEGAL_HEX				 178
#define ASN1_R_ILLEGAL_IMPLICIT_TAG			 179
#define ASN1_R_ILLEGAL_INTEGER				 180
#define ASN1_R_ILLEGAL_NESTED_TAGGING			 181
#define ASN1_R_ILLEGAL_NULL				 125
#define ASN1_R_ILLEGAL_NULL_VALUE			 182
#define ASN1_R_ILLEGAL_OBJECT				 183
#define ASN1_R_ILLEGAL_OPTIONAL_ANY			 126
#define ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE		 170
#define ASN1_R_ILLEGAL_TAGGED_ANY			 127
#define ASN1_R_ILLEGAL_TIME_VALUE			 184
#define ASN1_R_INTEGER_NOT_ASCII_FORMAT			 185
#define ASN1_R_INTEGER_TOO_LARGE_FOR_LONG		 128
#define ASN1_R_INVALID_BMPSTRING_LENGTH			 129
#define ASN1_R_INVALID_DIGIT				 130
#define ASN1_R_INVALID_MIME_TYPE			 205
#define ASN1_R_INVALID_MODIFIER				 186
#define ASN1_R_INVALID_NUMBER				 187
#define ASN1_R_INVALID_OBJECT_ENCODING			 216
#define ASN1_R_INVALID_SEPARATOR			 131
#define ASN1_R_INVALID_TIME_FORMAT			 132
#define ASN1_R_INVALID_UNIVERSALSTRING_LENGTH		 133
#define ASN1_R_INVALID_UTF8STRING			 134
#define ASN1_R_IV_TOO_LARGE				 135
#define ASN1_R_LENGTH_ERROR				 136
#define ASN1_R_LIST_ERROR				 188
#define ASN1_R_MIME_NO_CONTENT_TYPE			 206
#define ASN1_R_MIME_PARSE_ERROR				 207
#define ASN1_R_MIME_SIG_PARSE_ERROR			 208
#define ASN1_R_MISSING_EOC				 137
#define ASN1_R_MISSING_SECOND_NUMBER			 138
#define ASN1_R_MISSING_VALUE				 189
#define ASN1_R_MSTRING_NOT_UNIVERSAL			 139
#define ASN1_R_MSTRING_WRONG_TAG			 140
#define ASN1_R_NESTED_ASN1_STRING			 197
#define ASN1_R_NON_HEX_CHARACTERS			 141
#define ASN1_R_NOT_ASCII_FORMAT				 190
#define ASN1_R_NOT_ENOUGH_DATA				 142
#define ASN1_R_NO_CONTENT_TYPE				 209
#define ASN1_R_NO_DEFAULT_DIGEST			 201
#define ASN1_R_NO_MATCHING_CHOICE_TYPE			 143
#define ASN1_R_NO_MULTIPART_BODY_FAILURE		 210
#define ASN1_R_NO_MULTIPART_BOUNDARY			 211
#define ASN1_R_NO_SIG_CONTENT_TYPE			 212
#define ASN1_R_NULL_IS_WRONG_LENGTH			 144
#define ASN1_R_OBJECT_NOT_ASCII_FORMAT			 191
#define ASN1_R_ODD_NUMBER_OF_CHARS			 145
#define ASN1_R_PRIVATE_KEY_HEADER_MISSING		 146
#define ASN1_R_SECOND_NUMBER_TOO_LARGE			 147
#define ASN1_R_SEQUENCE_LENGTH_MISMATCH			 148
#define ASN1_R_SEQUENCE_NOT_CONSTRUCTED			 149
#define ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG		 192
#define ASN1_R_SHORT_LINE				 150
#define ASN1_R_SIG_INVALID_MIME_TYPE			 213
#define ASN1_R_STREAMING_NOT_SUPPORTED			 202
#define ASN1_R_STRING_TOO_LONG				 151
#define ASN1_R_STRING_TOO_SHORT				 152
#define ASN1_R_TAG_VALUE_TOO_HIGH			 153
#define ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD 154
#define ASN1_R_TIME_NOT_ASCII_FORMAT			 193
#define ASN1_R_TOO_LONG					 155
#define ASN1_R_TYPE_NOT_CONSTRUCTED			 156
#define ASN1_R_UNABLE_TO_DECODE_RSA_KEY			 157
#define ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY		 158
#define ASN1_R_UNEXPECTED_EOC				 159
#define ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH		 215
#define ASN1_R_UNKNOWN_FORMAT				 160
#define ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM		 161
#define ASN1_R_UNKNOWN_OBJECT_TYPE			 162
#define ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE			 163
#define ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM		 199
#define ASN1_R_UNKNOWN_TAG				 194
#define ASN1_R_UNKOWN_FORMAT				 195
#define ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE		 164
#define ASN1_R_UNSUPPORTED_CIPHER			 165
#define ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM		 166
#define ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE		 167
#define ASN1_R_UNSUPPORTED_TYPE				 196
#define ASN1_R_WRONG_PUBLIC_KEY_TYPE			 200
#define ASN1_R_WRONG_TAG				 168
#define ASN1_R_WRONG_TYPE				 169

	/* library */
#define ERR_LIB_NONE		1
#define ERR_LIB_SYS		2
#define ERR_LIB_BN		3
#define ERR_LIB_RSA		4
#define ERR_LIB_DH		5
#define ERR_LIB_EVP		6
#define ERR_LIB_BUF		7
#define ERR_LIB_OBJ		8
#define ERR_LIB_PEM		9
#define ERR_LIB_DSA		10
#define ERR_LIB_X509		11
	/* #define ERR_LIB_METH         12 */
#define ERR_LIB_ASN1		13
#define ERR_LIB_CONF		14
#define ERR_LIB_CRYPTO		15
#define ERR_LIB_EC		16
#define ERR_LIB_SSL		20
	/* #define ERR_LIB_SSL23        21 */
	/* #define ERR_LIB_SSL2         22 */
	/* #define ERR_LIB_SSL3         23 */
	/* #define ERR_LIB_RSAREF       30 */
	/* #define ERR_LIB_PROXY        31 */
#define ERR_LIB_BIO		32
#define ERR_LIB_PKCS7		33
#define ERR_LIB_X509V3		34
#define ERR_LIB_PKCS12		35
#define ERR_LIB_RAND		36
#define ERR_LIB_DSO		37
#define ERR_LIB_ENGINE		38
#define ERR_LIB_OCSP            39
#define ERR_LIB_UI              40
#define ERR_LIB_COMP            41
#define ERR_LIB_ECDSA		42
#define ERR_LIB_ECDH		43
#define ERR_LIB_STORE           44
#define ERR_LIB_FIPS		45
#define ERR_LIB_CMS		46
#define ERR_LIB_TS		47
#define ERR_LIB_HMAC		48
#define ERR_LIB_JPAKE		49
	
#define ERR_LIB_USER		128

	/* Function codes. */
#define BN_F_BNRAND					 127
#define BN_F_BN_BLINDING_CONVERT_EX			 100
#define BN_F_BN_BLINDING_CREATE_PARAM			 128
#define BN_F_BN_BLINDING_INVERT_EX			 101
#define BN_F_BN_BLINDING_NEW				 102
#define BN_F_BN_BLINDING_UPDATE				 103
#define BN_F_BN_BN2DEC					 104
#define BN_F_BN_BN2HEX					 105
#define BN_F_BN_CTX_GET					 116
#define BN_F_BN_CTX_NEW					 106
#define BN_F_BN_CTX_START				 129
#define BN_F_BN_DIV					 107
#define BN_F_BN_DIV_NO_BRANCH				 138
#define BN_F_BN_DIV_RECP				 130
#define BN_F_BN_EXP					 123
#define BN_F_BN_EXPAND2					 108
#define BN_F_BN_EXPAND_INTERNAL				 120
#define BN_F_BN_GF2M_MOD				 131
#define BN_F_BN_GF2M_MOD_EXP				 132
#define BN_F_BN_GF2M_MOD_MUL				 133
#define BN_F_BN_GF2M_MOD_SOLVE_QUAD			 134
#define BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR			 135
#define BN_F_BN_GF2M_MOD_SQR				 136
#define BN_F_BN_GF2M_MOD_SQRT				 137
#define BN_F_BN_MOD_EXP2_MONT				 118
#define BN_F_BN_MOD_EXP_MONT				 109
#define BN_F_BN_MOD_EXP_MONT_CONSTTIME			 124
#define BN_F_BN_MOD_EXP_MONT_WORD			 117
#define BN_F_BN_MOD_EXP_RECP				 125
#define BN_F_BN_MOD_EXP_SIMPLE				 126
#define BN_F_BN_MOD_INVERSE				 110
#define BN_F_BN_MOD_INVERSE_NO_BRANCH			 139
#define BN_F_BN_MOD_LSHIFT_QUICK			 119
#define BN_F_BN_MOD_MUL_RECIPROCAL			 111
#define BN_F_BN_MOD_SQRT				 121
#define BN_F_BN_MPI2BN					 112
#define BN_F_BN_NEW					 113
#define BN_F_BN_RAND					 114
#define BN_F_BN_RAND_RANGE				 122
#define BN_F_BN_USUB					 115
	
	/* Reason codes. */
#define BN_R_ARG2_LT_ARG3				 100
#define BN_R_BAD_RECIPROCAL				 101
#define BN_R_BIGNUM_TOO_LONG				 114
#define BN_R_CALLED_WITH_EVEN_MODULUS			 102
#define BN_R_DIV_BY_ZERO				 103
#define BN_R_ENCODING_ERROR				 104
#define BN_R_EXPAND_ON_STATIC_BIGNUM_DATA		 105
#define BN_R_INPUT_NOT_REDUCED				 110
#define BN_R_INVALID_LENGTH				 106
#define BN_R_INVALID_RANGE				 115
#define BN_R_NOT_A_SQUARE				 111
#define BN_R_NOT_INITIALIZED				 107
#define BN_R_NO_INVERSE					 108
#define BN_R_NO_SOLUTION				 116
#define BN_R_P_IS_NOT_PRIME				 112
#define BN_R_TOO_MANY_ITERATIONS			 113
#define BN_R_TOO_MANY_TEMPORARY_VARIABLES		 109

#define EC_FLAGS_DEFAULT_OCT	0x1
#define EC_F_EC_POINT_ADD				 112
#define EC_F_EC_POINT_DBL				 115
#define EC_F_EC_POINT_CMP				 113
#define EC_F_EC_POINTS_MAKE_AFFINE			 136
#define EC_F_EC_POINT_INVERT				 210
#define EC_F_EC_GROUP_GET_DEGREE			 173
#define EC_F_EC_EX_DATA_SET_DATA			 211
#define EC_F_EC_GROUP_NEW_BY_CURVE_NAME			 174
#define EC_F_EC_GROUP_NEW				 108
#define EC_R_NOT_A_NIST_PRIME				 135
#define EC_R_NOT_A_SUPPORTED_NIST_PRIME			 136
#define EC_F_EC_GROUP_SET_CURVE_GFP			 109
#define EC_F_EC_POINT_NEW				 121
#define EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP	 124
#define EC_F_EC_GROUP_GET0_GENERATOR			 139
#define EC_F_EC_POINT_COPY				 114
#define EC_F_EC_KEY_GENERATE_KEY			 179
#define EC_F_EC_WNAF_MUL				 187
#define EC_F_EC_WNAF_PRECOMPUTE_MULT			 188

#define V_ASN1_UNIVERSAL		0x00
#define	V_ASN1_APPLICATION		0x40
#define V_ASN1_CONTEXT_SPECIFIC		0x80
#define V_ASN1_PRIVATE			0xc0
	
#define V_ASN1_CONSTRUCTED		0x20
#define V_ASN1_PRIMITIVE_TAG		0x1f
#define V_ASN1_PRIMATIVE_TAG		0x1f
	
#define V_ASN1_APP_CHOOSE		-2	/* let the recipient choose */
#define V_ASN1_OTHER			-3	/* used in ASN1_TYPE */
#define V_ASN1_ANY			-4	/* used in ASN1 template code */
	
#define V_ASN1_NEG			0x100	/* negative flag */
	
#define V_ASN1_UNDEF			-1
#define V_ASN1_EOC			0
#define V_ASN1_BOOLEAN			1	/**/
#define V_ASN1_INTEGER			2
#define V_ASN1_NEG_INTEGER		(2 | V_ASN1_NEG)
#define V_ASN1_BIT_STRING		3
#define V_ASN1_OCTET_STRING		4
#define V_ASN1_NULL			5
#define V_ASN1_OBJECT			6
#define V_ASN1_OBJECT_DESCRIPTOR	7
#define V_ASN1_EXTERNAL			8
#define V_ASN1_REAL			9
#define V_ASN1_ENUMERATED		10
#define V_ASN1_NEG_ENUMERATED		(10 | V_ASN1_NEG)
#define V_ASN1_UTF8STRING		12
#define V_ASN1_SEQUENCE			16
#define V_ASN1_SET			17
#define V_ASN1_NUMERICSTRING		18	/**/
#define V_ASN1_PRINTABLESTRING		19
#define V_ASN1_T61STRING		20
#define V_ASN1_TELETEXSTRING		20	/* alias */
#define V_ASN1_VIDEOTEXSTRING		21	/**/
#define V_ASN1_IA5STRING		22
#define V_ASN1_UTCTIME			23
#define V_ASN1_GENERALIZEDTIME		24	/**/
#define V_ASN1_GRAPHICSTRING		25	/**/
#define V_ASN1_ISO64STRING		26	/**/
#define V_ASN1_VISIBLESTRING		26	/* alias */
#define V_ASN1_GENERALSTRING		27	/**/
#define V_ASN1_UNIVERSALSTRING		28	/**/
#define V_ASN1_BMPSTRING		30
	
	/* For use with d2i_ASN1_type_bytes() */
#define B_ASN1_NUMERICSTRING	0x0001
#define B_ASN1_PRINTABLESTRING	0x0002
#define B_ASN1_T61STRING	0x0004
#define B_ASN1_TELETEXSTRING	0x0004
#define B_ASN1_VIDEOTEXSTRING	0x0008
#define B_ASN1_IA5STRING	0x0010
#define B_ASN1_GRAPHICSTRING	0x0020
#define B_ASN1_ISO64STRING	0x0040
#define B_ASN1_VISIBLESTRING	0x0040
#define B_ASN1_GENERALSTRING	0x0080
#define B_ASN1_UNIVERSALSTRING	0x0100
#define B_ASN1_OCTET_STRING	0x0200
#define B_ASN1_BIT_STRING	0x0400
#define B_ASN1_BMPSTRING	0x0800
#define B_ASN1_UNKNOWN		0x1000
#define B_ASN1_UTF8STRING	0x2000
#define B_ASN1_UTCTIME		0x4000
#define B_ASN1_GENERALIZEDTIME	0x8000
#define B_ASN1_SEQUENCE		0x10000

#define CHECKED_STACK_OF(type, p) \
((_STACK*) (1 ? p : (STACK_OF(type)*)0))
	
	/* For use with ASN1_mbstring_copy() */
#define MBSTRING_FLAG		0x1000
#define MBSTRING_UTF8		(MBSTRING_FLAG)
#define MBSTRING_ASC		(MBSTRING_FLAG|1)
#define MBSTRING_BMP		(MBSTRING_FLAG|2)
#define MBSTRING_UNIV		(MBSTRING_FLAG|4)
	
#define SMIME_OLDMIME		0x400
#define SMIME_CRLFEOL		0x800
#define SMIME_STREAM		0x1000

#define ERR_R_FATAL				64
#define	ERR_R_MALLOC_FAILURE			(1|ERR_R_FATAL)
#define	ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED	(2|ERR_R_FATAL)
#define	ERR_R_PASSED_NULL_PARAMETER		(3|ERR_R_FATAL)
#define	ERR_R_INTERNAL_ERROR			(4|ERR_R_FATAL)
#define	ERR_R_DISABLED				(5|ERR_R_FATAL)	

#define X509V3_F_DO_DIRNAME				 144
#define X509V3_F_X509V3_GET_VALUE_BOOL			 110

#define X509V3_F_S2I_ASN1_INTEGER			 108
#define X509V3_F_A2I_GENERAL_NAME			 164
#define X509V3_R_MISSING_VALUE				 124
#define X509V3_R_BAD_IP_ADDRESS				 118
#define X509V3_R_BAD_OBJECT				 119
#define X509V3_R_UNSUPPORTED_OPTION			 117
#define X509V3_R_UNSUPPORTED_TYPE			 167
#define X509V3_R_USER_TOO_LONG				 132
#define X509V3_F_STRING_TO_HEX				 113
#define X509V3_R_INVALID_NULL_VALUE			 109
#define X509V3_R_BN_DEC2BN_ERROR			 100
#define X509V3_R_BN_TO_ASN1_INTEGER_ERROR		 101
#define X509V3_R_DIRNAME_ERROR				 149
#define X509V3_R_SECTION_NOT_FOUND			 150
#define X509V3_R_INVALID_BOOLEAN_STRING			 104
#define X509V3_R_INVALID_NULL_ARGUMENT			 107
#define X509V3_R_ODD_NUMBER_OF_DIGITS			 112
#define X509V3_R_ILLEGAL_HEX_DIGIT			 113
#define X509V3_R_OTHERNAME_ERROR			 147

#define EC_R_INCOMPATIBLE_OBJECTS			 101
#define EC_R_SLOT_FULL					 108
#define EC_R_UNKNOWN_GROUP				 129
#define EC_F_EC_GROUP_SET_CURVE_GF2M			 176
#define EC_F_EC_POINT_SET_TO_INFINITY			 127
#define EC_R_UNDEFINED_GENERATOR			 113
#define EC_F_EC_GROUP_SET_GENERATOR			 111

#define BN_FLG_STATIC_DATA	0x02
	
#define MS_FAR /* FIXME */

#ifdef HAVE_LONG_DOUBLE
#define LDOUBLE long double
#else
#define LDOUBLE double
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

#define ERR_R_ASN1_LIB	ERR_LIB_ASN1     /* 13 */
#define BN_ULONG	unsigned int

#ifdef __GNUC__
#  define __bio_h__attr__ __attribute__
#endif

#define IMPL_CHECK if(!impl) impl_check();

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

#define LHM_lh_retrieve(type, lh, inst) \
((type *)lh_retrieve(CHECKED_LHASH_OF(type, lh), \
CHECKED_PTR_OF(type, inst)))

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
#define engine_ref_debug(e, isfunct, diff)
#endif

/* file: sk_ENGINE_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_ENGINE_value(st, i) SKM_sk_value(ENGINE, (st), (i))

/* file: ENGINEerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define ENGINEerr(f,r) ERR_PUT_error(ERR_LIB_ENGINE,(f),(r),__FILE__,__LINE__)

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


#endif /* !BN_LLONG */

/* file: sk_ASN1_STRING_TABLE_find : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_ASN1_STRING_TABLE_find(st, val) SKM_sk_find(ASN1_STRING_TABLE, (st), (val))

/* file: SKM_sk_find : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define SKM_sk_find(type, st, val) \
	sk_find(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val))

/* file: sk_ASN1_STRING_TABLE_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_ASN1_STRING_TABLE_value(st, i) SKM_sk_value(ASN1_STRING_TABLE, (st), (i))

/* file: char_to_int : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
#define char_to_int(p) (p - '0')

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

#define curve_list_length (sizeof(curve_list)/sizeof(ec_list_element))

#define LHM_lh_new(type, name) \
((LHASH_OF(type) *)lh_new(LHASH_HASH_FN(name), LHASH_COMP_FN(name)))

#define IMPLEMENT_LHASH_COMP_FN(name, o_type) \
int name##_LHASH_COMP(const void *arg1, const void *arg2) { \
const o_type *a = arg1;		    \
const o_type *b = arg2; \
return name##_cmp(a,b); }
	
#define LHASH_COMP_FN(name) name##_LHASH_COMP
	
#define LHASH_HASH_FN(name) name##_LHASH_HASH

#define DECLARE_LHASH_HASH_FN(name, o_type) \
unsigned long name##_LHASH_HASH(const void *);

#define IMPLEMENT_LHASH_HASH_FN(name, o_type) \
unsigned long name##_LHASH_HASH(const void *arg) { \
const o_type *a = arg; \
return name##_hash(a); }
#define LHASH_HASH_FN(name) name##_LHASH_HASH

#define CHECKED_LHASH_OF(type,lh) \
((_LHASH *)CHECKED_PTR_OF(LHASH_OF(type),lh))

/* file: CHECKED_PTR_OF : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define CHECKED_PTR_OF(type, p) \
((void*) (1 ? p : (type*)0))

#define SKM_sk_new_null(type) \
((STACK_OF(type) *)sk_new_null())

#define LHM_lh_delete(type, lh, inst) \
((type *)lh_delete(CHECKED_LHASH_OF(type, lh),			\
CHECKED_PTR_OF(type, inst)))

/* file: SKM_sk_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define SKM_sk_value(type, st,i) \
((type *)sk_value(CHECKED_STACK_OF(type, st), i))

#define SKM_sk_set(type, st,i,val) \
sk_set(CHECKED_STACK_OF(type, st), i, CHECKED_PTR_OF(type, val))

/* file: sk_X509_NAME_ENTRY_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_X509_NAME_ENTRY_value(st, i) SKM_sk_value(X509_NAME_ENTRY, (st), (i))

/* file: sk_CONF_VALUE_value : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_CONF_VALUE_value(st, i) SKM_sk_value(CONF_VALUE, (st), (i))

#define ASN1_OCTET_STRING_free(a) 1;

/* file: SKM_sk_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define SKM_sk_num(type, st) \
sk_num(CHECKED_STACK_OF(type, st))

/* file: sk_X509_NAME_ENTRY_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_X509_NAME_ENTRY_num(st) SKM_sk_num(X509_NAME_ENTRY, (st))

/* file: sk_X509_NAME_ENTRY_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_X509_NAME_ENTRY_insert(st, val, i) SKM_sk_insert(X509_NAME_ENTRY, (st), (val), (i))

	/* file: sk_X509_NAME_ENTRY_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_X509_NAME_ENTRY_num(st) SKM_sk_num(X509_NAME_ENTRY, (st))
	
	/* file: sk_X509_NAME_ENTRY_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_X509_NAME_ENTRY_insert(st, val, i) SKM_sk_insert(X509_NAME_ENTRY, (st), (val), (i))
	
/* file: SKM_sk_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define SKM_sk_insert(type, st,val, i) \
sk_insert(CHECKED_STACK_OF(type, st), CHECKED_PTR_OF(type, val), i)

/* file: sk_CONF_VALUE_num : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define sk_CONF_VALUE_num(st) SKM_sk_num(CONF_VALUE, (st))

	/* file: lh_MEM_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stacksafestack.h */
#define lh_MEM_insert(lh,inst) LHM_lh_insert(MEM,lh,inst)

#define LHM_lh_insert(type, lh, inst) \
((type *)lh_insert(CHECKED_LHASH_OF(type, lh), \
CHECKED_PTR_OF(type, inst)))

/* file: bn_wexpand : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define bn_wexpand(a,words) (((words) <= (a)->dmax)?(a):bn_expand2((a),(words)))

/* file: bn_expand : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define bn_expand(a,bits) ((((((bits+BN_BITS2-1))/BN_BITS2)) <= (a)->dmax)?\
(a):bn_expand2((a),(bits+BN_BITS2-1)/BN_BITS2))

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

#define bn_check_top(a) \
do { \
const BIGNUM *_bnum2 = (a); \
if (_bnum2 != NULL) { \
assert((_bnum2->top == 0) || \
(_bnum2->d[_bnum2->top - 1] != 0)); \
bn_pollute(_bnum2); \
} \
} while(0)

	/* file: OPENSSL_realloc : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define OPENSSL_realloc(addr,num) \
CRYPTO_realloc((char *)addr,(int)num,__FILE__,__LINE__)
	
	/* file: BUFerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define BUFerr(f,r)  ERR_PUT_error(ERR_LIB_BUF,(f),(r),__FILE__,__LINE__)
	
	/* file: CONFerr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define CONFerr(f,r) ERR_PUT_error(ERR_LIB_CONF,(f),(r),__FILE__,__LINE__)
	
	/* file: X509err : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
#define X509err(f,r) ERR_PUT_error(ERR_LIB_X509,(f),(r),__FILE__,__LINE__)

#define LBITS(a)	((a)&BN_MASK2l)
#define HBITS(a)	(((a)>>BN_BITS4)&BN_MASK2l)

#define DECIMAL_SIZE(type)	((sizeof(type)*8+2)/3+1)

#define CTXDBG_RET(ctx,ret)

#define CTXDBG_EXIT(ctx)

#define CTXDBG_ENTRY(str, ctx)	fprintf(stderr, "Starting");
//ctxdbg_cur = (str); \ FixMe
//fprintf(stderr,"Starting %s\n", ctxdbg_cur); \
//ctxdbg(ctx); \
} while(0)

#ifndef CRYPTO_w_lock
#define CRYPTO_w_unlock(type)	\
CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#else
	/* file: CRYPTO_w_unlock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define CRYPTO_w_unlock(a)
#endif

#ifndef CRYPTO_w_lock
#define CRYPTO_r_unlock(type)	\
CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#else
	/* file: CRYPTO_r_unlock : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#define CRYPTO_r_unlock(a)
#endif

	/* file: CRYPTO_add : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_add(addr,amount,type)	\
CRYPTO_add_lock(addr,amount,type,__FILE__,__LINE__)
#endif
#else
#endif

#define CRYPTO_add(a,b,c)	((*(a))+=(b))

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
	
#define BN_is_zero(a)       ((a)->top == 0)

/* file: BN_get_flags : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
#define BN_get_flags(b,n)	((b)->flags&(n))

#define mul_add(r,a,bl,bh,c) { \
BN_ULONG l,h; \
}

#define mul(r,a,bl,bh,c) { \
BN_ULONG l,h; \
}

/********** Global Variabls and Structures **********/ 

	extern const unsigned char os_toebcdic[256];
	extern const unsigned char os_toascii[256];

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

#define ERR_NUM_ERRORS	16
	typedef struct err_state_st ERR_STATE;
	
	struct st_ERR_FNS
	{
		/* Works on the "error_hash" string table */
		/* Works on the "thread_hash" error-state table */
		/* Returns the next available error "library" numbers */
		ERR_STATE *(*cb_thread_get_item)(const ERR_STATE *);
		ERR_STATE *(*cb_thread_set_item)(ERR_STATE *);
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

#define LLONG long long
	
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
		int (*comp)(const void *, const void *);
	} _STACK;  /* Use STACK_OF(...) instead */
	
	
	typedef char *OPENSSL_STRING;
	
	struct rand_meth_st
	{
		int (*pseudorand)(unsigned char *buf, int num);
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
		void *(*dup_func)(void *);
		void (*free_func)(void *);
		void (*clear_free_func)(void *);
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
		
		unsigned char *seed; /* optional seed for parameters (appears in ASN1) */
		
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
		char * (*get_string)(void *db, char *section, char *value);
		STACK_OF(CONF_VALUE) * (*get_section)(void *db, char *section);
		void (*free_string)(void *db, char * string);
		void (*free_section)(void *db, STACK_OF(CONF_VALUE) *section);
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
		const EC_METHOD *(*meth)(void);
		const char *comment;
	} ec_list_element;

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
	
	struct err_state_st
	{
		CRYPTO_THREADID tid;
		int err_flags[ERR_NUM_ERRORS];
		unsigned long err_buffer[ERR_NUM_ERRORS];
		char *err_data[ERR_NUM_ERRORS];
		int err_data_flags[ERR_NUM_ERRORS];
		const char *err_file[ERR_NUM_ERRORS];
		int err_line[ERR_NUM_ERRORS];
		int top,bottom;
	};
	
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
	typedef struct x509_store_ctx_st X509_STORE_CTX;
	typedef struct x509_store_st X509_STORE;
	typedef struct X509_POLICY_NODE_st X509_POLICY_NODE;
	typedef struct X509_POLICY_LEVEL_st X509_POLICY_LEVEL;
	typedef struct X509_POLICY_TREE_st X509_POLICY_TREE;
	typedef struct v3_ext_ctx X509V3_CTX;
	typedef struct v3_ext_method X509V3_EXT_METHOD;

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
	(*X509V3_EXT_I2V)(const X509V3_EXT_METHOD *method, void *ext,
					  STACK_OF(CONF_VALUE) *extlist);
	typedef void * (*X509V3_EXT_V2I)(const X509V3_EXT_METHOD *method,
									 X509V3_CTX *ctx,
									 STACK_OF(CONF_VALUE) *values);
	typedef char * (*X509V3_EXT_I2S)(const X509V3_EXT_METHOD *method, void *ext);
	typedef void * (*X509V3_EXT_S2I)(const X509V3_EXT_METHOD *method,
									 X509V3_CTX *ctx, const char *str);
	typedef int (*X509V3_EXT_I2R)(const X509V3_EXT_METHOD *method, void *ext,
								  BIO *out, int indent);
	typedef void * (*X509V3_EXT_R2I)(const X509V3_EXT_METHOD *method,
									 X509V3_CTX *ctx, const char *str);
	typedef void bio_info_cb(struct bio_st *, int, const char *, int, long, long);
#if 1
	/* "userdata": new with OpenSSL 0.9.4 */
	typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);
#else
	/* OpenSSL 0.9.3, 0.9.3a */
	typedef int pem_password_cb(char *buf, int size, int rwflag);
#endif
	
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
	
	struct STORE_OBJECT_st
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
	};
	
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
	
	struct x509_cinf_st
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
		int (*init)(EC_KEY *);
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

	struct ASIdentifiers_st {
		ASIdentifierChoice *asnum, *rdi;
	};
	
	typedef struct IPAddressFamily_st {
		ASN1_OCTET_STRING	*addressFamily;
		IPAddressChoice	*ipAddressChoice;
	} IPAddressFamily;
	
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

	static const ECDH_METHOD *default_ECDH_method = NULL;
	
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
		// GEN_SESSION_CB generate_session_id; FixMe
		
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
		// SRP_CTX srp_ctx; /* ctx for SRP authentication */ FixMe
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
	
	typedef struct ssl_ctx_st SSL_CTX;
	
	static SSL_CTX *ctx=NULL;
	
	DECLARE_LHASH_OF(ENGINE_PILE);
	
	/* The type exposed in eng_int.h */
	struct st_engine_table
	{
		LHASH_OF(ENGINE_PILE) piles;
	}; /* ENGINE_TABLE */
	
	typedef struct st_engine_table ENGINE_TABLE;
	
	static ENGINE_TABLE *rand_table = NULL;
	static ENGINE_TABLE *ecdh_table = NULL;
	
	struct x509_store_st
	{
		/* The following is a cache of trusted certs */
		int cache; 	/* if true, stash any hits */
		STACK_OF(X509_OBJECT) *objs;	/* Cache of all objects */
		
		/* These are external lookup methods */
		STACK_OF(X509_LOOKUP) *get_cert_methods;
		
		X509_VERIFY_PARAM *param;
		
		/* Callbacks for various operations */
		int (*verify)(X509_STORE_CTX *ctx);	/* called to verify a certificate */
		int (*verify_cb)(int ok,X509_STORE_CTX *ctx);	/* error callback */
		int (*get_issuer)(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);	/* get issuers cert from ctx */
		int (*check_issued)(X509_STORE_CTX *ctx, X509 *x, X509 *issuer); /* check issued */
		int (*check_revocation)(X509_STORE_CTX *ctx); /* Check revocation status of chain */
		int (*get_crl)(X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x); /* retrieve CRL */
		int (*check_crl)(X509_STORE_CTX *ctx, X509_CRL *crl); /* Check CRL validity */
		int (*cert_crl)(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x); /* Check certificate against CRL */
		STACK_OF(X509) * (*lookup_certs)(X509_STORE_CTX *ctx, X509_NAME *nm);
		STACK_OF(X509_CRL) * (*lookup_crls)(X509_STORE_CTX *ctx, X509_NAME *nm);
		int (*cleanup)(X509_STORE_CTX *ctx);
		
		CRYPTO_EX_DATA ex_data;
		int references;
	} /* X509_STORE */;
	
	struct x509_store_ctx_st      /* X509_STORE_CTX */
	{
		X509_STORE *ctx;
		int current_method;	/* used when looking up certs */
		
		/* The following are set by the caller */
		X509 *cert;		/* The cert to check */
		STACK_OF(X509) *untrusted;	/* chain of X509s - untrusted - passed in */
		STACK_OF(X509_CRL) *crls;	/* set of CRLs passed in */
		
		X509_VERIFY_PARAM *param;
		void *other_ctx;	/* Other info for use with get_issuer() */
		
		/* Callbacks for various operations */
		int (*verify)(X509_STORE_CTX *ctx);	/* called to verify a certificate */
		int (*verify_cb)(int ok,X509_STORE_CTX *ctx);		/* error callback */
		int (*get_issuer)(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);	/* get issuers cert from ctx */
		int (*check_issued)(X509_STORE_CTX *ctx, X509 *x, X509 *issuer); /* check issued */
		int (*check_revocation)(X509_STORE_CTX *ctx); /* Check revocation status of chain */
		int (*get_crl)(X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x); /* retrieve CRL */
		int (*check_crl)(X509_STORE_CTX *ctx, X509_CRL *crl); /* Check CRL validity */
		int (*cert_crl)(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x); /* Check certificate against CRL */
		int (*check_policy)(X509_STORE_CTX *ctx);
		STACK_OF(X509) * (*lookup_certs)(X509_STORE_CTX *ctx, X509_NAME *nm);
		STACK_OF(X509_CRL) * (*lookup_crls)(X509_STORE_CTX *ctx, X509_NAME *nm);
		int (*cleanup)(X509_STORE_CTX *ctx);
		
		/* The following is built up */
		int valid;		/* if 0, rebuild chain */
		int last_untrusted;	/* index of last untrusted cert */
		STACK_OF(X509) *chain; 		/* chain of X509s - built up and trusted */
		X509_POLICY_TREE *tree;	/* Valid policy tree */
		
		int explicit_policy;	/* Require explicit policy value */
		
		/* When something goes wrong, this is why */
		int error_depth;
		int error;
		X509 *current_cert;
		X509 *current_issuer;	/* cert currently being tested as valid issuer */
		X509_CRL *current_crl;	/* current CRL */
		
		int current_crl_score;  /* score of current CRL */
		unsigned int current_reasons;  /* Reason mask */
		
		X509_STORE_CTX *parent; /* For CRL path validation: parent context */
		
		CRYPTO_EX_DATA ex_data;
	} /* X509_STORE_CTX */;
	
	struct X509_POLICY_NODE_st
	{
		/* node data this refers to */
		const X509_POLICY_DATA *data;
		/* Parent node */
		X509_POLICY_NODE *parent;
		/* Number of child nodes */
		int nchild;
	};
	
	struct X509_POLICY_LEVEL_st
	{
		/* Cert for this level */
		X509 *cert;
		/* nodes at this level */
		STACK_OF(X509_POLICY_NODE) *nodes;
		/* anyPolicy node */
		X509_POLICY_NODE *anyPolicy;
		/* Extra data */
		/*STACK_OF(X509_POLICY_DATA) *extra_data;*/
		unsigned int flags;
	};
	
	struct X509_POLICY_TREE_st
	{
		/* This is the tree 'level' data */
		X509_POLICY_LEVEL *levels;
		int nlevel;
		/* Extra policy data when additional nodes (not from the certificate)
		 * are required.
		 */
		STACK_OF(X509_POLICY_DATA) *extra_data;
		/* This is the authority constained policy set */
		STACK_OF(X509_POLICY_NODE) *auth_policies;
		STACK_OF(X509_POLICY_NODE) *user_policies;
		unsigned int flags;
	};
	
	EVP_PKEY *pkey;
	
	typedef struct DSA_SIG_st
	{
		BIGNUM *r;
		BIGNUM *s;
	} DSA_SIG;
	
	struct dsa_st
	{
		/* This first variable is used to pick up errors where
		 * a DSA is passed instead of of a EVP_PKEY */
		int pad;
		long version;
		int write_params;
		BIGNUM *p;
		BIGNUM *q;	/* == 20 */
		BIGNUM *g;
		
		BIGNUM *pub_key;  /* y public key */
		BIGNUM *priv_key; /* x private key */
		
		BIGNUM *kinv;	/* Signing pre-calc */
		BIGNUM *r;	/* Signing pre-calc */
		
		int flags;
		/* Normally used to cache montgomery values */
		BN_MONT_CTX *method_mont_p;
		int references;
		CRYPTO_EX_DATA ex_data;
		const DSA_METHOD *meth;
		/* functional reference if 'meth' is ENGINE-provided */
		ENGINE *engine;
	};
	
	typedef struct dsa_st DSA;
	
	DECLARE_LHASH_OF(MEM);
	static LHASH_OF(MEM) *mh=NULL; /* hash-table of memory requests*/
	
	DECLARE_LHASH_OF(APP_INFO);
	static LHASH_OF(APP_INFO) *amih=NULL; /* hash-table with those
										   * app_mem_info_st's that are at
										   * the top of their thread's
										   * stack (with `thread' as key);
										   * access requires MALLOC2
										   * lock */
	
	struct ec_method_st {
		/* Various method flags */
		int flags;
		/* used by EC_METHOD_get_field_type: */
		int field_type; /* a NID */
		
		/* used by EC_GROUP_new, EC_GROUP_free, EC_GROUP_clear_free, EC_GROUP_copy: */
		int (*group_init)(EC_GROUP *);
		void (*group_finish)(EC_GROUP *);
		void (*group_clear_finish)(EC_GROUP *);
		int (*group_copy)(EC_GROUP *, const EC_GROUP *);
		
		/* used by EC_GROUP_set_curve_GFp, EC_GROUP_get_curve_GFp, */
		/* EC_GROUP_set_curve_GF2m, and EC_GROUP_get_curve_GF2m: */
		int (*group_set_curve)(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
		int (*group_get_curve)(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);
		
		/* used by EC_GROUP_get_degree: */
		int (*group_get_degree)(const EC_GROUP *);
		
		/* used by EC_GROUP_check: */
		int (*group_check_discriminant)(const EC_GROUP *, BN_CTX *);
		
		/* used by EC_POINT_new, EC_POINT_free, EC_POINT_clear_free, EC_POINT_copy: */
		int (*point_init)(EC_POINT *);
		void (*point_finish)(EC_POINT *);
		void (*point_clear_finish)(EC_POINT *);
		int (*point_copy)(EC_POINT *, const EC_POINT *);
		
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
		int (*point_set_affine_coordinates)(const EC_GROUP *, EC_POINT *,
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
		int (*mul)(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
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
	
	struct ecdh_method 
	{
		const char *name;
		int (*compute_key)(void *key, size_t outlen, const EC_POINT *pub_key, EC_KEY *ecdh,
						   void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
		int (*init)(EC_KEY *eckey);
		int (*finish)(EC_KEY *eckey);
		int flags;
		char *app_data;
	};
	
	struct dh_method
	{
		const char *name;
		/* Methods here */
		
		int (*bn_mod_exp)(const DH *dh, BIGNUM *r, const BIGNUM *a,
						  const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
						  BN_MONT_CTX *m_ctx); /* Can be null */
		
		int flags;
		char *app_data;
		/* If this is non-NULL, it will be used to generate parameters */
	};
	
	static const ASN1_OBJECT nid_objs[1];
	//const EC_METHOD *EC_GFp_nistp256_method(void);
	//const EC_METHOD *EC_GFp_nistp224_method(void);
	//const EC_METHOD *EC_GFp_nistp521_method(void);
	
	/* the nist prime curves */
	static const struct { EC_CURVE_DATA h; unsigned char data[20+24*6]; }
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
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+28*6]; }
	_EC_NIST_PRIME_224 = {
		{ NID_X9_62_prime_field,20,28,1 },
		{ 0xBD,0x71,0x34,0x47,0x99,0xD5,0xC7,0xFC,0xDC,0x45,	/* seed */
			0xB5,0x9F,0xA3,0xB9,0xAB,0x8F,0x6A,0x94,0x8B,0xC5,
			
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* a */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
			0xB4,0x05,0x0A,0x85,0x0C,0x04,0xB3,0xAB,0xF5,0x41,	/* b */
			0x32,0x56,0x50,0x44,0xB0,0xB7,0xD7,0xBF,0xD8,0xBA,
			0x27,0x0B,0x39,0x43,0x23,0x55,0xFF,0xB4,
			0xB7,0x0E,0x0C,0xBD,0x6B,0xB4,0xBF,0x7F,0x32,0x13,	/* x */
			0x90,0xB9,0x4A,0x03,0xC1,0xD3,0x56,0xC2,0x11,0x22,
			0x34,0x32,0x80,0xD6,0x11,0x5C,0x1D,0x21,
			0xbd,0x37,0x63,0x88,0xb5,0xf7,0x23,0xfb,0x4c,0x22,	/* y */
			0xdf,0xe6,0xcd,0x43,0x75,0xa0,0x5a,0x07,0x47,0x64,
			0x44,0xd5,0x81,0x99,0x85,0x00,0x7e,0x34,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0xFF,0xFF,0x16,0xA2,0xE0,0xB8,0xF0,0x3E,
			0x13,0xDD,0x29,0x45,0x5C,0x5C,0x2A,0x3D }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+48*6]; }
	_EC_NIST_PRIME_384 = {
		{ NID_X9_62_prime_field,20,48,1 },
		{ 0xA3,0x35,0x92,0x6A,0xA3,0x19,0xA2,0x7A,0x1D,0x00,	/* seed */
			0x89,0x6A,0x67,0x73,0xA4,0x82,0x7A,0xCD,0xAC,0x73,
			
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* a */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFC,
			0xB3,0x31,0x2F,0xA7,0xE2,0x3E,0xE7,0xE4,0x98,0x8E,	/* b */
			0x05,0x6B,0xE3,0xF8,0x2D,0x19,0x18,0x1D,0x9C,0x6E,
			0xFE,0x81,0x41,0x12,0x03,0x14,0x08,0x8F,0x50,0x13,
			0x87,0x5A,0xC6,0x56,0x39,0x8D,0x8A,0x2E,0xD1,0x9D,
			0x2A,0x85,0xC8,0xED,0xD3,0xEC,0x2A,0xEF,
			0xAA,0x87,0xCA,0x22,0xBE,0x8B,0x05,0x37,0x8E,0xB1,	/* x */
			0xC7,0x1E,0xF3,0x20,0xAD,0x74,0x6E,0x1D,0x3B,0x62,
			0x8B,0xA7,0x9B,0x98,0x59,0xF7,0x41,0xE0,0x82,0x54,
			0x2A,0x38,0x55,0x02,0xF2,0x5D,0xBF,0x55,0x29,0x6C,
			0x3A,0x54,0x5E,0x38,0x72,0x76,0x0A,0xB7,
			0x36,0x17,0xde,0x4a,0x96,0x26,0x2c,0x6f,0x5d,0x9e,	/* y */
			0x98,0xbf,0x92,0x92,0xdc,0x29,0xf8,0xf4,0x1d,0xbd,
			0x28,0x9a,0x14,0x7c,0xe9,0xda,0x31,0x13,0xb5,0xf0,
			0xb8,0xc0,0x0a,0x60,0xb1,0xce,0x1d,0x7e,0x81,0x9d,
			0x7a,0x43,0x1d,0x7c,0x90,0xea,0x0e,0x5f,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xC7,0x63,0x4D,0x81,0xF4,0x37,
			0x2D,0xDF,0x58,0x1A,0x0D,0xB2,0x48,0xB0,0xA7,0x7A,
			0xEC,0xEC,0x19,0x6A,0xCC,0xC5,0x29,0x73 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+66*6]; }
	_EC_NIST_PRIME_521 = {
		{ NID_X9_62_prime_field,20,66,1 },
		{ 0xD0,0x9E,0x88,0x00,0x29,0x1C,0xB8,0x53,0x96,0xCC,	/* seed */
			0x67,0x17,0x39,0x32,0x84,0xAA,0xA0,0xDA,0x64,0xBA,
			
			0x01,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0x01,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* a */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,
			0x00,0x51,0x95,0x3E,0xB9,0x61,0x8E,0x1C,0x9A,0x1F,	/* b */
			0x92,0x9A,0x21,0xA0,0xB6,0x85,0x40,0xEE,0xA2,0xDA,
			0x72,0x5B,0x99,0xB3,0x15,0xF3,0xB8,0xB4,0x89,0x91,
			0x8E,0xF1,0x09,0xE1,0x56,0x19,0x39,0x51,0xEC,0x7E,
			0x93,0x7B,0x16,0x52,0xC0,0xBD,0x3B,0xB1,0xBF,0x07,
			0x35,0x73,0xDF,0x88,0x3D,0x2C,0x34,0xF1,0xEF,0x45,
			0x1F,0xD4,0x6B,0x50,0x3F,0x00,
			0x00,0xC6,0x85,0x8E,0x06,0xB7,0x04,0x04,0xE9,0xCD,	/* x */
			0x9E,0x3E,0xCB,0x66,0x23,0x95,0xB4,0x42,0x9C,0x64,
			0x81,0x39,0x05,0x3F,0xB5,0x21,0xF8,0x28,0xAF,0x60,
			0x6B,0x4D,0x3D,0xBA,0xA1,0x4B,0x5E,0x77,0xEF,0xE7,
			0x59,0x28,0xFE,0x1D,0xC1,0x27,0xA2,0xFF,0xA8,0xDE,
			0x33,0x48,0xB3,0xC1,0x85,0x6A,0x42,0x9B,0xF9,0x7E,
			0x7E,0x31,0xC2,0xE5,0xBD,0x66,
			0x01,0x18,0x39,0x29,0x6a,0x78,0x9a,0x3b,0xc0,0x04,	/* y */
			0x5c,0x8a,0x5f,0xb4,0x2c,0x7d,0x1b,0xd9,0x98,0xf5,
			0x44,0x49,0x57,0x9b,0x44,0x68,0x17,0xaf,0xbd,0x17,
			0x27,0x3e,0x66,0x2c,0x97,0xee,0x72,0x99,0x5e,0xf4,
			0x26,0x40,0xc5,0x50,0xb9,0x01,0x3f,0xad,0x07,0x61,
			0x35,0x3c,0x70,0x86,0xa2,0x72,0xc2,0x40,0x88,0xbe,
			0x94,0x76,0x9f,0xd1,0x66,0x50,
			0x01,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFA,0x51,0x86,0x87,0x83,0xBF,0x2F,
			0x96,0x6B,0x7F,0xCC,0x01,0x48,0xF7,0x09,0xA5,0xD0,
			0x3B,0xB5,0xC9,0xB8,0x89,0x9C,0x47,0xAE,0xBB,0x6F,
			0xB7,0x1E,0x91,0x38,0x64,0x09 }
	};
	
	/* the x9.62 prime curves (minus the nist prime curves) */
	static const struct { EC_CURVE_DATA h; unsigned char data[20+24*6]; }
	_EC_X9_62_PRIME_192V2 = {
		{ NID_X9_62_prime_field,20,24,1 },
		{ 0x31,0xA9,0x2E,0xE2,0x02,0x9F,0xD1,0x0D,0x90,0x1B,	/* seed */
			0x11,0x3E,0x99,0x07,0x10,0xF0,0xD2,0x1A,0xC6,0xB6,
			
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* a */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFC,
			0xCC,0x22,0xD6,0xDF,0xB9,0x5C,0x6B,0x25,0xE4,0x9C,	/* b */
			0x0D,0x63,0x64,0xA4,0xE5,0x98,0x0C,0x39,0x3A,0xA2,
			0x16,0x68,0xD9,0x53,
			0xEE,0xA2,0xBA,0xE7,0xE1,0x49,0x78,0x42,0xF2,0xDE,	/* x */
			0x77,0x69,0xCF,0xE9,0xC9,0x89,0xC0,0x72,0xAD,0x69,
			0x6F,0x48,0x03,0x4A,
			0x65,0x74,0xd1,0x1d,0x69,0xb6,0xec,0x7a,0x67,0x2b,	/* y */
			0xb8,0x2a,0x08,0x3d,0xf2,0xf2,0xb0,0x84,0x7d,0xe9,
			0x70,0xb2,0xde,0x15,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFE,0x5F,0xB1,0xA7,0x24,0xDC,0x80,0x41,0x86,
			0x48,0xD8,0xDD,0x31 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+24*6]; }
	_EC_X9_62_PRIME_192V3 = {
		{ NID_X9_62_prime_field,20,24,1 },
		{ 0xC4,0x69,0x68,0x44,0x35,0xDE,0xB3,0x78,0xC4,0xB6,	/* seed */
			0x5C,0xA9,0x59,0x1E,0x2A,0x57,0x63,0x05,0x9A,0x2E,
			
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* a */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFC,
			0x22,0x12,0x3D,0xC2,0x39,0x5A,0x05,0xCA,0xA7,0x42,	/* b */
			0x3D,0xAE,0xCC,0xC9,0x47,0x60,0xA7,0xD4,0x62,0x25,
			0x6B,0xD5,0x69,0x16,
			0x7D,0x29,0x77,0x81,0x00,0xC6,0x5A,0x1D,0xA1,0x78,	/* x */
			0x37,0x16,0x58,0x8D,0xCE,0x2B,0x8B,0x4A,0xEE,0x8E,
			0x22,0x8F,0x18,0x96,
			0x38,0xa9,0x0f,0x22,0x63,0x73,0x37,0x33,0x4b,0x49,	/* y */
			0xdc,0xb6,0x6a,0x6d,0xc8,0xf9,0x97,0x8a,0xca,0x76,
			0x48,0xa9,0x43,0xb0,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0x7A,0x62,0xD0,0x31,0xC8,0x3F,0x42,0x94,
			0xF6,0x40,0xEC,0x13 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+30*6]; }
	_EC_X9_62_PRIME_239V1 = {
		{ NID_X9_62_prime_field,20,30,1 },
		{ 0xE4,0x3B,0xB4,0x60,0xF0,0xB8,0x0C,0xC0,0xC0,0xB0,	/* seed */
			0x75,0x79,0x8E,0x94,0x80,0x60,0xF8,0x32,0x1B,0x7D,
			
			0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0x80,0x00,
			0x00,0x00,0x00,0x00,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,
			
			0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* a */
			0xFF,0xFF,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0x80,0x00,
			0x00,0x00,0x00,0x00,0x7F,0xFF,0xFF,0xFF,0xFF,0xFC,
			
			0x6B,0x01,0x6C,0x3B,0xDC,0xF1,0x89,0x41,0xD0,0xD6,	/* b */
			0x54,0x92,0x14,0x75,0xCA,0x71,0xA9,0xDB,0x2F,0xB2,
			0x7D,0x1D,0x37,0x79,0x61,0x85,0xC2,0x94,0x2C,0x0A,
			
			0x0F,0xFA,0x96,0x3C,0xDC,0xA8,0x81,0x6C,0xCC,0x33,	/* x */
			0xB8,0x64,0x2B,0xED,0xF9,0x05,0xC3,0xD3,0x58,0x57,
			0x3D,0x3F,0x27,0xFB,0xBD,0x3B,0x3C,0xB9,0xAA,0xAF,
			
			0x7d,0xeb,0xe8,0xe4,0xe9,0x0a,0x5d,0xae,0x6e,0x40,	/* y */
			0x54,0xca,0x53,0x0b,0xa0,0x46,0x54,0xb3,0x68,0x18,
			0xce,0x22,0x6b,0x39,0xfc,0xcb,0x7b,0x02,0xf1,0xae,
			
			0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0x7F,0xFF,0xFF,0x9E,0x5E,0x9A,0x9F,0x5D,
			0x90,0x71,0xFB,0xD1,0x52,0x26,0x88,0x90,0x9D,0x0B }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+30*6]; }
	_EC_X9_62_PRIME_239V2 = {
		{ NID_X9_62_prime_field,20,30,1 },
		{ 0xE8,0xB4,0x01,0x16,0x04,0x09,0x53,0x03,0xCA,0x3B,	/* seed */
			0x80,0x99,0x98,0x2B,0xE0,0x9F,0xCB,0x9A,0xE6,0x16,
			
			0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0x80,0x00,
			0x00,0x00,0x00,0x00,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,
			
			0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* a */
			0xFF,0xFF,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0x80,0x00,
			0x00,0x00,0x00,0x00,0x7F,0xFF,0xFF,0xFF,0xFF,0xFC,
			
			0x61,0x7F,0xAB,0x68,0x32,0x57,0x6C,0xBB,0xFE,0xD5,	/* b */
			0x0D,0x99,0xF0,0x24,0x9C,0x3F,0xEE,0x58,0xB9,0x4B,
			0xA0,0x03,0x8C,0x7A,0xE8,0x4C,0x8C,0x83,0x2F,0x2C,
			
			0x38,0xAF,0x09,0xD9,0x87,0x27,0x70,0x51,0x20,0xC9,	/* x */
			0x21,0xBB,0x5E,0x9E,0x26,0x29,0x6A,0x3C,0xDC,0xF2,
			0xF3,0x57,0x57,0xA0,0xEA,0xFD,0x87,0xB8,0x30,0xE7,
			
			0x5b,0x01,0x25,0xe4,0xdb,0xea,0x0e,0xc7,0x20,0x6d,	/* y */
			0xa0,0xfc,0x01,0xd9,0xb0,0x81,0x32,0x9f,0xb5,0x55,
			0xde,0x6e,0xf4,0x60,0x23,0x7d,0xff,0x8b,0xe4,0xba,
			
			0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0x80,0x00,0x00,0xCF,0xA7,0xE8,0x59,0x43,
			0x77,0xD4,0x14,0xC0,0x38,0x21,0xBC,0x58,0x20,0x63 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+30*6]; }
	_EC_X9_62_PRIME_239V3 = {
		{ NID_X9_62_prime_field,20,30,1 },
		{ 0x7D,0x73,0x74,0x16,0x8F,0xFE,0x34,0x71,0xB6,0x0A,	/* seed */
			0x85,0x76,0x86,0xA1,0x94,0x75,0xD3,0xBF,0xA2,0xFF,
			
			0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0x80,0x00,
			0x00,0x00,0x00,0x00,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,
			
			0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* a */
			0xFF,0xFF,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0x80,0x00,
			0x00,0x00,0x00,0x00,0x7F,0xFF,0xFF,0xFF,0xFF,0xFC,
			
			0x25,0x57,0x05,0xFA,0x2A,0x30,0x66,0x54,0xB1,0xF4,	/* b */
			0xCB,0x03,0xD6,0xA7,0x50,0xA3,0x0C,0x25,0x01,0x02,
			0xD4,0x98,0x87,0x17,0xD9,0xBA,0x15,0xAB,0x6D,0x3E,
			
			0x67,0x68,0xAE,0x8E,0x18,0xBB,0x92,0xCF,0xCF,0x00,	/* x */
			0x5C,0x94,0x9A,0xA2,0xC6,0xD9,0x48,0x53,0xD0,0xE6,
			0x60,0xBB,0xF8,0x54,0xB1,0xC9,0x50,0x5F,0xE9,0x5A,
			
			0x16,0x07,0xe6,0x89,0x8f,0x39,0x0c,0x06,0xbc,0x1d,	/* y */
			0x55,0x2b,0xad,0x22,0x6f,0x3b,0x6f,0xcf,0xe4,0x8b,
			0x6e,0x81,0x84,0x99,0xaf,0x18,0xe3,0xed,0x6c,0xf3,
			
			0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0x7F,0xFF,0xFF,0x97,0x5D,0xEB,0x41,0xB3,
			0xA6,0x05,0x7C,0x3C,0x43,0x21,0x46,0x52,0x65,0x51 }
	};
	
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+32*6]; }
	_EC_X9_62_PRIME_256V1 = {
		{ NID_X9_62_prime_field,20,32,1 },
		{ 0xC4,0x9D,0x36,0x08,0x86,0xE7,0x04,0x93,0x6A,0x66,	/* seed */
			0x78,0xE1,0x13,0x9D,0x26,0xB7,0x81,0x9F,0x7E,0x90,
			
			0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFC,
			0x5A,0xC6,0x35,0xD8,0xAA,0x3A,0x93,0xE7,0xB3,0xEB,	/* b */
			0xBD,0x55,0x76,0x98,0x86,0xBC,0x65,0x1D,0x06,0xB0,
			0xCC,0x53,0xB0,0xF6,0x3B,0xCE,0x3C,0x3E,0x27,0xD2,
			0x60,0x4B,
			0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,0xF8,0xBC,	/* x */
			0xE6,0xE5,0x63,0xA4,0x40,0xF2,0x77,0x03,0x7D,0x81,
			0x2D,0xEB,0x33,0xA0,0xF4,0xA1,0x39,0x45,0xD8,0x98,
			0xC2,0x96,
			0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,	/* y */
			0xeb,0x4a,0x7c,0x0f,0x9e,0x16,0x2b,0xce,0x33,0x57,
			0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,
			0x51,0xf5,
			0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,	/* order */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xBC,0xE6,0xFA,0xAD,
			0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,
			0x25,0x51 }
	};
	
	/* the secg prime curves (minus the nist and x9.62 prime curves) */
	static const struct { EC_CURVE_DATA h; unsigned char data[20+14*6]; }
	_EC_SECG_PRIME_112R1 = {
		{ NID_X9_62_prime_field,20,14,1 },
		{ 0x00,0xF5,0x0B,0x02,0x8E,0x4D,0x69,0x6E,0x67,0x68,	/* seed */
			0x75,0x61,0x51,0x75,0x29,0x04,0x72,0x78,0x3F,0xB1,
			
			0xDB,0x7C,0x2A,0xBF,0x62,0xE3,0x5E,0x66,0x80,0x76,	/* p */
			0xBE,0xAD,0x20,0x8B,
			0xDB,0x7C,0x2A,0xBF,0x62,0xE3,0x5E,0x66,0x80,0x76,	/* a */
			0xBE,0xAD,0x20,0x88,
			0x65,0x9E,0xF8,0xBA,0x04,0x39,0x16,0xEE,0xDE,0x89,	/* b */
			0x11,0x70,0x2B,0x22,
			0x09,0x48,0x72,0x39,0x99,0x5A,0x5E,0xE7,0x6B,0x55,	/* x */
			0xF9,0xC2,0xF0,0x98,
			0xa8,0x9c,0xe5,0xaf,0x87,0x24,0xc0,0xa2,0x3e,0x0e,	/* y */
			0x0f,0xf7,0x75,0x00,
			0xDB,0x7C,0x2A,0xBF,0x62,0xE3,0x5E,0x76,0x28,0xDF,	/* order */
			0xAC,0x65,0x61,0xC5 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+14*6]; }
	_EC_SECG_PRIME_112R2 = {
		{ NID_X9_62_prime_field,20,14,4 },
		{ 0x00,0x27,0x57,0xA1,0x11,0x4D,0x69,0x6E,0x67,0x68,	/* seed */
			0x75,0x61,0x51,0x75,0x53,0x16,0xC0,0x5E,0x0B,0xD4,
			
			0xDB,0x7C,0x2A,0xBF,0x62,0xE3,0x5E,0x66,0x80,0x76,	/* p */
			0xBE,0xAD,0x20,0x8B,
			0x61,0x27,0xC2,0x4C,0x05,0xF3,0x8A,0x0A,0xAA,0xF6,	/* a */
			0x5C,0x0E,0xF0,0x2C,
			0x51,0xDE,0xF1,0x81,0x5D,0xB5,0xED,0x74,0xFC,0xC3,	/* b */
			0x4C,0x85,0xD7,0x09,
			0x4B,0xA3,0x0A,0xB5,0xE8,0x92,0xB4,0xE1,0x64,0x9D,	/* x */
			0xD0,0x92,0x86,0x43,
			0xad,0xcd,0x46,0xf5,0x88,0x2e,0x37,0x47,0xde,0xf3,	/* y */
			0x6e,0x95,0x6e,0x97,
			0x36,0xDF,0x0A,0xAF,0xD8,0xB8,0xD7,0x59,0x7C,0xA1,	/* order */
			0x05,0x20,0xD0,0x4B }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+16*6]; }
	_EC_SECG_PRIME_128R1 = {
		{ NID_X9_62_prime_field,20,16,1 },
		{ 0x00,0x0E,0x0D,0x4D,0x69,0x6E,0x67,0x68,0x75,0x61,	/* seed */
			0x51,0x75,0x0C,0xC0,0x3A,0x44,0x73,0xD0,0x36,0x79,
			
			0xFF,0xFF,0xFF,0xFD,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFD,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* a */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,
			0xE8,0x75,0x79,0xC1,0x10,0x79,0xF4,0x3D,0xD8,0x24,	/* b */
			0x99,0x3C,0x2C,0xEE,0x5E,0xD3,
			0x16,0x1F,0xF7,0x52,0x8B,0x89,0x9B,0x2D,0x0C,0x28,	/* x */
			0x60,0x7C,0xA5,0x2C,0x5B,0x86,
			0xcf,0x5a,0xc8,0x39,0x5b,0xaf,0xeb,0x13,0xc0,0x2d,	/* y */
			0xa2,0x92,0xdd,0xed,0x7a,0x83,
			0xFF,0xFF,0xFF,0xFE,0x00,0x00,0x00,0x00,0x75,0xA3,	/* order */
			0x0D,0x1B,0x90,0x38,0xA1,0x15 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+16*6]; }
	_EC_SECG_PRIME_128R2 = {
		{ NID_X9_62_prime_field,20,16,4 },
		{ 0x00,0x4D,0x69,0x6E,0x67,0x68,0x75,0x61,0x51,0x75,	/* seed */
			0x12,0xD8,0xF0,0x34,0x31,0xFC,0xE6,0x3B,0x88,0xF4,
			
			0xFF,0xFF,0xFF,0xFD,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xD6,0x03,0x19,0x98,0xD1,0xB3,0xBB,0xFE,0xBF,0x59,	/* a */
			0xCC,0x9B,0xBF,0xF9,0xAE,0xE1,
			0x5E,0xEE,0xFC,0xA3,0x80,0xD0,0x29,0x19,0xDC,0x2C,	/* b */
			0x65,0x58,0xBB,0x6D,0x8A,0x5D,
			0x7B,0x6A,0xA5,0xD8,0x5E,0x57,0x29,0x83,0xE6,0xFB,	/* x */
			0x32,0xA7,0xCD,0xEB,0xC1,0x40,
			0x27,0xb6,0x91,0x6a,0x89,0x4d,0x3a,0xee,0x71,0x06,	/* y */
			0xfe,0x80,0x5f,0xc3,0x4b,0x44,
			0x3F,0xFF,0xFF,0xFF,0x7F,0xFF,0xFF,0xFF,0xBE,0x00,	/* order */
			0x24,0x72,0x06,0x13,0xB5,0xA3 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+21*6]; }
	_EC_SECG_PRIME_160K1 = {
		{ NID_X9_62_prime_field,0,21,1 },
		{							/* no seed */
			0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xAC,
			0x73,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x07,
			0x00,0x3B,0x4C,0x38,0x2C,0xE3,0x7A,0xA1,0x92,0xA4,	/* x */
			0x01,0x9E,0x76,0x30,0x36,0xF4,0xF5,0xDD,0x4D,0x7E,
			0xBB,
			0x00,0x93,0x8c,0xf9,0x35,0x31,0x8f,0xdc,0xed,0x6b,	/* y */
			0xc2,0x82,0x86,0x53,0x17,0x33,0xc3,0xf0,0x3c,0x4f,
			0xee,
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x01,0xB8,0xFA,0x16,0xDF,0xAB,0x9A,0xCA,0x16,0xB6,
			0xB3 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+21*6]; }
	_EC_SECG_PRIME_160R1 = {
		{ NID_X9_62_prime_field,20,21,1 },
		{ 0x10,0x53,0xCD,0xE4,0x2C,0x14,0xD6,0x96,0xE6,0x76,	/* seed */
			0x87,0x56,0x15,0x17,0x53,0x3B,0xF3,0xF8,0x33,0x45,
			
			0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F,0xFF,0xFF,
			0xFF,
			0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* a */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F,0xFF,0xFF,
			0xFC,
			0x00,0x1C,0x97,0xBE,0xFC,0x54,0xBD,0x7A,0x8B,0x65,	/* b */
			0xAC,0xF8,0x9F,0x81,0xD4,0xD4,0xAD,0xC5,0x65,0xFA,
			0x45,
			0x00,0x4A,0x96,0xB5,0x68,0x8E,0xF5,0x73,0x28,0x46,	/* x */
			0x64,0x69,0x89,0x68,0xC3,0x8B,0xB9,0x13,0xCB,0xFC,
			0x82,
			0x00,0x23,0xa6,0x28,0x55,0x31,0x68,0x94,0x7d,0x59,	/* y */
			0xdc,0xc9,0x12,0x04,0x23,0x51,0x37,0x7a,0xc5,0xfb,
			0x32,
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x01,0xF4,0xC8,0xF9,0x27,0xAE,0xD3,0xCA,0x75,0x22,
			0x57 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+21*6]; }
	_EC_SECG_PRIME_160R2 = {
		{ NID_X9_62_prime_field,20,21,1 },
		{ 0xB9,0x9B,0x99,0xB0,0x99,0xB3,0x23,0xE0,0x27,0x09,	/* seed */
			0xA4,0xD6,0x96,0xE6,0x76,0x87,0x56,0x15,0x17,0x51,
			
			0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xAC,
			0x73,
			0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* a */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xAC,
			0x70,
			0x00,0xB4,0xE1,0x34,0xD3,0xFB,0x59,0xEB,0x8B,0xAB,	/* b */
			0x57,0x27,0x49,0x04,0x66,0x4D,0x5A,0xF5,0x03,0x88,
			0xBA,
			0x00,0x52,0xDC,0xB0,0x34,0x29,0x3A,0x11,0x7E,0x1F,	/* x */
			0x4F,0xF1,0x1B,0x30,0xF7,0x19,0x9D,0x31,0x44,0xCE,
			0x6D,
			0x00,0xfe,0xaf,0xfe,0xf2,0xe3,0x31,0xf2,0x96,0xe0,	/* y */
			0x71,0xfa,0x0d,0xf9,0x98,0x2c,0xfe,0xa7,0xd4,0x3f,
			0x2e,
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x00,0x35,0x1E,0xE7,0x86,0xA8,0x18,0xF3,0xA1,0xA1,
			0x6B }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+24*6]; }
	_EC_SECG_PRIME_192K1 = {
		{ NID_X9_62_prime_field,0,24,1 },
		{							/* no seed */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
			0xFF,0xFF,0xEE,0x37,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x03,
			0xDB,0x4F,0xF1,0x0E,0xC0,0x57,0xE9,0xAE,0x26,0xB0,	/* x */
			0x7D,0x02,0x80,0xB7,0xF4,0x34,0x1D,0xA5,0xD1,0xB1,
			0xEA,0xE0,0x6C,0x7D,
			0x9b,0x2f,0x2f,0x6d,0x9c,0x56,0x28,0xa7,0x84,0x41,	/* y */
			0x63,0xd0,0x15,0xbe,0x86,0x34,0x40,0x82,0xaa,0x88,
			0xd9,0x5e,0x2f,0x9d,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFE,0x26,0xF2,0xFC,0x17,0x0F,0x69,0x46,0x6A,
			0x74,0xDE,0xFD,0x8D }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+29*6]; }
	_EC_SECG_PRIME_224K1 = {
		{ NID_X9_62_prime_field,0,29,1 },
		{							/* no seed */
			0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xE5,0x6D,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,
			0x00,0xA1,0x45,0x5B,0x33,0x4D,0xF0,0x99,0xDF,0x30,	/* x */
			0xFC,0x28,0xA1,0x69,0xA4,0x67,0xE9,0xE4,0x70,0x75,
			0xA9,0x0F,0x7E,0x65,0x0E,0xB6,0xB7,0xA4,0x5C,
			0x00,0x7e,0x08,0x9f,0xed,0x7f,0xba,0x34,0x42,0x82,	/* y */
			0xca,0xfb,0xd6,0xf7,0xe3,0x19,0xf7,0xc0,0xb0,0xbd,
			0x59,0xe2,0xca,0x4b,0xdb,0x55,0x6d,0x61,0xa5,
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x00,0x00,0x00,0x00,0x01,0xDC,0xE8,0xD2,0xEC,0x61,
			0x84,0xCA,0xF0,0xA9,0x71,0x76,0x9F,0xB1,0xF7 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+32*6]; }
	_EC_SECG_PRIME_256K1 = {
		{ NID_X9_62_prime_field,0,32,1 },
		{							/* no seed */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,
			0xFC,0x2F,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x07,
			0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,	/* x */
			0x62,0x95,0xCE,0x87,0x0B,0x07,0x02,0x9B,0xFC,0xDB,
			0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
			0x17,0x98,
			0x48,0x3a,0xda,0x77,0x26,0xa3,0xc4,0x65,0x5d,0xa4,	/* y */
			0xfb,0xfc,0x0e,0x11,0x08,0xa8,0xfd,0x17,0xb4,0x48,
			0xa6,0x85,0x54,0x19,0x9c,0x47,0xd0,0x8f,0xfb,0x10,
			0xd4,0xb8,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,
			0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,
			0x41,0x41 }
	};
	
	/* some wap/wtls curves */
	static const struct { EC_CURVE_DATA h; unsigned char data[0+15*6]; }
	_EC_WTLS_8 = {
		{ NID_X9_62_prime_field,0,15,1 },
		{							/* no seed */
			0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFD,0xE7,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x03,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* x */
			0x00,0x00,0x00,0x00,0x01,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* y */
			0x00,0x00,0x00,0x00,0x02,
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xEC,0xEA,	/* order */
			0x55,0x1A,0xD8,0x37,0xE9 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+21*6]; }
	_EC_WTLS_9 = {
		{ NID_X9_62_prime_field,0,21,1 },
		{							/* no seed */
			0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,0x80,
			0x8F,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x03,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* x */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x01,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* y */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x02,
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x01,0xCD,0xC9,0x8A,0xE0,0xE2,0xDE,0x57,0x4A,0xBF,
			0x33 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+28*6]; }
	_EC_WTLS_12 = {
		{ NID_X9_62_prime_field,0,28,1 },
		{							/* no seed */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* a */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
			0xB4,0x05,0x0A,0x85,0x0C,0x04,0xB3,0xAB,0xF5,0x41,	/* b */
			0x32,0x56,0x50,0x44,0xB0,0xB7,0xD7,0xBF,0xD8,0xBA,
			0x27,0x0B,0x39,0x43,0x23,0x55,0xFF,0xB4,
			0xB7,0x0E,0x0C,0xBD,0x6B,0xB4,0xBF,0x7F,0x32,0x13,	/* x */
			0x90,0xB9,0x4A,0x03,0xC1,0xD3,0x56,0xC2,0x11,0x22,
			0x34,0x32,0x80,0xD6,0x11,0x5C,0x1D,0x21,
			0xbd,0x37,0x63,0x88,0xb5,0xf7,0x23,0xfb,0x4c,0x22,	/* y */
			0xdf,0xe6,0xcd,0x43,0x75,0xa0,0x5a,0x07,0x47,0x64,
			0x44,0xd5,0x81,0x99,0x85,0x00,0x7e,0x34,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0xFF,0xFF,0x16,0xA2,0xE0,0xB8,0xF0,0x3E,
			0x13,0xDD,0x29,0x45,0x5C,0x5C,0x2A,0x3D }
	};
	
#ifndef OPENSSL_NO_EC2M
	
	/* characteristic two curves */
	static const struct { EC_CURVE_DATA h; unsigned char data[20+15*6]; }
	_EC_SECG_CHAR2_113R1 = {
		{ NID_X9_62_characteristic_two_field,20,15,2 },
		{ 0x10,0xE7,0x23,0xAB,0x14,0xD6,0x96,0xE6,0x76,0x87,	/* seed */
			0x56,0x15,0x17,0x56,0xFE,0xBF,0x8F,0xCB,0x49,0xA9,
			
			0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x02,0x01,
			0x00,0x30,0x88,0x25,0x0C,0xA6,0xE7,0xC7,0xFE,0x64,	/* a */
			0x9C,0xE8,0x58,0x20,0xF7,
			0x00,0xE8,0xBE,0xE4,0xD3,0xE2,0x26,0x07,0x44,0x18,	/* b */
			0x8B,0xE0,0xE9,0xC7,0x23,
			0x00,0x9D,0x73,0x61,0x6F,0x35,0xF4,0xAB,0x14,0x07,	/* x */
			0xD7,0x35,0x62,0xC1,0x0F,
			0x00,0xA5,0x28,0x30,0x27,0x79,0x58,0xEE,0x84,0xD1,	/* y */
			0x31,0x5E,0xD3,0x18,0x86,
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xD9,0xCC,	/* order */
			0xEC,0x8A,0x39,0xE5,0x6F }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+15*6]; }
	_EC_SECG_CHAR2_113R2 = {
		{ NID_X9_62_characteristic_two_field,20,15,2 },
		{ 0x10,0xC0,0xFB,0x15,0x76,0x08,0x60,0xDE,0xF1,0xEE,	/* seed */
			0xF4,0xD6,0x96,0xE6,0x76,0x87,0x56,0x15,0x17,0x5D,
			
			0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x02,0x01,
			0x00,0x68,0x99,0x18,0xDB,0xEC,0x7E,0x5A,0x0D,0xD6,	/* a */
			0xDF,0xC0,0xAA,0x55,0xC7,
			0x00,0x95,0xE9,0xA9,0xEC,0x9B,0x29,0x7B,0xD4,0xBF,	/* b */
			0x36,0xE0,0x59,0x18,0x4F,
			0x01,0xA5,0x7A,0x6A,0x7B,0x26,0xCA,0x5E,0xF5,0x2F,	/* x */
			0xCD,0xB8,0x16,0x47,0x97,
			0x00,0xB3,0xAD,0xC9,0x4E,0xD1,0xFE,0x67,0x4C,0x06,	/* y */
			0xE6,0x95,0xBA,0xBA,0x1D,
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x08,0x78,	/* order */
			0x9B,0x24,0x96,0xAF,0x93 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+17*6]; }
	_EC_SECG_CHAR2_131R1 = {
		{ NID_X9_62_characteristic_two_field,20,17,2 },
		{ 0x4D,0x69,0x6E,0x67,0x68,0x75,0x61,0x51,0x75,0x98,	/* seed */
			0x5B,0xD3,0xAD,0xBA,0xDA,0x21,0xB4,0x3A,0x97,0xE2,
			
			0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x01,0x0D,
			0x07,0xA1,0x1B,0x09,0xA7,0x6B,0x56,0x21,0x44,0x41,	/* a */
			0x8F,0xF3,0xFF,0x8C,0x25,0x70,0xB8,
			0x02,0x17,0xC0,0x56,0x10,0x88,0x4B,0x63,0xB9,0xC6,	/* b */
			0xC7,0x29,0x16,0x78,0xF9,0xD3,0x41,
			0x00,0x81,0xBA,0xF9,0x1F,0xDF,0x98,0x33,0xC4,0x0F,	/* x */
			0x9C,0x18,0x13,0x43,0x63,0x83,0x99,
			0x07,0x8C,0x6E,0x7E,0xA3,0x8C,0x00,0x1F,0x73,0xC8,	/* y */
			0x13,0x4B,0x1B,0x4E,0xF9,0xE1,0x50,
			0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x31,	/* order */
			0x23,0x95,0x3A,0x94,0x64,0xB5,0x4D }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+17*6]; }
	_EC_SECG_CHAR2_131R2 = {
		{ NID_X9_62_characteristic_two_field,20,17,2 },
		{ 0x98,0x5B,0xD3,0xAD,0xBA,0xD4,0xD6,0x96,0xE6,0x76,	/* seed */
			0x87,0x56,0x15,0x17,0x5A,0x21,0xB4,0x3A,0x97,0xE3,
			
			0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x01,0x0D,
			0x03,0xE5,0xA8,0x89,0x19,0xD7,0xCA,0xFC,0xBF,0x41,	/* a */
			0x5F,0x07,0xC2,0x17,0x65,0x73,0xB2,
			0x04,0xB8,0x26,0x6A,0x46,0xC5,0x56,0x57,0xAC,0x73,	/* b */
			0x4C,0xE3,0x8F,0x01,0x8F,0x21,0x92,
			0x03,0x56,0xDC,0xD8,0xF2,0xF9,0x50,0x31,0xAD,0x65,	/* x */
			0x2D,0x23,0x95,0x1B,0xB3,0x66,0xA8,
			0x06,0x48,0xF0,0x6D,0x86,0x79,0x40,0xA5,0x36,0x6D,	/* y */
			0x9E,0x26,0x5D,0xE9,0xEB,0x24,0x0F,
			0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x69,	/* order */
			0x54,0xA2,0x33,0x04,0x9B,0xA9,0x8F }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+21*6]; }
	_EC_NIST_CHAR2_163K = {
		{ NID_X9_62_characteristic_two_field,0,21,2 },
		{							/* no seed */
			0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0xC9,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x01,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x01,
			0x02,0xFE,0x13,0xC0,0x53,0x7B,0xBC,0x11,0xAC,0xAA,	/* x */
			0x07,0xD7,0x93,0xDE,0x4E,0x6D,0x5E,0x5C,0x94,0xEE,
			0xE8,
			0x02,0x89,0x07,0x0F,0xB0,0x5D,0x38,0xFF,0x58,0x32,	/* y */
			0x1F,0x2E,0x80,0x05,0x36,0xD5,0x38,0xCC,0xDA,0xA3,
			0xD9,
			0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x02,0x01,0x08,0xA2,0xE0,0xCC,0x0D,0x99,0xF8,0xA5,
			0xEF }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+21*6]; }
	_EC_SECG_CHAR2_163R1 = {
		{ NID_X9_62_characteristic_two_field,0,21,2 },
		{							/* no seed */
#if 0
			/* The algorithm used to derive the curve parameters from
			 * the seed used here is slightly different than the
			 * algorithm described in X9.62 . */
			0x24,0xB7,0xB1,0x37,0xC8,0xA1,0x4D,0x69,0x6E,0x67,
			0x68,0x75,0x61,0x51,0x75,0x6F,0xD0,0xDA,0x2E,0x5C,
#endif
			0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0xC9,
			0x07,0xB6,0x88,0x2C,0xAA,0xEF,0xA8,0x4F,0x95,0x54,	/* a */
			0xFF,0x84,0x28,0xBD,0x88,0xE2,0x46,0xD2,0x78,0x2A,
			0xE2,
			0x07,0x13,0x61,0x2D,0xCD,0xDC,0xB4,0x0A,0xAB,0x94,	/* b */
			0x6B,0xDA,0x29,0xCA,0x91,0xF7,0x3A,0xF9,0x58,0xAF,
			0xD9,
			0x03,0x69,0x97,0x96,0x97,0xAB,0x43,0x89,0x77,0x89,	/* x */
			0x56,0x67,0x89,0x56,0x7F,0x78,0x7A,0x78,0x76,0xA6,
			0x54,
			0x00,0x43,0x5E,0xDB,0x42,0xEF,0xAF,0xB2,0x98,0x9D,	/* y */
			0x51,0xFE,0xFC,0xE3,0xC8,0x09,0x88,0xF4,0x1F,0xF8,
			0x83,
			0x03,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0x48,0xAA,0xB6,0x89,0xC2,0x9C,0xA7,0x10,0x27,
			0x9B }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+21*6]; }
	_EC_NIST_CHAR2_163B = {
		{ NID_X9_62_characteristic_two_field,0,21,2 },
		{							/* no seed */
#if 0
			/* The seed here was used to created the curve parameters in normal
			 * basis representation (and not the polynomial representation used here) */
			0x85,0xE2,0x5B,0xFE,0x5C,0x86,0x22,0x6C,0xDB,0x12,
			0x01,0x6F,0x75,0x53,0xF9,0xD0,0xE6,0x93,0xA2,0x68,
#endif
			0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0xC9,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x01,
			0x02,0x0A,0x60,0x19,0x07,0xB8,0xC9,0x53,0xCA,0x14,	/* b */
			0x81,0xEB,0x10,0x51,0x2F,0x78,0x74,0x4A,0x32,0x05,
			0xFD,
			0x03,0xF0,0xEB,0xA1,0x62,0x86,0xA2,0xD5,0x7E,0xA0,	/* x */
			0x99,0x11,0x68,0xD4,0x99,0x46,0x37,0xE8,0x34,0x3E,
			0x36,
			0x00,0xD5,0x1F,0xBC,0x6C,0x71,0xA0,0x09,0x4F,0xA2,	/* y */
			0xCD,0xD5,0x45,0xB1,0x1C,0x5C,0x0C,0x79,0x73,0x24,
			0xF1,
			0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x02,0x92,0xFE,0x77,0xE7,0x0C,0x12,0xA4,0x23,0x4C,
			0x33 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+25*6]; }
	_EC_SECG_CHAR2_193R1 = {
		{ NID_X9_62_characteristic_two_field,20,25,2 },
		{ 0x10,0x3F,0xAE,0xC7,0x4D,0x69,0x6E,0x67,0x68,0x75,	/* seed */
			0x61,0x51,0x75,0x77,0x7F,0xC5,0xB1,0x91,0xEF,0x30,
			
			0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x80,0x01,
			0x00,0x17,0x85,0x8F,0xEB,0x7A,0x98,0x97,0x51,0x69,	/* a */
			0xE1,0x71,0xF7,0x7B,0x40,0x87,0xDE,0x09,0x8A,0xC8,
			0xA9,0x11,0xDF,0x7B,0x01,
			0x00,0xFD,0xFB,0x49,0xBF,0xE6,0xC3,0xA8,0x9F,0xAC,	/* b */
			0xAD,0xAA,0x7A,0x1E,0x5B,0xBC,0x7C,0xC1,0xC2,0xE5,
			0xD8,0x31,0x47,0x88,0x14,
			0x01,0xF4,0x81,0xBC,0x5F,0x0F,0xF8,0x4A,0x74,0xAD,	/* x */
			0x6C,0xDF,0x6F,0xDE,0xF4,0xBF,0x61,0x79,0x62,0x53,
			0x72,0xD8,0xC0,0xC5,0xE1,
			0x00,0x25,0xE3,0x99,0xF2,0x90,0x37,0x12,0xCC,0xF3,	/* y */
			0xEA,0x9E,0x3A,0x1A,0xD1,0x7F,0xB0,0xB3,0x20,0x1B,
			0x6A,0xF7,0xCE,0x1B,0x05,
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x00,0x00,0x00,0xC7,0xF3,0x4A,0x77,0x8F,0x44,0x3A,
			0xCC,0x92,0x0E,0xBA,0x49 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+25*6]; }
	_EC_SECG_CHAR2_193R2 = {
		{ NID_X9_62_characteristic_two_field,20,25,2 },
		{ 0x10,0xB7,0xB4,0xD6,0x96,0xE6,0x76,0x87,0x56,0x15,	/* seed */
			0x17,0x51,0x37,0xC8,0xA1,0x6F,0xD0,0xDA,0x22,0x11,
			
			0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x80,0x01,
			0x01,0x63,0xF3,0x5A,0x51,0x37,0xC2,0xCE,0x3E,0xA6,	/* a */
			0xED,0x86,0x67,0x19,0x0B,0x0B,0xC4,0x3E,0xCD,0x69,
			0x97,0x77,0x02,0x70,0x9B,
			0x00,0xC9,0xBB,0x9E,0x89,0x27,0xD4,0xD6,0x4C,0x37,	/* b */
			0x7E,0x2A,0xB2,0x85,0x6A,0x5B,0x16,0xE3,0xEF,0xB7,
			0xF6,0x1D,0x43,0x16,0xAE,
			0x00,0xD9,0xB6,0x7D,0x19,0x2E,0x03,0x67,0xC8,0x03,	/* x */
			0xF3,0x9E,0x1A,0x7E,0x82,0xCA,0x14,0xA6,0x51,0x35,
			0x0A,0xAE,0x61,0x7E,0x8F,
			0x01,0xCE,0x94,0x33,0x56,0x07,0xC3,0x04,0xAC,0x29,	/* y */
			0xE7,0xDE,0xFB,0xD9,0xCA,0x01,0xF5,0x96,0xF9,0x27,
			0x22,0x4C,0xDE,0xCF,0x6C,
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x00,0x00,0x01,0x5A,0xAB,0x56,0x1B,0x00,0x54,0x13,
			0xCC,0xD4,0xEE,0x99,0xD5 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+30*6]; }
	_EC_NIST_CHAR2_233K = {
		{ NID_X9_62_characteristic_two_field,0,30,4 },
		{							/* no seed */
			0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
			
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
			
			0x01,0x72,0x32,0xBA,0x85,0x3A,0x7E,0x73,0x1A,0xF1,	/* x */
			0x29,0xF2,0x2F,0xF4,0x14,0x95,0x63,0xA4,0x19,0xC2,
			0x6B,0xF5,0x0A,0x4C,0x9D,0x6E,0xEF,0xAD,0x61,0x26,
			
			0x01,0xDB,0x53,0x7D,0xEC,0xE8,0x19,0xB7,0xF7,0x0F,	/* y */
			0x55,0x5A,0x67,0xC4,0x27,0xA8,0xCD,0x9B,0xF1,0x8A,
			0xEB,0x9B,0x56,0xE0,0xC1,0x10,0x56,0xFA,0xE6,0xA3,
			
			0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x00,0x00,0x00,0x00,0x00,0x06,0x9D,0x5B,0xB9,0x15,
			0xBC,0xD4,0x6E,0xFB,0x1A,0xD5,0xF1,0x73,0xAB,0xDF }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+30*6]; }
	_EC_NIST_CHAR2_233B = {
		{ NID_X9_62_characteristic_two_field,20,30,2 },
		{ 0x74,0xD5,0x9F,0xF0,0x7F,0x6B,0x41,0x3D,0x0E,0xA1,	/* seed */
			0x4B,0x34,0x4B,0x20,0xA2,0xDB,0x04,0x9B,0x50,0xC3,
			
			0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
			
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
			
			0x00,0x66,0x64,0x7E,0xDE,0x6C,0x33,0x2C,0x7F,0x8C,	/* b */
			0x09,0x23,0xBB,0x58,0x21,0x3B,0x33,0x3B,0x20,0xE9,
			0xCE,0x42,0x81,0xFE,0x11,0x5F,0x7D,0x8F,0x90,0xAD,
			
			0x00,0xFA,0xC9,0xDF,0xCB,0xAC,0x83,0x13,0xBB,0x21,	/* x */
			0x39,0xF1,0xBB,0x75,0x5F,0xEF,0x65,0xBC,0x39,0x1F,
			0x8B,0x36,0xF8,0xF8,0xEB,0x73,0x71,0xFD,0x55,0x8B,
			
			0x01,0x00,0x6A,0x08,0xA4,0x19,0x03,0x35,0x06,0x78,	/* y */
			0xE5,0x85,0x28,0xBE,0xBF,0x8A,0x0B,0xEF,0xF8,0x67,
			0xA7,0xCA,0x36,0x71,0x6F,0x7E,0x01,0xF8,0x10,0x52,
			
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x00,0x00,0x00,0x00,0x00,0x13,0xE9,0x74,0xE7,0x2F,
			0x8A,0x69,0x22,0x03,0x1D,0x26,0x03,0xCF,0xE0,0xD7 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+30*6]; }
	_EC_SECG_CHAR2_239K1 = {
		{ NID_X9_62_characteristic_two_field,0,30,4 },
		{							/* no seed */
			0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
			
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
			
			0x29,0xA0,0xB6,0xA8,0x87,0xA9,0x83,0xE9,0x73,0x09,	/* x */
			0x88,0xA6,0x87,0x27,0xA8,0xB2,0xD1,0x26,0xC4,0x4C,
			0xC2,0xCC,0x7B,0x2A,0x65,0x55,0x19,0x30,0x35,0xDC,
			
			0x76,0x31,0x08,0x04,0xF1,0x2E,0x54,0x9B,0xDB,0x01,	/* y */
			0x1C,0x10,0x30,0x89,0xE7,0x35,0x10,0xAC,0xB2,0x75,
			0xFC,0x31,0x2A,0x5D,0xC6,0xB7,0x65,0x53,0xF0,0xCA,
			
			0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x00,0x00,0x00,0x00,0x00,0x5A,0x79,0xFE,0xC6,0x7C,
			0xB6,0xE9,0x1F,0x1C,0x1D,0xA8,0x00,0xE4,0x78,0xA5 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+36*6]; }
	_EC_NIST_CHAR2_283K = {
		{ NID_X9_62_characteristic_two_field,0,36,4 },
		{							/* no seed */
			0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x10,0xA1,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x01,
			0x05,0x03,0x21,0x3F,0x78,0xCA,0x44,0x88,0x3F,0x1A,	/* x */
			0x3B,0x81,0x62,0xF1,0x88,0xE5,0x53,0xCD,0x26,0x5F,
			0x23,0xC1,0x56,0x7A,0x16,0x87,0x69,0x13,0xB0,0xC2,
			0xAC,0x24,0x58,0x49,0x28,0x36,
			0x01,0xCC,0xDA,0x38,0x0F,0x1C,0x9E,0x31,0x8D,0x90,	/* y */
			0xF9,0x5D,0x07,0xE5,0x42,0x6F,0xE8,0x7E,0x45,0xC0,
			0xE8,0x18,0x46,0x98,0xE4,0x59,0x62,0x36,0x4E,0x34,
			0x11,0x61,0x77,0xDD,0x22,0x59,
			0x01,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xE9,0xAE,
			0x2E,0xD0,0x75,0x77,0x26,0x5D,0xFF,0x7F,0x94,0x45,
			0x1E,0x06,0x1E,0x16,0x3C,0x61 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+36*6]; }
	_EC_NIST_CHAR2_283B = {
		{ NID_X9_62_characteristic_two_field,20,36,2 },
		{ 0x77,0xE2,0xB0,0x73,0x70,0xEB,0x0F,0x83,0x2A,0x6D,	/* no seed */
			0xD5,0xB6,0x2D,0xFC,0x88,0xCD,0x06,0xBB,0x84,0xBE,
			
			0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x10,0xA1,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x01,
			0x02,0x7B,0x68,0x0A,0xC8,0xB8,0x59,0x6D,0xA5,0xA4,	/* b */
			0xAF,0x8A,0x19,0xA0,0x30,0x3F,0xCA,0x97,0xFD,0x76,
			0x45,0x30,0x9F,0xA2,0xA5,0x81,0x48,0x5A,0xF6,0x26,
			0x3E,0x31,0x3B,0x79,0xA2,0xF5,
			0x05,0xF9,0x39,0x25,0x8D,0xB7,0xDD,0x90,0xE1,0x93,	/* x */
			0x4F,0x8C,0x70,0xB0,0xDF,0xEC,0x2E,0xED,0x25,0xB8,
			0x55,0x7E,0xAC,0x9C,0x80,0xE2,0xE1,0x98,0xF8,0xCD,
			0xBE,0xCD,0x86,0xB1,0x20,0x53,
			0x03,0x67,0x68,0x54,0xFE,0x24,0x14,0x1C,0xB9,0x8F,	/* y */
			0xE6,0xD4,0xB2,0x0D,0x02,0xB4,0x51,0x6F,0xF7,0x02,
			0x35,0x0E,0xDD,0xB0,0x82,0x67,0x79,0xC8,0x13,0xF0,
			0xDF,0x45,0xBE,0x81,0x12,0xF4,
			0x03,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xEF,0x90,
			0x39,0x96,0x60,0xFC,0x93,0x8A,0x90,0x16,0x5B,0x04,
			0x2A,0x7C,0xEF,0xAD,0xB3,0x07 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+52*6]; }
	_EC_NIST_CHAR2_409K = {
		{ NID_X9_62_characteristic_two_field,0,52,4 },
		{							/* no seed */
			0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x01,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x01,
			0x00,0x60,0xF0,0x5F,0x65,0x8F,0x49,0xC1,0xAD,0x3A,	/* x */
			0xB1,0x89,0x0F,0x71,0x84,0x21,0x0E,0xFD,0x09,0x87,
			0xE3,0x07,0xC8,0x4C,0x27,0xAC,0xCF,0xB8,0xF9,0xF6,
			0x7C,0xC2,0xC4,0x60,0x18,0x9E,0xB5,0xAA,0xAA,0x62,
			0xEE,0x22,0x2E,0xB1,0xB3,0x55,0x40,0xCF,0xE9,0x02,
			0x37,0x46,
			0x01,0xE3,0x69,0x05,0x0B,0x7C,0x4E,0x42,0xAC,0xBA,	/* y */
			0x1D,0xAC,0xBF,0x04,0x29,0x9C,0x34,0x60,0x78,0x2F,
			0x91,0x8E,0xA4,0x27,0xE6,0x32,0x51,0x65,0xE9,0xEA,
			0x10,0xE3,0xDA,0x5F,0x6C,0x42,0xE9,0xC5,0x52,0x15,
			0xAA,0x9C,0xA2,0x7A,0x58,0x63,0xEC,0x48,0xD8,0xE0,
			0x28,0x6B,
			0x00,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0x5F,0x83,0xB2,
			0xD4,0xEA,0x20,0x40,0x0E,0xC4,0x55,0x7D,0x5E,0xD3,
			0xE3,0xE7,0xCA,0x5B,0x4B,0x5C,0x83,0xB8,0xE0,0x1E,
			0x5F,0xCF }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+52*6]; }
	_EC_NIST_CHAR2_409B = {
		{ NID_X9_62_characteristic_two_field,20,52,2 },
		{ 0x40,0x99,0xB5,0xA4,0x57,0xF9,0xD6,0x9F,0x79,0x21,	/* seed */
			0x3D,0x09,0x4C,0x4B,0xCD,0x4D,0x42,0x62,0x21,0x0B,
			
			0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x01,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x01,
			0x00,0x21,0xA5,0xC2,0xC8,0xEE,0x9F,0xEB,0x5C,0x4B,	/* b */
			0x9A,0x75,0x3B,0x7B,0x47,0x6B,0x7F,0xD6,0x42,0x2E,
			0xF1,0xF3,0xDD,0x67,0x47,0x61,0xFA,0x99,0xD6,0xAC,
			0x27,0xC8,0xA9,0xA1,0x97,0xB2,0x72,0x82,0x2F,0x6C,
			0xD5,0x7A,0x55,0xAA,0x4F,0x50,0xAE,0x31,0x7B,0x13,
			0x54,0x5F,
			0x01,0x5D,0x48,0x60,0xD0,0x88,0xDD,0xB3,0x49,0x6B,	/* x */
			0x0C,0x60,0x64,0x75,0x62,0x60,0x44,0x1C,0xDE,0x4A,
			0xF1,0x77,0x1D,0x4D,0xB0,0x1F,0xFE,0x5B,0x34,0xE5,
			0x97,0x03,0xDC,0x25,0x5A,0x86,0x8A,0x11,0x80,0x51,
			0x56,0x03,0xAE,0xAB,0x60,0x79,0x4E,0x54,0xBB,0x79,
			0x96,0xA7,
			0x00,0x61,0xB1,0xCF,0xAB,0x6B,0xE5,0xF3,0x2B,0xBF,	/* y */
			0xA7,0x83,0x24,0xED,0x10,0x6A,0x76,0x36,0xB9,0xC5,
			0xA7,0xBD,0x19,0x8D,0x01,0x58,0xAA,0x4F,0x54,0x88,
			0xD0,0x8F,0x38,0x51,0x4F,0x1F,0xDF,0x4B,0x4F,0x40,
			0xD2,0x18,0x1B,0x36,0x81,0xC3,0x64,0xBA,0x02,0x73,
			0xC7,0x06,
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xE2,0xAA,0xD6,
			0xA6,0x12,0xF3,0x33,0x07,0xBE,0x5F,0xA4,0x7C,0x3C,
			0x9E,0x05,0x2F,0x83,0x81,0x64,0xCD,0x37,0xD9,0xA2,
			0x11,0x73 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+72*6]; }
	_EC_NIST_CHAR2_571K = {
		{ NID_X9_62_characteristic_two_field,0,72,4 },
		{							/* no seed */
			0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x04,0x25,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x01,
			0x02,0x6E,0xB7,0xA8,0x59,0x92,0x3F,0xBC,0x82,0x18,	/* x */
			0x96,0x31,0xF8,0x10,0x3F,0xE4,0xAC,0x9C,0xA2,0x97,
			0x00,0x12,0xD5,0xD4,0x60,0x24,0x80,0x48,0x01,0x84,
			0x1C,0xA4,0x43,0x70,0x95,0x84,0x93,0xB2,0x05,0xE6,
			0x47,0xDA,0x30,0x4D,0xB4,0xCE,0xB0,0x8C,0xBB,0xD1,
			0xBA,0x39,0x49,0x47,0x76,0xFB,0x98,0x8B,0x47,0x17,
			0x4D,0xCA,0x88,0xC7,0xE2,0x94,0x52,0x83,0xA0,0x1C,
			0x89,0x72,
			0x03,0x49,0xDC,0x80,0x7F,0x4F,0xBF,0x37,0x4F,0x4A,	/* y */
			0xEA,0xDE,0x3B,0xCA,0x95,0x31,0x4D,0xD5,0x8C,0xEC,
			0x9F,0x30,0x7A,0x54,0xFF,0xC6,0x1E,0xFC,0x00,0x6D,
			0x8A,0x2C,0x9D,0x49,0x79,0xC0,0xAC,0x44,0xAE,0xA7,
			0x4F,0xBE,0xBB,0xB9,0xF7,0x72,0xAE,0xDC,0xB6,0x20,
			0xB0,0x1A,0x7B,0xA7,0xAF,0x1B,0x32,0x04,0x30,0xC8,
			0x59,0x19,0x84,0xF6,0x01,0xCD,0x4C,0x14,0x3E,0xF1,
			0xC7,0xA3,
			0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x13,0x18,0x50,0xE1,
			0xF1,0x9A,0x63,0xE4,0xB3,0x91,0xA8,0xDB,0x91,0x7F,
			0x41,0x38,0xB6,0x30,0xD8,0x4B,0xE5,0xD6,0x39,0x38,
			0x1E,0x91,0xDE,0xB4,0x5C,0xFE,0x77,0x8F,0x63,0x7C,
			0x10,0x01 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+72*6]; }
	_EC_NIST_CHAR2_571B = {
		{ NID_X9_62_characteristic_two_field,20,72,2 },
		{ 0x2A,0xA0,0x58,0xF7,0x3A,0x0E,0x33,0xAB,0x48,0x6B,	/* seed */
			0x0F,0x61,0x04,0x10,0xC5,0x3A,0x7F,0x13,0x23,0x10,
			
			0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x04,0x25,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x01,
			0x02,0xF4,0x0E,0x7E,0x22,0x21,0xF2,0x95,0xDE,0x29,	/* b */
			0x71,0x17,0xB7,0xF3,0xD6,0x2F,0x5C,0x6A,0x97,0xFF,
			0xCB,0x8C,0xEF,0xF1,0xCD,0x6B,0xA8,0xCE,0x4A,0x9A,
			0x18,0xAD,0x84,0xFF,0xAB,0xBD,0x8E,0xFA,0x59,0x33,
			0x2B,0xE7,0xAD,0x67,0x56,0xA6,0x6E,0x29,0x4A,0xFD,
			0x18,0x5A,0x78,0xFF,0x12,0xAA,0x52,0x0E,0x4D,0xE7,
			0x39,0xBA,0xCA,0x0C,0x7F,0xFE,0xFF,0x7F,0x29,0x55,
			0x72,0x7A,
			0x03,0x03,0x00,0x1D,0x34,0xB8,0x56,0x29,0x6C,0x16,	/* x */
			0xC0,0xD4,0x0D,0x3C,0xD7,0x75,0x0A,0x93,0xD1,0xD2,
			0x95,0x5F,0xA8,0x0A,0xA5,0xF4,0x0F,0xC8,0xDB,0x7B,
			0x2A,0xBD,0xBD,0xE5,0x39,0x50,0xF4,0xC0,0xD2,0x93,
			0xCD,0xD7,0x11,0xA3,0x5B,0x67,0xFB,0x14,0x99,0xAE,
			0x60,0x03,0x86,0x14,0xF1,0x39,0x4A,0xBF,0xA3,0xB4,
			0xC8,0x50,0xD9,0x27,0xE1,0xE7,0x76,0x9C,0x8E,0xEC,
			0x2D,0x19,
			0x03,0x7B,0xF2,0x73,0x42,0xDA,0x63,0x9B,0x6D,0xCC,	/* y */
			0xFF,0xFE,0xB7,0x3D,0x69,0xD7,0x8C,0x6C,0x27,0xA6,
			0x00,0x9C,0xBB,0xCA,0x19,0x80,0xF8,0x53,0x39,0x21,
			0xE8,0xA6,0x84,0x42,0x3E,0x43,0xBA,0xB0,0x8A,0x57,
			0x62,0x91,0xAF,0x8F,0x46,0x1B,0xB2,0xA8,0xB3,0x53,
			0x1D,0x2F,0x04,0x85,0xC1,0x9B,0x16,0xE2,0xF1,0x51,
			0x6E,0x23,0xDD,0x3C,0x1A,0x48,0x27,0xAF,0x1B,0x8A,
			0xC1,0x5B,
			0x03,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xE6,0x61,0xCE,0x18,
			0xFF,0x55,0x98,0x73,0x08,0x05,0x9B,0x18,0x68,0x23,
			0x85,0x1E,0xC7,0xDD,0x9C,0xA1,0x16,0x1D,0xE9,0x3D,
			0x51,0x74,0xD6,0x6E,0x83,0x82,0xE9,0xBB,0x2F,0xE8,
			0x4E,0x47 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+21*6]; }
	_EC_X9_62_CHAR2_163V1 = {
		{ NID_X9_62_characteristic_two_field,20,21,2 },
		{ 0xD2,0xC0,0xFB,0x15,0x76,0x08,0x60,0xDE,0xF1,0xEE,
			0xF4,0xD6,0x96,0xE6,0x76,0x87,0x56,0x15,0x17,0x54,	/* seed */
			
			0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
			0x07,
			0x07,0x25,0x46,0xB5,0x43,0x52,0x34,0xA4,0x22,0xE0,	/* a */
			0x78,0x96,0x75,0xF4,0x32,0xC8,0x94,0x35,0xDE,0x52,
			0x42,
			0x00,0xC9,0x51,0x7D,0x06,0xD5,0x24,0x0D,0x3C,0xFF,	/* b */
			0x38,0xC7,0x4B,0x20,0xB6,0xCD,0x4D,0x6F,0x9D,0xD4,
			0xD9,
			0x07,0xAF,0x69,0x98,0x95,0x46,0x10,0x3D,0x79,0x32,	/* x */
			0x9F,0xCC,0x3D,0x74,0x88,0x0F,0x33,0xBB,0xE8,0x03,
			0xCB,
			0x01,0xEC,0x23,0x21,0x1B,0x59,0x66,0xAD,0xEA,0x1D,	/* y */
			0x3F,0x87,0xF7,0xEA,0x58,0x48,0xAE,0xF0,0xB7,0xCA,
			0x9F,
			0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x01,0xE6,0x0F,0xC8,0x82,0x1C,0xC7,0x4D,0xAE,0xAF,
			0xC1 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+21*6]; }
	_EC_X9_62_CHAR2_163V2 = {
		{ NID_X9_62_characteristic_two_field,20,21,2 },
		{ 0x53,0x81,0x4C,0x05,0x0D,0x44,0xD6,0x96,0xE6,0x76,	/* seed */
			0x87,0x56,0x15,0x17,0x58,0x0C,0xA4,0xE2,0x9F,0xFD,
			
			0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
			0x07,
			0x01,0x08,0xB3,0x9E,0x77,0xC4,0xB1,0x08,0xBE,0xD9,	/* a */
			0x81,0xED,0x0E,0x89,0x0E,0x11,0x7C,0x51,0x1C,0xF0,
			0x72,
			0x06,0x67,0xAC,0xEB,0x38,0xAF,0x4E,0x48,0x8C,0x40,	/* b */
			0x74,0x33,0xFF,0xAE,0x4F,0x1C,0x81,0x16,0x38,0xDF,
			0x20,
			0x00,0x24,0x26,0x6E,0x4E,0xB5,0x10,0x6D,0x0A,0x96,	/* x */
			0x4D,0x92,0xC4,0x86,0x0E,0x26,0x71,0xDB,0x9B,0x6C,
			0xC5,
			0x07,0x9F,0x68,0x4D,0xDF,0x66,0x84,0xC5,0xCD,0x25,	/* y */
			0x8B,0x38,0x90,0x02,0x1B,0x23,0x86,0xDF,0xD1,0x9F,
			0xC5,
			0x03,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFD,0xF6,0x4D,0xE1,0x15,0x1A,0xDB,0xB7,0x8F,0x10,
			0xA7 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+21*6]; }
	_EC_X9_62_CHAR2_163V3 = {
		{ NID_X9_62_characteristic_two_field,20,21,2 },
		{ 0x50,0xCB,0xF1,0xD9,0x5C,0xA9,0x4D,0x69,0x6E,0x67,	/* seed */
			0x68,0x75,0x61,0x51,0x75,0xF1,0x6A,0x36,0xA3,0xB8,
			
			0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
			0x07,
			0x07,0xA5,0x26,0xC6,0x3D,0x3E,0x25,0xA2,0x56,0xA0,	/* a */
			0x07,0x69,0x9F,0x54,0x47,0xE3,0x2A,0xE4,0x56,0xB5,
			0x0E,
			0x03,0xF7,0x06,0x17,0x98,0xEB,0x99,0xE2,0x38,0xFD,	/* b */
			0x6F,0x1B,0xF9,0x5B,0x48,0xFE,0xEB,0x48,0x54,0x25,
			0x2B,
			0x02,0xF9,0xF8,0x7B,0x7C,0x57,0x4D,0x0B,0xDE,0xCF,	/* x */
			0x8A,0x22,0xE6,0x52,0x47,0x75,0xF9,0x8C,0xDE,0xBD,
			0xCB,
			0x05,0xB9,0x35,0x59,0x0C,0x15,0x5E,0x17,0xEA,0x48,	/* y */
			0xEB,0x3F,0xF3,0x71,0x8B,0x89,0x3D,0xF5,0x9A,0x05,
			0xD0,
			0x03,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFE,0x1A,0xEE,0x14,0x0F,0x11,0x0A,0xFF,0x96,0x13,
			0x09 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+23*6]; }
	_EC_X9_62_CHAR2_176V1 = {
		{ NID_X9_62_characteristic_two_field,0,23,0xFF6E },
		{							/* no seed */
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,
			0x00,0x00,0x07,
			0x00,0xE4,0xE6,0xDB,0x29,0x95,0x06,0x5C,0x40,0x7D,	/* a */
			0x9D,0x39,0xB8,0xD0,0x96,0x7B,0x96,0x70,0x4B,0xA8,
			0xE9,0xC9,0x0B,
			0x00,0x5D,0xDA,0x47,0x0A,0xBE,0x64,0x14,0xDE,0x8E,	/* b */
			0xC1,0x33,0xAE,0x28,0xE9,0xBB,0xD7,0xFC,0xEC,0x0A,
			0xE0,0xFF,0xF2,
			0x00,0x8D,0x16,0xC2,0x86,0x67,0x98,0xB6,0x00,0xF9,	/* x */
			0xF0,0x8B,0xB4,0xA8,0xE8,0x60,0xF3,0x29,0x8C,0xE0,
			0x4A,0x57,0x98,
			0x00,0x6F,0xA4,0x53,0x9C,0x2D,0xAD,0xDD,0xD6,0xBA,	/* y */
			0xB5,0x16,0x7D,0x61,0xB4,0x36,0xE1,0xD9,0x2B,0xB1,
			0x6A,0x56,0x2C,
			0x00,0x00,0x01,0x00,0x92,0x53,0x73,0x97,0xEC,0xA4,	/* order */
			0xF6,0x14,0x57,0x99,0xD6,0x2B,0x0A,0x19,0xCE,0x06,
			0xFE,0x26,0xAD }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+24*6]; }
	_EC_X9_62_CHAR2_191V1 = {
		{ NID_X9_62_characteristic_two_field,20,24,2 },
		{ 0x4E,0x13,0xCA,0x54,0x27,0x44,0xD6,0x96,0xE6,0x76,	/* seed */
			0x87,0x56,0x15,0x17,0x55,0x2F,0x27,0x9A,0x8C,0x84,
			
			0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x02,0x01,
			0x28,0x66,0x53,0x7B,0x67,0x67,0x52,0x63,0x6A,0x68,	/* a */
			0xF5,0x65,0x54,0xE1,0x26,0x40,0x27,0x6B,0x64,0x9E,
			0xF7,0x52,0x62,0x67,
			0x2E,0x45,0xEF,0x57,0x1F,0x00,0x78,0x6F,0x67,0xB0,	/* b */
			0x08,0x1B,0x94,0x95,0xA3,0xD9,0x54,0x62,0xF5,0xDE,
			0x0A,0xA1,0x85,0xEC,
			0x36,0xB3,0xDA,0xF8,0xA2,0x32,0x06,0xF9,0xC4,0xF2,	/* x */
			0x99,0xD7,0xB2,0x1A,0x9C,0x36,0x91,0x37,0xF2,0xC8,
			0x4A,0xE1,0xAA,0x0D,
			0x76,0x5B,0xE7,0x34,0x33,0xB3,0xF9,0x5E,0x33,0x29,	/* y */
			0x32,0xE7,0x0E,0xA2,0x45,0xCA,0x24,0x18,0xEA,0x0E,
			0xF9,0x80,0x18,0xFB,
			0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x00,0x00,0x04,0xA2,0x0E,0x90,0xC3,0x90,0x67,0xC8,
			0x93,0xBB,0xB9,0xA5 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+24*6]; }
	_EC_X9_62_CHAR2_191V2 = {
		{ NID_X9_62_characteristic_two_field,20,24,4 },
		{ 0x08,0x71,0xEF,0x2F,0xEF,0x24,0xD6,0x96,0xE6,0x76,	/* seed */
			0x87,0x56,0x15,0x17,0x58,0xBE,0xE0,0xD9,0x5C,0x15,
			
			0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x02,0x01,
			0x40,0x10,0x28,0x77,0x4D,0x77,0x77,0xC7,0xB7,0x66,	/* a */
			0x6D,0x13,0x66,0xEA,0x43,0x20,0x71,0x27,0x4F,0x89,
			0xFF,0x01,0xE7,0x18,
			0x06,0x20,0x04,0x8D,0x28,0xBC,0xBD,0x03,0xB6,0x24,	/* b */
			0x9C,0x99,0x18,0x2B,0x7C,0x8C,0xD1,0x97,0x00,0xC3,
			0x62,0xC4,0x6A,0x01,
			0x38,0x09,0xB2,0xB7,0xCC,0x1B,0x28,0xCC,0x5A,0x87,	/* x */
			0x92,0x6A,0xAD,0x83,0xFD,0x28,0x78,0x9E,0x81,0xE2,
			0xC9,0xE3,0xBF,0x10,
			0x17,0x43,0x43,0x86,0x62,0x6D,0x14,0xF3,0xDB,0xF0,	/* y */
			0x17,0x60,0xD9,0x21,0x3A,0x3E,0x1C,0xF3,0x7A,0xEC,
			0x43,0x7D,0x66,0x8A,
			0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x00,0x00,0x50,0x50,0x8C,0xB8,0x9F,0x65,0x28,0x24,
			0xE0,0x6B,0x81,0x73 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+24*6]; }
	_EC_X9_62_CHAR2_191V3 = {
		{ NID_X9_62_characteristic_two_field,20,24,6 },
		{ 0xE0,0x53,0x51,0x2D,0xC6,0x84,0xD6,0x96,0xE6,0x76,	/* seed */
			0x87,0x56,0x15,0x17,0x50,0x67,0xAE,0x78,0x6D,0x1F,
			
			0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x02,0x01,
			0x6C,0x01,0x07,0x47,0x56,0x09,0x91,0x22,0x22,0x10,	/* a */
			0x56,0x91,0x1C,0x77,0xD7,0x7E,0x77,0xA7,0x77,0xE7,
			0xE7,0xE7,0x7F,0xCB,
			0x71,0xFE,0x1A,0xF9,0x26,0xCF,0x84,0x79,0x89,0xEF,	/* b */
			0xEF,0x8D,0xB4,0x59,0xF6,0x63,0x94,0xD9,0x0F,0x32,
			0xAD,0x3F,0x15,0xE8,
			0x37,0x5D,0x4C,0xE2,0x4F,0xDE,0x43,0x44,0x89,0xDE,	/* x */
			0x87,0x46,0xE7,0x17,0x86,0x01,0x50,0x09,0xE6,0x6E,
			0x38,0xA9,0x26,0xDD,
			0x54,0x5A,0x39,0x17,0x61,0x96,0x57,0x5D,0x98,0x59,	/* y */
			0x99,0x36,0x6E,0x6A,0xD3,0x4C,0xE0,0xA7,0x7C,0xD7,
			0x12,0x7B,0x06,0xBE,
			0x15,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,	/* order */
			0x55,0x55,0x61,0x0C,0x0B,0x19,0x68,0x12,0xBF,0xB6,
			0x28,0x8A,0x3E,0xA3 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+27*6]; }
	_EC_X9_62_CHAR2_208W1 = {
		{ NID_X9_62_characteristic_two_field,0,27,0xFE48 },
		{							/* no seed */
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x07,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0xC8,0x61,0x9E,0xD4,0x5A,0x62,0xE6,0x21,0x2E,	/* b */
			0x11,0x60,0x34,0x9E,0x2B,0xFA,0x84,0x44,0x39,0xFA,
			0xFC,0x2A,0x3F,0xD1,0x63,0x8F,0x9E,
			0x00,0x89,0xFD,0xFB,0xE4,0xAB,0xE1,0x93,0xDF,0x95,	/* x */
			0x59,0xEC,0xF0,0x7A,0xC0,0xCE,0x78,0x55,0x4E,0x27,
			0x84,0xEB,0x8C,0x1E,0xD1,0xA5,0x7A,
			0x00,0x0F,0x55,0xB5,0x1A,0x06,0xE7,0x8E,0x9A,0xC3,	/* y */
			0x8A,0x03,0x5F,0xF5,0x20,0xD8,0xB0,0x17,0x81,0xBE,
			0xB1,0xA6,0xBB,0x08,0x61,0x7D,0xE3,
			0x00,0x00,0x01,0x01,0xBA,0xF9,0x5C,0x97,0x23,0xC5,	/* order */
			0x7B,0x6C,0x21,0xDA,0x2E,0xFF,0x2D,0x5E,0xD5,0x88,
			0xBD,0xD5,0x71,0x7E,0x21,0x2F,0x9D }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+30*6]; }
	_EC_X9_62_CHAR2_239V1 = {
		{ NID_X9_62_characteristic_two_field,20,30,4 },
		{ 0xD3,0x4B,0x9A,0x4D,0x69,0x6E,0x67,0x68,0x75,0x61,	/* seed */
			0x51,0x75,0xCA,0x71,0xB9,0x20,0xBF,0xEF,0xB0,0x5D,
			
			0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x01,
			
			0x32,0x01,0x08,0x57,0x07,0x7C,0x54,0x31,0x12,0x3A,	/* a */
			0x46,0xB8,0x08,0x90,0x67,0x56,0xF5,0x43,0x42,0x3E,
			0x8D,0x27,0x87,0x75,0x78,0x12,0x57,0x78,0xAC,0x76,
			
			0x79,0x04,0x08,0xF2,0xEE,0xDA,0xF3,0x92,0xB0,0x12,	/* b */
			0xED,0xEF,0xB3,0x39,0x2F,0x30,0xF4,0x32,0x7C,0x0C,
			0xA3,0xF3,0x1F,0xC3,0x83,0xC4,0x22,0xAA,0x8C,0x16,
			
			0x57,0x92,0x70,0x98,0xFA,0x93,0x2E,0x7C,0x0A,0x96,	/* x */
			0xD3,0xFD,0x5B,0x70,0x6E,0xF7,0xE5,0xF5,0xC1,0x56,
			0xE1,0x6B,0x7E,0x7C,0x86,0x03,0x85,0x52,0xE9,0x1D,
			
			0x61,0xD8,0xEE,0x50,0x77,0xC3,0x3F,0xEC,0xF6,0xF1,	/* y */
			0xA1,0x6B,0x26,0x8D,0xE4,0x69,0xC3,0xC7,0x74,0x4E,
			0xA9,0xA9,0x71,0x64,0x9F,0xC7,0xA9,0x61,0x63,0x05,
			
			0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* order */
			0x00,0x00,0x00,0x00,0x00,0x0F,0x4D,0x42,0xFF,0xE1,
			0x49,0x2A,0x49,0x93,0xF1,0xCA,0xD6,0x66,0xE4,0x47 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+30*6]; }
	_EC_X9_62_CHAR2_239V2 = {
		{ NID_X9_62_characteristic_two_field,20,30,6 },
		{ 0x2A,0xA6,0x98,0x2F,0xDF,0xA4,0xD6,0x96,0xE6,0x76,	/* seed */
			0x87,0x56,0x15,0x17,0x5D,0x26,0x67,0x27,0x27,0x7D,
			
			0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x01,
			
			0x42,0x30,0x01,0x77,0x57,0xA7,0x67,0xFA,0xE4,0x23,	/* a */
			0x98,0x56,0x9B,0x74,0x63,0x25,0xD4,0x53,0x13,0xAF,
			0x07,0x66,0x26,0x64,0x79,0xB7,0x56,0x54,0xE6,0x5F,
			
			0x50,0x37,0xEA,0x65,0x41,0x96,0xCF,0xF0,0xCD,0x82,	/* b */
			0xB2,0xC1,0x4A,0x2F,0xCF,0x2E,0x3F,0xF8,0x77,0x52,
			0x85,0xB5,0x45,0x72,0x2F,0x03,0xEA,0xCD,0xB7,0x4B,
			
			0x28,0xF9,0xD0,0x4E,0x90,0x00,0x69,0xC8,0xDC,0x47,	/* x */
			0xA0,0x85,0x34,0xFE,0x76,0xD2,0xB9,0x00,0xB7,0xD7,
			0xEF,0x31,0xF5,0x70,0x9F,0x20,0x0C,0x4C,0xA2,0x05,
			
			0x56,0x67,0x33,0x4C,0x45,0xAF,0xF3,0xB5,0xA0,0x3B,	/* y */
			0xAD,0x9D,0xD7,0x5E,0x2C,0x71,0xA9,0x93,0x62,0x56,
			0x7D,0x54,0x53,0xF7,0xFA,0x6E,0x22,0x7E,0xC8,0x33,
			
			0x15,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,	/* order */
			0x55,0x55,0x55,0x55,0x55,0x3C,0x6F,0x28,0x85,0x25,
			0x9C,0x31,0xE3,0xFC,0xDF,0x15,0x46,0x24,0x52,0x2D }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+30*6]; }
	_EC_X9_62_CHAR2_239V3 = {
		{ NID_X9_62_characteristic_two_field,20,30,0xA },
		{ 0x9E,0x07,0x6F,0x4D,0x69,0x6E,0x67,0x68,0x75,0x61,	/* seed */
			0x51,0x75,0xE1,0x1E,0x9F,0xDD,0x77,0xF9,0x20,0x41,
			
			0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x01,
			
			0x01,0x23,0x87,0x74,0x66,0x6A,0x67,0x76,0x6D,0x66,	/* a */
			0x76,0xF7,0x78,0xE6,0x76,0xB6,0x69,0x99,0x17,0x66,
			0x66,0xE6,0x87,0x66,0x6D,0x87,0x66,0xC6,0x6A,0x9F,
			
			0x6A,0x94,0x19,0x77,0xBA,0x9F,0x6A,0x43,0x51,0x99,	/* b */
			0xAC,0xFC,0x51,0x06,0x7E,0xD5,0x87,0xF5,0x19,0xC5,
			0xEC,0xB5,0x41,0xB8,0xE4,0x41,0x11,0xDE,0x1D,0x40,
			
			0x70,0xF6,0xE9,0xD0,0x4D,0x28,0x9C,0x4E,0x89,0x91,	/* x */
			0x3C,0xE3,0x53,0x0B,0xFD,0xE9,0x03,0x97,0x7D,0x42,
			0xB1,0x46,0xD5,0x39,0xBF,0x1B,0xDE,0x4E,0x9C,0x92,
			
			0x2E,0x5A,0x0E,0xAF,0x6E,0x5E,0x13,0x05,0xB9,0x00,	/* y */
			0x4D,0xCE,0x5C,0x0E,0xD7,0xFE,0x59,0xA3,0x56,0x08,
			0xF3,0x38,0x37,0xC8,0x16,0xD8,0x0B,0x79,0xF4,0x61,
			
			0x0C,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,	/* order */
			0xCC,0xCC,0xCC,0xCC,0xCC,0xAC,0x49,0x12,0xD2,0xD9,
			0xDF,0x90,0x3E,0xF9,0x88,0x8B,0x8A,0x0E,0x4C,0xFF }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+35*6]; }
	_EC_X9_62_CHAR2_272W1 = {
		{ NID_X9_62_characteristic_two_field,0,35,0xFF06 },
		{							/* no seed */
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,
			0x00,0x00,0x00,0x00,0x0B,
			0x00,0x91,0xA0,0x91,0xF0,0x3B,0x5F,0xBA,0x4A,0xB2,	/* a */
			0xCC,0xF4,0x9C,0x4E,0xDD,0x22,0x0F,0xB0,0x28,0x71,
			0x2D,0x42,0xBE,0x75,0x2B,0x2C,0x40,0x09,0x4D,0xBA,
			0xCD,0xB5,0x86,0xFB,0x20,
			0x00,0x71,0x67,0xEF,0xC9,0x2B,0xB2,0xE3,0xCE,0x7C,	/* b */
			0x8A,0xAA,0xFF,0x34,0xE1,0x2A,0x9C,0x55,0x70,0x03,
			0xD7,0xC7,0x3A,0x6F,0xAF,0x00,0x3F,0x99,0xF6,0xCC,
			0x84,0x82,0xE5,0x40,0xF7,
			0x00,0x61,0x08,0xBA,0xBB,0x2C,0xEE,0xBC,0xF7,0x87,	/* x */
			0x05,0x8A,0x05,0x6C,0xBE,0x0C,0xFE,0x62,0x2D,0x77,
			0x23,0xA2,0x89,0xE0,0x8A,0x07,0xAE,0x13,0xEF,0x0D,
			0x10,0xD1,0x71,0xDD,0x8D,
			0x00,0x10,0xC7,0x69,0x57,0x16,0x85,0x1E,0xEF,0x6B,	/* y */
			0xA7,0xF6,0x87,0x2E,0x61,0x42,0xFB,0xD2,0x41,0xB8,
			0x30,0xFF,0x5E,0xFC,0xAC,0xEC,0xCA,0xB0,0x5E,0x02,
			0x00,0x5D,0xDE,0x9D,0x23,
			0x00,0x00,0x01,0x00,0xFA,0xF5,0x13,0x54,0xE0,0xE3,	/* order */
			0x9E,0x48,0x92,0xDF,0x6E,0x31,0x9C,0x72,0xC8,0x16,
			0x16,0x03,0xFA,0x45,0xAA,0x7B,0x99,0x8A,0x16,0x7B,
			0x8F,0x1E,0x62,0x95,0x21 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+39*6]; }
	_EC_X9_62_CHAR2_304W1 = {
		{ NID_X9_62_characteristic_two_field,0,39,0xFE2E },
		{							/* no seed */
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x07,
			0x00,0xFD,0x0D,0x69,0x31,0x49,0xA1,0x18,0xF6,0x51,	/* a */
			0xE6,0xDC,0xE6,0x80,0x20,0x85,0x37,0x7E,0x5F,0x88,
			0x2D,0x1B,0x51,0x0B,0x44,0x16,0x00,0x74,0xC1,0x28,
			0x80,0x78,0x36,0x5A,0x03,0x96,0xC8,0xE6,0x81,
			0x00,0xBD,0xDB,0x97,0xE5,0x55,0xA5,0x0A,0x90,0x8E,	/* b */
			0x43,0xB0,0x1C,0x79,0x8E,0xA5,0xDA,0xA6,0x78,0x8F,
			0x1E,0xA2,0x79,0x4E,0xFC,0xF5,0x71,0x66,0xB8,0xC1,
			0x40,0x39,0x60,0x1E,0x55,0x82,0x73,0x40,0xBE,
			0x00,0x19,0x7B,0x07,0x84,0x5E,0x9B,0xE2,0xD9,0x6A,	/* x */
			0xDB,0x0F,0x5F,0x3C,0x7F,0x2C,0xFF,0xBD,0x7A,0x3E,
			0xB8,0xB6,0xFE,0xC3,0x5C,0x7F,0xD6,0x7F,0x26,0xDD,
			0xF6,0x28,0x5A,0x64,0x4F,0x74,0x0A,0x26,0x14,
			0x00,0xE1,0x9F,0xBE,0xB7,0x6E,0x0D,0xA1,0x71,0x51,	/* y */
			0x7E,0xCF,0x40,0x1B,0x50,0x28,0x9B,0xF0,0x14,0x10,
			0x32,0x88,0x52,0x7A,0x9B,0x41,0x6A,0x10,0x5E,0x80,
			0x26,0x0B,0x54,0x9F,0xDC,0x1B,0x92,0xC0,0x3B,
			0x00,0x00,0x01,0x01,0xD5,0x56,0x57,0x2A,0xAB,0xAC,	/* order */
			0x80,0x01,0x01,0xD5,0x56,0x57,0x2A,0xAB,0xAC,0x80,
			0x01,0x02,0x2D,0x5C,0x91,0xDD,0x17,0x3F,0x8F,0xB5,
			0x61,0xDA,0x68,0x99,0x16,0x44,0x43,0x05,0x1D }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[20+45*6]; }
	_EC_X9_62_CHAR2_359V1 = {
		{ NID_X9_62_characteristic_two_field,20,45,0x4C },
		{ 0x2B,0x35,0x49,0x20,0xB7,0x24,0xD6,0x96,0xE6,0x76,	/* seed */
			0x87,0x56,0x15,0x17,0x58,0x5B,0xA1,0x33,0x2D,0xC6,
			
			0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x01,
			0x56,0x67,0x67,0x6A,0x65,0x4B,0x20,0x75,0x4F,0x35,	/* a */
			0x6E,0xA9,0x20,0x17,0xD9,0x46,0x56,0x7C,0x46,0x67,
			0x55,0x56,0xF1,0x95,0x56,0xA0,0x46,0x16,0xB5,0x67,
			0xD2,0x23,0xA5,0xE0,0x56,0x56,0xFB,0x54,0x90,0x16,
			0xA9,0x66,0x56,0xA5,0x57,
			0x24,0x72,0xE2,0xD0,0x19,0x7C,0x49,0x36,0x3F,0x1F,	/* b */
			0xE7,0xF5,0xB6,0xDB,0x07,0x5D,0x52,0xB6,0x94,0x7D,
			0x13,0x5D,0x8C,0xA4,0x45,0x80,0x5D,0x39,0xBC,0x34,
			0x56,0x26,0x08,0x96,0x87,0x74,0x2B,0x63,0x29,0xE7,
			0x06,0x80,0x23,0x19,0x88,
			0x3C,0x25,0x8E,0xF3,0x04,0x77,0x67,0xE7,0xED,0xE0,	/* x */
			0xF1,0xFD,0xAA,0x79,0xDA,0xEE,0x38,0x41,0x36,0x6A,
			0x13,0x2E,0x16,0x3A,0xCE,0xD4,0xED,0x24,0x01,0xDF,
			0x9C,0x6B,0xDC,0xDE,0x98,0xE8,0xE7,0x07,0xC0,0x7A,
			0x22,0x39,0xB1,0xB0,0x97,
			0x53,0xD7,0xE0,0x85,0x29,0x54,0x70,0x48,0x12,0x1E,	/* y */
			0x9C,0x95,0xF3,0x79,0x1D,0xD8,0x04,0x96,0x39,0x48,
			0xF3,0x4F,0xAE,0x7B,0xF4,0x4E,0xA8,0x23,0x65,0xDC,
			0x78,0x68,0xFE,0x57,0xE4,0xAE,0x2D,0xE2,0x11,0x30,
			0x5A,0x40,0x71,0x04,0xBD,
			0x01,0xAF,0x28,0x6B,0xCA,0x1A,0xF2,0x86,0xBC,0xA1,	/* order */
			0xAF,0x28,0x6B,0xCA,0x1A,0xF2,0x86,0xBC,0xA1,0xAF,
			0x28,0x6B,0xC9,0xFB,0x8F,0x6B,0x85,0xC5,0x56,0x89,
			0x2C,0x20,0xA7,0xEB,0x96,0x4F,0xE7,0x71,0x9E,0x74,
			0xF4,0x90,0x75,0x8D,0x3B }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+47*6]; }
	_EC_X9_62_CHAR2_368W1 = {
		{ NID_X9_62_characteristic_two_field,0,47,0xFF70 },
		{							/* no seed */
			0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x07,
			0x00,0xE0,0xD2,0xEE,0x25,0x09,0x52,0x06,0xF5,0xE2,	/* a */
			0xA4,0xF9,0xED,0x22,0x9F,0x1F,0x25,0x6E,0x79,0xA0,
			0xE2,0xB4,0x55,0x97,0x0D,0x8D,0x0D,0x86,0x5B,0xD9,
			0x47,0x78,0xC5,0x76,0xD6,0x2F,0x0A,0xB7,0x51,0x9C,
			0xCD,0x2A,0x1A,0x90,0x6A,0xE3,0x0D,
			0x00,0xFC,0x12,0x17,0xD4,0x32,0x0A,0x90,0x45,0x2C,	/* b */
			0x76,0x0A,0x58,0xED,0xCD,0x30,0xC8,0xDD,0x06,0x9B,
			0x3C,0x34,0x45,0x38,0x37,0xA3,0x4E,0xD5,0x0C,0xB5,
			0x49,0x17,0xE1,0xC2,0x11,0x2D,0x84,0xD1,0x64,0xF4,
			0x44,0xF8,0xF7,0x47,0x86,0x04,0x6A,
			0x00,0x10,0x85,0xE2,0x75,0x53,0x81,0xDC,0xCC,0xE3,	/* x */
			0xC1,0x55,0x7A,0xFA,0x10,0xC2,0xF0,0xC0,0xC2,0x82,
			0x56,0x46,0xC5,0xB3,0x4A,0x39,0x4C,0xBC,0xFA,0x8B,
			0xC1,0x6B,0x22,0xE7,0xE7,0x89,0xE9,0x27,0xBE,0x21,
			0x6F,0x02,0xE1,0xFB,0x13,0x6A,0x5F,
			0x00,0x7B,0x3E,0xB1,0xBD,0xDC,0xBA,0x62,0xD5,0xD8,	/* y */
			0xB2,0x05,0x9B,0x52,0x57,0x97,0xFC,0x73,0x82,0x2C,
			0x59,0x05,0x9C,0x62,0x3A,0x45,0xFF,0x38,0x43,0xCE,
			0xE8,0xF8,0x7C,0xD1,0x85,0x5A,0xDA,0xA8,0x1E,0x2A,
			0x07,0x50,0xB8,0x0F,0xDA,0x23,0x10,
			0x00,0x00,0x01,0x00,0x90,0x51,0x2D,0xA9,0xAF,0x72,	/* order */
			0xB0,0x83,0x49,0xD9,0x8A,0x5D,0xD4,0xC7,0xB0,0x53,
			0x2E,0xCA,0x51,0xCE,0x03,0xE2,0xD1,0x0F,0x3B,0x7A,
			0xC5,0x79,0xBD,0x87,0xE9,0x09,0xAE,0x40,0xA6,0xF1,
			0x31,0xE9,0xCF,0xCE,0x5B,0xD9,0x67 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+54*6]; }
	_EC_X9_62_CHAR2_431R1 = {
		{ NID_X9_62_characteristic_two_field,0,54,0x2760 },
		{							/* no seed */
			0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x01,
			0x1A,0x82,0x7E,0xF0,0x0D,0xD6,0xFC,0x0E,0x23,0x4C,	/* a */
			0xAF,0x04,0x6C,0x6A,0x5D,0x8A,0x85,0x39,0x5B,0x23,
			0x6C,0xC4,0xAD,0x2C,0xF3,0x2A,0x0C,0xAD,0xBD,0xC9,
			0xDD,0xF6,0x20,0xB0,0xEB,0x99,0x06,0xD0,0x95,0x7F,
			0x6C,0x6F,0xEA,0xCD,0x61,0x54,0x68,0xDF,0x10,0x4D,
			0xE2,0x96,0xCD,0x8F,
			0x10,0xD9,0xB4,0xA3,0xD9,0x04,0x7D,0x8B,0x15,0x43,	/* b */
			0x59,0xAB,0xFB,0x1B,0x7F,0x54,0x85,0xB0,0x4C,0xEB,
			0x86,0x82,0x37,0xDD,0xC9,0xDE,0xDA,0x98,0x2A,0x67,
			0x9A,0x5A,0x91,0x9B,0x62,0x6D,0x4E,0x50,0xA8,0xDD,
			0x73,0x1B,0x10,0x7A,0x99,0x62,0x38,0x1F,0xB5,0xD8,
			0x07,0xBF,0x26,0x18,
			0x12,0x0F,0xC0,0x5D,0x3C,0x67,0xA9,0x9D,0xE1,0x61,	/* x */
			0xD2,0xF4,0x09,0x26,0x22,0xFE,0xCA,0x70,0x1B,0xE4,
			0xF5,0x0F,0x47,0x58,0x71,0x4E,0x8A,0x87,0xBB,0xF2,
			0xA6,0x58,0xEF,0x8C,0x21,0xE7,0xC5,0xEF,0xE9,0x65,
			0x36,0x1F,0x6C,0x29,0x99,0xC0,0xC2,0x47,0xB0,0xDB,
			0xD7,0x0C,0xE6,0xB7,
			0x20,0xD0,0xAF,0x89,0x03,0xA9,0x6F,0x8D,0x5F,0xA2,	/* y */
			0xC2,0x55,0x74,0x5D,0x3C,0x45,0x1B,0x30,0x2C,0x93,
			0x46,0xD9,0xB7,0xE4,0x85,0xE7,0xBC,0xE4,0x1F,0x6B,
			0x59,0x1F,0x3E,0x8F,0x6A,0xDD,0xCB,0xB0,0xBC,0x4C,
			0x2F,0x94,0x7A,0x7D,0xE1,0xA8,0x9B,0x62,0x5D,0x6A,
			0x59,0x8B,0x37,0x60,
			0x00,0x03,0x40,0x34,0x03,0x40,0x34,0x03,0x40,0x34,	/* order */
			0x03,0x40,0x34,0x03,0x40,0x34,0x03,0x40,0x34,0x03,
			0x40,0x34,0x03,0x40,0x34,0x03,0x40,0x34,0x03,0x23,
			0xC3,0x13,0xFA,0xB5,0x05,0x89,0x70,0x3B,0x5E,0xC6,
			0x8D,0x35,0x87,0xFE,0xC6,0x0D,0x16,0x1C,0xC1,0x49,
			0xC1,0xAD,0x4A,0x91 }
	};
	
	static const struct { EC_CURVE_DATA h; unsigned char data[0+15*6]; }
	_EC_WTLS_1 = {
		{ NID_X9_62_characteristic_two_field,0,15,2 },
		{							/* no seed */
			0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x02,0x01,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x01,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x01,
			0x01,0x66,0x79,0x79,0xA4,0x0B,0xA4,0x97,0xE5,0xD5,	/* x */
			0xC2,0x70,0x78,0x06,0x17,
			0x00,0xF4,0x4B,0x4A,0xF1,0xEC,0xC2,0x63,0x0E,0x08,	/* y */
			0x78,0x5C,0xEB,0xCC,0x15,
			0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFD,0xBF,	/* order */
			0x91,0xAF,0x6D,0xEA,0x73 }
	};
	
	/* IPSec curves */
	/* NOTE: The of curves over a extension field of non prime degree
	 * is not recommended (Weil-descent).
	 * As the group order is not a prime this curve is not suitable
	 * for ECDSA.
	 */
	static const struct { EC_CURVE_DATA h; unsigned char data[0+20*6]; }
	_EC_IPSEC_155_ID3 = {
		{ NID_X9_62_characteristic_two_field,0,20,3 },
		{							/* no seed */
			0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
			
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x33,0x8f,
			
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* x */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7b,
			
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* y */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xc8,
			
			0x02,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,	/* order */
			0xC7,0xF3,0xC7,0x88,0x1B,0xD0,0x86,0x8F,0xA8,0x6C }
	};
	
	/* NOTE: The of curves over a extension field of non prime degree
	 * is not recommended (Weil-descent).
	 * As the group order is not a prime this curve is not suitable
	 * for ECDSA.
	 */
	static const struct { EC_CURVE_DATA h; unsigned char data[0+24*6]; }
	_EC_IPSEC_185_ID4 = {
		{ NID_X9_62_characteristic_two_field,0,24,2 },
		{							/* no seed */
			0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* p */
			0x00,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x01,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* a */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* b */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x1e,0xe9,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* x */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x18,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	/* y */
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x0d,
			0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
			0xFF,0xFF,0xED,0xF9,0x7C,0x44,0xDB,0x9F,0x24,0x20,
			0xBA,0xFC,0xA7,0x5E }
	};
	
#endif
	
	
	static const ec_list_element curve_list[] = {
		/* prime field curves */
		/* secg curves */
		{ NID_secp112r1, &_EC_SECG_PRIME_112R1.h, 0, "SECG/WTLS curve over a 112 bit prime field" },
		{ NID_secp112r2, &_EC_SECG_PRIME_112R2.h, 0, "SECG curve over a 112 bit prime field" },
		{ NID_secp128r1, &_EC_SECG_PRIME_128R1.h, 0, "SECG curve over a 128 bit prime field" },
		{ NID_secp128r2, &_EC_SECG_PRIME_128R2.h, 0, "SECG curve over a 128 bit prime field" },
		{ NID_secp160k1, &_EC_SECG_PRIME_160K1.h, 0, "SECG curve over a 160 bit prime field" },
		{ NID_secp160r1, &_EC_SECG_PRIME_160R1.h, 0, "SECG curve over a 160 bit prime field" },
		{ NID_secp160r2, &_EC_SECG_PRIME_160R2.h, 0, "SECG/WTLS curve over a 160 bit prime field" },
		/* SECG secp192r1 is the same as X9.62 prime192v1 and hence omitted */
		{ NID_secp192k1, &_EC_SECG_PRIME_192K1.h, 0, "SECG curve over a 192 bit prime field" },
		{ NID_secp224k1, &_EC_SECG_PRIME_224K1.h, 0, "SECG curve over a 224 bit prime field" },
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
		//{ NID_secp224r1, &_EC_NIST_PRIME_224.h, EC_GFp_nistp224_method, "NIST/SECG curve over a 224 bit prime field" },
#else
		{ NID_secp224r1, &_EC_NIST_PRIME_224.h, 0, "NIST/SECG curve over a 224 bit prime field" },
#endif
		{ NID_secp256k1, &_EC_SECG_PRIME_256K1.h, 0, "SECG curve over a 256 bit prime field" },
		/* SECG secp256r1 is the same as X9.62 prime256v1 and hence omitted */
		{ NID_secp384r1, &_EC_NIST_PRIME_384.h, 0, "NIST/SECG curve over a 384 bit prime field" },
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
		//{ NID_secp521r1, &_EC_NIST_PRIME_521.h, EC_GFp_nistp521_method, "NIST/SECG curve over a 521 bit prime field" },
#else
		{ NID_secp521r1, &_EC_NIST_PRIME_521.h, 0, "NIST/SECG curve over a 521 bit prime field" },
#endif
		/* X9.62 curves */
		{ NID_X9_62_prime192v1, &_EC_NIST_PRIME_192.h, 0, "NIST/X9.62/SECG curve over a 192 bit prime field" },
		{ NID_X9_62_prime192v2, &_EC_X9_62_PRIME_192V2.h, 0, "X9.62 curve over a 192 bit prime field" },
		{ NID_X9_62_prime192v3, &_EC_X9_62_PRIME_192V3.h, 0, "X9.62 curve over a 192 bit prime field" },
		{ NID_X9_62_prime239v1, &_EC_X9_62_PRIME_239V1.h, 0, "X9.62 curve over a 239 bit prime field" },
		{ NID_X9_62_prime239v2, &_EC_X9_62_PRIME_239V2.h, 0, "X9.62 curve over a 239 bit prime field" },
		{ NID_X9_62_prime239v3, &_EC_X9_62_PRIME_239V3.h, 0, "X9.62 curve over a 239 bit prime field" },
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
		//{ NID_X9_62_prime256v1, &_EC_X9_62_PRIME_256V1.h, EC_GFp_nistp256_method, "X9.62/SECG curve over a 256 bit prime field" },
#else
		{ NID_X9_62_prime256v1, &_EC_X9_62_PRIME_256V1.h, 0, "X9.62/SECG curve over a 256 bit prime field" },
#endif
#ifndef OPENSSL_NO_EC2M
		/* characteristic two field curves */
		/* NIST/SECG curves */
		{ NID_sect113r1, &_EC_SECG_CHAR2_113R1.h, 0, "SECG curve over a 113 bit binary field" },
		{ NID_sect113r2, &_EC_SECG_CHAR2_113R2.h, 0, "SECG curve over a 113 bit binary field" },
		{ NID_sect131r1, &_EC_SECG_CHAR2_131R1.h, 0, "SECG/WTLS curve over a 131 bit binary field" },
		{ NID_sect131r2, &_EC_SECG_CHAR2_131R2.h, 0, "SECG curve over a 131 bit binary field" },
		{ NID_sect163k1, &_EC_NIST_CHAR2_163K.h, 0, "NIST/SECG/WTLS curve over a 163 bit binary field" },
		{ NID_sect163r1, &_EC_SECG_CHAR2_163R1.h, 0, "SECG curve over a 163 bit binary field" },
		{ NID_sect163r2, &_EC_NIST_CHAR2_163B.h, 0, "NIST/SECG curve over a 163 bit binary field" },
		{ NID_sect193r1, &_EC_SECG_CHAR2_193R1.h, 0, "SECG curve over a 193 bit binary field" },
		{ NID_sect193r2, &_EC_SECG_CHAR2_193R2.h, 0, "SECG curve over a 193 bit binary field" },
		{ NID_sect233k1, &_EC_NIST_CHAR2_233K.h, 0, "NIST/SECG/WTLS curve over a 233 bit binary field" },
		{ NID_sect233r1, &_EC_NIST_CHAR2_233B.h, 0, "NIST/SECG/WTLS curve over a 233 bit binary field" },
		{ NID_sect239k1, &_EC_SECG_CHAR2_239K1.h, 0, "SECG curve over a 239 bit binary field" },
		{ NID_sect283k1, &_EC_NIST_CHAR2_283K.h, 0, "NIST/SECG curve over a 283 bit binary field" },
		{ NID_sect283r1, &_EC_NIST_CHAR2_283B.h, 0, "NIST/SECG curve over a 283 bit binary field" },
		{ NID_sect409k1, &_EC_NIST_CHAR2_409K.h, 0, "NIST/SECG curve over a 409 bit binary field" },
		{ NID_sect409r1, &_EC_NIST_CHAR2_409B.h, 0, "NIST/SECG curve over a 409 bit binary field" },
		{ NID_sect571k1, &_EC_NIST_CHAR2_571K.h, 0, "NIST/SECG curve over a 571 bit binary field" },
		{ NID_sect571r1, &_EC_NIST_CHAR2_571B.h, 0, "NIST/SECG curve over a 571 bit binary field" },
		/* X9.62 curves */
		{ NID_X9_62_c2pnb163v1, &_EC_X9_62_CHAR2_163V1.h, 0, "X9.62 curve over a 163 bit binary field" },
		{ NID_X9_62_c2pnb163v2, &_EC_X9_62_CHAR2_163V2.h, 0, "X9.62 curve over a 163 bit binary field" },
		{ NID_X9_62_c2pnb163v3, &_EC_X9_62_CHAR2_163V3.h, 0, "X9.62 curve over a 163 bit binary field" },
		{ NID_X9_62_c2pnb176v1, &_EC_X9_62_CHAR2_176V1.h, 0, "X9.62 curve over a 176 bit binary field" },
		{ NID_X9_62_c2tnb191v1, &_EC_X9_62_CHAR2_191V1.h, 0, "X9.62 curve over a 191 bit binary field" },
		{ NID_X9_62_c2tnb191v2, &_EC_X9_62_CHAR2_191V2.h, 0, "X9.62 curve over a 191 bit binary field" },
		{ NID_X9_62_c2tnb191v3, &_EC_X9_62_CHAR2_191V3.h, 0, "X9.62 curve over a 191 bit binary field" },
		{ NID_X9_62_c2pnb208w1, &_EC_X9_62_CHAR2_208W1.h, 0, "X9.62 curve over a 208 bit binary field" },
		{ NID_X9_62_c2tnb239v1, &_EC_X9_62_CHAR2_239V1.h, 0, "X9.62 curve over a 239 bit binary field" },
		{ NID_X9_62_c2tnb239v2, &_EC_X9_62_CHAR2_239V2.h, 0, "X9.62 curve over a 239 bit binary field" },
		{ NID_X9_62_c2tnb239v3, &_EC_X9_62_CHAR2_239V3.h, 0, "X9.62 curve over a 239 bit binary field" },
		{ NID_X9_62_c2pnb272w1, &_EC_X9_62_CHAR2_272W1.h, 0, "X9.62 curve over a 272 bit binary field" },
		{ NID_X9_62_c2pnb304w1, &_EC_X9_62_CHAR2_304W1.h, 0, "X9.62 curve over a 304 bit binary field" },
		{ NID_X9_62_c2tnb359v1, &_EC_X9_62_CHAR2_359V1.h, 0, "X9.62 curve over a 359 bit binary field" },
		{ NID_X9_62_c2pnb368w1, &_EC_X9_62_CHAR2_368W1.h, 0, "X9.62 curve over a 368 bit binary field" },
		{ NID_X9_62_c2tnb431r1, &_EC_X9_62_CHAR2_431R1.h, 0, "X9.62 curve over a 431 bit binary field" },
		/* the WAP/WTLS curves
		 * [unlike SECG, spec has its own OIDs for curves from X9.62] */
		{ NID_wap_wsg_idm_ecid_wtls1, &_EC_WTLS_1.h, 0, "WTLS curve over a 113 bit binary field" },
		{ NID_wap_wsg_idm_ecid_wtls3, &_EC_NIST_CHAR2_163K.h, 0, "NIST/SECG/WTLS curve over a 163 bit binary field" },
		{ NID_wap_wsg_idm_ecid_wtls4, &_EC_SECG_CHAR2_113R1.h, 0, "SECG curve over a 113 bit binary field" },
		{ NID_wap_wsg_idm_ecid_wtls5, &_EC_X9_62_CHAR2_163V1.h, 0, "X9.62 curve over a 163 bit binary field" },
#endif
		{ NID_wap_wsg_idm_ecid_wtls6, &_EC_SECG_PRIME_112R1.h, 0, "SECG/WTLS curve over a 112 bit prime field" },
		{ NID_wap_wsg_idm_ecid_wtls7, &_EC_SECG_PRIME_160R2.h, 0, "SECG/WTLS curve over a 160 bit prime field" },
		{ NID_wap_wsg_idm_ecid_wtls8, &_EC_WTLS_8.h, 0, "WTLS curve over a 112 bit prime field" },
		{ NID_wap_wsg_idm_ecid_wtls9, &_EC_WTLS_9.h, 0, "WTLS curve over a 160 bit prime field" },
#ifndef OPENSSL_NO_EC2M
		{ NID_wap_wsg_idm_ecid_wtls10, &_EC_NIST_CHAR2_233K.h, 0, "NIST/SECG/WTLS curve over a 233 bit binary field" },
		{ NID_wap_wsg_idm_ecid_wtls11, &_EC_NIST_CHAR2_233B.h, 0, "NIST/SECG/WTLS curve over a 233 bit binary field" },
#endif
		{ NID_wap_wsg_idm_ecid_wtls12, &_EC_WTLS_12.h, 0, "WTLS curvs over a 224 bit prime field" },
#ifndef OPENSSL_NO_EC2M
		/* IPSec curves */
		{ NID_ipsec3, &_EC_IPSEC_155_ID3.h, 0, "\n\tIPSec/IKE/Oakley curve #3 over a 155 bit binary field.\n"
			"\tNot suitable for ECDSA.\n\tQuestionable extension field!" },
		{ NID_ipsec4, &_EC_IPSEC_185_ID4.h, 0, "\n\tIPSec/IKE/Oakley curve #4 over a 185 bit binary field.\n"
			"\tNot suitable for ECDSA.\n\tQuestionable extension field!" },
#endif
	};
	
	static int ecdh_compute_key(void *out, size_t len, const EC_POINT *pub_key,
								EC_KEY *ecdh, 
								void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
	
	static ECDH_METHOD openssl_ecdh_meth = {
		"OpenSSL ECDH method",
		ecdh_compute_key,
#if 0
		NULL, /* init     */
		NULL, /* finish   */
#endif
		0,    /* flags    */
		NULL  /* app_data */
	};
	
	/* Table to convert tags to bit values, used for MSTRING type */
	static const unsigned long tag2bit[32] = {
		0,	0,	0,	B_ASN1_BIT_STRING,	/* tags  0 -  3 */
		B_ASN1_OCTET_STRING,	0,	0,		B_ASN1_UNKNOWN,/* tags  4- 7 */
		B_ASN1_UNKNOWN,	B_ASN1_UNKNOWN,	B_ASN1_UNKNOWN,	B_ASN1_UNKNOWN,/* tags  8-11 */
		B_ASN1_UTF8STRING,B_ASN1_UNKNOWN,B_ASN1_UNKNOWN,B_ASN1_UNKNOWN,/* tags 12-15 */
		B_ASN1_SEQUENCE,0,B_ASN1_NUMERICSTRING,B_ASN1_PRINTABLESTRING, /* tags 16-19 */
		B_ASN1_T61STRING,B_ASN1_VIDEOTEXSTRING,B_ASN1_IA5STRING,       /* tags 20-22 */
		B_ASN1_UTCTIME, B_ASN1_GENERALIZEDTIME,			       /* tags 23-24 */	
		B_ASN1_GRAPHICSTRING,B_ASN1_ISO64STRING,B_ASN1_GENERALSTRING,  /* tags 25-27 */
		B_ASN1_UNIVERSALSTRING,B_ASN1_UNKNOWN,B_ASN1_BMPSTRING,B_ASN1_UNKNOWN, /* tags 28-31 */
	};
	
	typedef int ASN1_aux_cb(int operation, ASN1_VALUE **in, const ASN1_ITEM *it,
							void *exarg);
	
	ASN1_aux_cb *asn1_cb;
	
	int ttag;
	
	/* This table must be kept in NID order */	
	static const ASN1_STRING_TABLE tbl_standard[] = {
		{NID_commonName,		1, ub_common_name, DIRSTRING_TYPE, 0},
		{NID_countryName,		2, 2, B_ASN1_PRINTABLESTRING, STABLE_NO_MASK},
		{NID_localityName,		1, ub_locality_name, DIRSTRING_TYPE, 0},
		{NID_stateOrProvinceName,	1, ub_state_name, DIRSTRING_TYPE, 0},
		{NID_organizationName,		1, ub_organization_name, DIRSTRING_TYPE, 0},
		{NID_organizationalUnitName,	1, ub_organization_unit_name, DIRSTRING_TYPE, 0},
		{NID_pkcs9_emailAddress,	1, ub_email_address, B_ASN1_IA5STRING, STABLE_NO_MASK},
		{NID_pkcs9_unstructuredName,	1, -1, PKCS9STRING_TYPE, 0},
		{NID_pkcs9_challengePassword,	1, -1, PKCS9STRING_TYPE, 0},
		{NID_pkcs9_unstructuredAddress,	1, -1, DIRSTRING_TYPE, 0},
		{NID_givenName,			1, ub_name, DIRSTRING_TYPE, 0},
		{NID_surname,			1, ub_name, DIRSTRING_TYPE, 0},
		{NID_initials,			1, ub_name, DIRSTRING_TYPE, 0},
		{NID_serialNumber,		1, ub_serial_number, B_ASN1_PRINTABLESTRING, STABLE_NO_MASK},
		{NID_friendlyName,		-1, -1, B_ASN1_BMPSTRING, STABLE_NO_MASK},
		{NID_name,			1, ub_name, DIRSTRING_TYPE, 0},
		{NID_dnQualifier,		-1, -1, B_ASN1_PRINTABLESTRING, STABLE_NO_MASK},
		{NID_domainComponent,		1, -1, B_ASN1_IA5STRING, STABLE_NO_MASK},
		{NID_ms_csp_name,		-1, -1, B_ASN1_BMPSTRING, STABLE_NO_MASK}
	};
	
	static STACK_OF(OPENSSL_STRING) *app_locks=NULL;
	
	/* obj_dat.h is generated from objects.h by obj_dat.pl */
#ifndef OPENSSL_NO_OBJECT
	static const unsigned int sn_objs[NUM_SN]={
		364,	/* "AD_DVCS" */
		419,	/* "AES-128-CBC" */
		916,	/* "AES-128-CBC-HMAC-SHA1" */
		421,	/* "AES-128-CFB" */
		650,	/* "AES-128-CFB1" */
		653,	/* "AES-128-CFB8" */
		904,	/* "AES-128-CTR" */
		418,	/* "AES-128-ECB" */
		420,	/* "AES-128-OFB" */
		913,	/* "AES-128-XTS" */
		423,	/* "AES-192-CBC" */
		917,	/* "AES-192-CBC-HMAC-SHA1" */
		425,	/* "AES-192-CFB" */
		651,	/* "AES-192-CFB1" */
		654,	/* "AES-192-CFB8" */
		905,	/* "AES-192-CTR" */
		422,	/* "AES-192-ECB" */
		424,	/* "AES-192-OFB" */
		427,	/* "AES-256-CBC" */
		918,	/* "AES-256-CBC-HMAC-SHA1" */
		429,	/* "AES-256-CFB" */
		652,	/* "AES-256-CFB1" */
		655,	/* "AES-256-CFB8" */
		906,	/* "AES-256-CTR" */
		426,	/* "AES-256-ECB" */
		428,	/* "AES-256-OFB" */
		914,	/* "AES-256-XTS" */
		91,	/* "BF-CBC" */
		93,	/* "BF-CFB" */
		92,	/* "BF-ECB" */
		94,	/* "BF-OFB" */
		14,	/* "C" */
		751,	/* "CAMELLIA-128-CBC" */
		757,	/* "CAMELLIA-128-CFB" */
		760,	/* "CAMELLIA-128-CFB1" */
		763,	/* "CAMELLIA-128-CFB8" */
		754,	/* "CAMELLIA-128-ECB" */
		766,	/* "CAMELLIA-128-OFB" */
		752,	/* "CAMELLIA-192-CBC" */
		758,	/* "CAMELLIA-192-CFB" */
		761,	/* "CAMELLIA-192-CFB1" */
		764,	/* "CAMELLIA-192-CFB8" */
		755,	/* "CAMELLIA-192-ECB" */
		767,	/* "CAMELLIA-192-OFB" */
		753,	/* "CAMELLIA-256-CBC" */
		759,	/* "CAMELLIA-256-CFB" */
		762,	/* "CAMELLIA-256-CFB1" */
		765,	/* "CAMELLIA-256-CFB8" */
		756,	/* "CAMELLIA-256-ECB" */
		768,	/* "CAMELLIA-256-OFB" */
		108,	/* "CAST5-CBC" */
		110,	/* "CAST5-CFB" */
		109,	/* "CAST5-ECB" */
		111,	/* "CAST5-OFB" */
		894,	/* "CMAC" */
		13,	/* "CN" */
		141,	/* "CRLReason" */
		417,	/* "CSPName" */
		367,	/* "CrlID" */
		391,	/* "DC" */
		31,	/* "DES-CBC" */
		643,	/* "DES-CDMF" */
		30,	/* "DES-CFB" */
		656,	/* "DES-CFB1" */
		657,	/* "DES-CFB8" */
		29,	/* "DES-ECB" */
		32,	/* "DES-EDE" */
		43,	/* "DES-EDE-CBC" */
		60,	/* "DES-EDE-CFB" */
		62,	/* "DES-EDE-OFB" */
		33,	/* "DES-EDE3" */
		44,	/* "DES-EDE3-CBC" */
		61,	/* "DES-EDE3-CFB" */
		658,	/* "DES-EDE3-CFB1" */
		659,	/* "DES-EDE3-CFB8" */
		63,	/* "DES-EDE3-OFB" */
		45,	/* "DES-OFB" */
		80,	/* "DESX-CBC" */
		380,	/* "DOD" */
		116,	/* "DSA" */
		66,	/* "DSA-SHA" */
		113,	/* "DSA-SHA1" */
		70,	/* "DSA-SHA1-old" */
		67,	/* "DSA-old" */
		297,	/* "DVCS" */
		99,	/* "GN" */
		855,	/* "HMAC" */
		780,	/* "HMAC-MD5" */
		781,	/* "HMAC-SHA1" */
		381,	/* "IANA" */
		34,	/* "IDEA-CBC" */
		35,	/* "IDEA-CFB" */
		36,	/* "IDEA-ECB" */
		46,	/* "IDEA-OFB" */
		181,	/* "ISO" */
		183,	/* "ISO-US" */
		645,	/* "ITU-T" */
		646,	/* "JOINT-ISO-ITU-T" */
		773,	/* "KISA" */
		15,	/* "L" */
		856,	/* "LocalKeySet" */
		3,	/* "MD2" */
		257,	/* "MD4" */
		4,	/* "MD5" */
		114,	/* "MD5-SHA1" */
		95,	/* "MDC2" */
		911,	/* "MGF1" */
		388,	/* "Mail" */
		393,	/* "NULL" */
		404,	/* "NULL" */
		57,	/* "Netscape" */
		366,	/* "Nonce" */
		17,	/* "O" */
		178,	/* "OCSP" */
		180,	/* "OCSPSigning" */
		379,	/* "ORG" */
		18,	/* "OU" */
		749,	/* "Oakley-EC2N-3" */
		750,	/* "Oakley-EC2N-4" */
		9,	/* "PBE-MD2-DES" */
		168,	/* "PBE-MD2-RC2-64" */
		10,	/* "PBE-MD5-DES" */
		169,	/* "PBE-MD5-RC2-64" */
		147,	/* "PBE-SHA1-2DES" */
		146,	/* "PBE-SHA1-3DES" */
		170,	/* "PBE-SHA1-DES" */
		148,	/* "PBE-SHA1-RC2-128" */
		149,	/* "PBE-SHA1-RC2-40" */
		68,	/* "PBE-SHA1-RC2-64" */
		144,	/* "PBE-SHA1-RC4-128" */
		145,	/* "PBE-SHA1-RC4-40" */
		161,	/* "PBES2" */
		69,	/* "PBKDF2" */
		162,	/* "PBMAC1" */
		127,	/* "PKIX" */
		98,	/* "RC2-40-CBC" */
		166,	/* "RC2-64-CBC" */
		37,	/* "RC2-CBC" */
		39,	/* "RC2-CFB" */
		38,	/* "RC2-ECB" */
		40,	/* "RC2-OFB" */
		5,	/* "RC4" */
		97,	/* "RC4-40" */
		915,	/* "RC4-HMAC-MD5" */
		120,	/* "RC5-CBC" */
		122,	/* "RC5-CFB" */
		121,	/* "RC5-ECB" */
		123,	/* "RC5-OFB" */
		117,	/* "RIPEMD160" */
		124,	/* "RLE" */
		19,	/* "RSA" */
		7,	/* "RSA-MD2" */
		396,	/* "RSA-MD4" */
		8,	/* "RSA-MD5" */
		96,	/* "RSA-MDC2" */
		104,	/* "RSA-NP-MD5" */
		119,	/* "RSA-RIPEMD160" */
		42,	/* "RSA-SHA" */
		65,	/* "RSA-SHA1" */
		115,	/* "RSA-SHA1-2" */
		671,	/* "RSA-SHA224" */
		668,	/* "RSA-SHA256" */
		669,	/* "RSA-SHA384" */
		670,	/* "RSA-SHA512" */
		919,	/* "RSAES-OAEP" */
		912,	/* "RSASSA-PSS" */
		777,	/* "SEED-CBC" */
		779,	/* "SEED-CFB" */
		776,	/* "SEED-ECB" */
		778,	/* "SEED-OFB" */
		41,	/* "SHA" */
		64,	/* "SHA1" */
		675,	/* "SHA224" */
		672,	/* "SHA256" */
		673,	/* "SHA384" */
		674,	/* "SHA512" */
		188,	/* "SMIME" */
		167,	/* "SMIME-CAPS" */
		100,	/* "SN" */
		16,	/* "ST" */
		143,	/* "SXNetID" */
		458,	/* "UID" */
		0,	/* "UNDEF" */
		11,	/* "X500" */
		378,	/* "X500algorithms" */
		12,	/* "X509" */
		184,	/* "X9-57" */
		185,	/* "X9cm" */
		125,	/* "ZLIB" */
		478,	/* "aRecord" */
		289,	/* "aaControls" */
		287,	/* "ac-auditEntity" */
		397,	/* "ac-proxying" */
		288,	/* "ac-targeting" */
		368,	/* "acceptableResponses" */
		446,	/* "account" */
		363,	/* "ad_timestamping" */
		376,	/* "algorithm" */
		405,	/* "ansi-X9-62" */
		910,	/* "anyExtendedKeyUsage" */
		746,	/* "anyPolicy" */
		370,	/* "archiveCutoff" */
		484,	/* "associatedDomain" */
		485,	/* "associatedName" */
		501,	/* "audio" */
		177,	/* "authorityInfoAccess" */
		90,	/* "authorityKeyIdentifier" */
		882,	/* "authorityRevocationList" */
		87,	/* "basicConstraints" */
		365,	/* "basicOCSPResponse" */
		285,	/* "biometricInfo" */
		494,	/* "buildingName" */
		860,	/* "businessCategory" */
		691,	/* "c2onb191v4" */
		692,	/* "c2onb191v5" */
		697,	/* "c2onb239v4" */
		698,	/* "c2onb239v5" */
		684,	/* "c2pnb163v1" */
		685,	/* "c2pnb163v2" */
		686,	/* "c2pnb163v3" */
		687,	/* "c2pnb176v1" */
		693,	/* "c2pnb208w1" */
		699,	/* "c2pnb272w1" */
		700,	/* "c2pnb304w1" */
		702,	/* "c2pnb368w1" */
		688,	/* "c2tnb191v1" */
		689,	/* "c2tnb191v2" */
		690,	/* "c2tnb191v3" */
		694,	/* "c2tnb239v1" */
		695,	/* "c2tnb239v2" */
		696,	/* "c2tnb239v3" */
		701,	/* "c2tnb359v1" */
		703,	/* "c2tnb431r1" */
		881,	/* "cACertificate" */
		483,	/* "cNAMERecord" */
		179,	/* "caIssuers" */
		785,	/* "caRepository" */
		443,	/* "caseIgnoreIA5StringSyntax" */
		152,	/* "certBag" */
		677,	/* "certicom-arc" */
		771,	/* "certificateIssuer" */
		89,	/* "certificatePolicies" */
		883,	/* "certificateRevocationList" */
		54,	/* "challengePassword" */
		407,	/* "characteristic-two-field" */
		395,	/* "clearance" */
		130,	/* "clientAuth" */
		131,	/* "codeSigning" */
		50,	/* "contentType" */
		53,	/* "countersignature" */
		153,	/* "crlBag" */
		103,	/* "crlDistributionPoints" */
		88,	/* "crlNumber" */
		884,	/* "crossCertificatePair" */
		806,	/* "cryptocom" */
		805,	/* "cryptopro" */
		500,	/* "dITRedirect" */
		451,	/* "dNSDomain" */
		495,	/* "dSAQuality" */
		434,	/* "data" */
		390,	/* "dcobject" */
		140,	/* "deltaCRL" */
		891,	/* "deltaRevocationList" */
		107,	/* "description" */
		871,	/* "destinationIndicator" */
		28,	/* "dhKeyAgreement" */
		382,	/* "directory" */
		887,	/* "distinguishedName" */
		892,	/* "dmdName" */
		174,	/* "dnQualifier" */
		447,	/* "document" */
		471,	/* "documentAuthor" */
		468,	/* "documentIdentifier" */
		472,	/* "documentLocation" */
		502,	/* "documentPublisher" */
		449,	/* "documentSeries" */
		469,	/* "documentTitle" */
		470,	/* "documentVersion" */
		392,	/* "domain" */
		452,	/* "domainRelatedObject" */
		802,	/* "dsa_with_SHA224" */
		803,	/* "dsa_with_SHA256" */
		791,	/* "ecdsa-with-Recommended" */
		416,	/* "ecdsa-with-SHA1" */
		793,	/* "ecdsa-with-SHA224" */
		794,	/* "ecdsa-with-SHA256" */
		795,	/* "ecdsa-with-SHA384" */
		796,	/* "ecdsa-with-SHA512" */
		792,	/* "ecdsa-with-Specified" */
		48,	/* "emailAddress" */
		132,	/* "emailProtection" */
		885,	/* "enhancedSearchGuide" */
		389,	/* "enterprises" */
		384,	/* "experimental" */
		172,	/* "extReq" */
		56,	/* "extendedCertificateAttributes" */
		126,	/* "extendedKeyUsage" */
		372,	/* "extendedStatus" */
		867,	/* "facsimileTelephoneNumber" */
		462,	/* "favouriteDrink" */
		857,	/* "freshestCRL" */
		453,	/* "friendlyCountry" */
		490,	/* "friendlyCountryName" */
		156,	/* "friendlyName" */
		509,	/* "generationQualifier" */
		815,	/* "gost-mac" */
		811,	/* "gost2001" */
		851,	/* "gost2001cc" */
		813,	/* "gost89" */
		814,	/* "gost89-cnt" */
		812,	/* "gost94" */
		850,	/* "gost94cc" */
		797,	/* "hmacWithMD5" */
		163,	/* "hmacWithSHA1" */
		798,	/* "hmacWithSHA224" */
		799,	/* "hmacWithSHA256" */
		800,	/* "hmacWithSHA384" */
		801,	/* "hmacWithSHA512" */
		432,	/* "holdInstructionCallIssuer" */
		430,	/* "holdInstructionCode" */
		431,	/* "holdInstructionNone" */
		433,	/* "holdInstructionReject" */
		486,	/* "homePostalAddress" */
		473,	/* "homeTelephoneNumber" */
		466,	/* "host" */
		889,	/* "houseIdentifier" */
		442,	/* "iA5StringSyntax" */
		783,	/* "id-DHBasedMac" */
		824,	/* "id-Gost28147-89-CryptoPro-A-ParamSet" */
		825,	/* "id-Gost28147-89-CryptoPro-B-ParamSet" */
		826,	/* "id-Gost28147-89-CryptoPro-C-ParamSet" */
		827,	/* "id-Gost28147-89-CryptoPro-D-ParamSet" */
		819,	/* "id-Gost28147-89-CryptoPro-KeyMeshing" */
		829,	/* "id-Gost28147-89-CryptoPro-Oscar-1-0-ParamSet" */
		828,	/* "id-Gost28147-89-CryptoPro-Oscar-1-1-ParamSet" */
		830,	/* "id-Gost28147-89-CryptoPro-RIC-1-ParamSet" */
		820,	/* "id-Gost28147-89-None-KeyMeshing" */
		823,	/* "id-Gost28147-89-TestParamSet" */
		849,	/* "id-Gost28147-89-cc" */
		840,	/* "id-GostR3410-2001-CryptoPro-A-ParamSet" */
		841,	/* "id-GostR3410-2001-CryptoPro-B-ParamSet" */
		842,	/* "id-GostR3410-2001-CryptoPro-C-ParamSet" */
		843,	/* "id-GostR3410-2001-CryptoPro-XchA-ParamSet" */
		844,	/* "id-GostR3410-2001-CryptoPro-XchB-ParamSet" */
		854,	/* "id-GostR3410-2001-ParamSet-cc" */
		839,	/* "id-GostR3410-2001-TestParamSet" */
		817,	/* "id-GostR3410-2001DH" */
		832,	/* "id-GostR3410-94-CryptoPro-A-ParamSet" */
		833,	/* "id-GostR3410-94-CryptoPro-B-ParamSet" */
		834,	/* "id-GostR3410-94-CryptoPro-C-ParamSet" */
		835,	/* "id-GostR3410-94-CryptoPro-D-ParamSet" */
		836,	/* "id-GostR3410-94-CryptoPro-XchA-ParamSet" */
		837,	/* "id-GostR3410-94-CryptoPro-XchB-ParamSet" */
		838,	/* "id-GostR3410-94-CryptoPro-XchC-ParamSet" */
		831,	/* "id-GostR3410-94-TestParamSet" */
		845,	/* "id-GostR3410-94-a" */
		846,	/* "id-GostR3410-94-aBis" */
		847,	/* "id-GostR3410-94-b" */
		848,	/* "id-GostR3410-94-bBis" */
		818,	/* "id-GostR3410-94DH" */
		822,	/* "id-GostR3411-94-CryptoProParamSet" */
		821,	/* "id-GostR3411-94-TestParamSet" */
		807,	/* "id-GostR3411-94-with-GostR3410-2001" */
		853,	/* "id-GostR3411-94-with-GostR3410-2001-cc" */
		808,	/* "id-GostR3411-94-with-GostR3410-94" */
		852,	/* "id-GostR3411-94-with-GostR3410-94-cc" */
		810,	/* "id-HMACGostR3411-94" */
		782,	/* "id-PasswordBasedMAC" */
		266,	/* "id-aca" */
		355,	/* "id-aca-accessIdentity" */
		354,	/* "id-aca-authenticationInfo" */
		356,	/* "id-aca-chargingIdentity" */
		399,	/* "id-aca-encAttrs" */
		357,	/* "id-aca-group" */
		358,	/* "id-aca-role" */
		176,	/* "id-ad" */
		896,	/* "id-aes128-CCM" */
		895,	/* "id-aes128-GCM" */
		788,	/* "id-aes128-wrap" */
		897,	/* "id-aes128-wrap-pad" */
		899,	/* "id-aes192-CCM" */
		898,	/* "id-aes192-GCM" */
		789,	/* "id-aes192-wrap" */
		900,	/* "id-aes192-wrap-pad" */
		902,	/* "id-aes256-CCM" */
		901,	/* "id-aes256-GCM" */
		790,	/* "id-aes256-wrap" */
		903,	/* "id-aes256-wrap-pad" */
		262,	/* "id-alg" */
		893,	/* "id-alg-PWRI-KEK" */
		323,	/* "id-alg-des40" */
		326,	/* "id-alg-dh-pop" */
		325,	/* "id-alg-dh-sig-hmac-sha1" */
		324,	/* "id-alg-noSignature" */
		907,	/* "id-camellia128-wrap" */
		908,	/* "id-camellia192-wrap" */
		909,	/* "id-camellia256-wrap" */
		268,	/* "id-cct" */
		361,	/* "id-cct-PKIData" */
		362,	/* "id-cct-PKIResponse" */
		360,	/* "id-cct-crs" */
		81,	/* "id-ce" */
		680,	/* "id-characteristic-two-basis" */
		263,	/* "id-cmc" */
		334,	/* "id-cmc-addExtensions" */
		346,	/* "id-cmc-confirmCertAcceptance" */
		330,	/* "id-cmc-dataReturn" */
		336,	/* "id-cmc-decryptedPOP" */
		335,	/* "id-cmc-encryptedPOP" */
		339,	/* "id-cmc-getCRL" */
		338,	/* "id-cmc-getCert" */
		328,	/* "id-cmc-identification" */
		329,	/* "id-cmc-identityProof" */
		337,	/* "id-cmc-lraPOPWitness" */
		344,	/* "id-cmc-popLinkRandom" */
		345,	/* "id-cmc-popLinkWitness" */
		343,	/* "id-cmc-queryPending" */
		333,	/* "id-cmc-recipientNonce" */
		341,	/* "id-cmc-regInfo" */
		342,	/* "id-cmc-responseInfo" */
		340,	/* "id-cmc-revokeRequest" */
		332,	/* "id-cmc-senderNonce" */
		327,	/* "id-cmc-statusInfo" */
		331,	/* "id-cmc-transactionId" */
		787,	/* "id-ct-asciiTextWithCRLF" */
		408,	/* "id-ecPublicKey" */
		508,	/* "id-hex-multipart-message" */
		507,	/* "id-hex-partial-message" */
		260,	/* "id-it" */
		302,	/* "id-it-caKeyUpdateInfo" */
		298,	/* "id-it-caProtEncCert" */
		311,	/* "id-it-confirmWaitTime" */
		303,	/* "id-it-currentCRL" */
		300,	/* "id-it-encKeyPairTypes" */
		310,	/* "id-it-implicitConfirm" */
		308,	/* "id-it-keyPairParamRep" */
		307,	/* "id-it-keyPairParamReq" */
		312,	/* "id-it-origPKIMessage" */
		301,	/* "id-it-preferredSymmAlg" */
		309,	/* "id-it-revPassphrase" */
		299,	/* "id-it-signKeyPairTypes" */
		305,	/* "id-it-subscriptionRequest" */
		306,	/* "id-it-subscriptionResponse" */
		784,	/* "id-it-suppLangTags" */
		304,	/* "id-it-unsupportedOIDs" */
		128,	/* "id-kp" */
		280,	/* "id-mod-attribute-cert" */
		274,	/* "id-mod-cmc" */
		277,	/* "id-mod-cmp" */
		284,	/* "id-mod-cmp2000" */
		273,	/* "id-mod-crmf" */
		283,	/* "id-mod-dvcs" */
		275,	/* "id-mod-kea-profile-88" */
		276,	/* "id-mod-kea-profile-93" */
		282,	/* "id-mod-ocsp" */
		278,	/* "id-mod-qualified-cert-88" */
		279,	/* "id-mod-qualified-cert-93" */
		281,	/* "id-mod-timestamp-protocol" */
		264,	/* "id-on" */
		858,	/* "id-on-permanentIdentifier" */
		347,	/* "id-on-personalData" */
		265,	/* "id-pda" */
		352,	/* "id-pda-countryOfCitizenship" */
		353,	/* "id-pda-countryOfResidence" */
		348,	/* "id-pda-dateOfBirth" */
		351,	/* "id-pda-gender" */
		349,	/* "id-pda-placeOfBirth" */
		175,	/* "id-pe" */
		261,	/* "id-pkip" */
		258,	/* "id-pkix-mod" */
		269,	/* "id-pkix1-explicit-88" */
		271,	/* "id-pkix1-explicit-93" */
		270,	/* "id-pkix1-implicit-88" */
		272,	/* "id-pkix1-implicit-93" */
		662,	/* "id-ppl" */
		664,	/* "id-ppl-anyLanguage" */
		667,	/* "id-ppl-independent" */
		665,	/* "id-ppl-inheritAll" */
		267,	/* "id-qcs" */
		359,	/* "id-qcs-pkixQCSyntax-v1" */
		259,	/* "id-qt" */
		164,	/* "id-qt-cps" */
		165,	/* "id-qt-unotice" */
		313,	/* "id-regCtrl" */
		316,	/* "id-regCtrl-authenticator" */
		319,	/* "id-regCtrl-oldCertID" */
		318,	/* "id-regCtrl-pkiArchiveOptions" */
		317,	/* "id-regCtrl-pkiPublicationInfo" */
		320,	/* "id-regCtrl-protocolEncrKey" */
		315,	/* "id-regCtrl-regToken" */
		314,	/* "id-regInfo" */
		322,	/* "id-regInfo-certReq" */
		321,	/* "id-regInfo-utf8Pairs" */
		512,	/* "id-set" */
		191,	/* "id-smime-aa" */
		215,	/* "id-smime-aa-contentHint" */
		218,	/* "id-smime-aa-contentIdentifier" */
		221,	/* "id-smime-aa-contentReference" */
		240,	/* "id-smime-aa-dvcs-dvc" */
		217,	/* "id-smime-aa-encapContentType" */
		222,	/* "id-smime-aa-encrypKeyPref" */
		220,	/* "id-smime-aa-equivalentLabels" */
		232,	/* "id-smime-aa-ets-CertificateRefs" */
		233,	/* "id-smime-aa-ets-RevocationRefs" */
		238,	/* "id-smime-aa-ets-archiveTimeStamp" */
		237,	/* "id-smime-aa-ets-certCRLTimestamp" */
		234,	/* "id-smime-aa-ets-certValues" */
		227,	/* "id-smime-aa-ets-commitmentType" */
		231,	/* "id-smime-aa-ets-contentTimestamp" */
		236,	/* "id-smime-aa-ets-escTimeStamp" */
		230,	/* "id-smime-aa-ets-otherSigCert" */
		235,	/* "id-smime-aa-ets-revocationValues" */
		226,	/* "id-smime-aa-ets-sigPolicyId" */
		229,	/* "id-smime-aa-ets-signerAttr" */
		228,	/* "id-smime-aa-ets-signerLocation" */
		219,	/* "id-smime-aa-macValue" */
		214,	/* "id-smime-aa-mlExpandHistory" */
		216,	/* "id-smime-aa-msgSigDigest" */
		212,	/* "id-smime-aa-receiptRequest" */
		213,	/* "id-smime-aa-securityLabel" */
		239,	/* "id-smime-aa-signatureType" */
		223,	/* "id-smime-aa-signingCertificate" */
		224,	/* "id-smime-aa-smimeEncryptCerts" */
		225,	/* "id-smime-aa-timeStampToken" */
		192,	/* "id-smime-alg" */
		243,	/* "id-smime-alg-3DESwrap" */
		246,	/* "id-smime-alg-CMS3DESwrap" */
		247,	/* "id-smime-alg-CMSRC2wrap" */
		245,	/* "id-smime-alg-ESDH" */
		241,	/* "id-smime-alg-ESDHwith3DES" */
		242,	/* "id-smime-alg-ESDHwithRC2" */
		244,	/* "id-smime-alg-RC2wrap" */
		193,	/* "id-smime-cd" */
		248,	/* "id-smime-cd-ldap" */
		190,	/* "id-smime-ct" */
		210,	/* "id-smime-ct-DVCSRequestData" */
		211,	/* "id-smime-ct-DVCSResponseData" */
		208,	/* "id-smime-ct-TDTInfo" */
		207,	/* "id-smime-ct-TSTInfo" */
		205,	/* "id-smime-ct-authData" */
		786,	/* "id-smime-ct-compressedData" */
		209,	/* "id-smime-ct-contentInfo" */
		206,	/* "id-smime-ct-publishCert" */
		204,	/* "id-smime-ct-receipt" */
		195,	/* "id-smime-cti" */
		255,	/* "id-smime-cti-ets-proofOfApproval" */
		256,	/* "id-smime-cti-ets-proofOfCreation" */
		253,	/* "id-smime-cti-ets-proofOfDelivery" */
		251,	/* "id-smime-cti-ets-proofOfOrigin" */
		252,	/* "id-smime-cti-ets-proofOfReceipt" */
		254,	/* "id-smime-cti-ets-proofOfSender" */
		189,	/* "id-smime-mod" */
		196,	/* "id-smime-mod-cms" */
		197,	/* "id-smime-mod-ess" */
		202,	/* "id-smime-mod-ets-eSigPolicy-88" */
		203,	/* "id-smime-mod-ets-eSigPolicy-97" */
		200,	/* "id-smime-mod-ets-eSignature-88" */
		201,	/* "id-smime-mod-ets-eSignature-97" */
		199,	/* "id-smime-mod-msg-v3" */
		198,	/* "id-smime-mod-oid" */
		194,	/* "id-smime-spq" */
		250,	/* "id-smime-spq-ets-sqt-unotice" */
		249,	/* "id-smime-spq-ets-sqt-uri" */
		676,	/* "identified-organization" */
		461,	/* "info" */
		748,	/* "inhibitAnyPolicy" */
		101,	/* "initials" */
		647,	/* "international-organizations" */
		869,	/* "internationaliSDNNumber" */
		142,	/* "invalidityDate" */
		294,	/* "ipsecEndSystem" */
		295,	/* "ipsecTunnel" */
		296,	/* "ipsecUser" */
		86,	/* "issuerAltName" */
		770,	/* "issuingDistributionPoint" */
		492,	/* "janetMailbox" */
		150,	/* "keyBag" */
		83,	/* "keyUsage" */
		477,	/* "lastModifiedBy" */
		476,	/* "lastModifiedTime" */
		157,	/* "localKeyID" */
		480,	/* "mXRecord" */
		460,	/* "mail" */
		493,	/* "mailPreferenceOption" */
		467,	/* "manager" */
		809,	/* "md_gost94" */
		875,	/* "member" */
		182,	/* "member-body" */
		51,	/* "messageDigest" */
		383,	/* "mgmt" */
		504,	/* "mime-mhs" */
		506,	/* "mime-mhs-bodies" */
		505,	/* "mime-mhs-headings" */
		488,	/* "mobileTelephoneNumber" */
		136,	/* "msCTLSign" */
		135,	/* "msCodeCom" */
		134,	/* "msCodeInd" */
		138,	/* "msEFS" */
		171,	/* "msExtReq" */
		137,	/* "msSGC" */
		648,	/* "msSmartcardLogin" */
		649,	/* "msUPN" */
		481,	/* "nSRecord" */
		173,	/* "name" */
		666,	/* "nameConstraints" */
		369,	/* "noCheck" */
		403,	/* "noRevAvail" */
		72,	/* "nsBaseUrl" */
		76,	/* "nsCaPolicyUrl" */
		74,	/* "nsCaRevocationUrl" */
		58,	/* "nsCertExt" */
		79,	/* "nsCertSequence" */
		71,	/* "nsCertType" */
		78,	/* "nsComment" */
		59,	/* "nsDataType" */
		75,	/* "nsRenewalUrl" */
		73,	/* "nsRevocationUrl" */
		139,	/* "nsSGC" */
		77,	/* "nsSslServerName" */
		681,	/* "onBasis" */
		491,	/* "organizationalStatus" */
		475,	/* "otherMailbox" */
		876,	/* "owner" */
		489,	/* "pagerTelephoneNumber" */
		374,	/* "path" */
		112,	/* "pbeWithMD5AndCast5CBC" */
		499,	/* "personalSignature" */
		487,	/* "personalTitle" */
		464,	/* "photo" */
		863,	/* "physicalDeliveryOfficeName" */
		437,	/* "pilot" */
		439,	/* "pilotAttributeSyntax" */
		438,	/* "pilotAttributeType" */
		479,	/* "pilotAttributeType27" */
		456,	/* "pilotDSA" */
		441,	/* "pilotGroups" */
		444,	/* "pilotObject" */
		440,	/* "pilotObjectClass" */
		455,	/* "pilotOrganization" */
		445,	/* "pilotPerson" */
		2,	/* "pkcs" */
		186,	/* "pkcs1" */
		27,	/* "pkcs3" */
		187,	/* "pkcs5" */
		20,	/* "pkcs7" */
		21,	/* "pkcs7-data" */
		25,	/* "pkcs7-digestData" */
		26,	/* "pkcs7-encryptedData" */
		23,	/* "pkcs7-envelopedData" */
		24,	/* "pkcs7-signedAndEnvelopedData" */
		22,	/* "pkcs7-signedData" */
		151,	/* "pkcs8ShroudedKeyBag" */
		47,	/* "pkcs9" */
		401,	/* "policyConstraints" */
		747,	/* "policyMappings" */
		862,	/* "postOfficeBox" */
		861,	/* "postalAddress" */
		661,	/* "postalCode" */
		683,	/* "ppBasis" */
		872,	/* "preferredDeliveryMethod" */
		873,	/* "presentationAddress" */
		816,	/* "prf-gostr3411-94" */
		406,	/* "prime-field" */
		409,	/* "prime192v1" */
		410,	/* "prime192v2" */
		411,	/* "prime192v3" */
		412,	/* "prime239v1" */
		413,	/* "prime239v2" */
		414,	/* "prime239v3" */
		415,	/* "prime256v1" */
		385,	/* "private" */
		84,	/* "privateKeyUsagePeriod" */
		886,	/* "protocolInformation" */
		663,	/* "proxyCertInfo" */
		510,	/* "pseudonym" */
		435,	/* "pss" */
		286,	/* "qcStatements" */
		457,	/* "qualityLabelledData" */
		450,	/* "rFC822localPart" */
		870,	/* "registeredAddress" */
		400,	/* "role" */
		877,	/* "roleOccupant" */
		448,	/* "room" */
		463,	/* "roomNumber" */
		6,	/* "rsaEncryption" */
		644,	/* "rsaOAEPEncryptionSET" */
		377,	/* "rsaSignature" */
		1,	/* "rsadsi" */
		482,	/* "sOARecord" */
		155,	/* "safeContentsBag" */
		291,	/* "sbgp-autonomousSysNum" */
		290,	/* "sbgp-ipAddrBlock" */
		292,	/* "sbgp-routerIdentifier" */
		159,	/* "sdsiCertificate" */
		859,	/* "searchGuide" */
		704,	/* "secp112r1" */
		705,	/* "secp112r2" */
		706,	/* "secp128r1" */
		707,	/* "secp128r2" */
		708,	/* "secp160k1" */
		709,	/* "secp160r1" */
		710,	/* "secp160r2" */
		711,	/* "secp192k1" */
		712,	/* "secp224k1" */
		713,	/* "secp224r1" */
		714,	/* "secp256k1" */
		715,	/* "secp384r1" */
		716,	/* "secp521r1" */
		154,	/* "secretBag" */
		474,	/* "secretary" */
		717,	/* "sect113r1" */
		718,	/* "sect113r2" */
		719,	/* "sect131r1" */
		720,	/* "sect131r2" */
		721,	/* "sect163k1" */
		722,	/* "sect163r1" */
		723,	/* "sect163r2" */
		724,	/* "sect193r1" */
		725,	/* "sect193r2" */
		726,	/* "sect233k1" */
		727,	/* "sect233r1" */
		728,	/* "sect239k1" */
		729,	/* "sect283k1" */
		730,	/* "sect283r1" */
		731,	/* "sect409k1" */
		732,	/* "sect409r1" */
		733,	/* "sect571k1" */
		734,	/* "sect571r1" */
		386,	/* "security" */
		878,	/* "seeAlso" */
		394,	/* "selected-attribute-types" */
		105,	/* "serialNumber" */
		129,	/* "serverAuth" */
		371,	/* "serviceLocator" */
		625,	/* "set-addPolicy" */
		515,	/* "set-attr" */
		518,	/* "set-brand" */
		638,	/* "set-brand-AmericanExpress" */
		637,	/* "set-brand-Diners" */
		636,	/* "set-brand-IATA-ATA" */
		639,	/* "set-brand-JCB" */
		641,	/* "set-brand-MasterCard" */
		642,	/* "set-brand-Novus" */
		640,	/* "set-brand-Visa" */
		517,	/* "set-certExt" */
		513,	/* "set-ctype" */
		514,	/* "set-msgExt" */
		516,	/* "set-policy" */
		607,	/* "set-policy-root" */
		624,	/* "set-rootKeyThumb" */
		620,	/* "setAttr-Cert" */
		631,	/* "setAttr-GenCryptgrm" */
		623,	/* "setAttr-IssCap" */
		628,	/* "setAttr-IssCap-CVM" */
		630,	/* "setAttr-IssCap-Sig" */
		629,	/* "setAttr-IssCap-T2" */
		621,	/* "setAttr-PGWYcap" */
		635,	/* "setAttr-SecDevSig" */
		632,	/* "setAttr-T2Enc" */
		633,	/* "setAttr-T2cleartxt" */
		634,	/* "setAttr-TokICCsig" */
		627,	/* "setAttr-Token-B0Prime" */
		626,	/* "setAttr-Token-EMV" */
		622,	/* "setAttr-TokenType" */
		619,	/* "setCext-IssuerCapabilities" */
		615,	/* "setCext-PGWYcapabilities" */
		616,	/* "setCext-TokenIdentifier" */
		618,	/* "setCext-TokenType" */
		617,	/* "setCext-Track2Data" */
		611,	/* "setCext-cCertRequired" */
		609,	/* "setCext-certType" */
		608,	/* "setCext-hashedRoot" */
		610,	/* "setCext-merchData" */
		613,	/* "setCext-setExt" */
		614,	/* "setCext-setQualf" */
		612,	/* "setCext-tunneling" */
		540,	/* "setct-AcqCardCodeMsg" */
		576,	/* "setct-AcqCardCodeMsgTBE" */
		570,	/* "setct-AuthReqTBE" */
		534,	/* "setct-AuthReqTBS" */
		527,	/* "setct-AuthResBaggage" */
		571,	/* "setct-AuthResTBE" */
		572,	/* "setct-AuthResTBEX" */
		535,	/* "setct-AuthResTBS" */
		536,	/* "setct-AuthResTBSX" */
		528,	/* "setct-AuthRevReqBaggage" */
		577,	/* "setct-AuthRevReqTBE" */
		541,	/* "setct-AuthRevReqTBS" */
		529,	/* "setct-AuthRevResBaggage" */
		542,	/* "setct-AuthRevResData" */
		578,	/* "setct-AuthRevResTBE" */
		579,	/* "setct-AuthRevResTBEB" */
		543,	/* "setct-AuthRevResTBS" */
		573,	/* "setct-AuthTokenTBE" */
		537,	/* "setct-AuthTokenTBS" */
		600,	/* "setct-BCIDistributionTBS" */
		558,	/* "setct-BatchAdminReqData" */
		592,	/* "setct-BatchAdminReqTBE" */
		559,	/* "setct-BatchAdminResData" */
		593,	/* "setct-BatchAdminResTBE" */
		599,	/* "setct-CRLNotificationResTBS" */
		598,	/* "setct-CRLNotificationTBS" */
		580,	/* "setct-CapReqTBE" */
		581,	/* "setct-CapReqTBEX" */
		544,	/* "setct-CapReqTBS" */
		545,	/* "setct-CapReqTBSX" */
		546,	/* "setct-CapResData" */
		582,	/* "setct-CapResTBE" */
		583,	/* "setct-CapRevReqTBE" */
		584,	/* "setct-CapRevReqTBEX" */
		547,	/* "setct-CapRevReqTBS" */
		548,	/* "setct-CapRevReqTBSX" */
		549,	/* "setct-CapRevResData" */
		585,	/* "setct-CapRevResTBE" */
		538,	/* "setct-CapTokenData" */
		530,	/* "setct-CapTokenSeq" */
		574,	/* "setct-CapTokenTBE" */
		575,	/* "setct-CapTokenTBEX" */
		539,	/* "setct-CapTokenTBS" */
		560,	/* "setct-CardCInitResTBS" */
		566,	/* "setct-CertInqReqTBS" */
		563,	/* "setct-CertReqData" */
		595,	/* "setct-CertReqTBE" */
		596,	/* "setct-CertReqTBEX" */
		564,	/* "setct-CertReqTBS" */
		565,	/* "setct-CertResData" */
		597,	/* "setct-CertResTBE" */
		586,	/* "setct-CredReqTBE" */
		587,	/* "setct-CredReqTBEX" */
		550,	/* "setct-CredReqTBS" */
		551,	/* "setct-CredReqTBSX" */
		552,	/* "setct-CredResData" */
		588,	/* "setct-CredResTBE" */
		589,	/* "setct-CredRevReqTBE" */
		590,	/* "setct-CredRevReqTBEX" */
		553,	/* "setct-CredRevReqTBS" */
		554,	/* "setct-CredRevReqTBSX" */
		555,	/* "setct-CredRevResData" */
		591,	/* "setct-CredRevResTBE" */
		567,	/* "setct-ErrorTBS" */
		526,	/* "setct-HODInput" */
		561,	/* "setct-MeAqCInitResTBS" */
		522,	/* "setct-OIData" */
		519,	/* "setct-PANData" */
		521,	/* "setct-PANOnly" */
		520,	/* "setct-PANToken" */
		556,	/* "setct-PCertReqData" */
		557,	/* "setct-PCertResTBS" */
		523,	/* "setct-PI" */
		532,	/* "setct-PI-TBS" */
		524,	/* "setct-PIData" */
		525,	/* "setct-PIDataUnsigned" */
		568,	/* "setct-PIDualSignedTBE" */
		569,	/* "setct-PIUnsignedTBE" */
		531,	/* "setct-PInitResData" */
		533,	/* "setct-PResData" */
		594,	/* "setct-RegFormReqTBE" */
		562,	/* "setct-RegFormResTBS" */
		606,	/* "setext-cv" */
		601,	/* "setext-genCrypt" */
		602,	/* "setext-miAuth" */
		604,	/* "setext-pinAny" */
		603,	/* "setext-pinSecure" */
		605,	/* "setext-track2" */
		52,	/* "signingTime" */
		454,	/* "simpleSecurityObject" */
		496,	/* "singleLevelQuality" */
		387,	/* "snmpv2" */
		660,	/* "street" */
		85,	/* "subjectAltName" */
		769,	/* "subjectDirectoryAttributes" */
		398,	/* "subjectInfoAccess" */
		82,	/* "subjectKeyIdentifier" */
		498,	/* "subtreeMaximumQuality" */
		497,	/* "subtreeMinimumQuality" */
		890,	/* "supportedAlgorithms" */
		874,	/* "supportedApplicationContext" */
		402,	/* "targetInformation" */
		864,	/* "telephoneNumber" */
		866,	/* "teletexTerminalIdentifier" */
		865,	/* "telexNumber" */
		459,	/* "textEncodedORAddress" */
		293,	/* "textNotice" */
		133,	/* "timeStamping" */
		106,	/* "title" */
		682,	/* "tpBasis" */
		375,	/* "trustRoot" */
		436,	/* "ucl" */
		888,	/* "uniqueMember" */
		55,	/* "unstructuredAddress" */
		49,	/* "unstructuredName" */
		880,	/* "userCertificate" */
		465,	/* "userClass" */
		879,	/* "userPassword" */
		373,	/* "valid" */
		678,	/* "wap" */
		679,	/* "wap-wsg" */
		735,	/* "wap-wsg-idm-ecid-wtls1" */
		743,	/* "wap-wsg-idm-ecid-wtls10" */
		744,	/* "wap-wsg-idm-ecid-wtls11" */
		745,	/* "wap-wsg-idm-ecid-wtls12" */
		736,	/* "wap-wsg-idm-ecid-wtls3" */
		737,	/* "wap-wsg-idm-ecid-wtls4" */
		738,	/* "wap-wsg-idm-ecid-wtls5" */
		739,	/* "wap-wsg-idm-ecid-wtls6" */
		740,	/* "wap-wsg-idm-ecid-wtls7" */
		741,	/* "wap-wsg-idm-ecid-wtls8" */
		742,	/* "wap-wsg-idm-ecid-wtls9" */
		804,	/* "whirlpool" */
		868,	/* "x121Address" */
		503,	/* "x500UniqueIdentifier" */
		158,	/* "x509Certificate" */
		160,	/* "x509Crl" */
	};
	
	static const unsigned int ln_objs[NUM_LN]={
		363,	/* "AD Time Stamping" */
		405,	/* "ANSI X9.62" */
		368,	/* "Acceptable OCSP Responses" */
		910,	/* "Any Extended Key Usage" */
		664,	/* "Any language" */
		177,	/* "Authority Information Access" */
		365,	/* "Basic OCSP Response" */
		285,	/* "Biometric Info" */
		179,	/* "CA Issuers" */
		785,	/* "CA Repository" */
		131,	/* "Code Signing" */
		783,	/* "Diffie-Hellman based MAC" */
		382,	/* "Directory" */
		392,	/* "Domain" */
		132,	/* "E-mail Protection" */
		389,	/* "Enterprises" */
		384,	/* "Experimental" */
		372,	/* "Extended OCSP Status" */
		172,	/* "Extension Request" */
		813,	/* "GOST 28147-89" */
		849,	/* "GOST 28147-89 Cryptocom ParamSet" */
		815,	/* "GOST 28147-89 MAC" */
		851,	/* "GOST 34.10-2001 Cryptocom" */
		850,	/* "GOST 34.10-94 Cryptocom" */
		811,	/* "GOST R 34.10-2001" */
		817,	/* "GOST R 34.10-2001 DH" */
		812,	/* "GOST R 34.10-94" */
		818,	/* "GOST R 34.10-94 DH" */
		809,	/* "GOST R 34.11-94" */
		816,	/* "GOST R 34.11-94 PRF" */
		807,	/* "GOST R 34.11-94 with GOST R 34.10-2001" */
		853,	/* "GOST R 34.11-94 with GOST R 34.10-2001 Cryptocom" */
		808,	/* "GOST R 34.11-94 with GOST R 34.10-94" */
		852,	/* "GOST R 34.11-94 with GOST R 34.10-94 Cryptocom" */
		854,	/* "GOST R 3410-2001 Parameter Set Cryptocom" */
		810,	/* "HMAC GOST 34.11-94" */
		432,	/* "Hold Instruction Call Issuer" */
		430,	/* "Hold Instruction Code" */
		431,	/* "Hold Instruction None" */
		433,	/* "Hold Instruction Reject" */
		634,	/* "ICC or token signature" */
		294,	/* "IPSec End System" */
		295,	/* "IPSec Tunnel" */
		296,	/* "IPSec User" */
		182,	/* "ISO Member Body" */
		183,	/* "ISO US Member Body" */
		667,	/* "Independent" */
		665,	/* "Inherit all" */
		647,	/* "International Organizations" */
		142,	/* "Invalidity Date" */
		504,	/* "MIME MHS" */
		388,	/* "Mail" */
		383,	/* "Management" */
		417,	/* "Microsoft CSP Name" */
		135,	/* "Microsoft Commercial Code Signing" */
		138,	/* "Microsoft Encrypted File System" */
		171,	/* "Microsoft Extension Request" */
		134,	/* "Microsoft Individual Code Signing" */
		856,	/* "Microsoft Local Key set" */
		137,	/* "Microsoft Server Gated Crypto" */
		648,	/* "Microsoft Smartcardlogin" */
		136,	/* "Microsoft Trust List Signing" */
		649,	/* "Microsoft Universal Principal Name" */
		393,	/* "NULL" */
		404,	/* "NULL" */
		72,	/* "Netscape Base Url" */
		76,	/* "Netscape CA Policy Url" */
		74,	/* "Netscape CA Revocation Url" */
		71,	/* "Netscape Cert Type" */
		58,	/* "Netscape Certificate Extension" */
		79,	/* "Netscape Certificate Sequence" */
		78,	/* "Netscape Comment" */
		57,	/* "Netscape Communications Corp." */
		59,	/* "Netscape Data Type" */
		75,	/* "Netscape Renewal Url" */
		73,	/* "Netscape Revocation Url" */
		77,	/* "Netscape SSL Server Name" */
		139,	/* "Netscape Server Gated Crypto" */
		178,	/* "OCSP" */
		370,	/* "OCSP Archive Cutoff" */
		367,	/* "OCSP CRL ID" */
		369,	/* "OCSP No Check" */
		366,	/* "OCSP Nonce" */
		371,	/* "OCSP Service Locator" */
		180,	/* "OCSP Signing" */
		161,	/* "PBES2" */
		69,	/* "PBKDF2" */
		162,	/* "PBMAC1" */
		127,	/* "PKIX" */
		858,	/* "Permanent Identifier" */
		164,	/* "Policy Qualifier CPS" */
		165,	/* "Policy Qualifier User Notice" */
		385,	/* "Private" */
		663,	/* "Proxy Certificate Information" */
		1,	/* "RSA Data Security, Inc." */
		2,	/* "RSA Data Security, Inc. PKCS" */
		188,	/* "S/MIME" */
		167,	/* "S/MIME Capabilities" */
		387,	/* "SNMPv2" */
		512,	/* "Secure Electronic Transactions" */
		386,	/* "Security" */
		394,	/* "Selected Attribute Types" */
		143,	/* "Strong Extranet ID" */
		398,	/* "Subject Information Access" */
		130,	/* "TLS Web Client Authentication" */
		129,	/* "TLS Web Server Authentication" */
		133,	/* "Time Stamping" */
		375,	/* "Trust Root" */
		12,	/* "X509" */
		402,	/* "X509v3 AC Targeting" */
		746,	/* "X509v3 Any Policy" */
		90,	/* "X509v3 Authority Key Identifier" */
		87,	/* "X509v3 Basic Constraints" */
		103,	/* "X509v3 CRL Distribution Points" */
		88,	/* "X509v3 CRL Number" */
		141,	/* "X509v3 CRL Reason Code" */
		771,	/* "X509v3 Certificate Issuer" */
		89,	/* "X509v3 Certificate Policies" */
		140,	/* "X509v3 Delta CRL Indicator" */
		126,	/* "X509v3 Extended Key Usage" */
		857,	/* "X509v3 Freshest CRL" */
		748,	/* "X509v3 Inhibit Any Policy" */
		86,	/* "X509v3 Issuer Alternative Name" */
		770,	/* "X509v3 Issuing Distrubution Point" */
		83,	/* "X509v3 Key Usage" */
		666,	/* "X509v3 Name Constraints" */
		403,	/* "X509v3 No Revocation Available" */
		401,	/* "X509v3 Policy Constraints" */
		747,	/* "X509v3 Policy Mappings" */
		84,	/* "X509v3 Private Key Usage Period" */
		85,	/* "X509v3 Subject Alternative Name" */
		769,	/* "X509v3 Subject Directory Attributes" */
		82,	/* "X509v3 Subject Key Identifier" */
		184,	/* "X9.57" */
		185,	/* "X9.57 CM ?" */
		478,	/* "aRecord" */
		289,	/* "aaControls" */
		287,	/* "ac-auditEntity" */
		397,	/* "ac-proxying" */
		288,	/* "ac-targeting" */
		446,	/* "account" */
		364,	/* "ad dvcs" */
		606,	/* "additional verification" */
		419,	/* "aes-128-cbc" */
		916,	/* "aes-128-cbc-hmac-sha1" */
		896,	/* "aes-128-ccm" */
		421,	/* "aes-128-cfb" */
		650,	/* "aes-128-cfb1" */
		653,	/* "aes-128-cfb8" */
		904,	/* "aes-128-ctr" */
		418,	/* "aes-128-ecb" */
		895,	/* "aes-128-gcm" */
		420,	/* "aes-128-ofb" */
		913,	/* "aes-128-xts" */
		423,	/* "aes-192-cbc" */
		917,	/* "aes-192-cbc-hmac-sha1" */
		899,	/* "aes-192-ccm" */
		425,	/* "aes-192-cfb" */
		651,	/* "aes-192-cfb1" */
		654,	/* "aes-192-cfb8" */
		905,	/* "aes-192-ctr" */
		422,	/* "aes-192-ecb" */
		898,	/* "aes-192-gcm" */
		424,	/* "aes-192-ofb" */
		427,	/* "aes-256-cbc" */
		918,	/* "aes-256-cbc-hmac-sha1" */
		902,	/* "aes-256-ccm" */
		429,	/* "aes-256-cfb" */
		652,	/* "aes-256-cfb1" */
		655,	/* "aes-256-cfb8" */
		906,	/* "aes-256-ctr" */
		426,	/* "aes-256-ecb" */
		901,	/* "aes-256-gcm" */
		428,	/* "aes-256-ofb" */
		914,	/* "aes-256-xts" */
		376,	/* "algorithm" */
		484,	/* "associatedDomain" */
		485,	/* "associatedName" */
		501,	/* "audio" */
		882,	/* "authorityRevocationList" */
		91,	/* "bf-cbc" */
		93,	/* "bf-cfb" */
		92,	/* "bf-ecb" */
		94,	/* "bf-ofb" */
		494,	/* "buildingName" */
		860,	/* "businessCategory" */
		691,	/* "c2onb191v4" */
		692,	/* "c2onb191v5" */
		697,	/* "c2onb239v4" */
		698,	/* "c2onb239v5" */
		684,	/* "c2pnb163v1" */
		685,	/* "c2pnb163v2" */
		686,	/* "c2pnb163v3" */
		687,	/* "c2pnb176v1" */
		693,	/* "c2pnb208w1" */
		699,	/* "c2pnb272w1" */
		700,	/* "c2pnb304w1" */
		702,	/* "c2pnb368w1" */
		688,	/* "c2tnb191v1" */
		689,	/* "c2tnb191v2" */
		690,	/* "c2tnb191v3" */
		694,	/* "c2tnb239v1" */
		695,	/* "c2tnb239v2" */
		696,	/* "c2tnb239v3" */
		701,	/* "c2tnb359v1" */
		703,	/* "c2tnb431r1" */
		881,	/* "cACertificate" */
		483,	/* "cNAMERecord" */
		751,	/* "camellia-128-cbc" */
		757,	/* "camellia-128-cfb" */
		760,	/* "camellia-128-cfb1" */
		763,	/* "camellia-128-cfb8" */
		754,	/* "camellia-128-ecb" */
		766,	/* "camellia-128-ofb" */
		752,	/* "camellia-192-cbc" */
		758,	/* "camellia-192-cfb" */
		761,	/* "camellia-192-cfb1" */
		764,	/* "camellia-192-cfb8" */
		755,	/* "camellia-192-ecb" */
		767,	/* "camellia-192-ofb" */
		753,	/* "camellia-256-cbc" */
		759,	/* "camellia-256-cfb" */
		762,	/* "camellia-256-cfb1" */
		765,	/* "camellia-256-cfb8" */
		756,	/* "camellia-256-ecb" */
		768,	/* "camellia-256-ofb" */
		443,	/* "caseIgnoreIA5StringSyntax" */
		108,	/* "cast5-cbc" */
		110,	/* "cast5-cfb" */
		109,	/* "cast5-ecb" */
		111,	/* "cast5-ofb" */
		152,	/* "certBag" */
		677,	/* "certicom-arc" */
		517,	/* "certificate extensions" */
		883,	/* "certificateRevocationList" */
		54,	/* "challengePassword" */
		407,	/* "characteristic-two-field" */
		395,	/* "clearance" */
		633,	/* "cleartext track 2" */
		894,	/* "cmac" */
		13,	/* "commonName" */
		513,	/* "content types" */
		50,	/* "contentType" */
		53,	/* "countersignature" */
		14,	/* "countryName" */
		153,	/* "crlBag" */
		884,	/* "crossCertificatePair" */
		806,	/* "cryptocom" */
		805,	/* "cryptopro" */
		500,	/* "dITRedirect" */
		451,	/* "dNSDomain" */
		495,	/* "dSAQuality" */
		434,	/* "data" */
		390,	/* "dcObject" */
		891,	/* "deltaRevocationList" */
		31,	/* "des-cbc" */
		643,	/* "des-cdmf" */
		30,	/* "des-cfb" */
		656,	/* "des-cfb1" */
		657,	/* "des-cfb8" */
		29,	/* "des-ecb" */
		32,	/* "des-ede" */
		43,	/* "des-ede-cbc" */
		60,	/* "des-ede-cfb" */
		62,	/* "des-ede-ofb" */
		33,	/* "des-ede3" */
		44,	/* "des-ede3-cbc" */
		61,	/* "des-ede3-cfb" */
		658,	/* "des-ede3-cfb1" */
		659,	/* "des-ede3-cfb8" */
		63,	/* "des-ede3-ofb" */
		45,	/* "des-ofb" */
		107,	/* "description" */
		871,	/* "destinationIndicator" */
		80,	/* "desx-cbc" */
		28,	/* "dhKeyAgreement" */
		11,	/* "directory services (X.500)" */
		378,	/* "directory services - algorithms" */
		887,	/* "distinguishedName" */
		892,	/* "dmdName" */
		174,	/* "dnQualifier" */
		447,	/* "document" */
		471,	/* "documentAuthor" */
		468,	/* "documentIdentifier" */
		472,	/* "documentLocation" */
		502,	/* "documentPublisher" */
		449,	/* "documentSeries" */
		469,	/* "documentTitle" */
		470,	/* "documentVersion" */
		380,	/* "dod" */
		391,	/* "domainComponent" */
		452,	/* "domainRelatedObject" */
		116,	/* "dsaEncryption" */
		67,	/* "dsaEncryption-old" */
		66,	/* "dsaWithSHA" */
		113,	/* "dsaWithSHA1" */
		70,	/* "dsaWithSHA1-old" */
		802,	/* "dsa_with_SHA224" */
		803,	/* "dsa_with_SHA256" */
		297,	/* "dvcs" */
		791,	/* "ecdsa-with-Recommended" */
		416,	/* "ecdsa-with-SHA1" */
		793,	/* "ecdsa-with-SHA224" */
		794,	/* "ecdsa-with-SHA256" */
		795,	/* "ecdsa-with-SHA384" */
		796,	/* "ecdsa-with-SHA512" */
		792,	/* "ecdsa-with-Specified" */
		48,	/* "emailAddress" */
		632,	/* "encrypted track 2" */
		885,	/* "enhancedSearchGuide" */
		56,	/* "extendedCertificateAttributes" */
		867,	/* "facsimileTelephoneNumber" */
		462,	/* "favouriteDrink" */
		453,	/* "friendlyCountry" */
		490,	/* "friendlyCountryName" */
		156,	/* "friendlyName" */
		631,	/* "generate cryptogram" */
		509,	/* "generationQualifier" */
		601,	/* "generic cryptogram" */
		99,	/* "givenName" */
		814,	/* "gost89-cnt" */
		855,	/* "hmac" */
		780,	/* "hmac-md5" */
		781,	/* "hmac-sha1" */
		797,	/* "hmacWithMD5" */
		163,	/* "hmacWithSHA1" */
		798,	/* "hmacWithSHA224" */
		799,	/* "hmacWithSHA256" */
		800,	/* "hmacWithSHA384" */
		801,	/* "hmacWithSHA512" */
		486,	/* "homePostalAddress" */
		473,	/* "homeTelephoneNumber" */
		466,	/* "host" */
		889,	/* "houseIdentifier" */
		442,	/* "iA5StringSyntax" */
		381,	/* "iana" */
		824,	/* "id-Gost28147-89-CryptoPro-A-ParamSet" */
		825,	/* "id-Gost28147-89-CryptoPro-B-ParamSet" */
		826,	/* "id-Gost28147-89-CryptoPro-C-ParamSet" */
		827,	/* "id-Gost28147-89-CryptoPro-D-ParamSet" */
		819,	/* "id-Gost28147-89-CryptoPro-KeyMeshing" */
		829,	/* "id-Gost28147-89-CryptoPro-Oscar-1-0-ParamSet" */
		828,	/* "id-Gost28147-89-CryptoPro-Oscar-1-1-ParamSet" */
		830,	/* "id-Gost28147-89-CryptoPro-RIC-1-ParamSet" */
		820,	/* "id-Gost28147-89-None-KeyMeshing" */
		823,	/* "id-Gost28147-89-TestParamSet" */
		840,	/* "id-GostR3410-2001-CryptoPro-A-ParamSet" */
		841,	/* "id-GostR3410-2001-CryptoPro-B-ParamSet" */
		842,	/* "id-GostR3410-2001-CryptoPro-C-ParamSet" */
		843,	/* "id-GostR3410-2001-CryptoPro-XchA-ParamSet" */
		844,	/* "id-GostR3410-2001-CryptoPro-XchB-ParamSet" */
		839,	/* "id-GostR3410-2001-TestParamSet" */
		832,	/* "id-GostR3410-94-CryptoPro-A-ParamSet" */
		833,	/* "id-GostR3410-94-CryptoPro-B-ParamSet" */
		834,	/* "id-GostR3410-94-CryptoPro-C-ParamSet" */
		835,	/* "id-GostR3410-94-CryptoPro-D-ParamSet" */
		836,	/* "id-GostR3410-94-CryptoPro-XchA-ParamSet" */
		837,	/* "id-GostR3410-94-CryptoPro-XchB-ParamSet" */
		838,	/* "id-GostR3410-94-CryptoPro-XchC-ParamSet" */
		831,	/* "id-GostR3410-94-TestParamSet" */
		845,	/* "id-GostR3410-94-a" */
		846,	/* "id-GostR3410-94-aBis" */
		847,	/* "id-GostR3410-94-b" */
		848,	/* "id-GostR3410-94-bBis" */
		822,	/* "id-GostR3411-94-CryptoProParamSet" */
		821,	/* "id-GostR3411-94-TestParamSet" */
		266,	/* "id-aca" */
		355,	/* "id-aca-accessIdentity" */
		354,	/* "id-aca-authenticationInfo" */
		356,	/* "id-aca-chargingIdentity" */
		399,	/* "id-aca-encAttrs" */
		357,	/* "id-aca-group" */
		358,	/* "id-aca-role" */
		176,	/* "id-ad" */
		788,	/* "id-aes128-wrap" */
		897,	/* "id-aes128-wrap-pad" */
		789,	/* "id-aes192-wrap" */
		900,	/* "id-aes192-wrap-pad" */
		790,	/* "id-aes256-wrap" */
		903,	/* "id-aes256-wrap-pad" */
		262,	/* "id-alg" */
		893,	/* "id-alg-PWRI-KEK" */
		323,	/* "id-alg-des40" */
		326,	/* "id-alg-dh-pop" */
		325,	/* "id-alg-dh-sig-hmac-sha1" */
		324,	/* "id-alg-noSignature" */
		907,	/* "id-camellia128-wrap" */
		908,	/* "id-camellia192-wrap" */
		909,	/* "id-camellia256-wrap" */
		268,	/* "id-cct" */
		361,	/* "id-cct-PKIData" */
		362,	/* "id-cct-PKIResponse" */
		360,	/* "id-cct-crs" */
		81,	/* "id-ce" */
		680,	/* "id-characteristic-two-basis" */
		263,	/* "id-cmc" */
		334,	/* "id-cmc-addExtensions" */
		346,	/* "id-cmc-confirmCertAcceptance" */
		330,	/* "id-cmc-dataReturn" */
		336,	/* "id-cmc-decryptedPOP" */
		335,	/* "id-cmc-encryptedPOP" */
		339,	/* "id-cmc-getCRL" */
		338,	/* "id-cmc-getCert" */
		328,	/* "id-cmc-identification" */
		329,	/* "id-cmc-identityProof" */
		337,	/* "id-cmc-lraPOPWitness" */
		344,	/* "id-cmc-popLinkRandom" */
		345,	/* "id-cmc-popLinkWitness" */
		343,	/* "id-cmc-queryPending" */
		333,	/* "id-cmc-recipientNonce" */
		341,	/* "id-cmc-regInfo" */
		342,	/* "id-cmc-responseInfo" */
		340,	/* "id-cmc-revokeRequest" */
		332,	/* "id-cmc-senderNonce" */
		327,	/* "id-cmc-statusInfo" */
		331,	/* "id-cmc-transactionId" */
		787,	/* "id-ct-asciiTextWithCRLF" */
		408,	/* "id-ecPublicKey" */
		508,	/* "id-hex-multipart-message" */
		507,	/* "id-hex-partial-message" */
		260,	/* "id-it" */
		302,	/* "id-it-caKeyUpdateInfo" */
		298,	/* "id-it-caProtEncCert" */
		311,	/* "id-it-confirmWaitTime" */
		303,	/* "id-it-currentCRL" */
		300,	/* "id-it-encKeyPairTypes" */
		310,	/* "id-it-implicitConfirm" */
		308,	/* "id-it-keyPairParamRep" */
		307,	/* "id-it-keyPairParamReq" */
		312,	/* "id-it-origPKIMessage" */
		301,	/* "id-it-preferredSymmAlg" */
		309,	/* "id-it-revPassphrase" */
		299,	/* "id-it-signKeyPairTypes" */
		305,	/* "id-it-subscriptionRequest" */
		306,	/* "id-it-subscriptionResponse" */
		784,	/* "id-it-suppLangTags" */
		304,	/* "id-it-unsupportedOIDs" */
		128,	/* "id-kp" */
		280,	/* "id-mod-attribute-cert" */
		274,	/* "id-mod-cmc" */
		277,	/* "id-mod-cmp" */
		284,	/* "id-mod-cmp2000" */
		273,	/* "id-mod-crmf" */
		283,	/* "id-mod-dvcs" */
		275,	/* "id-mod-kea-profile-88" */
		276,	/* "id-mod-kea-profile-93" */
		282,	/* "id-mod-ocsp" */
		278,	/* "id-mod-qualified-cert-88" */
		279,	/* "id-mod-qualified-cert-93" */
		281,	/* "id-mod-timestamp-protocol" */
		264,	/* "id-on" */
		347,	/* "id-on-personalData" */
		265,	/* "id-pda" */
		352,	/* "id-pda-countryOfCitizenship" */
		353,	/* "id-pda-countryOfResidence" */
		348,	/* "id-pda-dateOfBirth" */
		351,	/* "id-pda-gender" */
		349,	/* "id-pda-placeOfBirth" */
		175,	/* "id-pe" */
		261,	/* "id-pkip" */
		258,	/* "id-pkix-mod" */
		269,	/* "id-pkix1-explicit-88" */
		271,	/* "id-pkix1-explicit-93" */
		270,	/* "id-pkix1-implicit-88" */
		272,	/* "id-pkix1-implicit-93" */
		662,	/* "id-ppl" */
		267,	/* "id-qcs" */
		359,	/* "id-qcs-pkixQCSyntax-v1" */
		259,	/* "id-qt" */
		313,	/* "id-regCtrl" */
		316,	/* "id-regCtrl-authenticator" */
		319,	/* "id-regCtrl-oldCertID" */
		318,	/* "id-regCtrl-pkiArchiveOptions" */
		317,	/* "id-regCtrl-pkiPublicationInfo" */
		320,	/* "id-regCtrl-protocolEncrKey" */
		315,	/* "id-regCtrl-regToken" */
		314,	/* "id-regInfo" */
		322,	/* "id-regInfo-certReq" */
		321,	/* "id-regInfo-utf8Pairs" */
		191,	/* "id-smime-aa" */
		215,	/* "id-smime-aa-contentHint" */
		218,	/* "id-smime-aa-contentIdentifier" */
		221,	/* "id-smime-aa-contentReference" */
		240,	/* "id-smime-aa-dvcs-dvc" */
		217,	/* "id-smime-aa-encapContentType" */
		222,	/* "id-smime-aa-encrypKeyPref" */
		220,	/* "id-smime-aa-equivalentLabels" */
		232,	/* "id-smime-aa-ets-CertificateRefs" */
		233,	/* "id-smime-aa-ets-RevocationRefs" */
		238,	/* "id-smime-aa-ets-archiveTimeStamp" */
		237,	/* "id-smime-aa-ets-certCRLTimestamp" */
		234,	/* "id-smime-aa-ets-certValues" */
		227,	/* "id-smime-aa-ets-commitmentType" */
		231,	/* "id-smime-aa-ets-contentTimestamp" */
		236,	/* "id-smime-aa-ets-escTimeStamp" */
		230,	/* "id-smime-aa-ets-otherSigCert" */
		235,	/* "id-smime-aa-ets-revocationValues" */
		226,	/* "id-smime-aa-ets-sigPolicyId" */
		229,	/* "id-smime-aa-ets-signerAttr" */
		228,	/* "id-smime-aa-ets-signerLocation" */
		219,	/* "id-smime-aa-macValue" */
		214,	/* "id-smime-aa-mlExpandHistory" */
		216,	/* "id-smime-aa-msgSigDigest" */
		212,	/* "id-smime-aa-receiptRequest" */
		213,	/* "id-smime-aa-securityLabel" */
		239,	/* "id-smime-aa-signatureType" */
		223,	/* "id-smime-aa-signingCertificate" */
		224,	/* "id-smime-aa-smimeEncryptCerts" */
		225,	/* "id-smime-aa-timeStampToken" */
		192,	/* "id-smime-alg" */
		243,	/* "id-smime-alg-3DESwrap" */
		246,	/* "id-smime-alg-CMS3DESwrap" */
		247,	/* "id-smime-alg-CMSRC2wrap" */
		245,	/* "id-smime-alg-ESDH" */
		241,	/* "id-smime-alg-ESDHwith3DES" */
		242,	/* "id-smime-alg-ESDHwithRC2" */
		244,	/* "id-smime-alg-RC2wrap" */
		193,	/* "id-smime-cd" */
		248,	/* "id-smime-cd-ldap" */
		190,	/* "id-smime-ct" */
		210,	/* "id-smime-ct-DVCSRequestData" */
		211,	/* "id-smime-ct-DVCSResponseData" */
		208,	/* "id-smime-ct-TDTInfo" */
		207,	/* "id-smime-ct-TSTInfo" */
		205,	/* "id-smime-ct-authData" */
		786,	/* "id-smime-ct-compressedData" */
		209,	/* "id-smime-ct-contentInfo" */
		206,	/* "id-smime-ct-publishCert" */
		204,	/* "id-smime-ct-receipt" */
		195,	/* "id-smime-cti" */
		255,	/* "id-smime-cti-ets-proofOfApproval" */
		256,	/* "id-smime-cti-ets-proofOfCreation" */
		253,	/* "id-smime-cti-ets-proofOfDelivery" */
		251,	/* "id-smime-cti-ets-proofOfOrigin" */
		252,	/* "id-smime-cti-ets-proofOfReceipt" */
		254,	/* "id-smime-cti-ets-proofOfSender" */
		189,	/* "id-smime-mod" */
		196,	/* "id-smime-mod-cms" */
		197,	/* "id-smime-mod-ess" */
		202,	/* "id-smime-mod-ets-eSigPolicy-88" */
		203,	/* "id-smime-mod-ets-eSigPolicy-97" */
		200,	/* "id-smime-mod-ets-eSignature-88" */
		201,	/* "id-smime-mod-ets-eSignature-97" */
		199,	/* "id-smime-mod-msg-v3" */
		198,	/* "id-smime-mod-oid" */
		194,	/* "id-smime-spq" */
		250,	/* "id-smime-spq-ets-sqt-unotice" */
		249,	/* "id-smime-spq-ets-sqt-uri" */
		34,	/* "idea-cbc" */
		35,	/* "idea-cfb" */
		36,	/* "idea-ecb" */
		46,	/* "idea-ofb" */
		676,	/* "identified-organization" */
		461,	/* "info" */
		101,	/* "initials" */
		869,	/* "internationaliSDNNumber" */
		749,	/* "ipsec3" */
		750,	/* "ipsec4" */
		181,	/* "iso" */
		623,	/* "issuer capabilities" */
		645,	/* "itu-t" */
		492,	/* "janetMailbox" */
		646,	/* "joint-iso-itu-t" */
		150,	/* "keyBag" */
		773,	/* "kisa" */
		477,	/* "lastModifiedBy" */
		476,	/* "lastModifiedTime" */
		157,	/* "localKeyID" */
		15,	/* "localityName" */
		480,	/* "mXRecord" */
		493,	/* "mailPreferenceOption" */
		467,	/* "manager" */
		3,	/* "md2" */
		7,	/* "md2WithRSAEncryption" */
		257,	/* "md4" */
		396,	/* "md4WithRSAEncryption" */
		4,	/* "md5" */
		114,	/* "md5-sha1" */
		104,	/* "md5WithRSA" */
		8,	/* "md5WithRSAEncryption" */
		95,	/* "mdc2" */
		96,	/* "mdc2WithRSA" */
		875,	/* "member" */
		602,	/* "merchant initiated auth" */
		514,	/* "message extensions" */
		51,	/* "messageDigest" */
		911,	/* "mgf1" */
		506,	/* "mime-mhs-bodies" */
		505,	/* "mime-mhs-headings" */
		488,	/* "mobileTelephoneNumber" */
		481,	/* "nSRecord" */
		173,	/* "name" */
		681,	/* "onBasis" */
		379,	/* "org" */
		17,	/* "organizationName" */
		491,	/* "organizationalStatus" */
		18,	/* "organizationalUnitName" */
		475,	/* "otherMailbox" */
		876,	/* "owner" */
		489,	/* "pagerTelephoneNumber" */
		782,	/* "password based MAC" */
		374,	/* "path" */
		621,	/* "payment gateway capabilities" */
		9,	/* "pbeWithMD2AndDES-CBC" */
		168,	/* "pbeWithMD2AndRC2-CBC" */
		112,	/* "pbeWithMD5AndCast5CBC" */
		10,	/* "pbeWithMD5AndDES-CBC" */
		169,	/* "pbeWithMD5AndRC2-CBC" */
		148,	/* "pbeWithSHA1And128BitRC2-CBC" */
		144,	/* "pbeWithSHA1And128BitRC4" */
		147,	/* "pbeWithSHA1And2-KeyTripleDES-CBC" */
		146,	/* "pbeWithSHA1And3-KeyTripleDES-CBC" */
		149,	/* "pbeWithSHA1And40BitRC2-CBC" */
		145,	/* "pbeWithSHA1And40BitRC4" */
		170,	/* "pbeWithSHA1AndDES-CBC" */
		68,	/* "pbeWithSHA1AndRC2-CBC" */
		499,	/* "personalSignature" */
		487,	/* "personalTitle" */
		464,	/* "photo" */
		863,	/* "physicalDeliveryOfficeName" */
		437,	/* "pilot" */
		439,	/* "pilotAttributeSyntax" */
		438,	/* "pilotAttributeType" */
		479,	/* "pilotAttributeType27" */
		456,	/* "pilotDSA" */
		441,	/* "pilotGroups" */
		444,	/* "pilotObject" */
		440,	/* "pilotObjectClass" */
		455,	/* "pilotOrganization" */
		445,	/* "pilotPerson" */
		186,	/* "pkcs1" */
		27,	/* "pkcs3" */
		187,	/* "pkcs5" */
		20,	/* "pkcs7" */
		21,	/* "pkcs7-data" */
		25,	/* "pkcs7-digestData" */
		26,	/* "pkcs7-encryptedData" */
		23,	/* "pkcs7-envelopedData" */
		24,	/* "pkcs7-signedAndEnvelopedData" */
		22,	/* "pkcs7-signedData" */
		151,	/* "pkcs8ShroudedKeyBag" */
		47,	/* "pkcs9" */
		862,	/* "postOfficeBox" */
		861,	/* "postalAddress" */
		661,	/* "postalCode" */
		683,	/* "ppBasis" */
		872,	/* "preferredDeliveryMethod" */
		873,	/* "presentationAddress" */
		406,	/* "prime-field" */
		409,	/* "prime192v1" */
		410,	/* "prime192v2" */
		411,	/* "prime192v3" */
		412,	/* "prime239v1" */
		413,	/* "prime239v2" */
		414,	/* "prime239v3" */
		415,	/* "prime256v1" */
		886,	/* "protocolInformation" */
		510,	/* "pseudonym" */
		435,	/* "pss" */
		286,	/* "qcStatements" */
		457,	/* "qualityLabelledData" */
		450,	/* "rFC822localPart" */
		98,	/* "rc2-40-cbc" */
		166,	/* "rc2-64-cbc" */
		37,	/* "rc2-cbc" */
		39,	/* "rc2-cfb" */
		38,	/* "rc2-ecb" */
		40,	/* "rc2-ofb" */
		5,	/* "rc4" */
		97,	/* "rc4-40" */
		915,	/* "rc4-hmac-md5" */
		120,	/* "rc5-cbc" */
		122,	/* "rc5-cfb" */
		121,	/* "rc5-ecb" */
		123,	/* "rc5-ofb" */
		870,	/* "registeredAddress" */
		460,	/* "rfc822Mailbox" */
		117,	/* "ripemd160" */
		119,	/* "ripemd160WithRSA" */
		400,	/* "role" */
		877,	/* "roleOccupant" */
		448,	/* "room" */
		463,	/* "roomNumber" */
		19,	/* "rsa" */
		6,	/* "rsaEncryption" */
		644,	/* "rsaOAEPEncryptionSET" */
		377,	/* "rsaSignature" */
		919,	/* "rsaesOaep" */
		912,	/* "rsassaPss" */
		124,	/* "run length compression" */
		482,	/* "sOARecord" */
		155,	/* "safeContentsBag" */
		291,	/* "sbgp-autonomousSysNum" */
		290,	/* "sbgp-ipAddrBlock" */
		292,	/* "sbgp-routerIdentifier" */
		159,	/* "sdsiCertificate" */
		859,	/* "searchGuide" */
		704,	/* "secp112r1" */
		705,	/* "secp112r2" */
		706,	/* "secp128r1" */
		707,	/* "secp128r2" */
		708,	/* "secp160k1" */
		709,	/* "secp160r1" */
		710,	/* "secp160r2" */
		711,	/* "secp192k1" */
		712,	/* "secp224k1" */
		713,	/* "secp224r1" */
		714,	/* "secp256k1" */
		715,	/* "secp384r1" */
		716,	/* "secp521r1" */
		154,	/* "secretBag" */
		474,	/* "secretary" */
		717,	/* "sect113r1" */
		718,	/* "sect113r2" */
		719,	/* "sect131r1" */
		720,	/* "sect131r2" */
		721,	/* "sect163k1" */
		722,	/* "sect163r1" */
		723,	/* "sect163r2" */
		724,	/* "sect193r1" */
		725,	/* "sect193r2" */
		726,	/* "sect233k1" */
		727,	/* "sect233r1" */
		728,	/* "sect239k1" */
		729,	/* "sect283k1" */
		730,	/* "sect283r1" */
		731,	/* "sect409k1" */
		732,	/* "sect409r1" */
		733,	/* "sect571k1" */
		734,	/* "sect571r1" */
		635,	/* "secure device signature" */
		878,	/* "seeAlso" */
		777,	/* "seed-cbc" */
		779,	/* "seed-cfb" */
		776,	/* "seed-ecb" */
		778,	/* "seed-ofb" */
		105,	/* "serialNumber" */
		625,	/* "set-addPolicy" */
		515,	/* "set-attr" */
		518,	/* "set-brand" */
		638,	/* "set-brand-AmericanExpress" */
		637,	/* "set-brand-Diners" */
		636,	/* "set-brand-IATA-ATA" */
		639,	/* "set-brand-JCB" */
		641,	/* "set-brand-MasterCard" */
		642,	/* "set-brand-Novus" */
		640,	/* "set-brand-Visa" */
		516,	/* "set-policy" */
		607,	/* "set-policy-root" */
		624,	/* "set-rootKeyThumb" */
		620,	/* "setAttr-Cert" */
		628,	/* "setAttr-IssCap-CVM" */
		630,	/* "setAttr-IssCap-Sig" */
		629,	/* "setAttr-IssCap-T2" */
		627,	/* "setAttr-Token-B0Prime" */
		626,	/* "setAttr-Token-EMV" */
		622,	/* "setAttr-TokenType" */
		619,	/* "setCext-IssuerCapabilities" */
		615,	/* "setCext-PGWYcapabilities" */
		616,	/* "setCext-TokenIdentifier" */
		618,	/* "setCext-TokenType" */
		617,	/* "setCext-Track2Data" */
		611,	/* "setCext-cCertRequired" */
		609,	/* "setCext-certType" */
		608,	/* "setCext-hashedRoot" */
		610,	/* "setCext-merchData" */
		613,	/* "setCext-setExt" */
		614,	/* "setCext-setQualf" */
		612,	/* "setCext-tunneling" */
		540,	/* "setct-AcqCardCodeMsg" */
		576,	/* "setct-AcqCardCodeMsgTBE" */
		570,	/* "setct-AuthReqTBE" */
		534,	/* "setct-AuthReqTBS" */
		527,	/* "setct-AuthResBaggage" */
		571,	/* "setct-AuthResTBE" */
		572,	/* "setct-AuthResTBEX" */
		535,	/* "setct-AuthResTBS" */
		536,	/* "setct-AuthResTBSX" */
		528,	/* "setct-AuthRevReqBaggage" */
		577,	/* "setct-AuthRevReqTBE" */
		541,	/* "setct-AuthRevReqTBS" */
		529,	/* "setct-AuthRevResBaggage" */
		542,	/* "setct-AuthRevResData" */
		578,	/* "setct-AuthRevResTBE" */
		579,	/* "setct-AuthRevResTBEB" */
		543,	/* "setct-AuthRevResTBS" */
		573,	/* "setct-AuthTokenTBE" */
		537,	/* "setct-AuthTokenTBS" */
		600,	/* "setct-BCIDistributionTBS" */
		558,	/* "setct-BatchAdminReqData" */
		592,	/* "setct-BatchAdminReqTBE" */
		559,	/* "setct-BatchAdminResData" */
		593,	/* "setct-BatchAdminResTBE" */
		599,	/* "setct-CRLNotificationResTBS" */
		598,	/* "setct-CRLNotificationTBS" */
		580,	/* "setct-CapReqTBE" */
		581,	/* "setct-CapReqTBEX" */
		544,	/* "setct-CapReqTBS" */
		545,	/* "setct-CapReqTBSX" */
		546,	/* "setct-CapResData" */
		582,	/* "setct-CapResTBE" */
		583,	/* "setct-CapRevReqTBE" */
		584,	/* "setct-CapRevReqTBEX" */
		547,	/* "setct-CapRevReqTBS" */
		548,	/* "setct-CapRevReqTBSX" */
		549,	/* "setct-CapRevResData" */
		585,	/* "setct-CapRevResTBE" */
		538,	/* "setct-CapTokenData" */
		530,	/* "setct-CapTokenSeq" */
		574,	/* "setct-CapTokenTBE" */
		575,	/* "setct-CapTokenTBEX" */
		539,	/* "setct-CapTokenTBS" */
		560,	/* "setct-CardCInitResTBS" */
		566,	/* "setct-CertInqReqTBS" */
		563,	/* "setct-CertReqData" */
		595,	/* "setct-CertReqTBE" */
		596,	/* "setct-CertReqTBEX" */
		564,	/* "setct-CertReqTBS" */
		565,	/* "setct-CertResData" */
		597,	/* "setct-CertResTBE" */
		586,	/* "setct-CredReqTBE" */
		587,	/* "setct-CredReqTBEX" */
		550,	/* "setct-CredReqTBS" */
		551,	/* "setct-CredReqTBSX" */
		552,	/* "setct-CredResData" */
		588,	/* "setct-CredResTBE" */
		589,	/* "setct-CredRevReqTBE" */
		590,	/* "setct-CredRevReqTBEX" */
		553,	/* "setct-CredRevReqTBS" */
		554,	/* "setct-CredRevReqTBSX" */
		555,	/* "setct-CredRevResData" */
		591,	/* "setct-CredRevResTBE" */
		567,	/* "setct-ErrorTBS" */
		526,	/* "setct-HODInput" */
		561,	/* "setct-MeAqCInitResTBS" */
		522,	/* "setct-OIData" */
		519,	/* "setct-PANData" */
		521,	/* "setct-PANOnly" */
		520,	/* "setct-PANToken" */
		556,	/* "setct-PCertReqData" */
		557,	/* "setct-PCertResTBS" */
		523,	/* "setct-PI" */
		532,	/* "setct-PI-TBS" */
		524,	/* "setct-PIData" */
		525,	/* "setct-PIDataUnsigned" */
		568,	/* "setct-PIDualSignedTBE" */
		569,	/* "setct-PIUnsignedTBE" */
		531,	/* "setct-PInitResData" */
		533,	/* "setct-PResData" */
		594,	/* "setct-RegFormReqTBE" */
		562,	/* "setct-RegFormResTBS" */
		604,	/* "setext-pinAny" */
		603,	/* "setext-pinSecure" */
		605,	/* "setext-track2" */
		41,	/* "sha" */
		64,	/* "sha1" */
		115,	/* "sha1WithRSA" */
		65,	/* "sha1WithRSAEncryption" */
		675,	/* "sha224" */
		671,	/* "sha224WithRSAEncryption" */
		672,	/* "sha256" */
		668,	/* "sha256WithRSAEncryption" */
		673,	/* "sha384" */
		669,	/* "sha384WithRSAEncryption" */
		674,	/* "sha512" */
		670,	/* "sha512WithRSAEncryption" */
		42,	/* "shaWithRSAEncryption" */
		52,	/* "signingTime" */
		454,	/* "simpleSecurityObject" */
		496,	/* "singleLevelQuality" */
		16,	/* "stateOrProvinceName" */
		660,	/* "streetAddress" */
		498,	/* "subtreeMaximumQuality" */
		497,	/* "subtreeMinimumQuality" */
		890,	/* "supportedAlgorithms" */
		874,	/* "supportedApplicationContext" */
		100,	/* "surname" */
		864,	/* "telephoneNumber" */
		866,	/* "teletexTerminalIdentifier" */
		865,	/* "telexNumber" */
		459,	/* "textEncodedORAddress" */
		293,	/* "textNotice" */
		106,	/* "title" */
		682,	/* "tpBasis" */
		436,	/* "ucl" */
		0,	/* "undefined" */
		888,	/* "uniqueMember" */
		55,	/* "unstructuredAddress" */
		49,	/* "unstructuredName" */
		880,	/* "userCertificate" */
		465,	/* "userClass" */
		458,	/* "userId" */
		879,	/* "userPassword" */
		373,	/* "valid" */
		678,	/* "wap" */
		679,	/* "wap-wsg" */
		735,	/* "wap-wsg-idm-ecid-wtls1" */
		743,	/* "wap-wsg-idm-ecid-wtls10" */
		744,	/* "wap-wsg-idm-ecid-wtls11" */
		745,	/* "wap-wsg-idm-ecid-wtls12" */
		736,	/* "wap-wsg-idm-ecid-wtls3" */
		737,	/* "wap-wsg-idm-ecid-wtls4" */
		738,	/* "wap-wsg-idm-ecid-wtls5" */
		739,	/* "wap-wsg-idm-ecid-wtls6" */
		740,	/* "wap-wsg-idm-ecid-wtls7" */
		741,	/* "wap-wsg-idm-ecid-wtls8" */
		742,	/* "wap-wsg-idm-ecid-wtls9" */
		804,	/* "whirlpool" */
		868,	/* "x121Address" */
		503,	/* "x500UniqueIdentifier" */
		158,	/* "x509Certificate" */
		160,	/* "x509Crl" */
		125,	/* "zlib compression" */
	};
	
	static const unsigned int obj_objs[NUM_OBJ]={
		0,	/* OBJ_undef                        0 */
		393,	/* OBJ_joint_iso_ccitt              OBJ_joint_iso_itu_t */
		404,	/* OBJ_ccitt                        OBJ_itu_t */
		645,	/* OBJ_itu_t                        0 */
		434,	/* OBJ_data                         0 9 */
		181,	/* OBJ_iso                          1 */
		182,	/* OBJ_member_body                  1 2 */
		379,	/* OBJ_org                          1 3 */
		676,	/* OBJ_identified_organization      1 3 */
		646,	/* OBJ_joint_iso_itu_t              2 */
		11,	/* OBJ_X500                         2 5 */
		647,	/* OBJ_international_organizations  2 23 */
		380,	/* OBJ_dod                          1 3 6 */
		12,	/* OBJ_X509                         2 5 4 */
		378,	/* OBJ_X500algorithms               2 5 8 */
		81,	/* OBJ_id_ce                        2 5 29 */
		512,	/* OBJ_id_set                       2 23 42 */
		678,	/* OBJ_wap                          2 23 43 */
		435,	/* OBJ_pss                          0 9 2342 */
		183,	/* OBJ_ISO_US                       1 2 840 */
		381,	/* OBJ_iana                         1 3 6 1 */
		677,	/* OBJ_certicom_arc                 1 3 132 */
		394,	/* OBJ_selected_attribute_types     2 5 1 5 */
		13,	/* OBJ_commonName                   2 5 4 3 */
		100,	/* OBJ_surname                      2 5 4 4 */
		105,	/* OBJ_serialNumber                 2 5 4 5 */
		14,	/* OBJ_countryName                  2 5 4 6 */
		15,	/* OBJ_localityName                 2 5 4 7 */
		16,	/* OBJ_stateOrProvinceName          2 5 4 8 */
		660,	/* OBJ_streetAddress                2 5 4 9 */
		17,	/* OBJ_organizationName             2 5 4 10 */
		18,	/* OBJ_organizationalUnitName       2 5 4 11 */
		106,	/* OBJ_title                        2 5 4 12 */
		107,	/* OBJ_description                  2 5 4 13 */
		859,	/* OBJ_searchGuide                  2 5 4 14 */
		860,	/* OBJ_businessCategory             2 5 4 15 */
		861,	/* OBJ_postalAddress                2 5 4 16 */
		661,	/* OBJ_postalCode                   2 5 4 17 */
		862,	/* OBJ_postOfficeBox                2 5 4 18 */
		863,	/* OBJ_physicalDeliveryOfficeName   2 5 4 19 */
		864,	/* OBJ_telephoneNumber              2 5 4 20 */
		865,	/* OBJ_telexNumber                  2 5 4 21 */
		866,	/* OBJ_teletexTerminalIdentifier    2 5 4 22 */
		867,	/* OBJ_facsimileTelephoneNumber     2 5 4 23 */
		868,	/* OBJ_x121Address                  2 5 4 24 */
		869,	/* OBJ_internationaliSDNNumber      2 5 4 25 */
		870,	/* OBJ_registeredAddress            2 5 4 26 */
		871,	/* OBJ_destinationIndicator         2 5 4 27 */
		872,	/* OBJ_preferredDeliveryMethod      2 5 4 28 */
		873,	/* OBJ_presentationAddress          2 5 4 29 */
		874,	/* OBJ_supportedApplicationContext  2 5 4 30 */
		875,	/* OBJ_member                       2 5 4 31 */
		876,	/* OBJ_owner                        2 5 4 32 */
		877,	/* OBJ_roleOccupant                 2 5 4 33 */
		878,	/* OBJ_seeAlso                      2 5 4 34 */
		879,	/* OBJ_userPassword                 2 5 4 35 */
		880,	/* OBJ_userCertificate              2 5 4 36 */
		881,	/* OBJ_cACertificate                2 5 4 37 */
		882,	/* OBJ_authorityRevocationList      2 5 4 38 */
		883,	/* OBJ_certificateRevocationList    2 5 4 39 */
		884,	/* OBJ_crossCertificatePair         2 5 4 40 */
		173,	/* OBJ_name                         2 5 4 41 */
		99,	/* OBJ_givenName                    2 5 4 42 */
		101,	/* OBJ_initials                     2 5 4 43 */
		509,	/* OBJ_generationQualifier          2 5 4 44 */
		503,	/* OBJ_x500UniqueIdentifier         2 5 4 45 */
		174,	/* OBJ_dnQualifier                  2 5 4 46 */
		885,	/* OBJ_enhancedSearchGuide          2 5 4 47 */
		886,	/* OBJ_protocolInformation          2 5 4 48 */
		887,	/* OBJ_distinguishedName            2 5 4 49 */
		888,	/* OBJ_uniqueMember                 2 5 4 50 */
		889,	/* OBJ_houseIdentifier              2 5 4 51 */
		890,	/* OBJ_supportedAlgorithms          2 5 4 52 */
		891,	/* OBJ_deltaRevocationList          2 5 4 53 */
		892,	/* OBJ_dmdName                      2 5 4 54 */
		510,	/* OBJ_pseudonym                    2 5 4 65 */
		400,	/* OBJ_role                         2 5 4 72 */
		769,	/* OBJ_subject_directory_attributes 2 5 29 9 */
		82,	/* OBJ_subject_key_identifier       2 5 29 14 */
		83,	/* OBJ_key_usage                    2 5 29 15 */
		84,	/* OBJ_private_key_usage_period     2 5 29 16 */
		85,	/* OBJ_subject_alt_name             2 5 29 17 */
		86,	/* OBJ_issuer_alt_name              2 5 29 18 */
		87,	/* OBJ_basic_constraints            2 5 29 19 */
		88,	/* OBJ_crl_number                   2 5 29 20 */
		141,	/* OBJ_crl_reason                   2 5 29 21 */
		430,	/* OBJ_hold_instruction_code        2 5 29 23 */
		142,	/* OBJ_invalidity_date              2 5 29 24 */
		140,	/* OBJ_delta_crl                    2 5 29 27 */
		770,	/* OBJ_issuing_distribution_point   2 5 29 28 */
		771,	/* OBJ_certificate_issuer           2 5 29 29 */
		666,	/* OBJ_name_constraints             2 5 29 30 */
		103,	/* OBJ_crl_distribution_points      2 5 29 31 */
		89,	/* OBJ_certificate_policies         2 5 29 32 */
		747,	/* OBJ_policy_mappings              2 5 29 33 */
		90,	/* OBJ_authority_key_identifier     2 5 29 35 */
		401,	/* OBJ_policy_constraints           2 5 29 36 */
		126,	/* OBJ_ext_key_usage                2 5 29 37 */
		857,	/* OBJ_freshest_crl                 2 5 29 46 */
		748,	/* OBJ_inhibit_any_policy           2 5 29 54 */
		402,	/* OBJ_target_information           2 5 29 55 */
		403,	/* OBJ_no_rev_avail                 2 5 29 56 */
		513,	/* OBJ_set_ctype                    2 23 42 0 */
		514,	/* OBJ_set_msgExt                   2 23 42 1 */
		515,	/* OBJ_set_attr                     2 23 42 3 */
		516,	/* OBJ_set_policy                   2 23 42 5 */
		517,	/* OBJ_set_certExt                  2 23 42 7 */
		518,	/* OBJ_set_brand                    2 23 42 8 */
		679,	/* OBJ_wap_wsg                      2 23 43 1 */
		382,	/* OBJ_Directory                    1 3 6 1 1 */
		383,	/* OBJ_Management                   1 3 6 1 2 */
		384,	/* OBJ_Experimental                 1 3 6 1 3 */
		385,	/* OBJ_Private                      1 3 6 1 4 */
		386,	/* OBJ_Security                     1 3 6 1 5 */
		387,	/* OBJ_SNMPv2                       1 3 6 1 6 */
		388,	/* OBJ_Mail                         1 3 6 1 7 */
		376,	/* OBJ_algorithm                    1 3 14 3 2 */
		395,	/* OBJ_clearance                    2 5 1 5 55 */
		19,	/* OBJ_rsa                          2 5 8 1 1 */
		96,	/* OBJ_mdc2WithRSA                  2 5 8 3 100 */
		95,	/* OBJ_mdc2                         2 5 8 3 101 */
		746,	/* OBJ_any_policy                   2 5 29 32 0 */
		910,	/* OBJ_anyExtendedKeyUsage          2 5 29 37 0 */
		519,	/* OBJ_setct_PANData                2 23 42 0 0 */
		520,	/* OBJ_setct_PANToken               2 23 42 0 1 */
		521,	/* OBJ_setct_PANOnly                2 23 42 0 2 */
		522,	/* OBJ_setct_OIData                 2 23 42 0 3 */
		523,	/* OBJ_setct_PI                     2 23 42 0 4 */
		524,	/* OBJ_setct_PIData                 2 23 42 0 5 */
		525,	/* OBJ_setct_PIDataUnsigned         2 23 42 0 6 */
		526,	/* OBJ_setct_HODInput               2 23 42 0 7 */
		527,	/* OBJ_setct_AuthResBaggage         2 23 42 0 8 */
		528,	/* OBJ_setct_AuthRevReqBaggage      2 23 42 0 9 */
		529,	/* OBJ_setct_AuthRevResBaggage      2 23 42 0 10 */
		530,	/* OBJ_setct_CapTokenSeq            2 23 42 0 11 */
		531,	/* OBJ_setct_PInitResData           2 23 42 0 12 */
		532,	/* OBJ_setct_PI_TBS                 2 23 42 0 13 */
		533,	/* OBJ_setct_PResData               2 23 42 0 14 */
		534,	/* OBJ_setct_AuthReqTBS             2 23 42 0 16 */
		535,	/* OBJ_setct_AuthResTBS             2 23 42 0 17 */
		536,	/* OBJ_setct_AuthResTBSX            2 23 42 0 18 */
		537,	/* OBJ_setct_AuthTokenTBS           2 23 42 0 19 */
		538,	/* OBJ_setct_CapTokenData           2 23 42 0 20 */
		539,	/* OBJ_setct_CapTokenTBS            2 23 42 0 21 */
		540,	/* OBJ_setct_AcqCardCodeMsg         2 23 42 0 22 */
		541,	/* OBJ_setct_AuthRevReqTBS          2 23 42 0 23 */
		542,	/* OBJ_setct_AuthRevResData         2 23 42 0 24 */
		543,	/* OBJ_setct_AuthRevResTBS          2 23 42 0 25 */
		544,	/* OBJ_setct_CapReqTBS              2 23 42 0 26 */
		545,	/* OBJ_setct_CapReqTBSX             2 23 42 0 27 */
		546,	/* OBJ_setct_CapResData             2 23 42 0 28 */
		547,	/* OBJ_setct_CapRevReqTBS           2 23 42 0 29 */
		548,	/* OBJ_setct_CapRevReqTBSX          2 23 42 0 30 */
		549,	/* OBJ_setct_CapRevResData          2 23 42 0 31 */
		550,	/* OBJ_setct_CredReqTBS             2 23 42 0 32 */
		551,	/* OBJ_setct_CredReqTBSX            2 23 42 0 33 */
		552,	/* OBJ_setct_CredResData            2 23 42 0 34 */
		553,	/* OBJ_setct_CredRevReqTBS          2 23 42 0 35 */
		554,	/* OBJ_setct_CredRevReqTBSX         2 23 42 0 36 */
		555,	/* OBJ_setct_CredRevResData         2 23 42 0 37 */
		556,	/* OBJ_setct_PCertReqData           2 23 42 0 38 */
		557,	/* OBJ_setct_PCertResTBS            2 23 42 0 39 */
		558,	/* OBJ_setct_BatchAdminReqData      2 23 42 0 40 */
		559,	/* OBJ_setct_BatchAdminResData      2 23 42 0 41 */
		560,	/* OBJ_setct_CardCInitResTBS        2 23 42 0 42 */
		561,	/* OBJ_setct_MeAqCInitResTBS        2 23 42 0 43 */
		562,	/* OBJ_setct_RegFormResTBS          2 23 42 0 44 */
		563,	/* OBJ_setct_CertReqData            2 23 42 0 45 */
		564,	/* OBJ_setct_CertReqTBS             2 23 42 0 46 */
		565,	/* OBJ_setct_CertResData            2 23 42 0 47 */
		566,	/* OBJ_setct_CertInqReqTBS          2 23 42 0 48 */
		567,	/* OBJ_setct_ErrorTBS               2 23 42 0 49 */
		568,	/* OBJ_setct_PIDualSignedTBE        2 23 42 0 50 */
		569,	/* OBJ_setct_PIUnsignedTBE          2 23 42 0 51 */
		570,	/* OBJ_setct_AuthReqTBE             2 23 42 0 52 */
		571,	/* OBJ_setct_AuthResTBE             2 23 42 0 53 */
		572,	/* OBJ_setct_AuthResTBEX            2 23 42 0 54 */
		573,	/* OBJ_setct_AuthTokenTBE           2 23 42 0 55 */
		574,	/* OBJ_setct_CapTokenTBE            2 23 42 0 56 */
		575,	/* OBJ_setct_CapTokenTBEX           2 23 42 0 57 */
		576,	/* OBJ_setct_AcqCardCodeMsgTBE      2 23 42 0 58 */
		577,	/* OBJ_setct_AuthRevReqTBE          2 23 42 0 59 */
		578,	/* OBJ_setct_AuthRevResTBE          2 23 42 0 60 */
		579,	/* OBJ_setct_AuthRevResTBEB         2 23 42 0 61 */
		580,	/* OBJ_setct_CapReqTBE              2 23 42 0 62 */
		581,	/* OBJ_setct_CapReqTBEX             2 23 42 0 63 */
		582,	/* OBJ_setct_CapResTBE              2 23 42 0 64 */
		583,	/* OBJ_setct_CapRevReqTBE           2 23 42 0 65 */
		584,	/* OBJ_setct_CapRevReqTBEX          2 23 42 0 66 */
		585,	/* OBJ_setct_CapRevResTBE           2 23 42 0 67 */
		586,	/* OBJ_setct_CredReqTBE             2 23 42 0 68 */
		587,	/* OBJ_setct_CredReqTBEX            2 23 42 0 69 */
		588,	/* OBJ_setct_CredResTBE             2 23 42 0 70 */
		589,	/* OBJ_setct_CredRevReqTBE          2 23 42 0 71 */
		590,	/* OBJ_setct_CredRevReqTBEX         2 23 42 0 72 */
		591,	/* OBJ_setct_CredRevResTBE          2 23 42 0 73 */
		592,	/* OBJ_setct_BatchAdminReqTBE       2 23 42 0 74 */
		593,	/* OBJ_setct_BatchAdminResTBE       2 23 42 0 75 */
		594,	/* OBJ_setct_RegFormReqTBE          2 23 42 0 76 */
		595,	/* OBJ_setct_CertReqTBE             2 23 42 0 77 */
		596,	/* OBJ_setct_CertReqTBEX            2 23 42 0 78 */
		597,	/* OBJ_setct_CertResTBE             2 23 42 0 79 */
		598,	/* OBJ_setct_CRLNotificationTBS     2 23 42 0 80 */
		599,	/* OBJ_setct_CRLNotificationResTBS  2 23 42 0 81 */
		600,	/* OBJ_setct_BCIDistributionTBS     2 23 42 0 82 */
		601,	/* OBJ_setext_genCrypt              2 23 42 1 1 */
		602,	/* OBJ_setext_miAuth                2 23 42 1 3 */
		603,	/* OBJ_setext_pinSecure             2 23 42 1 4 */
		604,	/* OBJ_setext_pinAny                2 23 42 1 5 */
		605,	/* OBJ_setext_track2                2 23 42 1 7 */
		606,	/* OBJ_setext_cv                    2 23 42 1 8 */
		620,	/* OBJ_setAttr_Cert                 2 23 42 3 0 */
		621,	/* OBJ_setAttr_PGWYcap              2 23 42 3 1 */
		622,	/* OBJ_setAttr_TokenType            2 23 42 3 2 */
		623,	/* OBJ_setAttr_IssCap               2 23 42 3 3 */
		607,	/* OBJ_set_policy_root              2 23 42 5 0 */
		608,	/* OBJ_setCext_hashedRoot           2 23 42 7 0 */
		609,	/* OBJ_setCext_certType             2 23 42 7 1 */
		610,	/* OBJ_setCext_merchData            2 23 42 7 2 */
		611,	/* OBJ_setCext_cCertRequired        2 23 42 7 3 */
		612,	/* OBJ_setCext_tunneling            2 23 42 7 4 */
		613,	/* OBJ_setCext_setExt               2 23 42 7 5 */
		614,	/* OBJ_setCext_setQualf             2 23 42 7 6 */
		615,	/* OBJ_setCext_PGWYcapabilities     2 23 42 7 7 */
		616,	/* OBJ_setCext_TokenIdentifier      2 23 42 7 8 */
		617,	/* OBJ_setCext_Track2Data           2 23 42 7 9 */
		618,	/* OBJ_setCext_TokenType            2 23 42 7 10 */
		619,	/* OBJ_setCext_IssuerCapabilities   2 23 42 7 11 */
		636,	/* OBJ_set_brand_IATA_ATA           2 23 42 8 1 */
		640,	/* OBJ_set_brand_Visa               2 23 42 8 4 */
		641,	/* OBJ_set_brand_MasterCard         2 23 42 8 5 */
		637,	/* OBJ_set_brand_Diners             2 23 42 8 30 */
		638,	/* OBJ_set_brand_AmericanExpress    2 23 42 8 34 */
		639,	/* OBJ_set_brand_JCB                2 23 42 8 35 */
		805,	/* OBJ_cryptopro                    1 2 643 2 2 */
		806,	/* OBJ_cryptocom                    1 2 643 2 9 */
		184,	/* OBJ_X9_57                        1 2 840 10040 */
		405,	/* OBJ_ansi_X9_62                   1 2 840 10045 */
		389,	/* OBJ_Enterprises                  1 3 6 1 4 1 */
		504,	/* OBJ_mime_mhs                     1 3 6 1 7 1 */
		104,	/* OBJ_md5WithRSA                   1 3 14 3 2 3 */
		29,	/* OBJ_des_ecb                      1 3 14 3 2 6 */
		31,	/* OBJ_des_cbc                      1 3 14 3 2 7 */
		45,	/* OBJ_des_ofb64                    1 3 14 3 2 8 */
		30,	/* OBJ_des_cfb64                    1 3 14 3 2 9 */
		377,	/* OBJ_rsaSignature                 1 3 14 3 2 11 */
		67,	/* OBJ_dsa_2                        1 3 14 3 2 12 */
		66,	/* OBJ_dsaWithSHA                   1 3 14 3 2 13 */
		42,	/* OBJ_shaWithRSAEncryption         1 3 14 3 2 15 */
		32,	/* OBJ_des_ede_ecb                  1 3 14 3 2 17 */
		41,	/* OBJ_sha                          1 3 14 3 2 18 */
		64,	/* OBJ_sha1                         1 3 14 3 2 26 */
		70,	/* OBJ_dsaWithSHA1_2                1 3 14 3 2 27 */
		115,	/* OBJ_sha1WithRSA                  1 3 14 3 2 29 */
		117,	/* OBJ_ripemd160                    1 3 36 3 2 1 */
		143,	/* OBJ_sxnet                        1 3 101 1 4 1 */
		721,	/* OBJ_sect163k1                    1 3 132 0 1 */
		722,	/* OBJ_sect163r1                    1 3 132 0 2 */
		728,	/* OBJ_sect239k1                    1 3 132 0 3 */
		717,	/* OBJ_sect113r1                    1 3 132 0 4 */
		718,	/* OBJ_sect113r2                    1 3 132 0 5 */
		704,	/* OBJ_secp112r1                    1 3 132 0 6 */
		705,	/* OBJ_secp112r2                    1 3 132 0 7 */
		709,	/* OBJ_secp160r1                    1 3 132 0 8 */
		708,	/* OBJ_secp160k1                    1 3 132 0 9 */
		714,	/* OBJ_secp256k1                    1 3 132 0 10 */
		723,	/* OBJ_sect163r2                    1 3 132 0 15 */
		729,	/* OBJ_sect283k1                    1 3 132 0 16 */
		730,	/* OBJ_sect283r1                    1 3 132 0 17 */
		719,	/* OBJ_sect131r1                    1 3 132 0 22 */
		720,	/* OBJ_sect131r2                    1 3 132 0 23 */
		724,	/* OBJ_sect193r1                    1 3 132 0 24 */
		725,	/* OBJ_sect193r2                    1 3 132 0 25 */
		726,	/* OBJ_sect233k1                    1 3 132 0 26 */
		727,	/* OBJ_sect233r1                    1 3 132 0 27 */
		706,	/* OBJ_secp128r1                    1 3 132 0 28 */
		707,	/* OBJ_secp128r2                    1 3 132 0 29 */
		710,	/* OBJ_secp160r2                    1 3 132 0 30 */
		711,	/* OBJ_secp192k1                    1 3 132 0 31 */
		712,	/* OBJ_secp224k1                    1 3 132 0 32 */
		713,	/* OBJ_secp224r1                    1 3 132 0 33 */
		715,	/* OBJ_secp384r1                    1 3 132 0 34 */
		716,	/* OBJ_secp521r1                    1 3 132 0 35 */
		731,	/* OBJ_sect409k1                    1 3 132 0 36 */
		732,	/* OBJ_sect409r1                    1 3 132 0 37 */
		733,	/* OBJ_sect571k1                    1 3 132 0 38 */
		734,	/* OBJ_sect571r1                    1 3 132 0 39 */
		624,	/* OBJ_set_rootKeyThumb             2 23 42 3 0 0 */
		625,	/* OBJ_set_addPolicy                2 23 42 3 0 1 */
		626,	/* OBJ_setAttr_Token_EMV            2 23 42 3 2 1 */
		627,	/* OBJ_setAttr_Token_B0Prime        2 23 42 3 2 2 */
		628,	/* OBJ_setAttr_IssCap_CVM           2 23 42 3 3 3 */
		629,	/* OBJ_setAttr_IssCap_T2            2 23 42 3 3 4 */
		630,	/* OBJ_setAttr_IssCap_Sig           2 23 42 3 3 5 */
		642,	/* OBJ_set_brand_Novus              2 23 42 8 6011 */
		735,	/* OBJ_wap_wsg_idm_ecid_wtls1       2 23 43 1 4 1 */
		736,	/* OBJ_wap_wsg_idm_ecid_wtls3       2 23 43 1 4 3 */
		737,	/* OBJ_wap_wsg_idm_ecid_wtls4       2 23 43 1 4 4 */
		738,	/* OBJ_wap_wsg_idm_ecid_wtls5       2 23 43 1 4 5 */
		739,	/* OBJ_wap_wsg_idm_ecid_wtls6       2 23 43 1 4 6 */
		740,	/* OBJ_wap_wsg_idm_ecid_wtls7       2 23 43 1 4 7 */
		741,	/* OBJ_wap_wsg_idm_ecid_wtls8       2 23 43 1 4 8 */
		742,	/* OBJ_wap_wsg_idm_ecid_wtls9       2 23 43 1 4 9 */
		743,	/* OBJ_wap_wsg_idm_ecid_wtls10      2 23 43 1 4 10 */
		744,	/* OBJ_wap_wsg_idm_ecid_wtls11      2 23 43 1 4 11 */
		745,	/* OBJ_wap_wsg_idm_ecid_wtls12      2 23 43 1 4 12 */
		804,	/* OBJ_whirlpool                    1 0 10118 3 0 55 */
		124,	/* OBJ_rle_compression              1 1 1 1 666 1 */
		773,	/* OBJ_kisa                         1 2 410 200004 */
		807,	/* OBJ_id_GostR3411_94_with_GostR3410_2001 1 2 643 2 2 3 */
		808,	/* OBJ_id_GostR3411_94_with_GostR3410_94 1 2 643 2 2 4 */
		809,	/* OBJ_id_GostR3411_94              1 2 643 2 2 9 */
		810,	/* OBJ_id_HMACGostR3411_94          1 2 643 2 2 10 */
		811,	/* OBJ_id_GostR3410_2001            1 2 643 2 2 19 */
		812,	/* OBJ_id_GostR3410_94              1 2 643 2 2 20 */
		813,	/* OBJ_id_Gost28147_89              1 2 643 2 2 21 */
		815,	/* OBJ_id_Gost28147_89_MAC          1 2 643 2 2 22 */
		816,	/* OBJ_id_GostR3411_94_prf          1 2 643 2 2 23 */
		817,	/* OBJ_id_GostR3410_2001DH          1 2 643 2 2 98 */
		818,	/* OBJ_id_GostR3410_94DH            1 2 643 2 2 99 */
		1,	/* OBJ_rsadsi                       1 2 840 113549 */
		185,	/* OBJ_X9cm                         1 2 840 10040 4 */
		127,	/* OBJ_id_pkix                      1 3 6 1 5 5 7 */
		505,	/* OBJ_mime_mhs_headings            1 3 6 1 7 1 1 */
		506,	/* OBJ_mime_mhs_bodies              1 3 6 1 7 1 2 */
		119,	/* OBJ_ripemd160WithRSA             1 3 36 3 3 1 2 */
		631,	/* OBJ_setAttr_GenCryptgrm          2 23 42 3 3 3 1 */
		632,	/* OBJ_setAttr_T2Enc                2 23 42 3 3 4 1 */
		633,	/* OBJ_setAttr_T2cleartxt           2 23 42 3 3 4 2 */
		634,	/* OBJ_setAttr_TokICCsig            2 23 42 3 3 5 1 */
		635,	/* OBJ_setAttr_SecDevSig            2 23 42 3 3 5 2 */
		436,	/* OBJ_ucl                          0 9 2342 19200300 */
		820,	/* OBJ_id_Gost28147_89_None_KeyMeshing 1 2 643 2 2 14 0 */
		819,	/* OBJ_id_Gost28147_89_CryptoPro_KeyMeshing 1 2 643 2 2 14 1 */
		845,	/* OBJ_id_GostR3410_94_a            1 2 643 2 2 20 1 */
		846,	/* OBJ_id_GostR3410_94_aBis         1 2 643 2 2 20 2 */
		847,	/* OBJ_id_GostR3410_94_b            1 2 643 2 2 20 3 */
		848,	/* OBJ_id_GostR3410_94_bBis         1 2 643 2 2 20 4 */
		821,	/* OBJ_id_GostR3411_94_TestParamSet 1 2 643 2 2 30 0 */
		822,	/* OBJ_id_GostR3411_94_CryptoProParamSet 1 2 643 2 2 30 1 */
		823,	/* OBJ_id_Gost28147_89_TestParamSet 1 2 643 2 2 31 0 */
		824,	/* OBJ_id_Gost28147_89_CryptoPro_A_ParamSet 1 2 643 2 2 31 1 */
		825,	/* OBJ_id_Gost28147_89_CryptoPro_B_ParamSet 1 2 643 2 2 31 2 */
		826,	/* OBJ_id_Gost28147_89_CryptoPro_C_ParamSet 1 2 643 2 2 31 3 */
		827,	/* OBJ_id_Gost28147_89_CryptoPro_D_ParamSet 1 2 643 2 2 31 4 */
		828,	/* OBJ_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet 1 2 643 2 2 31 5 */
		829,	/* OBJ_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet 1 2 643 2 2 31 6 */
		830,	/* OBJ_id_Gost28147_89_CryptoPro_RIC_1_ParamSet 1 2 643 2 2 31 7 */
		831,	/* OBJ_id_GostR3410_94_TestParamSet 1 2 643 2 2 32 0 */
		832,	/* OBJ_id_GostR3410_94_CryptoPro_A_ParamSet 1 2 643 2 2 32 2 */
		833,	/* OBJ_id_GostR3410_94_CryptoPro_B_ParamSet 1 2 643 2 2 32 3 */
		834,	/* OBJ_id_GostR3410_94_CryptoPro_C_ParamSet 1 2 643 2 2 32 4 */
		835,	/* OBJ_id_GostR3410_94_CryptoPro_D_ParamSet 1 2 643 2 2 32 5 */
		836,	/* OBJ_id_GostR3410_94_CryptoPro_XchA_ParamSet 1 2 643 2 2 33 1 */
		837,	/* OBJ_id_GostR3410_94_CryptoPro_XchB_ParamSet 1 2 643 2 2 33 2 */
		838,	/* OBJ_id_GostR3410_94_CryptoPro_XchC_ParamSet 1 2 643 2 2 33 3 */
		839,	/* OBJ_id_GostR3410_2001_TestParamSet 1 2 643 2 2 35 0 */
		840,	/* OBJ_id_GostR3410_2001_CryptoPro_A_ParamSet 1 2 643 2 2 35 1 */
		841,	/* OBJ_id_GostR3410_2001_CryptoPro_B_ParamSet 1 2 643 2 2 35 2 */
		842,	/* OBJ_id_GostR3410_2001_CryptoPro_C_ParamSet 1 2 643 2 2 35 3 */
		843,	/* OBJ_id_GostR3410_2001_CryptoPro_XchA_ParamSet 1 2 643 2 2 36 0 */
		844,	/* OBJ_id_GostR3410_2001_CryptoPro_XchB_ParamSet 1 2 643 2 2 36 1 */
		2,	/* OBJ_pkcs                         1 2 840 113549 1 */
		431,	/* OBJ_hold_instruction_none        1 2 840 10040 2 1 */
		432,	/* OBJ_hold_instruction_call_issuer 1 2 840 10040 2 2 */
		433,	/* OBJ_hold_instruction_reject      1 2 840 10040 2 3 */
		116,	/* OBJ_dsa                          1 2 840 10040 4 1 */
		113,	/* OBJ_dsaWithSHA1                  1 2 840 10040 4 3 */
		406,	/* OBJ_X9_62_prime_field            1 2 840 10045 1 1 */
		407,	/* OBJ_X9_62_characteristic_two_field 1 2 840 10045 1 2 */
		408,	/* OBJ_X9_62_id_ecPublicKey         1 2 840 10045 2 1 */
		416,	/* OBJ_ecdsa_with_SHA1              1 2 840 10045 4 1 */
		791,	/* OBJ_ecdsa_with_Recommended       1 2 840 10045 4 2 */
		792,	/* OBJ_ecdsa_with_Specified         1 2 840 10045 4 3 */
		258,	/* OBJ_id_pkix_mod                  1 3 6 1 5 5 7 0 */
		175,	/* OBJ_id_pe                        1 3 6 1 5 5 7 1 */
		259,	/* OBJ_id_qt                        1 3 6 1 5 5 7 2 */
		128,	/* OBJ_id_kp                        1 3 6 1 5 5 7 3 */
		260,	/* OBJ_id_it                        1 3 6 1 5 5 7 4 */
		261,	/* OBJ_id_pkip                      1 3 6 1 5 5 7 5 */
		262,	/* OBJ_id_alg                       1 3 6 1 5 5 7 6 */
		263,	/* OBJ_id_cmc                       1 3 6 1 5 5 7 7 */
		264,	/* OBJ_id_on                        1 3 6 1 5 5 7 8 */
		265,	/* OBJ_id_pda                       1 3 6 1 5 5 7 9 */
		266,	/* OBJ_id_aca                       1 3 6 1 5 5 7 10 */
		267,	/* OBJ_id_qcs                       1 3 6 1 5 5 7 11 */
		268,	/* OBJ_id_cct                       1 3 6 1 5 5 7 12 */
		662,	/* OBJ_id_ppl                       1 3 6 1 5 5 7 21 */
		176,	/* OBJ_id_ad                        1 3 6 1 5 5 7 48 */
		507,	/* OBJ_id_hex_partial_message       1 3 6 1 7 1 1 1 */
		508,	/* OBJ_id_hex_multipart_message     1 3 6 1 7 1 1 2 */
		57,	/* OBJ_netscape                     2 16 840 1 113730 */
		754,	/* OBJ_camellia_128_ecb             0 3 4401 5 3 1 9 1 */
		766,	/* OBJ_camellia_128_ofb128          0 3 4401 5 3 1 9 3 */
		757,	/* OBJ_camellia_128_cfb128          0 3 4401 5 3 1 9 4 */
		755,	/* OBJ_camellia_192_ecb             0 3 4401 5 3 1 9 21 */
		767,	/* OBJ_camellia_192_ofb128          0 3 4401 5 3 1 9 23 */
		758,	/* OBJ_camellia_192_cfb128          0 3 4401 5 3 1 9 24 */
		756,	/* OBJ_camellia_256_ecb             0 3 4401 5 3 1 9 41 */
		768,	/* OBJ_camellia_256_ofb128          0 3 4401 5 3 1 9 43 */
		759,	/* OBJ_camellia_256_cfb128          0 3 4401 5 3 1 9 44 */
		437,	/* OBJ_pilot                        0 9 2342 19200300 100 */
		776,	/* OBJ_seed_ecb                     1 2 410 200004 1 3 */
		777,	/* OBJ_seed_cbc                     1 2 410 200004 1 4 */
		779,	/* OBJ_seed_cfb128                  1 2 410 200004 1 5 */
		778,	/* OBJ_seed_ofb128                  1 2 410 200004 1 6 */
		852,	/* OBJ_id_GostR3411_94_with_GostR3410_94_cc 1 2 643 2 9 1 3 3 */
		853,	/* OBJ_id_GostR3411_94_with_GostR3410_2001_cc 1 2 643 2 9 1 3 4 */
		850,	/* OBJ_id_GostR3410_94_cc           1 2 643 2 9 1 5 3 */
		851,	/* OBJ_id_GostR3410_2001_cc         1 2 643 2 9 1 5 4 */
		849,	/* OBJ_id_Gost28147_89_cc           1 2 643 2 9 1 6 1 */
		854,	/* OBJ_id_GostR3410_2001_ParamSet_cc 1 2 643 2 9 1 8 1 */
		186,	/* OBJ_pkcs1                        1 2 840 113549 1 1 */
		27,	/* OBJ_pkcs3                        1 2 840 113549 1 3 */
		187,	/* OBJ_pkcs5                        1 2 840 113549 1 5 */
		20,	/* OBJ_pkcs7                        1 2 840 113549 1 7 */
		47,	/* OBJ_pkcs9                        1 2 840 113549 1 9 */
		3,	/* OBJ_md2                          1 2 840 113549 2 2 */
		257,	/* OBJ_md4                          1 2 840 113549 2 4 */
		4,	/* OBJ_md5                          1 2 840 113549 2 5 */
		797,	/* OBJ_hmacWithMD5                  1 2 840 113549 2 6 */
		163,	/* OBJ_hmacWithSHA1                 1 2 840 113549 2 7 */
		798,	/* OBJ_hmacWithSHA224               1 2 840 113549 2 8 */
		799,	/* OBJ_hmacWithSHA256               1 2 840 113549 2 9 */
		800,	/* OBJ_hmacWithSHA384               1 2 840 113549 2 10 */
		801,	/* OBJ_hmacWithSHA512               1 2 840 113549 2 11 */
		37,	/* OBJ_rc2_cbc                      1 2 840 113549 3 2 */
		5,	/* OBJ_rc4                          1 2 840 113549 3 4 */
		44,	/* OBJ_des_ede3_cbc                 1 2 840 113549 3 7 */
		120,	/* OBJ_rc5_cbc                      1 2 840 113549 3 8 */
		643,	/* OBJ_des_cdmf                     1 2 840 113549 3 10 */
		680,	/* OBJ_X9_62_id_characteristic_two_basis 1 2 840 10045 1 2 3 */
		684,	/* OBJ_X9_62_c2pnb163v1             1 2 840 10045 3 0 1 */
		685,	/* OBJ_X9_62_c2pnb163v2             1 2 840 10045 3 0 2 */
		686,	/* OBJ_X9_62_c2pnb163v3             1 2 840 10045 3 0 3 */
		687,	/* OBJ_X9_62_c2pnb176v1             1 2 840 10045 3 0 4 */
		688,	/* OBJ_X9_62_c2tnb191v1             1 2 840 10045 3 0 5 */
		689,	/* OBJ_X9_62_c2tnb191v2             1 2 840 10045 3 0 6 */
		690,	/* OBJ_X9_62_c2tnb191v3             1 2 840 10045 3 0 7 */
		691,	/* OBJ_X9_62_c2onb191v4             1 2 840 10045 3 0 8 */
		692,	/* OBJ_X9_62_c2onb191v5             1 2 840 10045 3 0 9 */
		693,	/* OBJ_X9_62_c2pnb208w1             1 2 840 10045 3 0 10 */
		694,	/* OBJ_X9_62_c2tnb239v1             1 2 840 10045 3 0 11 */
		695,	/* OBJ_X9_62_c2tnb239v2             1 2 840 10045 3 0 12 */
		696,	/* OBJ_X9_62_c2tnb239v3             1 2 840 10045 3 0 13 */
		697,	/* OBJ_X9_62_c2onb239v4             1 2 840 10045 3 0 14 */
		698,	/* OBJ_X9_62_c2onb239v5             1 2 840 10045 3 0 15 */
		699,	/* OBJ_X9_62_c2pnb272w1             1 2 840 10045 3 0 16 */
		700,	/* OBJ_X9_62_c2pnb304w1             1 2 840 10045 3 0 17 */
		701,	/* OBJ_X9_62_c2tnb359v1             1 2 840 10045 3 0 18 */
		702,	/* OBJ_X9_62_c2pnb368w1             1 2 840 10045 3 0 19 */
		703,	/* OBJ_X9_62_c2tnb431r1             1 2 840 10045 3 0 20 */
		409,	/* OBJ_X9_62_prime192v1             1 2 840 10045 3 1 1 */
		410,	/* OBJ_X9_62_prime192v2             1 2 840 10045 3 1 2 */
		411,	/* OBJ_X9_62_prime192v3             1 2 840 10045 3 1 3 */
		412,	/* OBJ_X9_62_prime239v1             1 2 840 10045 3 1 4 */
		413,	/* OBJ_X9_62_prime239v2             1 2 840 10045 3 1 5 */
		414,	/* OBJ_X9_62_prime239v3             1 2 840 10045 3 1 6 */
		415,	/* OBJ_X9_62_prime256v1             1 2 840 10045 3 1 7 */
		793,	/* OBJ_ecdsa_with_SHA224            1 2 840 10045 4 3 1 */
		794,	/* OBJ_ecdsa_with_SHA256            1 2 840 10045 4 3 2 */
		795,	/* OBJ_ecdsa_with_SHA384            1 2 840 10045 4 3 3 */
		796,	/* OBJ_ecdsa_with_SHA512            1 2 840 10045 4 3 4 */
		269,	/* OBJ_id_pkix1_explicit_88         1 3 6 1 5 5 7 0 1 */
		270,	/* OBJ_id_pkix1_implicit_88         1 3 6 1 5 5 7 0 2 */
		271,	/* OBJ_id_pkix1_explicit_93         1 3 6 1 5 5 7 0 3 */
		272,	/* OBJ_id_pkix1_implicit_93         1 3 6 1 5 5 7 0 4 */
		273,	/* OBJ_id_mod_crmf                  1 3 6 1 5 5 7 0 5 */
		274,	/* OBJ_id_mod_cmc                   1 3 6 1 5 5 7 0 6 */
		275,	/* OBJ_id_mod_kea_profile_88        1 3 6 1 5 5 7 0 7 */
		276,	/* OBJ_id_mod_kea_profile_93        1 3 6 1 5 5 7 0 8 */
		277,	/* OBJ_id_mod_cmp                   1 3 6 1 5 5 7 0 9 */
		278,	/* OBJ_id_mod_qualified_cert_88     1 3 6 1 5 5 7 0 10 */
		279,	/* OBJ_id_mod_qualified_cert_93     1 3 6 1 5 5 7 0 11 */
		280,	/* OBJ_id_mod_attribute_cert        1 3 6 1 5 5 7 0 12 */
		281,	/* OBJ_id_mod_timestamp_protocol    1 3 6 1 5 5 7 0 13 */
		282,	/* OBJ_id_mod_ocsp                  1 3 6 1 5 5 7 0 14 */
		283,	/* OBJ_id_mod_dvcs                  1 3 6 1 5 5 7 0 15 */
		284,	/* OBJ_id_mod_cmp2000               1 3 6 1 5 5 7 0 16 */
		177,	/* OBJ_info_access                  1 3 6 1 5 5 7 1 1 */
		285,	/* OBJ_biometricInfo                1 3 6 1 5 5 7 1 2 */
		286,	/* OBJ_qcStatements                 1 3 6 1 5 5 7 1 3 */
		287,	/* OBJ_ac_auditEntity               1 3 6 1 5 5 7 1 4 */
		288,	/* OBJ_ac_targeting                 1 3 6 1 5 5 7 1 5 */
		289,	/* OBJ_aaControls                   1 3 6 1 5 5 7 1 6 */
		290,	/* OBJ_sbgp_ipAddrBlock             1 3 6 1 5 5 7 1 7 */
		291,	/* OBJ_sbgp_autonomousSysNum        1 3 6 1 5 5 7 1 8 */
		292,	/* OBJ_sbgp_routerIdentifier        1 3 6 1 5 5 7 1 9 */
		397,	/* OBJ_ac_proxying                  1 3 6 1 5 5 7 1 10 */
		398,	/* OBJ_sinfo_access                 1 3 6 1 5 5 7 1 11 */
		663,	/* OBJ_proxyCertInfo                1 3 6 1 5 5 7 1 14 */
		164,	/* OBJ_id_qt_cps                    1 3 6 1 5 5 7 2 1 */
		165,	/* OBJ_id_qt_unotice                1 3 6 1 5 5 7 2 2 */
		293,	/* OBJ_textNotice                   1 3 6 1 5 5 7 2 3 */
		129,	/* OBJ_server_auth                  1 3 6 1 5 5 7 3 1 */
		130,	/* OBJ_client_auth                  1 3 6 1 5 5 7 3 2 */
		131,	/* OBJ_code_sign                    1 3 6 1 5 5 7 3 3 */
		132,	/* OBJ_email_protect                1 3 6 1 5 5 7 3 4 */
		294,	/* OBJ_ipsecEndSystem               1 3 6 1 5 5 7 3 5 */
		295,	/* OBJ_ipsecTunnel                  1 3 6 1 5 5 7 3 6 */
		296,	/* OBJ_ipsecUser                    1 3 6 1 5 5 7 3 7 */
		133,	/* OBJ_time_stamp                   1 3 6 1 5 5 7 3 8 */
		180,	/* OBJ_OCSP_sign                    1 3 6 1 5 5 7 3 9 */
		297,	/* OBJ_dvcs                         1 3 6 1 5 5 7 3 10 */
		298,	/* OBJ_id_it_caProtEncCert          1 3 6 1 5 5 7 4 1 */
		299,	/* OBJ_id_it_signKeyPairTypes       1 3 6 1 5 5 7 4 2 */
		300,	/* OBJ_id_it_encKeyPairTypes        1 3 6 1 5 5 7 4 3 */
		301,	/* OBJ_id_it_preferredSymmAlg       1 3 6 1 5 5 7 4 4 */
		302,	/* OBJ_id_it_caKeyUpdateInfo        1 3 6 1 5 5 7 4 5 */
		303,	/* OBJ_id_it_currentCRL             1 3 6 1 5 5 7 4 6 */
		304,	/* OBJ_id_it_unsupportedOIDs        1 3 6 1 5 5 7 4 7 */
		305,	/* OBJ_id_it_subscriptionRequest    1 3 6 1 5 5 7 4 8 */
		306,	/* OBJ_id_it_subscriptionResponse   1 3 6 1 5 5 7 4 9 */
		307,	/* OBJ_id_it_keyPairParamReq        1 3 6 1 5 5 7 4 10 */
		308,	/* OBJ_id_it_keyPairParamRep        1 3 6 1 5 5 7 4 11 */
		309,	/* OBJ_id_it_revPassphrase          1 3 6 1 5 5 7 4 12 */
		310,	/* OBJ_id_it_implicitConfirm        1 3 6 1 5 5 7 4 13 */
		311,	/* OBJ_id_it_confirmWaitTime        1 3 6 1 5 5 7 4 14 */
		312,	/* OBJ_id_it_origPKIMessage         1 3 6 1 5 5 7 4 15 */
		784,	/* OBJ_id_it_suppLangTags           1 3 6 1 5 5 7 4 16 */
		313,	/* OBJ_id_regCtrl                   1 3 6 1 5 5 7 5 1 */
		314,	/* OBJ_id_regInfo                   1 3 6 1 5 5 7 5 2 */
		323,	/* OBJ_id_alg_des40                 1 3 6 1 5 5 7 6 1 */
		324,	/* OBJ_id_alg_noSignature           1 3 6 1 5 5 7 6 2 */
		325,	/* OBJ_id_alg_dh_sig_hmac_sha1      1 3 6 1 5 5 7 6 3 */
		326,	/* OBJ_id_alg_dh_pop                1 3 6 1 5 5 7 6 4 */
		327,	/* OBJ_id_cmc_statusInfo            1 3 6 1 5 5 7 7 1 */
		328,	/* OBJ_id_cmc_identification        1 3 6 1 5 5 7 7 2 */
		329,	/* OBJ_id_cmc_identityProof         1 3 6 1 5 5 7 7 3 */
		330,	/* OBJ_id_cmc_dataReturn            1 3 6 1 5 5 7 7 4 */
		331,	/* OBJ_id_cmc_transactionId         1 3 6 1 5 5 7 7 5 */
		332,	/* OBJ_id_cmc_senderNonce           1 3 6 1 5 5 7 7 6 */
		333,	/* OBJ_id_cmc_recipientNonce        1 3 6 1 5 5 7 7 7 */
		334,	/* OBJ_id_cmc_addExtensions         1 3 6 1 5 5 7 7 8 */
		335,	/* OBJ_id_cmc_encryptedPOP          1 3 6 1 5 5 7 7 9 */
		336,	/* OBJ_id_cmc_decryptedPOP          1 3 6 1 5 5 7 7 10 */
		337,	/* OBJ_id_cmc_lraPOPWitness         1 3 6 1 5 5 7 7 11 */
		338,	/* OBJ_id_cmc_getCert               1 3 6 1 5 5 7 7 15 */
		339,	/* OBJ_id_cmc_getCRL                1 3 6 1 5 5 7 7 16 */
		340,	/* OBJ_id_cmc_revokeRequest         1 3 6 1 5 5 7 7 17 */
		341,	/* OBJ_id_cmc_regInfo               1 3 6 1 5 5 7 7 18 */
		342,	/* OBJ_id_cmc_responseInfo          1 3 6 1 5 5 7 7 19 */
		343,	/* OBJ_id_cmc_queryPending          1 3 6 1 5 5 7 7 21 */
		344,	/* OBJ_id_cmc_popLinkRandom         1 3 6 1 5 5 7 7 22 */
		345,	/* OBJ_id_cmc_popLinkWitness        1 3 6 1 5 5 7 7 23 */
		346,	/* OBJ_id_cmc_confirmCertAcceptance 1 3 6 1 5 5 7 7 24 */
		347,	/* OBJ_id_on_personalData           1 3 6 1 5 5 7 8 1 */
		858,	/* OBJ_id_on_permanentIdentifier    1 3 6 1 5 5 7 8 3 */
		348,	/* OBJ_id_pda_dateOfBirth           1 3 6 1 5 5 7 9 1 */
		349,	/* OBJ_id_pda_placeOfBirth          1 3 6 1 5 5 7 9 2 */
		351,	/* OBJ_id_pda_gender                1 3 6 1 5 5 7 9 3 */
		352,	/* OBJ_id_pda_countryOfCitizenship  1 3 6 1 5 5 7 9 4 */
		353,	/* OBJ_id_pda_countryOfResidence    1 3 6 1 5 5 7 9 5 */
		354,	/* OBJ_id_aca_authenticationInfo    1 3 6 1 5 5 7 10 1 */
		355,	/* OBJ_id_aca_accessIdentity        1 3 6 1 5 5 7 10 2 */
		356,	/* OBJ_id_aca_chargingIdentity      1 3 6 1 5 5 7 10 3 */
		357,	/* OBJ_id_aca_group                 1 3 6 1 5 5 7 10 4 */
		358,	/* OBJ_id_aca_role                  1 3 6 1 5 5 7 10 5 */
		399,	/* OBJ_id_aca_encAttrs              1 3 6 1 5 5 7 10 6 */
		359,	/* OBJ_id_qcs_pkixQCSyntax_v1       1 3 6 1 5 5 7 11 1 */
		360,	/* OBJ_id_cct_crs                   1 3 6 1 5 5 7 12 1 */
		361,	/* OBJ_id_cct_PKIData               1 3 6 1 5 5 7 12 2 */
		362,	/* OBJ_id_cct_PKIResponse           1 3 6 1 5 5 7 12 3 */
		664,	/* OBJ_id_ppl_anyLanguage           1 3 6 1 5 5 7 21 0 */
		665,	/* OBJ_id_ppl_inheritAll            1 3 6 1 5 5 7 21 1 */
		667,	/* OBJ_Independent                  1 3 6 1 5 5 7 21 2 */
		178,	/* OBJ_ad_OCSP                      1 3 6 1 5 5 7 48 1 */
		179,	/* OBJ_ad_ca_issuers                1 3 6 1 5 5 7 48 2 */
		363,	/* OBJ_ad_timeStamping              1 3 6 1 5 5 7 48 3 */
		364,	/* OBJ_ad_dvcs                      1 3 6 1 5 5 7 48 4 */
		785,	/* OBJ_caRepository                 1 3 6 1 5 5 7 48 5 */
		780,	/* OBJ_hmac_md5                     1 3 6 1 5 5 8 1 1 */
		781,	/* OBJ_hmac_sha1                    1 3 6 1 5 5 8 1 2 */
		58,	/* OBJ_netscape_cert_extension      2 16 840 1 113730 1 */
		59,	/* OBJ_netscape_data_type           2 16 840 1 113730 2 */
		438,	/* OBJ_pilotAttributeType           0 9 2342 19200300 100 1 */
		439,	/* OBJ_pilotAttributeSyntax         0 9 2342 19200300 100 3 */
		440,	/* OBJ_pilotObjectClass             0 9 2342 19200300 100 4 */
		441,	/* OBJ_pilotGroups                  0 9 2342 19200300 100 10 */
		108,	/* OBJ_cast5_cbc                    1 2 840 113533 7 66 10 */
		112,	/* OBJ_pbeWithMD5AndCast5_CBC       1 2 840 113533 7 66 12 */
		782,	/* OBJ_id_PasswordBasedMAC          1 2 840 113533 7 66 13 */
		783,	/* OBJ_id_DHBasedMac                1 2 840 113533 7 66 30 */
		6,	/* OBJ_rsaEncryption                1 2 840 113549 1 1 1 */
		7,	/* OBJ_md2WithRSAEncryption         1 2 840 113549 1 1 2 */
		396,	/* OBJ_md4WithRSAEncryption         1 2 840 113549 1 1 3 */
		8,	/* OBJ_md5WithRSAEncryption         1 2 840 113549 1 1 4 */
		65,	/* OBJ_sha1WithRSAEncryption        1 2 840 113549 1 1 5 */
		644,	/* OBJ_rsaOAEPEncryptionSET         1 2 840 113549 1 1 6 */
		919,	/* OBJ_rsaesOaep                    1 2 840 113549 1 1 7 */
		911,	/* OBJ_mgf1                         1 2 840 113549 1 1 8 */
		912,	/* OBJ_rsassaPss                    1 2 840 113549 1 1 10 */
		668,	/* OBJ_sha256WithRSAEncryption      1 2 840 113549 1 1 11 */
		669,	/* OBJ_sha384WithRSAEncryption      1 2 840 113549 1 1 12 */
		670,	/* OBJ_sha512WithRSAEncryption      1 2 840 113549 1 1 13 */
		671,	/* OBJ_sha224WithRSAEncryption      1 2 840 113549 1 1 14 */
		28,	/* OBJ_dhKeyAgreement               1 2 840 113549 1 3 1 */
		9,	/* OBJ_pbeWithMD2AndDES_CBC         1 2 840 113549 1 5 1 */
		10,	/* OBJ_pbeWithMD5AndDES_CBC         1 2 840 113549 1 5 3 */
		168,	/* OBJ_pbeWithMD2AndRC2_CBC         1 2 840 113549 1 5 4 */
		169,	/* OBJ_pbeWithMD5AndRC2_CBC         1 2 840 113549 1 5 6 */
		170,	/* OBJ_pbeWithSHA1AndDES_CBC        1 2 840 113549 1 5 10 */
		68,	/* OBJ_pbeWithSHA1AndRC2_CBC        1 2 840 113549 1 5 11 */
		69,	/* OBJ_id_pbkdf2                    1 2 840 113549 1 5 12 */
		161,	/* OBJ_pbes2                        1 2 840 113549 1 5 13 */
		162,	/* OBJ_pbmac1                       1 2 840 113549 1 5 14 */
		21,	/* OBJ_pkcs7_data                   1 2 840 113549 1 7 1 */
		22,	/* OBJ_pkcs7_signed                 1 2 840 113549 1 7 2 */
		23,	/* OBJ_pkcs7_enveloped              1 2 840 113549 1 7 3 */
		24,	/* OBJ_pkcs7_signedAndEnveloped     1 2 840 113549 1 7 4 */
		25,	/* OBJ_pkcs7_digest                 1 2 840 113549 1 7 5 */
		26,	/* OBJ_pkcs7_encrypted              1 2 840 113549 1 7 6 */
		48,	/* OBJ_pkcs9_emailAddress           1 2 840 113549 1 9 1 */
		49,	/* OBJ_pkcs9_unstructuredName       1 2 840 113549 1 9 2 */
		50,	/* OBJ_pkcs9_contentType            1 2 840 113549 1 9 3 */
		51,	/* OBJ_pkcs9_messageDigest          1 2 840 113549 1 9 4 */
		52,	/* OBJ_pkcs9_signingTime            1 2 840 113549 1 9 5 */
		53,	/* OBJ_pkcs9_countersignature       1 2 840 113549 1 9 6 */
		54,	/* OBJ_pkcs9_challengePassword      1 2 840 113549 1 9 7 */
		55,	/* OBJ_pkcs9_unstructuredAddress    1 2 840 113549 1 9 8 */
		56,	/* OBJ_pkcs9_extCertAttributes      1 2 840 113549 1 9 9 */
		172,	/* OBJ_ext_req                      1 2 840 113549 1 9 14 */
		167,	/* OBJ_SMIMECapabilities            1 2 840 113549 1 9 15 */
		188,	/* OBJ_SMIME                        1 2 840 113549 1 9 16 */
		156,	/* OBJ_friendlyName                 1 2 840 113549 1 9 20 */
		157,	/* OBJ_localKeyID                   1 2 840 113549 1 9 21 */
		681,	/* OBJ_X9_62_onBasis                1 2 840 10045 1 2 3 1 */
		682,	/* OBJ_X9_62_tpBasis                1 2 840 10045 1 2 3 2 */
		683,	/* OBJ_X9_62_ppBasis                1 2 840 10045 1 2 3 3 */
		417,	/* OBJ_ms_csp_name                  1 3 6 1 4 1 311 17 1 */
		856,	/* OBJ_LocalKeySet                  1 3 6 1 4 1 311 17 2 */
		390,	/* OBJ_dcObject                     1 3 6 1 4 1 1466 344 */
		91,	/* OBJ_bf_cbc                       1 3 6 1 4 1 3029 1 2 */
		315,	/* OBJ_id_regCtrl_regToken          1 3 6 1 5 5 7 5 1 1 */
		316,	/* OBJ_id_regCtrl_authenticator     1 3 6 1 5 5 7 5 1 2 */
		317,	/* OBJ_id_regCtrl_pkiPublicationInfo 1 3 6 1 5 5 7 5 1 3 */
		318,	/* OBJ_id_regCtrl_pkiArchiveOptions 1 3 6 1 5 5 7 5 1 4 */
		319,	/* OBJ_id_regCtrl_oldCertID         1 3 6 1 5 5 7 5 1 5 */
		320,	/* OBJ_id_regCtrl_protocolEncrKey   1 3 6 1 5 5 7 5 1 6 */
		321,	/* OBJ_id_regInfo_utf8Pairs         1 3 6 1 5 5 7 5 2 1 */
		322,	/* OBJ_id_regInfo_certReq           1 3 6 1 5 5 7 5 2 2 */
		365,	/* OBJ_id_pkix_OCSP_basic           1 3 6 1 5 5 7 48 1 1 */
		366,	/* OBJ_id_pkix_OCSP_Nonce           1 3 6 1 5 5 7 48 1 2 */
		367,	/* OBJ_id_pkix_OCSP_CrlID           1 3 6 1 5 5 7 48 1 3 */
		368,	/* OBJ_id_pkix_OCSP_acceptableResponses 1 3 6 1 5 5 7 48 1 4 */
		369,	/* OBJ_id_pkix_OCSP_noCheck         1 3 6 1 5 5 7 48 1 5 */
		370,	/* OBJ_id_pkix_OCSP_archiveCutoff   1 3 6 1 5 5 7 48 1 6 */
		371,	/* OBJ_id_pkix_OCSP_serviceLocator  1 3 6 1 5 5 7 48 1 7 */
		372,	/* OBJ_id_pkix_OCSP_extendedStatus  1 3 6 1 5 5 7 48 1 8 */
		373,	/* OBJ_id_pkix_OCSP_valid           1 3 6 1 5 5 7 48 1 9 */
		374,	/* OBJ_id_pkix_OCSP_path            1 3 6 1 5 5 7 48 1 10 */
		375,	/* OBJ_id_pkix_OCSP_trustRoot       1 3 6 1 5 5 7 48 1 11 */
		418,	/* OBJ_aes_128_ecb                  2 16 840 1 101 3 4 1 1 */
		419,	/* OBJ_aes_128_cbc                  2 16 840 1 101 3 4 1 2 */
		420,	/* OBJ_aes_128_ofb128               2 16 840 1 101 3 4 1 3 */
		421,	/* OBJ_aes_128_cfb128               2 16 840 1 101 3 4 1 4 */
		788,	/* OBJ_id_aes128_wrap               2 16 840 1 101 3 4 1 5 */
		895,	/* OBJ_aes_128_gcm                  2 16 840 1 101 3 4 1 6 */
		896,	/* OBJ_aes_128_ccm                  2 16 840 1 101 3 4 1 7 */
		897,	/* OBJ_id_aes128_wrap_pad           2 16 840 1 101 3 4 1 8 */
		422,	/* OBJ_aes_192_ecb                  2 16 840 1 101 3 4 1 21 */
		423,	/* OBJ_aes_192_cbc                  2 16 840 1 101 3 4 1 22 */
		424,	/* OBJ_aes_192_ofb128               2 16 840 1 101 3 4 1 23 */
		425,	/* OBJ_aes_192_cfb128               2 16 840 1 101 3 4 1 24 */
		789,	/* OBJ_id_aes192_wrap               2 16 840 1 101 3 4 1 25 */
		898,	/* OBJ_aes_192_gcm                  2 16 840 1 101 3 4 1 26 */
		899,	/* OBJ_aes_192_ccm                  2 16 840 1 101 3 4 1 27 */
		900,	/* OBJ_id_aes192_wrap_pad           2 16 840 1 101 3 4 1 28 */
		426,	/* OBJ_aes_256_ecb                  2 16 840 1 101 3 4 1 41 */
		427,	/* OBJ_aes_256_cbc                  2 16 840 1 101 3 4 1 42 */
		428,	/* OBJ_aes_256_ofb128               2 16 840 1 101 3 4 1 43 */
		429,	/* OBJ_aes_256_cfb128               2 16 840 1 101 3 4 1 44 */
		790,	/* OBJ_id_aes256_wrap               2 16 840 1 101 3 4 1 45 */
		901,	/* OBJ_aes_256_gcm                  2 16 840 1 101 3 4 1 46 */
		902,	/* OBJ_aes_256_ccm                  2 16 840 1 101 3 4 1 47 */
		903,	/* OBJ_id_aes256_wrap_pad           2 16 840 1 101 3 4 1 48 */
		672,	/* OBJ_sha256                       2 16 840 1 101 3 4 2 1 */
		673,	/* OBJ_sha384                       2 16 840 1 101 3 4 2 2 */
		674,	/* OBJ_sha512                       2 16 840 1 101 3 4 2 3 */
		675,	/* OBJ_sha224                       2 16 840 1 101 3 4 2 4 */
		802,	/* OBJ_dsa_with_SHA224              2 16 840 1 101 3 4 3 1 */
		803,	/* OBJ_dsa_with_SHA256              2 16 840 1 101 3 4 3 2 */
		71,	/* OBJ_netscape_cert_type           2 16 840 1 113730 1 1 */
		72,	/* OBJ_netscape_base_url            2 16 840 1 113730 1 2 */
		73,	/* OBJ_netscape_revocation_url      2 16 840 1 113730 1 3 */
		74,	/* OBJ_netscape_ca_revocation_url   2 16 840 1 113730 1 4 */
		75,	/* OBJ_netscape_renewal_url         2 16 840 1 113730 1 7 */
		76,	/* OBJ_netscape_ca_policy_url       2 16 840 1 113730 1 8 */
		77,	/* OBJ_netscape_ssl_server_name     2 16 840 1 113730 1 12 */
		78,	/* OBJ_netscape_comment             2 16 840 1 113730 1 13 */
		79,	/* OBJ_netscape_cert_sequence       2 16 840 1 113730 2 5 */
		139,	/* OBJ_ns_sgc                       2 16 840 1 113730 4 1 */
		458,	/* OBJ_userId                       0 9 2342 19200300 100 1 1 */
		459,	/* OBJ_textEncodedORAddress         0 9 2342 19200300 100 1 2 */
		460,	/* OBJ_rfc822Mailbox                0 9 2342 19200300 100 1 3 */
		461,	/* OBJ_info                         0 9 2342 19200300 100 1 4 */
		462,	/* OBJ_favouriteDrink               0 9 2342 19200300 100 1 5 */
		463,	/* OBJ_roomNumber                   0 9 2342 19200300 100 1 6 */
		464,	/* OBJ_photo                        0 9 2342 19200300 100 1 7 */
		465,	/* OBJ_userClass                    0 9 2342 19200300 100 1 8 */
		466,	/* OBJ_host                         0 9 2342 19200300 100 1 9 */
		467,	/* OBJ_manager                      0 9 2342 19200300 100 1 10 */
		468,	/* OBJ_documentIdentifier           0 9 2342 19200300 100 1 11 */
		469,	/* OBJ_documentTitle                0 9 2342 19200300 100 1 12 */
		470,	/* OBJ_documentVersion              0 9 2342 19200300 100 1 13 */
		471,	/* OBJ_documentAuthor               0 9 2342 19200300 100 1 14 */
		472,	/* OBJ_documentLocation             0 9 2342 19200300 100 1 15 */
		473,	/* OBJ_homeTelephoneNumber          0 9 2342 19200300 100 1 20 */
		474,	/* OBJ_secretary                    0 9 2342 19200300 100 1 21 */
		475,	/* OBJ_otherMailbox                 0 9 2342 19200300 100 1 22 */
		476,	/* OBJ_lastModifiedTime             0 9 2342 19200300 100 1 23 */
		477,	/* OBJ_lastModifiedBy               0 9 2342 19200300 100 1 24 */
		391,	/* OBJ_domainComponent              0 9 2342 19200300 100 1 25 */
		478,	/* OBJ_aRecord                      0 9 2342 19200300 100 1 26 */
		479,	/* OBJ_pilotAttributeType27         0 9 2342 19200300 100 1 27 */
		480,	/* OBJ_mXRecord                     0 9 2342 19200300 100 1 28 */
		481,	/* OBJ_nSRecord                     0 9 2342 19200300 100 1 29 */
		482,	/* OBJ_sOARecord                    0 9 2342 19200300 100 1 30 */
		483,	/* OBJ_cNAMERecord                  0 9 2342 19200300 100 1 31 */
		484,	/* OBJ_associatedDomain             0 9 2342 19200300 100 1 37 */
		485,	/* OBJ_associatedName               0 9 2342 19200300 100 1 38 */
		486,	/* OBJ_homePostalAddress            0 9 2342 19200300 100 1 39 */
		487,	/* OBJ_personalTitle                0 9 2342 19200300 100 1 40 */
		488,	/* OBJ_mobileTelephoneNumber        0 9 2342 19200300 100 1 41 */
		489,	/* OBJ_pagerTelephoneNumber         0 9 2342 19200300 100 1 42 */
		490,	/* OBJ_friendlyCountryName          0 9 2342 19200300 100 1 43 */
		491,	/* OBJ_organizationalStatus         0 9 2342 19200300 100 1 45 */
		492,	/* OBJ_janetMailbox                 0 9 2342 19200300 100 1 46 */
		493,	/* OBJ_mailPreferenceOption         0 9 2342 19200300 100 1 47 */
		494,	/* OBJ_buildingName                 0 9 2342 19200300 100 1 48 */
		495,	/* OBJ_dSAQuality                   0 9 2342 19200300 100 1 49 */
		496,	/* OBJ_singleLevelQuality           0 9 2342 19200300 100 1 50 */
		497,	/* OBJ_subtreeMinimumQuality        0 9 2342 19200300 100 1 51 */
		498,	/* OBJ_subtreeMaximumQuality        0 9 2342 19200300 100 1 52 */
		499,	/* OBJ_personalSignature            0 9 2342 19200300 100 1 53 */
		500,	/* OBJ_dITRedirect                  0 9 2342 19200300 100 1 54 */
		501,	/* OBJ_audio                        0 9 2342 19200300 100 1 55 */
		502,	/* OBJ_documentPublisher            0 9 2342 19200300 100 1 56 */
		442,	/* OBJ_iA5StringSyntax              0 9 2342 19200300 100 3 4 */
		443,	/* OBJ_caseIgnoreIA5StringSyntax    0 9 2342 19200300 100 3 5 */
		444,	/* OBJ_pilotObject                  0 9 2342 19200300 100 4 3 */
		445,	/* OBJ_pilotPerson                  0 9 2342 19200300 100 4 4 */
		446,	/* OBJ_account                      0 9 2342 19200300 100 4 5 */
		447,	/* OBJ_document                     0 9 2342 19200300 100 4 6 */
		448,	/* OBJ_room                         0 9 2342 19200300 100 4 7 */
		449,	/* OBJ_documentSeries               0 9 2342 19200300 100 4 9 */
		392,	/* OBJ_Domain                       0 9 2342 19200300 100 4 13 */
		450,	/* OBJ_rFC822localPart              0 9 2342 19200300 100 4 14 */
		451,	/* OBJ_dNSDomain                    0 9 2342 19200300 100 4 15 */
		452,	/* OBJ_domainRelatedObject          0 9 2342 19200300 100 4 17 */
		453,	/* OBJ_friendlyCountry              0 9 2342 19200300 100 4 18 */
		454,	/* OBJ_simpleSecurityObject         0 9 2342 19200300 100 4 19 */
		455,	/* OBJ_pilotOrganization            0 9 2342 19200300 100 4 20 */
		456,	/* OBJ_pilotDSA                     0 9 2342 19200300 100 4 21 */
		457,	/* OBJ_qualityLabelledData          0 9 2342 19200300 100 4 22 */
		189,	/* OBJ_id_smime_mod                 1 2 840 113549 1 9 16 0 */
		190,	/* OBJ_id_smime_ct                  1 2 840 113549 1 9 16 1 */
		191,	/* OBJ_id_smime_aa                  1 2 840 113549 1 9 16 2 */
		192,	/* OBJ_id_smime_alg                 1 2 840 113549 1 9 16 3 */
		193,	/* OBJ_id_smime_cd                  1 2 840 113549 1 9 16 4 */
		194,	/* OBJ_id_smime_spq                 1 2 840 113549 1 9 16 5 */
		195,	/* OBJ_id_smime_cti                 1 2 840 113549 1 9 16 6 */
		158,	/* OBJ_x509Certificate              1 2 840 113549 1 9 22 1 */
		159,	/* OBJ_sdsiCertificate              1 2 840 113549 1 9 22 2 */
		160,	/* OBJ_x509Crl                      1 2 840 113549 1 9 23 1 */
		144,	/* OBJ_pbe_WithSHA1And128BitRC4     1 2 840 113549 1 12 1 1 */
		145,	/* OBJ_pbe_WithSHA1And40BitRC4      1 2 840 113549 1 12 1 2 */
		146,	/* OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC 1 2 840 113549 1 12 1 3 */
		147,	/* OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC 1 2 840 113549 1 12 1 4 */
		148,	/* OBJ_pbe_WithSHA1And128BitRC2_CBC 1 2 840 113549 1 12 1 5 */
		149,	/* OBJ_pbe_WithSHA1And40BitRC2_CBC  1 2 840 113549 1 12 1 6 */
		171,	/* OBJ_ms_ext_req                   1 3 6 1 4 1 311 2 1 14 */
		134,	/* OBJ_ms_code_ind                  1 3 6 1 4 1 311 2 1 21 */
		135,	/* OBJ_ms_code_com                  1 3 6 1 4 1 311 2 1 22 */
		136,	/* OBJ_ms_ctl_sign                  1 3 6 1 4 1 311 10 3 1 */
		137,	/* OBJ_ms_sgc                       1 3 6 1 4 1 311 10 3 3 */
		138,	/* OBJ_ms_efs                       1 3 6 1 4 1 311 10 3 4 */
		648,	/* OBJ_ms_smartcard_login           1 3 6 1 4 1 311 20 2 2 */
		649,	/* OBJ_ms_upn                       1 3 6 1 4 1 311 20 2 3 */
		751,	/* OBJ_camellia_128_cbc             1 2 392 200011 61 1 1 1 2 */
		752,	/* OBJ_camellia_192_cbc             1 2 392 200011 61 1 1 1 3 */
		753,	/* OBJ_camellia_256_cbc             1 2 392 200011 61 1 1 1 4 */
		907,	/* OBJ_id_camellia128_wrap          1 2 392 200011 61 1 1 3 2 */
		908,	/* OBJ_id_camellia192_wrap          1 2 392 200011 61 1 1 3 3 */
		909,	/* OBJ_id_camellia256_wrap          1 2 392 200011 61 1 1 3 4 */
		196,	/* OBJ_id_smime_mod_cms             1 2 840 113549 1 9 16 0 1 */
		197,	/* OBJ_id_smime_mod_ess             1 2 840 113549 1 9 16 0 2 */
		198,	/* OBJ_id_smime_mod_oid             1 2 840 113549 1 9 16 0 3 */
		199,	/* OBJ_id_smime_mod_msg_v3          1 2 840 113549 1 9 16 0 4 */
		200,	/* OBJ_id_smime_mod_ets_eSignature_88 1 2 840 113549 1 9 16 0 5 */
		201,	/* OBJ_id_smime_mod_ets_eSignature_97 1 2 840 113549 1 9 16 0 6 */
		202,	/* OBJ_id_smime_mod_ets_eSigPolicy_88 1 2 840 113549 1 9 16 0 7 */
		203,	/* OBJ_id_smime_mod_ets_eSigPolicy_97 1 2 840 113549 1 9 16 0 8 */
		204,	/* OBJ_id_smime_ct_receipt          1 2 840 113549 1 9 16 1 1 */
		205,	/* OBJ_id_smime_ct_authData         1 2 840 113549 1 9 16 1 2 */
		206,	/* OBJ_id_smime_ct_publishCert      1 2 840 113549 1 9 16 1 3 */
		207,	/* OBJ_id_smime_ct_TSTInfo          1 2 840 113549 1 9 16 1 4 */
		208,	/* OBJ_id_smime_ct_TDTInfo          1 2 840 113549 1 9 16 1 5 */
		209,	/* OBJ_id_smime_ct_contentInfo      1 2 840 113549 1 9 16 1 6 */
		210,	/* OBJ_id_smime_ct_DVCSRequestData  1 2 840 113549 1 9 16 1 7 */
		211,	/* OBJ_id_smime_ct_DVCSResponseData 1 2 840 113549 1 9 16 1 8 */
		786,	/* OBJ_id_smime_ct_compressedData   1 2 840 113549 1 9 16 1 9 */
		787,	/* OBJ_id_ct_asciiTextWithCRLF      1 2 840 113549 1 9 16 1 27 */
		212,	/* OBJ_id_smime_aa_receiptRequest   1 2 840 113549 1 9 16 2 1 */
		213,	/* OBJ_id_smime_aa_securityLabel    1 2 840 113549 1 9 16 2 2 */
		214,	/* OBJ_id_smime_aa_mlExpandHistory  1 2 840 113549 1 9 16 2 3 */
		215,	/* OBJ_id_smime_aa_contentHint      1 2 840 113549 1 9 16 2 4 */
		216,	/* OBJ_id_smime_aa_msgSigDigest     1 2 840 113549 1 9 16 2 5 */
		217,	/* OBJ_id_smime_aa_encapContentType 1 2 840 113549 1 9 16 2 6 */
		218,	/* OBJ_id_smime_aa_contentIdentifier 1 2 840 113549 1 9 16 2 7 */
		219,	/* OBJ_id_smime_aa_macValue         1 2 840 113549 1 9 16 2 8 */
		220,	/* OBJ_id_smime_aa_equivalentLabels 1 2 840 113549 1 9 16 2 9 */
		221,	/* OBJ_id_smime_aa_contentReference 1 2 840 113549 1 9 16 2 10 */
		222,	/* OBJ_id_smime_aa_encrypKeyPref    1 2 840 113549 1 9 16 2 11 */
		223,	/* OBJ_id_smime_aa_signingCertificate 1 2 840 113549 1 9 16 2 12 */
		224,	/* OBJ_id_smime_aa_smimeEncryptCerts 1 2 840 113549 1 9 16 2 13 */
		225,	/* OBJ_id_smime_aa_timeStampToken   1 2 840 113549 1 9 16 2 14 */
		226,	/* OBJ_id_smime_aa_ets_sigPolicyId  1 2 840 113549 1 9 16 2 15 */
		227,	/* OBJ_id_smime_aa_ets_commitmentType 1 2 840 113549 1 9 16 2 16 */
		228,	/* OBJ_id_smime_aa_ets_signerLocation 1 2 840 113549 1 9 16 2 17 */
		229,	/* OBJ_id_smime_aa_ets_signerAttr   1 2 840 113549 1 9 16 2 18 */
		230,	/* OBJ_id_smime_aa_ets_otherSigCert 1 2 840 113549 1 9 16 2 19 */
		231,	/* OBJ_id_smime_aa_ets_contentTimestamp 1 2 840 113549 1 9 16 2 20 */
		232,	/* OBJ_id_smime_aa_ets_CertificateRefs 1 2 840 113549 1 9 16 2 21 */
		233,	/* OBJ_id_smime_aa_ets_RevocationRefs 1 2 840 113549 1 9 16 2 22 */
		234,	/* OBJ_id_smime_aa_ets_certValues   1 2 840 113549 1 9 16 2 23 */
		235,	/* OBJ_id_smime_aa_ets_revocationValues 1 2 840 113549 1 9 16 2 24 */
		236,	/* OBJ_id_smime_aa_ets_escTimeStamp 1 2 840 113549 1 9 16 2 25 */
		237,	/* OBJ_id_smime_aa_ets_certCRLTimestamp 1 2 840 113549 1 9 16 2 26 */
		238,	/* OBJ_id_smime_aa_ets_archiveTimeStamp 1 2 840 113549 1 9 16 2 27 */
		239,	/* OBJ_id_smime_aa_signatureType    1 2 840 113549 1 9 16 2 28 */
		240,	/* OBJ_id_smime_aa_dvcs_dvc         1 2 840 113549 1 9 16 2 29 */
		241,	/* OBJ_id_smime_alg_ESDHwith3DES    1 2 840 113549 1 9 16 3 1 */
		242,	/* OBJ_id_smime_alg_ESDHwithRC2     1 2 840 113549 1 9 16 3 2 */
		243,	/* OBJ_id_smime_alg_3DESwrap        1 2 840 113549 1 9 16 3 3 */
		244,	/* OBJ_id_smime_alg_RC2wrap         1 2 840 113549 1 9 16 3 4 */
		245,	/* OBJ_id_smime_alg_ESDH            1 2 840 113549 1 9 16 3 5 */
		246,	/* OBJ_id_smime_alg_CMS3DESwrap     1 2 840 113549 1 9 16 3 6 */
		247,	/* OBJ_id_smime_alg_CMSRC2wrap      1 2 840 113549 1 9 16 3 7 */
		125,	/* OBJ_zlib_compression             1 2 840 113549 1 9 16 3 8 */
		893,	/* OBJ_id_alg_PWRI_KEK              1 2 840 113549 1 9 16 3 9 */
		248,	/* OBJ_id_smime_cd_ldap             1 2 840 113549 1 9 16 4 1 */
		249,	/* OBJ_id_smime_spq_ets_sqt_uri     1 2 840 113549 1 9 16 5 1 */
		250,	/* OBJ_id_smime_spq_ets_sqt_unotice 1 2 840 113549 1 9 16 5 2 */
		251,	/* OBJ_id_smime_cti_ets_proofOfOrigin 1 2 840 113549 1 9 16 6 1 */
		252,	/* OBJ_id_smime_cti_ets_proofOfReceipt 1 2 840 113549 1 9 16 6 2 */
		253,	/* OBJ_id_smime_cti_ets_proofOfDelivery 1 2 840 113549 1 9 16 6 3 */
		254,	/* OBJ_id_smime_cti_ets_proofOfSender 1 2 840 113549 1 9 16 6 4 */
		255,	/* OBJ_id_smime_cti_ets_proofOfApproval 1 2 840 113549 1 9 16 6 5 */
		256,	/* OBJ_id_smime_cti_ets_proofOfCreation 1 2 840 113549 1 9 16 6 6 */
		150,	/* OBJ_keyBag                       1 2 840 113549 1 12 10 1 1 */
		151,	/* OBJ_pkcs8ShroudedKeyBag          1 2 840 113549 1 12 10 1 2 */
		152,	/* OBJ_certBag                      1 2 840 113549 1 12 10 1 3 */
		153,	/* OBJ_crlBag                       1 2 840 113549 1 12 10 1 4 */
		154,	/* OBJ_secretBag                    1 2 840 113549 1 12 10 1 5 */
		155,	/* OBJ_safeContentsBag              1 2 840 113549 1 12 10 1 6 */
		34,	/* OBJ_idea_cbc                     1 3 6 1 4 1 188 7 1 1 2 */
	};
	
#else
	static const unsigned char lvalues[1];
	static const ASN1_OBJECT nid_objs[1];
	static const unsigned int sn_objs[1];
	static const unsigned int ln_objs[1];
	static const unsigned int obj_objs[1];
#endif

	DECLARE_LHASH_OF(ADDED_OBJ);
	
	static int new_nid=NUM_NID;
	static LHASH_OF(ADDED_OBJ) *added=NULL;
	static STACK_OF(ASN1_STRING_TABLE) *stable = NULL;
	
	static void (*free_func)(void *)            = free;
	

	/********** Headers **********/ 
	
	typedef int (*LHASH_COMP_FN_TYPE)(const void *, const void *);
	typedef unsigned long (*LHASH_HASH_FN_TYPE)(const void *);
	
	typedef struct lhash_node_st
	{
		void *data;
		struct lhash_node_st *next;
#ifndef OPENSSL_NO_HASH_COMP
		unsigned long hash;
#endif
	} LHASH_NODE;
	
	typedef struct lhash_st
	{
		LHASH_NODE **b;
		LHASH_COMP_FN_TYPE comp;
		LHASH_HASH_FN_TYPE hash;
		unsigned int num_nodes;
		unsigned int num_alloc_nodes;
		unsigned int p;
		unsigned int pmax;
		unsigned long up_load; /* load times 256 */
		unsigned long down_load; /* load times 256 */
		unsigned long num_items;
		
		unsigned long num_expands;
		unsigned long num_expand_reallocs;
		unsigned long num_contracts;
		unsigned long num_contract_reallocs;
		unsigned long num_hash_calls;
		unsigned long num_comp_calls;
		unsigned long num_insert;
		unsigned long num_replace;
		unsigned long num_delete;
		unsigned long num_no_delete;
		unsigned long num_retrieve;
		unsigned long num_retrieve_miss;
		unsigned long num_hash_comps;
		
		int error;
	} _LHASH;	/* Do not use _LHASH directly, use LHASH_OF*/
	
	
	_LHASH *lh_new(LHASH_HASH_FN_TYPE h, LHASH_COMP_FN_TYPE c);
	
	void *lh_retrieve(_LHASH *lh, const void *data);
	void *lh_delete(_LHASH *lh, const void *data);
	
	/* file: _dopr : /Volumes/work/Phd/ECDH/kv_openssl/crypto/biob_print.c */
	static void _dopr(char **sbuffer, char **buffer,
					  size_t *maxlen, size_t *retlen, int *truncated,
					  const char *format, va_list args);
	
	static STACK_OF(CRYPTO_dynlock) *dyn_locks=NULL;
	static const ERR_FNS *err_fns = NULL;
	
	static void *ec_pre_comp_dup(void *);
	static void ec_pre_comp_free(void *);
	static void ec_pre_comp_clear_free(void *);
	unsigned long ASN1_tag2bit(int tag);
	void *sk_set(_STACK *, int, void *);
	
	static int in_utf8(unsigned long value, void *arg);
	static int out_utf8(unsigned long value, void *arg);
	static int type_str(unsigned long value, void *arg);
	static int cpy_asc(unsigned long value, void *arg);
	static int cpy_bmp(unsigned long value, void *arg);
	static int cpy_univ(unsigned long value, void *arg);
	static int cpy_utf8(unsigned long value, void *arg);
	
	/*static void ssleay_rand_cleanup(void);
	static void ssleay_rand_seed(const void *buf, int num);
	static void ssleay_rand_add(const void *buf, int num, double add_entropy);
	static int ssleay_rand_bytes(unsigned char *buf, int num, int pseudo);
	static int ssleay_rand_nopseudo_bytes(unsigned char *buf, int num);
	static int ssleay_rand_pseudo_bytes(unsigned char *buf, int num);
	static int ssleay_rand_status(void);*/
	
	RAND_METHOD rand_ssleay_meth={
	/*	ssleay_rand_seed,
		ssleay_rand_nopseudo_bytes,
		ssleay_rand_cleanup,
		ssleay_rand_add,
		ssleay_rand_pseudo_bytes,
		ssleay_rand_status*/
	};
	_STACK *sk_new_null(void);
	
	void *lh_insert(_LHASH *lh, void *data);
	
	static int ipv6_cb(const char *elem, int len, void *usr);
	
	static int bitstr_cb(const char *elem, int len, void *bitstr);
	
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
	
	/* file: EC_KEY_new_by_curve_name : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
	EC_KEY *EC_KEY_new_by_curve_name(int nid);
	
	/* file: EC_KEY_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
	EC_KEY *EC_KEY_new(void);
	
	/* file: CRYPTO_THREADID_current : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	void CRYPTO_THREADID_current(CRYPTO_THREADID *id);
	
	/* file: threadid_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
	static void (MS_FAR *threadid_callback)(CRYPTO_THREADID *)=0;
	
	/* file: id_callback : /Volumes/work/Phd/ECDH/kv_openssl/cryptocryptlib.c */
#ifndef OPENSSL_NO_DEPRECATED
	static unsigned long (MS_FAR *id_callback)(void)=0;
#endif
	
	/* file: a2i_GENERAL_NAME : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
	GENERAL_NAME *a2i_GENERAL_NAME(GENERAL_NAME *out,
								   const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
								   int gen_type, char *value, int is_nc);
	
	/* file: ERR_get_state : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
	ERR_STATE *ERR_get_state(void);
	
	/* file: ERR_STATE_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.c */
	static void ERR_STATE_free(ERR_STATE *s);
	
	/* file: app_info_free : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem_dbg.c */
	static void app_info_free(APP_INFO *);
	
	/* file: free_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	int CRYPTO_set_locked_mem_functions(void *(*m)(size_t), void (*free_func)(void *));
	
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
	
	/* file: BN_new : /Volumes/work/Phd/ECDH/kv_openssl/crypto/bnbn.h */
	BIGNUM *BN_new(void);
	
	/* file: LHASH_OF : /Volumes/work/Phd/ECDH/kv_openssl/appsopenssl.c */
	static LHASH_OF(FUNCTION) *prog_init(void );
	
	/* file: engine_unlocked_init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
	int engine_unlocked_init(ENGINE *e);
	
	/* file: init : /Volumes/work/Phd/ECDH/kv_openssl/crypto/evpevp.h */
	int (*init)(EVP_PKEY_CTX *ctx);
	
	/* file: engine_unlocked_finish : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
	int engine_unlocked_finish(ENGINE *e, int unlock_for_handlers);
	
	/* file: engine_free_util : /Volumes/work/Phd/ECDH/kv_openssl/crypto/engineeng_int.h */
	int engine_free_util(ENGINE *e, int locked);
	
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
	
	/* file: ASN1_OBJECT_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
	void		ASN1_OBJECT_free(ASN1_OBJECT *a);
	
	/* file: ERR_add_error_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
	void ERR_add_error_data(int num, ...);
	
	/* file: ERR_add_error_vdata : /Volumes/work/Phd/ECDH/kv_openssl/crypto/errerr.h */
	void ERR_add_error_vdata(int num, va_list args); 
	
	/* file: realloc_func : /Volumes/work/Phd/ECDH/kv_openssl/cryptomem.c */
	static void *(*realloc_func)(void *, size_t)= realloc;
	
	/* file: a2i_IPADDRESS_NC : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
	ASN1_OCTET_STRING *a2i_IPADDRESS_NC(const char *ipasc);
	
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
	
	/* file: ASN1_STRING_set : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
	int 		ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);
	
	/* file: ASN1_STRING_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
	void		ASN1_STRING_free(ASN1_STRING *a);
	
	/* file: ASN1_mbstring_copy : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
	int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
						   int inform, unsigned long mask);
	
	/* file: X509_NAME_add_entry : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
	int 		X509_NAME_add_entry(X509_NAME *name,X509_NAME_ENTRY *ne,
									int loc, int set);
	
	/* file: X509_NAME_ENTRY_dup : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509x509.h */
	X509_NAME_ENTRY *X509_NAME_ENTRY_dup(X509_NAME_ENTRY *ne);
	
	/* file: sk_insert : /Volumes/work/Phd/ECDH/kv_openssl/crypto/stackstack.h */
	int sk_insert(_STACK *sk, void *data, int where);
	
	/* file: X509V3_section_free : /Volumes/work/Phd/ECDH/kv_openssl/crypto/x509v3x509v3.h */
	void X509V3_section_free( X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section);
	
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
		
	static void impl_check(void);	
	
	/* file: ASN1_TIME_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
	int ASN1_TIME_check(ASN1_TIME *t);
	
	/* file: ASN1_GENERALIZEDTIME_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
	int ASN1_GENERALIZEDTIME_check(ASN1_GENERALIZEDTIME *a);
	
	/* file: ASN1_UTCTIME_check : /Volumes/work/Phd/ECDH/kv_openssl/crypto/asn1asn1.h */
	int ASN1_UTCTIME_check(ASN1_UTCTIME *a);	
	
	/* file: CRYPTO_get_dynlock_value : /Volumes/work/Phd/ECDH/kv_openssl/cryptocrypto.h */
	struct CRYPTO_dynlock_value *CRYPTO_get_dynlock_value(int i);
	
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
	int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
	
	
	/* file: EC_KEY_insert_key_method_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec.h */
	void *EC_KEY_insert_key_method_data(EC_KEY *key, void *data,
										void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));
	
	/* file: EC_EX_DATA_set_data : /Volumes/work/Phd/ECDH/kv_openssl/crypto/ecec_lcl.h */
	int EC_EX_DATA_set_data(EC_EXTRA_DATA **, void *data,
							void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));
	
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
	
	/* DSA stuff */
	static	DSA_SIG * surewarehk_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa);
	
	static signed char *compute_wNAF(const BIGNUM *scalar, int w, size_t *ret_len);
	static int int_table_check(ENGINE_TABLE **t, int create);
	static ECDH_DATA *ECDH_DATA_new_method(ENGINE *engine);
	static int bn_rand_range(int pseudo, BIGNUM *r, const BIGNUM *range);
	static EC_GROUP *ec_group_new_from_data(const ec_list_element curve);
	static BN_ULONG *bn_expand_internal(const BIGNUM *b, int words);
	static int internal_find(_STACK *st, void *data, int ret_val_options);
	ASN1_INTEGER *s2i_ASN1_INTEGER(X509V3_EXT_METHOD *method, char *value);
	int     BN_rand(BIGNUM *rnd, int bits, int top,int bottom);
	
	int STORE_method_set_initialise_function(STORE_METHOD *sm, STORE_INITIALISE_FUNC_PTR init_f);
	int STORE_method_set_cleanup_function( STORE_METHOD *sm, STORE_CLEANUP_FUNC_PTR clean_f);
	int STORE_method_set_generate_function( STORE_METHOD *sm, STORE_GENERATE_OBJECT_FUNC_PTR generate_f);
	int STORE_method_set_get_function(STORE_METHOD *sm, STORE_GET_OBJECT_FUNC_PTR get_f);
	int STORE_method_set_store_function( STORE_METHOD *sm, STORE_STORE_OBJECT_FUNC_PTR store_f);
	int STORE_method_set_modify_function( STORE_METHOD *sm, STORE_MODIFY_OBJECT_FUNC_PTR store_f);
	int STORE_method_set_revoke_function( STORE_METHOD *sm, STORE_HANDLE_OBJECT_FUNC_PTR revoke_f);
	int STORE_method_set_delete_function( STORE_METHOD *sm, STORE_HANDLE_OBJECT_FUNC_PTR delete_f);
	int STORE_method_set_list_start_function( STORE_METHOD *sm, STORE_START_OBJECT_FUNC_PTR list_start_f);
	int STORE_method_set_list_next_function( STORE_METHOD *sm, STORE_NEXT_OBJECT_FUNC_PTR list_next_f);
	int STORE_method_set_list_end_function( STORE_METHOD *sm, STORE_END_OBJECT_FUNC_PTR list_end_f);
	int STORE_method_set_update_store_function( STORE_METHOD *sm, STORE_GENERIC_FUNC_PTR);
	int STORE_method_set_lock_store_function( STORE_METHOD *sm, STORE_GENERIC_FUNC_PTR);
	int STORE_method_set_unlock_store_function( STORE_METHOD *sm, STORE_GENERIC_FUNC_PTR);
	int STORE_method_set_ctrl_function( STORE_METHOD *sm, STORE_CTRL_FUNC_PTR ctrl_f);
	
	STORE_INITIALISE_FUNC_PTR STORE_method_get_initialise_function( STORE_METHOD *sm);
	STORE_CLEANUP_FUNC_PTR STORE_method_get_cleanup_function( STORE_METHOD *sm);
	STORE_GENERATE_OBJECT_FUNC_PTR STORE_method_get_generate_function( STORE_METHOD *sm);
	STORE_GET_OBJECT_FUNC_PTR STORE_method_get_get_function( STORE_METHOD *sm);
	STORE_STORE_OBJECT_FUNC_PTR STORE_method_get_store_function( STORE_METHOD *sm);
	STORE_MODIFY_OBJECT_FUNC_PTR STORE_method_get_modify_function( STORE_METHOD *sm);
	STORE_HANDLE_OBJECT_FUNC_PTR STORE_method_get_revoke_function( STORE_METHOD *sm);
	STORE_HANDLE_OBJECT_FUNC_PTR STORE_method_get_delete_function( STORE_METHOD *sm);
	STORE_START_OBJECT_FUNC_PTR STORE_method_get_list_start_function( STORE_METHOD *sm);
	STORE_NEXT_OBJECT_FUNC_PTR STORE_method_get_list_next_function( STORE_METHOD *sm);
	STORE_END_OBJECT_FUNC_PTR STORE_method_get_list_end_function( STORE_METHOD *sm);
	STORE_GENERIC_FUNC_PTR STORE_method_get_update_store_function( STORE_METHOD *sm);
	STORE_GENERIC_FUNC_PTR STORE_method_get_lock_store_function( STORE_METHOD *sm);
	STORE_GENERIC_FUNC_PTR STORE_method_get_unlock_store_function( STORE_METHOD *sm);
	STORE_CTRL_FUNC_PTR STORE_method_get_ctrl_function( STORE_METHOD *sm);
	
	int ec_GFp_simple_group_init(EC_GROUP *);
	void ec_GFp_simple_group_finish(EC_GROUP *);
	void ec_GFp_simple_group_clear_finish(EC_GROUP *);
	int ec_GFp_simple_group_copy(EC_GROUP *, const EC_GROUP *);
	int ec_GFp_simple_group_set_curve(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
	int ec_GFp_simple_group_get_curve(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);
	int ec_GFp_simple_group_get_degree(const EC_GROUP *);
	int ec_GFp_simple_group_check_discriminant(const EC_GROUP *, BN_CTX *);
	int ec_GFp_simple_point_init(EC_POINT *);
	void ec_GFp_simple_point_finish(EC_POINT *);
	void ec_GFp_simple_point_clear_finish(EC_POINT *);
	int ec_GFp_simple_point_copy(EC_POINT *, const EC_POINT *);
	int ec_GFp_simple_point_set_to_infinity(const EC_GROUP *, EC_POINT *);
	int ec_GFp_simple_set_Jprojective_coordinates_GFp(const EC_GROUP *, EC_POINT *,
													  const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *);
	int ec_GFp_simple_get_Jprojective_coordinates_GFp(const EC_GROUP *, const EC_POINT *,
													  BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *);
	int ec_GFp_simple_point_set_affine_coordinates(const EC_GROUP *, EC_POINT *,
												   const BIGNUM *x, const BIGNUM *y, BN_CTX *);
	int ec_GFp_simple_point_get_affine_coordinates(const EC_GROUP *, const EC_POINT *,
												   BIGNUM *x, BIGNUM *y, BN_CTX *);
	
	static void *ecdh_data_dup(void *);
												   											   
	int ec_GFp_nist_group_copy(EC_GROUP *dest, const EC_GROUP *src);
	int ec_GFp_nist_group_set_curve(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
	int ec_GFp_nist_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
	int ec_GFp_nist_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
																							   											   											   
	int ec_GFp_simple_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
	int ec_GFp_simple_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
	int ec_GFp_simple_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);
	int ec_GFp_simple_is_at_infinity(const EC_GROUP *, const EC_POINT *);
	int ec_GFp_simple_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
	int ec_GFp_simple_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
	int ec_GFp_simple_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
	int ec_GFp_simple_points_make_affine(const EC_GROUP *group, size_t num, EC_POINT *points[], BN_CTX *ctx);
	
	int ec_GFp_simple_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
	int ec_GFp_simple_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
	
	static int out_utf8(unsigned long value, void *arg);
	
#ifdef __cplusplus
}
#endif	
