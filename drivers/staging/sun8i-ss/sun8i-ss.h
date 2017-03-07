#include <crypto/aes.h>
#include <crypto/akcipher.h>
#include <crypto/skcipher.h>
#include <crypto/engine.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/internal/rsa.h>
#include <linux/crypto.h>
#include <linux/hw_random.h>
#include <linux/scatterlist.h>

/* CE Registers */
#define CE_TDQ	0x00
#define CE_CTR	0x04
#define CE_ICR	0x08
#define CE_ISR	0x0C
#define CE_TLR	0x10
#define CE_TSR	0x14
#define CE_ESR	0x18
#define CE_CSSGR	0x1C
#define CE_CDSGR	0x20
#define CE_CSAR	0x24
#define CE_CDAR	0x28
#define CE_TPR	0x2C

/* Operation direction - bit 8 */
#define SS_ENCRYPTION		0
#define SS_DECRYPTION		BIT(8)

/* CE Method H3/A64 */
#define CE_OP_AES		0
#define CE_OP_DES		1
#define CE_OP_3DES		2
#define CE_OP_MD5		16
#define CE_OP_SHA1		17
#define CE_OP_SHA224		18
#define CE_OP_SHA256		19
#define CE_OP_SHA384		20
#define CE_OP_SHA512		21
#define CE_OP_TRNG		48
#define CE_OP_PRNG		49

/* SS Method A83T */
#define SS_OP_AES		0
#define SS_OP_DES		1
#define SS_OP_3DES		2
#define SS_OP_MD5		3
#define SS_OP_PRNG		4
#define SS_OP_SHA1		6
#define SS_OP_SHA224		7
#define SS_OP_SHA256		8

/* A80/A83T SS Registers */
#define SS_CTL_REG		0x00
#define SS_INT_CTL_REG		0x04
#define SS_INT_STA_REG		0x08
#define SS_KEY_ADR_REG		0x10
#define SS_IV_ADR_REG		0x18
#define SS_SRC_ADR_REG		0x20
#define SS_DST_ADR_REG		0x28
#define SS_LEN_ADR_REG		0x30

#define CE_ID_HASH_MD5		1
#define CE_ID_HASH_SHA1		2
#define CE_ID_HASH_SHA224	3
#define CE_ID_HASH_SHA256	4
#define CE_ID_HASH_SHA384	5
#define CE_ID_HASH_SHA512	6
#define CE_ID_HASH_MAX		7
#define CE_ID_NOTSUPP		0xFF

#define CE_ID_CIPHER_AES	1
#define CE_ID_CIPHER_DES	2
#define CE_ID_CIPHER_3DES	3
#define CE_ID_CIPHER_MAX	4

#define CE_ID_MODE_ECB	1
#define CE_ID_MODE_CBC	2
#define CE_ID_MODE_CTR	3
#define CE_ID_MODE_CTS	4
#define CE_ID_MODE_OFB	5
#define CE_ID_MODE_CFB	6
#define CE_ID_MODE_CBCMAC	7
#define CE_ID_MODE_MAX	8

#define SS_AES_128BITS 0
#define SS_AES_192BITS 1
#define SS_AES_256BITS 2

#define CE_ECB	0
#define CE_CBC	BIT(8)

#define SS_ECB	0
#define SS_CBC	BIT(13)

#define TRNG_DATA_SIZE (256 / 8)
#define PRNG_DATA_SIZE (160 / 8)
#define PRNG_SEED_SIZE ((175 / 8) * 8)

#define MAXCHAN 4
#define MAX_SG 8

struct ce_variant {
	char alg_hash[CE_ID_HASH_MAX];
	char alg_cipher[CE_ID_CIPHER_MAX];
	u32 op_mode[CE_ID_MODE_MAX];
	char prng;
	char trng;
	bool is_ss;
};

struct plop {
	u32 addr;
	u32 len;
} __packed;

struct ss_task {
	u32 t_id;
	u32 t_common_ctl;
	u32 t_sym_ctl;
	u32 t_asym_ctl;
	u32 t_key;
	u32 t_iv;
	u32 t_ctr;
	u32 t_dlen;
	struct plop t_src[MAX_SG];
	struct plop t_dst[MAX_SG];
	u32 next;
	u32 reserved[3];
} __packed __aligned(8);

struct sun8i_ce_chan {
	struct scatterlist *bounce_src;
	struct scatterlist *bounce_dst;
	void *bufsrc;
	void *bufdst;
	/* IV to use */
	void *bounce_iv;
	void *next_iv;
	unsigned int ivlen;
	struct completion complete;
	int status;
	u32 method;
	u32 op_dir;
	u32 op_mode;
	unsigned int keylen;
};

struct sun8i_ce_hwrng {
	const char *name;
	struct hwrng hwrng;
	unsigned int datasize;
	unsigned int seedsize;
	void *seed;
	u32 ce_op;
	struct sun8i_ss_ctx *ss;
	struct random_ready_callback random_ready;
	struct work_struct seed_work;
};

struct sun8i_ss_ctx {
	void __iomem *base;
	void __iomem *nsbase;
	int irq;
	int ns_irq;
	struct clk *busclk;
	struct clk *ssclk;
	struct reset_control *reset;
	struct device *dev;
	struct resource *res;
	struct mutex mlock; /* control the use of the device */
	struct mutex chanlock[MAXCHAN];
	struct ss_task *tl[MAXCHAN] ____cacheline_aligned;
	dma_addr_t ce_t_phy[MAXCHAN] ____cacheline_aligned;
	struct sun8i_ce_chan chanlist[MAXCHAN];
	struct crypto_engine *engines[MAXCHAN];
	int flow; /* flow to use in next request */
	struct sun8i_ce_hwrng prng;
	struct sun8i_ce_hwrng trng;
	const struct ce_variant *variant;
};

struct sun8i_cipher_req_ctx {
	u32 op_dir;
	int flow;
};

struct sun8i_hash_reqctx {
	struct scatterlist *sgbounce[MAX_SG];
	u32 mode;
	u64 byte_count;
	u64 byte_count2;/* for sha384 sha512*/
	u32 *hash;
	char *buf[MAX_SG];
	int sgflag[MAX_SG];
	unsigned long blen;
	unsigned int bsize;
	int flags;
	int cursg;
	struct scatterlist *src_sg;
	/*struct crypto_shash *fallback_tfm;*/
	int flow;
};

struct sun8i_tfm_ctx {
	u32 *key;
	u32 keylen;
	u32 keymode;
	struct sun8i_ss_ctx *ss;
	struct crypto_blkcipher *fallback_tfm;
};

struct sun8i_tfm_rsa_ctx {
	struct sun8i_ss_ctx *ss;
	struct rsa_key rsa_key;
	struct crypto_akcipher *fallback;
};

struct sun8i_ss_alg_template {
	u32 type;
	u32 mode;
	u32 ce_algo_id;
	u32 ce_blockmode;
	const void *hash_init;
	union {
		struct crypto_alg crypto;
		struct ahash_alg hash;
		struct akcipher_alg rsa;
		struct skcipher_alg skc;
	} alg;
	struct sun8i_ss_ctx *ss;
};

int sun8i_ss_cipher(struct ablkcipher_request *areq);
int sun8i_ss_thread(void *data);
int sun8i_ce_enqueue(struct crypto_async_request *areq, u32 type);

int sun8i_hash_init(struct ahash_request *areq);
int sun8i_hash_export_md5(struct ahash_request *areq, void *out);
int sun8i_hash_import_md5(struct ahash_request *areq, const void *in);
int sun8i_hash_export_sha1(struct ahash_request *areq, void *out);
int sun8i_hash_import_sha1(struct ahash_request *areq, const void *in);
int sun8i_hash_export_sha224(struct ahash_request *areq, void *out);
int sun8i_hash_import_sha224(struct ahash_request *areq, const void *in);
int sun8i_hash_export_sha256(struct ahash_request *areq, void *out);
int sun8i_hash_import_sha256(struct ahash_request *areq, const void *in);
int sun8i_hash_export_sha512(struct ahash_request *areq, void *out);
int sun8i_hash_import_sha512(struct ahash_request *areq, const void *in);
int sun8i_hash_update(struct ahash_request *areq);
int sun8i_hash_finup(struct ahash_request *areq);
int sun8i_hash_digest(struct ahash_request *areq);
int sun8i_hash_final(struct ahash_request *areq);
int sun8i_hash_crainit(struct crypto_tfm *tfm);
int sun8i_hash_craexit(struct crypto_tfm *tfm);
int sun8i_hash(struct ahash_request *areq);

int sun8i_ss_compact(struct scatterlist *sg, unsigned int len);
int sun8i_ss_bounce_dst(struct ablkcipher_request *areq, int flow);
int sun8i_ss_bounce_src(struct ablkcipher_request *areq, int flow);

int sun8i_ss_aes_setkey(struct crypto_ablkcipher *tfm, const u8 *key,
			unsigned int keylen);
int sun8i_ss_cipher_init(struct crypto_tfm *tfm);
void sun8i_ss_cipher_exit(struct crypto_tfm *tfm);
int sun8i_ss_cbc_aes_decrypt(struct ablkcipher_request *areq);
int sun8i_ss_cbc_aes_encrypt(struct ablkcipher_request *areq);
int handle_cipher_request(struct crypto_engine *engine,
			  struct ablkcipher_request *breq);

int get_engine_number(struct sun8i_ss_ctx *ss);

int sun8i_rsa_encrypt(struct akcipher_request *req);
int sun8i_rsa_decrypt(struct akcipher_request *req);
int sun8i_rsa_sign(struct akcipher_request *req);
int sun8i_rsa_verify(struct akcipher_request *req);
int sun8i_rsa_set_priv_key(struct crypto_akcipher *tfm, const void *key,
			   unsigned int keylen);
int sun8i_rsa_set_pub_key(struct crypto_akcipher *tfm, const void *key,
			  unsigned int keylen);
int sun8i_rsa_max_size(struct crypto_akcipher *tfm);
int sun8i_rsa_init(struct crypto_akcipher *tfm);
void sun8i_rsa_exit(struct crypto_akcipher *tfm);

int sun8i_ce_run_task(struct sun8i_ss_ctx *ss, int flow, const char *name);

/*int sun8i_ce_hwrng_register(struct hwrng *hwrng);*/
void sun8i_ce_hwrng_unregister(struct hwrng *hwrng);
int sun8i_ce_hwrng_register(struct sun8i_ce_hwrng *h, const char *name,
			    unsigned int seed_size, unsigned int datasize,
			    u32 ce_op, struct sun8i_ss_ctx *ss);
