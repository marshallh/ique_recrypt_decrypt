//
// ique_recrypt_decrypt 0.1
// 2018 marshallh
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aes.h"
#include "sha1.h"

// little endian host platform is assumed, nop this if you're big endian
#define BYTESWAP_32(x)  ((x >> 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x << 24))

/*
void decrypt_sk(char *infilename, char *outfilename, uint8_t *skey, uint8_t *siv);
void decrypt_sa(char *infilename, char *outfilename, uint8_t *ckey, struct cmd *sa_cmd, unsigned char *sa_hash, int offset);*/
void decrypt_recentry(uint8_t *rec_entry, uint8_t *key, uint32_t content_id);

void die(char *reason);
int parse_hex_to_char(char *inp, char *outp, int len);
void print_key(char *msg, uint8_t *key);
void print_recentry(char *msg, uint8_t *recentry);
void print_hash(char *msg, uint8_t *hash);

/* these structs are not named correctly, just enough to get the job done */
typedef struct {
	uint32_t		dat[5];
} BbShaHash;

typedef struct {
	uint8_t			dat[64];
} BbEccPublicKey;

typedef struct {
	uint32_t		id;
} BbId;

typedef struct {
	uint8_t			dat[32];
} BbEccPrivateKey;

typedef struct {
	uint8_t			dat[16];
} BbAesKey;

typedef struct {
	BbShaHash skHash;
	uint32_t romPatch[16];
	BbEccPublicKey publicKey;
	BbId bbId;
	BbEccPrivateKey privateKey;
	BbAesKey bootAppKey;
	BbAesKey recryptListKey;
	BbAesKey appStateKey;
	BbAesKey selfMsgKey;
	uint32_t csumAdjust;
	uint32_t jtagEnable;
} BbOtp;

int verbose = 0;
                         
int main(int argc, char* argv[])
{
	int ca;
	int i;
	int z;

	char filename_otp[256] = { 0, };
	char filename_rec[256] = { 0, };
	char filename_recout[256] = { 0, };

	FILE *fp_otp;
	FILE *fp_rec;
	FILE *fp_recout;

	BbOtp otp;

	uint8_t rec_entry[32];
	uint8_t rec_empty[32 - 4] = {0, };

	uint32_t content_id = 0;
	uint32_t content_id_also_check = 0;
	uint32_t content_ids[] = { 
		5101, 
		4101,
		6101, 
		1101,
		2101,
		5201,
		5202,
		1102,
		2102,
		4102,
		5102,
		1201,
		2105,
		2104,
		2103,
		2106,
		0
	};

	char *content_ids_str_en[] = {
		"Wave Race 64",
		"Star Fox 64",
		"Dr. Mario 64",
		"Super Mario 64",
		"The Legend of Zelda: Ocarina of Time",
		"Mario Kart 64",
		"F-Zero X",
		"Yoshi's Story",
		"Paper Mario",
		"Sin and Punishment: Successor of the Earth",
		"Excitebike 64",
		"Super Smash Bros.",
		"Custom Robo",
		"Animal Crossing",
		"The Legend of Zelda: Majora's Mask",
		"The Legend of Zelda: Ocarina of Time (Traditional Chinese)",
		0
	};

	int num_rec_entries;
	uint32_t bbid;
	
	printf("ique_recrypt_decrypt 0.1 by marshallh\n");
	printf("-------------------------------------\n");
	if (argc == 1){
		printf("Arguments: ique_recrypt_decrypt\n");

		printf("\t -otp <otp.bin>\n");
		printf("\t -rec <recrypt.sys from same console>\n");
		printf("\t -recout <decrypted rec output>\n");
	
		printf("\nFor each recrypted title slot in the file details will be printed.\n");
	}
	
	for (ca = 1; ca < argc; ca++){
		if (!strcmp(argv[ca], "-otp")) {
			if (++ca < argc ) sscanf(argv[ca], "%s", filename_otp);
			else {printf("No filename specified for otp"); return -1;}
		} else if (!strcmp(argv[ca], "-rec")) {
			if (++ca < argc) sscanf(argv[ca], "%s", filename_rec);
			else {printf("No rec filename specified"); return -1;}
		} else if (!strcmp(argv[ca], "-recout")) {
			if (++ca < argc) sscanf(argv[ca], "%s", filename_recout);
			else printf("No rec out filename specified"); 
		} else if(!strcmp(argv[ca], "-v")) {
			verbose = 1;
		}
	}
	if (filename_otp[0] == 0) die("No filename specified for otp");
	if (filename_rec[0] == 0) die("No filename specified for rec");
	

	printf("* Opening OTP binary %s\n", filename_otp);
	fp_otp = fopen(filename_otp, "rb"); if (fp_otp == NULL) die("Couldn't open inputfile");
	fread(&otp, sizeof(otp), 1, fp_otp);
	printf("- OTP was dumped from a console with BBID of %08X\n", BYTESWAP_32(otp.bbId.id));
	if(verbose) printf("- OTP was dumped from a console with jtagEnable of %08X\n", BYTESWAP_32(otp.jtagEnable));
	bbid = BYTESWAP_32(otp.bbId.id);

	printf("* Opening REC binary %s\n", filename_rec);
	fp_rec = fopen(filename_rec, "rb"); if (fp_rec == NULL) die("Couldn't open inputfile");

	printf("* Opening RECout binary %s\n", filename_recout);
	fp_recout = fopen(filename_recout, "wb"); if (fp_recout == NULL) die("Couldn't open outputfile");


	fseek(fp_rec, 0x40, SEEK_SET);
	fread(&num_rec_entries, 4, 1, fp_rec);
	num_rec_entries = BYTESWAP_32(num_rec_entries);
	printf("* Found %d recrypt entries in this file\n", num_rec_entries);

	for (i = 0; i < num_rec_entries; i++) {
		
		// read the slot from file
		fread(rec_entry, 32, 1, fp_rec);
		if (verbose) {
			printf("- Checking slot %d\n", i);
			printf("- REC entry %d is raw: ", i);
			print_recentry("", rec_entry);
		}

		decrypt_recentry(rec_entry, otp.recryptListKey.dat, bbid);
		content_id = rec_entry[0] << 24 | rec_entry[1] << 16 | rec_entry[2] << 8 | rec_entry[3] << 0;

		printf("* Entry %d:\n", i);
		printf("  Content ID   : %d (0x%08X)\n", content_id, content_id);
		// try to look up the game name in the list
		z = 0;
		while (1){
			if (content_ids[z] == (content_id / 1000)){
				printf("  Content name : %s\n", content_ids_str_en[z]);
				break;
			}
			z++;
			// check if we already reached the end of known CIDs
			if (content_ids[z] == 0) break;
		}
		printf("  Content key  :");
		print_key("", &rec_entry[4]);

		if (verbose) {
			printf("- REC entry %d is dec: ", i);
			print_recentry("", rec_entry);
			printf("---\n");
		}		
	}

	fclose(fp_otp);
	fclose(fp_rec);
	fclose(fp_recout);

	printf("* Done\n");
	return 0;
}

void decrypt_recentry(uint8_t *rec_entry, uint8_t *key, uint32_t content_id)
{
	struct AES_ctx ctx;
	uint8_t rec_iv[16];

	for (int j = 0; j < 4; j++){
		rec_iv[0 + j * 4] = (content_id >> 24) & 0xFF;
		rec_iv[1 + j * 4] = (content_id >> 16) & 0xFF;
		rec_iv[2 + j * 4] = (content_id >> 8) & 0xFF;
		rec_iv[3 + j * 4] = ((content_id >> 0) & 0xFF) + j;
	}
	if (verbose)  {
		printf("Trying to decrypt entry with contentid %d\n", content_id);
		print_key("REC Key: ", key);
		print_key("REC IV : ", rec_iv);
	}

	AES_init_ctx_iv(&ctx, key, rec_iv);
	AES_CBC_decrypt_buffer(&ctx, rec_entry, 32);
}


void die(char *reason)
{
	printf("\nDIE: %s, exiting\n", reason);
	exit(-1);
}

int parse_hex_to_char(char *inp, char *outp, int len)
{
	char *src = inp;
	char *dst = outp;
	char *end = outp + len;
	unsigned int u;

	while (dst < end && sscanf(src, "%2x", &u) == 1){
		*dst++ = u;
		src += 2;
	}
	return 0;
}

void print_key(char *msg, uint8_t *key)
{
	//if (!verbose) return;
	printf("%s ", msg);
	for (int k = 0; k <16; k++) { 
		printf("%02X", key[k]);
	} 
	printf("\n");
}

void print_recentry(char *msg, uint8_t *recentry)
{
	if (!verbose) return;
	printf("%s ", msg);
	for (int k = 0; k <32; k++) {
		printf("%02X", recentry[k]);
	}
	printf("\n");
}

void print_hash(char *msg, uint8_t *hash)
{
	if (!verbose) return;
	printf("%s ", msg);
	for (int k = 0; k < 20; k++) {
		printf("%02X", hash[k]);
	}
	printf("\n");
}



