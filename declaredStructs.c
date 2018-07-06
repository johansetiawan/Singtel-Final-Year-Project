
//msg0 and msg1 concatenated into one message with no other redundant variables
//unlinkable attestation for msg2
//for sigrl check against ':' as delimiter 

#pragma pack(1)
typedef struct server_msg0
{
	unsigned char  type[50];     /* set to one of ra_msg_type_t*/
    uint32_t    epid;
}server_msg0;

typedef struct server_msg1
{
    unsigned char  type[50];     /* set to one of ra_msg_type_t*/
    sgx_epid_group_id_t      gid[4];         /* the Endian-ness of GID is Little-Endian */
}server_msg1;


typedef struct server_msg3
{
	unsigned char  type[50];
    sgx_ps_sec_prop_desc_t   ps_sec_prop; //define as 0 as not required
    uint8_t		quote[];
}server_msg3;

typedef struct client_msg2
{
	unsigned char  type[50];
    uint8_t spid[16];
    uint16_t quote_type;
    uint32_t sig_rl_size;
    uint8_t sig_rl[];
}client_msg2;

typedef struct messageSIGRL
{
    unsigned char type[50];
    unsigned char *sig;
    unsigned int siglength;
    unsigned char gidURL[83];

}messageSIGRL;

typedef struct client_msg4
{
	unsigned char  type[50];
	unsigned char attestation_status[50];
} client_msg4;

typedef struct attestation_result
{
	unsigned char  type[50];
    uint32_t                id;
    unsigned char      status[50];
    unsigned char		revocation_error[256];
    unsigned char        pse_status[50];
    uint32_t                policy_report_size;
    uint8_t                 policy_report[];// IAS_Q: Why does it specify a
                                            // list of reports?
} attestation_result;

	