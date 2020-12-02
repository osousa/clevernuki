#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "include/tweetnacl.h"
#include "include/sha2.h"
#include "include/hmac_sha256.h"
#include <string.h>
#include <sys/time.h>
#include <unistd.h>



#define MAGIC_NUMBER_PAIRING_CONTEXT 3355
#define PAIRING_NONCEBYTES 32
#define MTU_SIZE 36


#define ADATA_LENGTH  30
#define MAX_PDATA_LENGTH  120

#define CHALLENGE_MESSAGE_LENGTH  86
#define CHALLENGE_CMD_PDATA_LENGTH  10
#define ENCRYPTED_CHALLENGE_PDATA_LENGTH  (CHALLENGE_MESSAGE_LENGTH - ADATA_LENGTH)
#define DECRYPTED_CHALLENGE_PDATA_LENGTH  (ENCRYPTED_CHALLENGE_PDATA_LENGTH - crypto_secretbox_MACBYTES)

#define LOCK_ACTION_PDATA_LENGTH 46
#define KEYTURNER_STATE_PDATA_LENGTH 39
#define CLIENT_NONCE_LENGTH crypto_box_NONCEBYTES
#define SMARTLOCK_NONCE_LENGTH 32
#define crypto_secretbox_MACBYTES (crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES)


uint8_t send_buffer[200];

uint8_t public_key_nuki[32];
uint8_t public_key_fob[32];
uint8_t private_key_fob[32];

static const uint16_t request_data_cmd = 0x0001;
static const uint16_t public_key_cmd = 0x0003;
static const uint16_t challenge_cmd = 0x0004;
static const uint16_t authorization_authenticator_cmd = 0x0005;
static const uint16_t authorization_data_cmd = 0x0006;
static const uint16_t lock_action_cmd = 0x000D;
static const uint16_t authorization_id_confirmation_cmd = 0x001E;
static const uint16_t keyturner_states = 0x000C;

static const uint8_t APP_TYPE_FOB = 0x02;


static void (*m_response_callback)(uint8_t*, uint16_t) = NULL;
static uint16_t m_out_message_length = 0;
static uint16_t m_out_message_progress = 0;
static uint8_t m_out_message_buffer[200];

static uint16_t m_expected_response_length = 0;
static uint8_t m_response_message_progress = 0;
static uint8_t m_response_message_buffer[200];
uint16_t enc_pay_size = 0;


enum lock_action {
    unlock = 0x01,
    lock = 0x02,
    unlatch = 0x03,
    lock_n_go = 0x04,
    lock_n_go_with_unlatch = 0x05,
    fob_action_1 = 0x81,
    fob_action_2 = 0x82,
    fob_action_3 = 0x83
};


typedef struct 
{
    uint8_t shared_secret[32];
    uint32_t authorization_id;
    uint32_t app_id;
    uint8_t paired_lock_uuid[6];
    uint16_t magic_number;
} __attribute__((packed, aligned(4))) pairing_context;


typedef struct {
    uint8_t     write_op;
    uint8_t     flags;
    uint16_t    handle;
    uint16_t    offset;
    uint16_t    len;
    uint8_t const *p_value;
} ble_write_params_t ;


static pairing_context pairing_ctx;
void generateNukiMessage(uint8_t* array);
void process_messages(uint16_t connection_handle, uint16_t attribute_handle);

int send_command_bool = 0;

uint32_t get_time_seconds(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}



void printMessage(uint8_t *msg, int size){
    int i = 0; 
    printf("0x");
    for(;i<size; i++){
        printf("%02x", msg[i]);
    }
    printf("\n");
}

// THIS IS BAD, CHANGE ASAP
void randombytes(unsigned char *ptr, unsigned long long length)
{
  int i ; 
  printf("\n\nrandombytes called!!!\n\n");
  //int i;
  uint32_t t = get_time_seconds();

  for(i = 0; i < length; i++){
      ptr[i] = t >> (i*8);
  }
}


void send_with_response(uint8_t* data, uint16_t data_length, uint16_t expected_response_length, void (*callback)(uint8_t*, uint16_t));

void send_with_response(uint8_t* message_out, uint16_t message_out_length, 
    uint16_t expected_response_length, void (*callback)(uint8_t*, uint16_t)) 
{
    memcpy(m_out_message_buffer, message_out, message_out_length);
    m_response_callback = callback;
    m_out_message_progress = 0;
    m_response_message_progress = 0;
    m_expected_response_length = expected_response_length;
    m_out_message_length = message_out_length;
    printf("\nSend with response -- Message Ready || m_out_message_length %d\n", m_out_message_length);
    printMessage(m_out_message_buffer, m_out_message_length);
}

static const uint16_t crc_table [256] = {

0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5,
0x60c6, 0x70e7, 0x8108, 0x9129, 0xa14a, 0xb16b,
0xc18c, 0xd1ad, 0xe1ce, 0xf1ef, 0x1231, 0x0210,
0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c,
0xf3ff, 0xe3de, 0x2462, 0x3443, 0x0420, 0x1401,
0x64e6, 0x74c7, 0x44a4, 0x5485, 0xa56a, 0xb54b,
0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6,
0x5695, 0x46b4, 0xb75b, 0xa77a, 0x9719, 0x8738,
0xf7df, 0xe7fe, 0xd79d, 0xc7bc, 0x48c4, 0x58e5,
0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969,
0xa90a, 0xb92b, 0x5af5, 0x4ad4, 0x7ab7, 0x6a96,
0x1a71, 0x0a50, 0x3a33, 0x2a12, 0xdbfd, 0xcbdc,
0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03,
0x0c60, 0x1c41, 0xedae, 0xfd8f, 0xcdec, 0xddcd,
0xad2a, 0xbd0b, 0x8d68, 0x9d49, 0x7e97, 0x6eb6,
0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a,
0x9f59, 0x8f78, 0x9188, 0x81a9, 0xb1ca, 0xa1eb,
0xd10c, 0xc12d, 0xf14e, 0xe16f, 0x1080, 0x00a1,
0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c,
0xe37f, 0xf35e, 0x02b1, 0x1290, 0x22f3, 0x32d2,
0x4235, 0x5214, 0x6277, 0x7256, 0xb5ea, 0xa5cb,
0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447,
0x5424, 0x4405, 0xa7db, 0xb7fa, 0x8799, 0x97b8,
0xe75f, 0xf77e, 0xc71d, 0xd73c, 0x26d3, 0x36f2,
0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9,
0xb98a, 0xa9ab, 0x5844, 0x4865, 0x7806, 0x6827,
0x18c0, 0x08e1, 0x3882, 0x28a3, 0xcb7d, 0xdb5c,
0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0,
0x2ab3, 0x3a92, 0xfd2e, 0xed0f, 0xdd6c, 0xcd4d,
0xbdaa, 0xad8b, 0x9de8, 0x8dc9, 0x7c26, 0x6c07,
0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba,
0x8fd9, 0x9ff8, 0x6e17, 0x7e36, 0x4e55, 0x5e74,
0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};


// Cyclic Redundancy Check function. Nothing else. 
uint16_t crc_16(uint8_t *data, uint32_t length, uint16_t initial_remainder)
{ 
   uint32_t count;
   uint16_t crc = initial_remainder;
   uint16_t temp;

   for (count = 0; count < length; count++)
   {
     temp = (*data++ ^ (crc >> 8)) & 0xff;
     crc = crc_table[temp] ^ (crc << 8);
   }
   return crc;
} 


uint16_t read_uint16LE(uint8_t* buffer, const uint32_t byte_offset) 
{
    uint16_t value = 0;
    value |= buffer[byte_offset+1] << 8;
    value |= buffer[byte_offset]; 
    return value;
}




// lkasd maklsdnals dalksdna lskdalksdnalksdn 
uint32_t read_uint32LE(uint8_t* buffer, const uint32_t byte_offset) 
{
    uint32_t value = 0;
    value |= buffer[byte_offset+3] << 24;
    value |= buffer[byte_offset+2] << 16;
    value |= buffer[byte_offset+1] << 8;
    value |= buffer[byte_offset]; 
    return value;
}




// Same as below. Let me practice a bit to better understand 
void write_uint8LE(uint8_t* buffer, const uint8_t value, const uint32_t byte_offset) 
{
    buffer[byte_offset] = value;
}




// Write to unsigned int 8 bit ... INCOMPLETE comment 
void write_uint16LE(uint8_t* buffer, const uint16_t value, const uint32_t byte_offset) 
{
    write_uint8LE(buffer, value & 0xFF, byte_offset);
    write_uint8LE(buffer, (value >> +8) & 0xFF, byte_offset+1);
}





// aisd lansd mansjda sdnajsd asdjk 
void write_uint32LE(uint8_t* buffer, const uint32_t value, const uint32_t byte_offset) 
{
    //fix for arm cortex m-0 where you can't write 32bit values between 4 byte boundaries
    write_uint8LE(buffer, value & 0xFF, byte_offset);
    write_uint8LE(buffer, (value >> +8) & 0xFF, byte_offset+1);
    write_uint8LE(buffer, (value >> +16) & 0xFF, byte_offset+2);
    write_uint8LE(buffer, (value >> +24) & 0xFF, byte_offset+3);
}





static uint16_t encrypt_payload(uint8_t* output_buffer, uint8_t* pdata_unencrypted, uint16_t pdata_length) {
    if(pdata_length > MAX_PDATA_LENGTH) {return 0;}
    uint8_t adata[ADATA_LENGTH];
    randombytes(adata, 24); //generate nonce
    write_uint32LE(adata, pairing_ctx.authorization_id, 24);
    write_uint16LE(adata, pdata_length + crypto_secretbox_MACBYTES, 28);
    
    uint16_t pdataCRC = crc_16(pdata_unencrypted, pdata_length-2, 0xFFFF);
    write_uint16LE(pdata_unencrypted, pdataCRC, pdata_length-2);

    uint8_t pdata_encrypted_with_padding[crypto_secretbox_ZEROBYTES + MAX_PDATA_LENGTH];
    memset(pdata_encrypted_with_padding, 0, crypto_secretbox_ZEROBYTES);
    memcpy(&pdata_encrypted_with_padding[32], pdata_unencrypted, pdata_length); //fill pdata_encrypted with pdata_unencrypted, encrypt in-place
    uint8_t* pdata_encrypted = &pdata_encrypted_with_padding[crypto_secretbox_BOXZEROBYTES];
    crypto_secretbox(
        pdata_encrypted_with_padding, 
        pdata_encrypted_with_padding, 
        crypto_secretbox_ZEROBYTES + pdata_length, 
        adata, //adata[0] to adata[23] contains the nonce
        pairing_ctx.shared_secret);

    memcpy(output_buffer, adata, ADATA_LENGTH);
    memcpy(output_buffer+ADATA_LENGTH, pdata_encrypted, pdata_length + crypto_secretbox_MACBYTES);
    return ADATA_LENGTH + pdata_length + crypto_secretbox_MACBYTES;
}


void thisDoesNothing(){
}

static bool decrypt_challenge(uint8_t* out_nonce, uint8_t* encrypted_challenge) {
    uint8_t decryption_buffer[ENCRYPTED_CHALLENGE_PDATA_LENGTH+crypto_box_ZEROBYTES];
    memset(decryption_buffer, 0, crypto_secretbox_BOXZEROBYTES);

    //check the size entry in adata
    printf("read_uint16LE(encrypted_challenge, 28) (%d) !=  ENCRYPTED_CHALLENGE_PDATA_LENGTH (%d)\n",read_uint16LE(encrypted_challenge, 28), ENCRYPTED_CHALLENGE_PDATA_LENGTH);
    if(read_uint16LE(encrypted_challenge, 28) != ENCRYPTED_CHALLENGE_PDATA_LENGTH) { return false; }
    //encrypted message contains
    //[0]: nonce (24 bytes)
    //[24]: auth_id (4 bytes)
    //[28]: length (2 bytes)
    //[30]: encrypted_pdata ((encrypted_message_length - 30) bytes)
    memcpy(&decryption_buffer[crypto_secretbox_BOXZEROBYTES], &encrypted_challenge[30], ENCRYPTED_CHALLENGE_PDATA_LENGTH); //decrypt in-place

    int32_t result = crypto_secretbox_open(
        decryption_buffer, 
        decryption_buffer, 
        crypto_secretbox_BOXZEROBYTES + ENCRYPTED_CHALLENGE_PDATA_LENGTH, 
        encrypted_challenge, //encrypted_message[0] to encrypted_message[23] contains the nonce
        pairing_ctx.shared_secret);
        
    if(result != 0) { return false; }

    uint8_t* decrypted_message = &decryption_buffer[crypto_box_ZEROBYTES];
    uint16_t crc_offset = DECRYPTED_CHALLENGE_PDATA_LENGTH - 2;
    uint16_t crc = crc_16(decrypted_message, crc_offset, 0xFFFF);
    if(read_uint16LE(decrypted_message, crc_offset) != crc || read_uint32LE(decrypted_message, 0) != pairing_ctx.authorization_id) {
        return false;
    }

    memcpy(out_nonce, &(decrypted_message[6]), SMARTLOCK_NONCE_LENGTH);
    return true;
}




static bool decrypt_keystate(uint8_t* out_nonce, uint8_t* encrypted_challenge) {
    uint8_t decryption_buffer[39+crypto_box_ZEROBYTES];
    memset(decryption_buffer, 0, crypto_secretbox_BOXZEROBYTES);

    //check the size entry in adata
    printf("read_uint16LE(encrypted_challenge, 28) %d != 39 (%d)  \n",read_uint16LE(encrypted_challenge, 28), 39);
    if(read_uint16LE(encrypted_challenge, 28) != 39) { return false; }
    //encrypted message contains
    //[0]: nonce (24 bytes)
    //[24]: auth_id (4 bytes)
    //[28]: length (2 bytes)
    //[30]: encrypted_pdata ((encrypted_message_length - 30) bytes)
    memcpy(&decryption_buffer[crypto_secretbox_BOXZEROBYTES], &encrypted_challenge[30], 39); //decrypt in-place

    printMessage(&encrypted_challenge[30],39); 

    int32_t result = crypto_secretbox_open(
        decryption_buffer, 
        decryption_buffer, 
        crypto_secretbox_BOXZEROBYTES + 39, 
        encrypted_challenge, //encrypted_message[0] to encrypted_message[23] contains the nonce
        pairing_ctx.shared_secret);
        

    printf("\n\nRESULT : %d\n", result);

    if(result != 0) { return false; }

    uint8_t* decrypted_message = &decryption_buffer[crypto_box_ZEROBYTES];

    printf("\n\n...........................................................................................................\n\n");
    printMessage(decrypted_message, 15);

    uint16_t crc_offset = 30 - 2;
    uint16_t crc = crc_16(decrypted_message, crc_offset, 0xFFFF);
    if(read_uint16LE(decrypted_message, crc_offset) != crc || read_uint32LE(decrypted_message, 0) != pairing_ctx.authorization_id) {
        return false;
    }

    memcpy(out_nonce, &(decrypted_message[6]), SMARTLOCK_NONCE_LENGTH);
    return true;
}



uint16_t create_keyturner_state_payload(uint8_t* output_buffer) {
    uint8_t pdata_unencrypted[CHALLENGE_CMD_PDATA_LENGTH];
    write_uint32LE(pdata_unencrypted, pairing_ctx.authorization_id, 0);
    write_uint16LE(pdata_unencrypted, request_data_cmd, 4);
    write_uint16LE(pdata_unencrypted, keyturner_states, 6);

    uint16_t encrypted_payload = encrypt_payload(output_buffer, pdata_unencrypted, CHALLENGE_CMD_PDATA_LENGTH);

    //REMOVE lATER
    printMessage(pdata_unencrypted, CHALLENGE_CMD_PDATA_LENGTH);
    printMessage(output_buffer, encrypted_payload);
    // ***********
    return encrypted_payload;
}


uint16_t create_challenge_payload(uint8_t* output_buffer) {
    uint8_t pdata_unencrypted[CHALLENGE_CMD_PDATA_LENGTH];
    write_uint32LE(pdata_unencrypted, pairing_ctx.authorization_id, 0);
    write_uint16LE(pdata_unencrypted, request_data_cmd, 4);
    write_uint16LE(pdata_unencrypted, challenge_cmd, 6);

    uint16_t encrypted_payload = encrypt_payload(output_buffer, pdata_unencrypted, CHALLENGE_CMD_PDATA_LENGTH);

    //REMOVE lATER
    printMessage(pdata_unencrypted, CHALLENGE_CMD_PDATA_LENGTH);
    printMessage(output_buffer, encrypted_payload);
    // ***********

    return encrypted_payload;
}

uint16_t create_lock_action_payload(uint8_t lock_action, uint8_t* output_buffer, uint8_t* encrypted_challenge) {
    uint8_t pdata_unencrypted[LOCK_ACTION_PDATA_LENGTH];
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
    printMessage(encrypted_challenge, CHALLENGE_MESSAGE_LENGTH);
    bool decrypted = decrypt_challenge(&pdata_unencrypted[12], encrypted_challenge);
    if(!decrypted) { return 0; }
    uint8_t flags = 0;
    write_uint32LE(pdata_unencrypted, pairing_ctx.authorization_id, 0);
    write_uint16LE(pdata_unencrypted, lock_action_cmd, 4);
    write_uint8LE(pdata_unencrypted, lock_action, 6);
    write_uint32LE(pdata_unencrypted, pairing_ctx.app_id, 7);
    write_uint8LE(pdata_unencrypted, flags, 11);

    printf("create_lock_action_payload:");
    printMessage(pdata_unencrypted, LOCK_ACTION_PDATA_LENGTH);

    return encrypt_payload(output_buffer, pdata_unencrypted, LOCK_ACTION_PDATA_LENGTH);
}


uint16_t create_keyturner_payload(uint8_t* output_buffer, uint8_t* encrypted_challenge) {
    uint8_t pdata_unencrypted[KEYTURNER_STATE_PDATA_LENGTH];
    bool decrypted = decrypt_keystate(&pdata_unencrypted[12], encrypted_challenge);
    if(!decrypted) { return 0; }
    uint8_t flags = 0;
    write_uint32LE(pdata_unencrypted, pairing_ctx.authorization_id, 0);
    write_uint16LE(pdata_unencrypted, lock_action_cmd, 4);
    write_uint32LE(pdata_unencrypted, pairing_ctx.app_id, 7);
    write_uint8LE(pdata_unencrypted, flags, 11);

    return encrypt_payload(output_buffer, pdata_unencrypted, LOCK_ACTION_PDATA_LENGTH);
}



static uint8_t lock_action_to_execute = 0;

void unlock_finished() {
    printf("==================================> unlock WORKED!!!!!!!!!!");
}


static void command_finished(uint8_t* received_message, uint16_t message_length) {
    printf("Unlock complete\r\n");
    unlock_finished();
}

static void send_command(uint8_t* received_message, uint16_t message_length) {
    uint8_t* received_msg = &received_message[0];
    printf("Send_command received_msg (len: %d) : \n", CHALLENGE_MESSAGE_LENGTH);
    printMessage(received_msg, CHALLENGE_MESSAGE_LENGTH);
    //crypto_box_keypair(public_key_fob, private_key_fob);
    uint16_t message_out_length = create_lock_action_payload(lock_action_to_execute, send_buffer, received_msg);
    send_with_response(send_buffer, message_out_length, 55u, command_finished);
}

static void send_keyturner(uint8_t* received_message, uint16_t message_length) {
    uint8_t* received_msg = &received_message[0];
    //crypto_box_keypair(public_key_fob, private_key_fob);
    uint16_t message_out_length = create_keyturner_payload(send_buffer, received_msg);
    send_with_response(send_buffer, message_out_length, 55u, command_finished);
}


void perform_lock_action(uint8_t lock_action) {
    lock_action_to_execute = lock_action;
    uint16_t message_out_length = create_challenge_payload(send_buffer);
    send_command_bool = 1;
    printf("(SEND BUFFER FACTER create_challenge_payload (bool %d)) lenght: %d \n", send_command_bool, message_out_length);
    printMessage(send_buffer, message_out_length);
    send_with_response(send_buffer, message_out_length, 86u, send_command);
}


void perform_keyturner_action() {
    //unecrypted payload
    uint16_t message_out_length = create_keyturner_state_payload(send_buffer);

    send_with_response(send_buffer, message_out_length, 69u, send_keyturner);
}






// Cyclic Rendundancy Check the payload, and writes the CRC to the payload .
static void crc_payload(uint8_t* output_buffer, uint16_t length) 
{
    uint16_t crc = crc_16(output_buffer, length-2, 0xFFFF);
    write_uint16LE(output_buffer, crc, length-2);
}




// aklsndlaksd lkasdlkamsdlkasd 
static void calculate_authenticator(uint8_t* output_buffer, uint8_t* message, uint16_t message_length) {
    HMAC_SHA256_compute(message, message_length, pairing_ctx.shared_secret, 32, output_buffer);
}



// alkskdna sdal knsdaslkdna sdalçsnd 
uint16_t create_authorization_data_payload(uint8_t* output_buffer, uint8_t* received_data) {
    printf("\ncreate authorization data payload\r\n");
    uint8_t* nonce = &received_data[2];
    uint16_t command_length = 105;
    write_uint16LE(output_buffer, authorization_data_cmd, 0);
    uint8_t app_id_buffer[4];
    randombytes(app_id_buffer, sizeof(pairing_ctx.app_id));
    pairing_ctx.app_id = read_uint32LE(app_id_buffer, 0);

    char name[33];
    snprintf(name, 32, "Open Nuki Fob %08lX               ", pairing_ctx.app_id);

    const uint16_t r_length = 101;
    uint8_t r[101];
    write_uint8LE(r, APP_TYPE_FOB, 0);
    write_uint32LE(r, pairing_ctx.app_id, 1);
    memcpy(&r[5], name, 32);
    randombytes(&r[37], PAIRING_NONCEBYTES);
    memcpy(&r[69], nonce, PAIRING_NONCEBYTES); 

    uint8_t authenticator[32];
    calculate_authenticator(authenticator, r, r_length);
    memcpy(&output_buffer[2], authenticator, crypto_auth_hmacsha512256_BYTES);
    memcpy(&output_buffer[34], r, 69);
    crc_payload(output_buffer, command_length);
    return command_length;
}





// asldaj jakljsda dklsa ms dlaskdmlasd
uint16_t create_authorization_id_confirmation_payload(uint8_t* output_buffer, uint8_t* received_data) {
    uint8_t* nonce = &received_data[54];
    uint16_t command_length = 40;
    write_uint16LE(output_buffer, authorization_id_confirmation_cmd, 0);
    pairing_ctx.authorization_id = read_uint32LE(received_data, 34);
    const uint16_t r_length = 36;
    uint8_t r[36];
    write_uint32LE(r, pairing_ctx.authorization_id, 0);
    memcpy(&r[4], nonce, PAIRING_NONCEBYTES); 

    uint8_t authenticator[32];
    calculate_authenticator(authenticator, r, r_length);
    memcpy(&output_buffer[2], authenticator, crypto_auth_hmacsha512256_BYTES);
    memcpy(&output_buffer[34], r, 4);
    crc_payload(output_buffer, command_length);
    return command_length;
}




// This can be in another file... but lets get the place all nitty gritty 
uint16_t create_authorization_authenticator_payload(uint8_t* output_buffer, uint8_t* received_data) 
{
    printf("\n\n\n\n\n\n\n\n\n IMPORTANT MAYDAY \n\n\n\n\n Create autorization authenticator payload");
    uint8_t* nonce = &received_data[2];
    uint16_t command_length = 36;
    write_uint16LE(output_buffer, authorization_authenticator_cmd, 0);

    //Shared key calculation
    uint8_t dh_key[crypto_scalarmult_BYTES];
    crypto_scalarmult(dh_key, private_key_fob, public_key_nuki);
    unsigned char _0[16];
    memset(_0, 0, 16);
    const unsigned char sigma[17] = "expand 32-byte k";
    crypto_core_hsalsa20(pairing_ctx.shared_secret, _0, dh_key, sigma);

    //keep r in a seperate buffer to prevent 32-bit boundary issues
    const uint16_t r_length = crypto_box_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES+PAIRING_NONCEBYTES;
    uint8_t r[crypto_box_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES+PAIRING_NONCEBYTES];
    memcpy(r, public_key_fob, crypto_box_PUBLICKEYBYTES);
    memcpy(&r[crypto_box_PUBLICKEYBYTES], public_key_nuki, crypto_box_PUBLICKEYBYTES);
    memcpy(&r[crypto_box_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES], nonce, PAIRING_NONCEBYTES);
    uint8_t authenticator[32];
    calculate_authenticator(authenticator, r, r_length);
    memcpy(&output_buffer[2], authenticator, crypto_auth_hmacsha512256_BYTES);
    crc_payload(output_buffer, command_length);
    return command_length;
}



void pairing_finished() {
    

    printf("\n\n\n\n\n\n\n\nPairing finished - Simulate an unlock now:\n");
    char name[20];
    printf("Press enter to continue protocol\n");
    //scanf("%s", &name);  - deprecated
    fgets(name,20,stdin);
    printf("lets go");

    perform_lock_action(unlock);

    printf("NUKI SENT MESSAGE: <{ NUKI sends keyturner_states (Encrypted) }> ");
    uint8_t response_emu6[] = "\x99\xC8\x61\x3A\x9F\x6A\xB6\xD3\xFB\x03\x99\xD3\x7A\xD3\x8C\x5C\x00\x3A\xC1\x39\xB1\x56\x7B\xC1\x02\x00\x00\x00\x38\x00\x28\xCD\xC8\xC0\x8D\xA4\x7B\xF3\x23\xBF\x93\x71\xEB\xF0\x68\xF6\xD4\x80\x43\x85\x63\x66\x07\x80\xA4\x23\x4D\x9A\x23\x79\x4E\x30\x5E\xE3\x78\x78\x87\x4E\xDE\x10\x6A\x0B\xBF\xCF\x5B\x60\xE0\xC2\xE2\xBA\x17\x24\x8A\x02\xB";
    //uint8_t response_emu6[] = "\x99\xC8\x61\x3A\x9F\x6A\xB6\xD3\xFB\x03\x99\xD3\x7A\xD3\x8C\x5C\x00\x3A\xC1\x39\xB1\x56\x7B\xC1\x02\x00\x00\x00\x38\x00\x28\xCD\xC8\xC0\x8D\xA4\x7B\xF3\x23\xBF\x93\x71\xEB\xF0\x68\xF6\xD4\x80\x43\x85\x63\x66\x07\x80\xA4\x23\x4D\x9A\x23\x79\x4E\x30\x5E\xE3\x78\x78\x87\x4E\xDE\x10\x6A\x0B\xBF\xCF\x5B\x60\xE0\xC2\xE2\xBA\x17\x24\x8A\x02\xB";
    // uint8_t response_emu6[] = "\x90\xB0\x75\x7C\xFE\xD0\x24\x30\x17\xEA\xF5\xE0\x89\xF8\x58\x3B\x98\x39\xD6\x1B\x05\x09\x24\xD2\x02\x00\x00\x00\x27\x00\xB1\x39\x38\xB6\x71\x21\xB6\xD5\x28\xE7\xDE\x20\x6B\x0D\x7C\x5A\x94\x58\x7A\x47\x1B\x33\xEB\xFB\x01\x2C\xED\x8F\x12\x61\x13\x55\x66\xED\x75\x6E\x39\x10\xB5";

    /*
    uint8_t pdata_plaint[] = "\x57\xD9\x55\x21\xBE\xA1\x86\xB5\xA9\x24\x4F\x02\x57\x37\x92\x4C\x5B\x7E\x33\x59\x2D\x06\x14\xD5\xF6\xEF\x2E\x2F\x14\x2C\x6D\x4B";
    enc_pay_size = encrypt_payload(send_buffer, pdata_plaint, 32);
    printf("ENCRYPTED PAYLOAD: (SIZE: %d) " ,enc_pay_size);
    printMessage(send_buffer, enc_pay_size); 
    */
    generateNukiMessage(response_emu6);

    process_messages(NULL, NULL);

}



//n asndmaklsdn asknd ijoajkds alsnd 
static void complete_confirmation_received(uint8_t* response, uint16_t length) 
{
    printf("Pairing complete\r\n");
    pairing_finished();
    exit(1);
}



// lkansdasdl asldnasd asnd asdk
static void authorization_id_received(uint8_t* response, uint16_t length) {
    printf(" ~~~~~~ ~~~~~~ ~~~~~~~ ~~~~~~~ (auth_id_received length ) lenght: %d \n", m_out_message_length);
    printMessage(response, length);

    printf("\nReceived authorization ID\r\n");
    uint16_t payload_length = create_authorization_id_confirmation_payload(send_buffer, response);
    send_with_response(send_buffer, payload_length, 5, complete_confirmation_received);
}



// asnotneaornk alksnda sdnlan sdjas 
static void challenge_for_authorization_data_received(uint8_t* response, uint16_t length) {
    printf("\nReceived challenge for authorization data\r\n");
    uint16_t payload_length = create_authorization_data_payload(send_buffer, response);
    send_with_response(send_buffer, payload_length, 88, authorization_id_received);
}




// write this one later too 
static void challenge_for_authorization_authenticator_received(uint8_t* response, uint16_t length) {
    printf("\nReceived challenge for authorization authenticator received\r\n");
    uint16_t payload_length = create_authorization_authenticator_payload(send_buffer, response);
    send_with_response(send_buffer, payload_length, 36, challenge_for_authorization_data_received);
}




// Function responsible for writing the command corresponding to nuki-request, 
// into the output_buffer(2 bytes for this). It also writes the public key [bt]
// A little reminder to self: *LE will make the arrays Little Endian 
uint16_t create_request_public_key_payload(uint8_t* output_buffer) {
    printf("\n::Create request public key payload\n");
    uint16_t command_length = 6;
    write_uint16LE(output_buffer, request_data_cmd, 0);
    write_uint16LE(output_buffer, public_key_cmd, 2);
    crc_payload(output_buffer, command_length);
    return command_length;
}




// Ill write this later.
uint16_t create_write_public_key_payload(uint8_t* output_buffer, uint8_t* received_data) 
{
    printf("\n::(getting ready to generate keys)\n");
    uint8_t* received_public_key = &received_data[2];
    //crypto_box_keypair(public_key_fob, private_key_fob);

    printf("THIS IS VERY IMPORTANT : \n");
    printMessage(received_public_key, 32u);


    uint8_t priv_key[]  = "\x8C\xAA\x54\x67\x23\x07\xBF\xFD\xF5\xEA\x18\x3F\xC6\x07\x15\x8D\x20\x11\xD0\x08\xEC\xA6\xA1\x08\x86\x14\xFF\x08\x53\xA5\xAA\x07";
    uint8_t pub_key[]   = "\xF8\x81\x27\xCC\xF4\x80\x23\xB5\xCB\xE9\x10\x1D\x24\xBA\xA8\xA3\x68\xDA\x94\xE8\xC2\xE3\xCD\xE2\xDE\xD2\x9C\xE9\x6A\xB5\x0C\x15";

    memcpy(private_key_fob, priv_key, crypto_box_SECRETKEYBYTES);
    memcpy(public_key_fob, pub_key, crypto_box_PUBLICKEYBYTES);
    memcpy(public_key_nuki, received_public_key, crypto_box_PUBLICKEYBYTES);

    uint16_t command_length = 36;
    write_uint16LE(output_buffer, public_key_cmd, 0);
    memcpy(&output_buffer[2], public_key_fob, crypto_box_PUBLICKEYBYTES);
    crc_payload(output_buffer, command_length);
    return command_length;
}





// lets do this one later 
static void public_key_received(uint8_t* response, uint16_t length) {
    printf(" ~~~~~~ ~~~~~~ ~~~~~~~ ~~~~~~~ (public_key_received length ) lenght: %d \n", length);
    printMessage(response, length);
    printf("Received public key from smartlock\r\n");
    uint16_t payload_length = create_write_public_key_payload(send_buffer, response);
    printf(" ~~~~~~ ~~~~~~ ~~~~~~~ (SeND BUFFER length ) lenght: %d \n", payload_length);
    printMessage(send_buffer, payload_length);
    send_with_response(send_buffer, payload_length, 36, challenge_for_authorization_authenticator_received);
}

//void send_with_response(uint8_t* data, uint16_t data_length, uint16_t expected_response_length, void (*callback)(uint8_t*, uint16_t));






// This starts the pairing with nuki at the protocol level, not bt (?)
void start_pairing() {
    printf("Start pairing\r\n");
    uint16_t payload_length = create_request_public_key_payload(send_buffer);
    send_with_response(send_buffer, payload_length , 36, public_key_received);

}


// NOT WELL DONE.... THINK BETTER .......

// Emulating a Nuki Device lol
void generateNukiMessage(uint8_t *response_emu){   
    // Write 18 bytes at a time, the HM-10 only takes 20bytes at once
    while(m_response_message_progress < m_expected_response_length){
        memcpy(&m_response_message_buffer[m_response_message_progress], &response_emu[m_response_message_progress], sizeof(char)*MTU_SIZE);
        m_response_message_progress = m_response_message_progress+MTU_SIZE < m_expected_response_length 
                                    ? m_response_message_progress+MTU_SIZE : m_expected_response_length;
    }
}




uint32_t ble_write(int connection_handle, ble_write_params_t *params ){
    printf("Wrote to Nuki and nuki responded fast\n");
    m_out_message_length = 0; 
    m_out_message_progress = 0; 
}



static void bt_long_write(uint16_t connection_handle, uint16_t attribute_handle) {
    printf("::::::WRITING TO NUKI::::::\n");
    if(m_out_message_progress < m_out_message_length) {
        int32_t remaining_message_length = m_out_message_length - m_out_message_progress;
        uint16_t mtu_length = MTU_SIZE;
        if(remaining_message_length < MTU_SIZE) {
            mtu_length = remaining_message_length;
        }

        ble_write_params_t write_params = {
            .write_op = 0,
            .flags    = 0,
            .handle   = attribute_handle,
            .offset   = m_out_message_progress,
            .len      = mtu_length,
            .p_value  = &m_out_message_buffer[m_out_message_progress]
        };


        uint32_t err_code = ble_write(connection_handle, &write_params);
        if(err_code == 0) {
            m_out_message_progress += mtu_length;
        }
   } 
   else 
   {
        ble_write_params_t write_params = {
            .write_op = 0,
            .flags    = 1,
            .handle   = attribute_handle,
            .len      = 0,
            .offset   = 0
        };
        m_out_message_length = 0;
        m_out_message_progress = 0;
        uint32_t err_code = ble_write(connection_handle, &write_params);
        if(err_code != 0) printf("Error during GATT write execute\r\n");
    }
}




void process_messages(uint16_t connection_handle, uint16_t attribute_handle) 
{
    printf("m_out_message_length: (>0?) %d \n", m_out_message_length);
    printf("m_out_message_progress: (==0?) %d \n", m_out_message_progress);
    if(m_out_message_length > 0 && m_out_message_progress == 0) 
    {

        bt_long_write(connection_handle, attribute_handle);
    }
    
    printf("m_expected_response_length: (>0?) %d \n ", m_out_message_length);
    printf("m_response_message_progress %d (==) m_expected_response_length %d \n", m_response_message_progress, m_expected_response_length);
    

    if(m_expected_response_length > 0 && m_response_message_progress == m_expected_response_length) 
    {
        
        printf("------>?????????<>>>>>>:::::::::::::::::::::::message_inside_buffer: %d ",m_expected_response_length );
        printf("SEND_COMMAND_BOOL %d", send_command_bool);
        printMessage(m_response_message_buffer,m_expected_response_length);
        void (*response_callback)(uint8_t*, uint16_t) = m_response_callback;
        m_response_callback = NULL;
        m_response_message_progress = 0;
        m_expected_response_length = 0;
        response_callback(m_response_message_buffer, m_expected_response_length);
        
    } 

}







int main(){
    int count = 0; 
    start_pairing();

    while(true){
        //sleep(1);
        printf("COUNT: %d\n", count);

        if(count == 1){
            printf("NUKI SENT MESSAGE: <{ Own public key }>: ");
            uint8_t response_emu[] = "\x03\x00\x2F\xE5\x7D\xA3\x47\xCD\x62\x43\x15\x28\xDA\xAC\x5F\xBB\x29\x07\x30\xFF\xF6\x84\xAF\xC4\xCF\xC2\xED\x90\x99\x5F\x58\xCB\x3B\x74\x9D\xB9";
            generateNukiMessage(response_emu);
        }else if(count==3){
            printf("NUKI SENT MESSAGE: <{ Challenge for authorization authenticator }> ");
            uint8_t response_emu2[] = "\x04\x00\x6C\xD4\x16\x3D\x15\x90\x50\xC7\x98\x55\x3E\xAA\x57\xE2\x78\xA5\x79\xAF\xFC\xBC\x56\xF0\x9F\xC5\x7F\xE8\x79\xE5\x1C\x42\xDF\x17\xC3\xDF";
            generateNukiMessage(response_emu2);
        }else if(count==5){
            printf("NUKI SENT MESSAGE: <{ Challenge for authorization data }> ");
            uint8_t response_emu3[] = "\x04\x00\xE0\x74\x2C\xFE\xA3\x9C\xB4\x61\x09\x38\x5B\xF9\x12\x86\xA3\xC0\x2F\x40\xEE\x86\xB0\xB6\x2F\xC3\x40\x33\x09\x4D\xE4\x1E\x2C\x0D\x7F\xE1";
            generateNukiMessage(response_emu3);
        }else if(count==7){
            printf("NUKI SENT MESSAGE: <{ Authorization id received }> ");
            uint8_t response_emu4[] = "\x07\x00\x3a\x27\x0a\x2e\x45\x34\x43\xc3\x79\x0e\x65\x7c\xeb\xe6\x34\xb0\x3f\x01\x02\xf4\x56\x81\xb4\x06\x71\xd4\x6e\x6e\x1f\x0c\x5e\xdf\x02\x00\x00\x00\x08\x3B\x33\x64\x3C\x6D\x97\xEF\x77\xED\x51\xC0\x2A\x27\x7C\xBF\x7E\xA4\x79\x91\x59\x82\xF1\x3C\x61\xD9\x97\xA5\x66\x78\xAD\x77\x79\x1B\xFA\x7E\x95\x22\x9A\x3D\xD3\x4F\x87\x13\x2B\xF3\xE3\xC9\x7D\xB9\xF";
            generateNukiMessage(response_emu4);
        }else if(count==9){
            printf("NUKI SENT MESSAGE: <{ Authorization id received }> ");
            uint8_t response_emu5[] = "\x0E\x00\x00\x9D\xD7";
            generateNukiMessage(response_emu5);

        }



        
        printf("\nm_out_message_buffer: ");
        printMessage(m_out_message_buffer, m_out_message_length);

        printf("\nm_response_message_buffer: ");
        printMessage(m_response_message_buffer, m_expected_response_length);

        printf("\npub_key_main: ");
        printMessage(public_key_fob, 32);

        printf("\npriv_key_main: ");
        printMessage(private_key_fob, 32);

        printf("\npublic_key_nuki: ");
        printMessage(public_key_nuki, 32);

        printf("\nshared_secret: ");
        printMessage(pairing_ctx.shared_secret, 32);
        

        process_messages(NULL , NULL);

        count++;

    }
}