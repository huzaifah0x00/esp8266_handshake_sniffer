#include "PCAP.h"
#include <driver/uart.h>


/* send file header to Serial */
uint32_t magic_number = 0xa1b2c3d4;
uint16_t version_major = 2;
uint16_t version_minor = 4;
uint32_t thiszone = 0;
uint32_t sigfigs = 0;
uint32_t snaplen = sizeof(int);
uint32_t network = 105;

void pcap_start_serial(){
  // Configure parameters of an UART driver,
  // communication pins and install the driver
  uart_config_t uart_config = {
      .baud_rate = 115200,
      .data_bits = UART_DATA_8_BITS,
      .parity    = UART_PARITY_DISABLE,
      .stop_bits = UART_STOP_BITS_1,
      .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
  };
  uart_param_config(UART_NUM_0, &uart_config);
  uart_driver_install(UART_NUM_0, 1024 * 2, 0, 0, NULL, 0);

  serialwrite_32(magic_number);
  serialwrite_16(version_major);
  serialwrite_16(version_minor);
  serialwrite_32(thiszone);
  serialwrite_32(sigfigs);
  serialwrite_32(snaplen);
  serialwrite_32(network);
}

/* write packet to Serial */
void pcap_new_packet_serial(uint32_t ts_sec, uint32_t ts_usec, uint32_t len, uint8_t* buf){
  uint32_t orig_len = len;
  uint32_t incl_len = len;

  serialwrite_32(ts_sec);
  serialwrite_32(ts_usec);
  serialwrite_32(incl_len);
  serialwrite_32(orig_len);

  uart_write_bytes(UART_NUM_0, (char* ) buf, incl_len);
}

/* write packet to file */

/* converts a 32 bit integer into 4 bytes */
void escape32(uint32_t n, char* buf){
  buf[0] = n;
  buf[1] = n >>  8;
  buf[2] = n >> 16;
  buf[3] = n >> 24;
}

/* converts a 16 bit integer into 2 bytes */
void escape16(uint16_t n, char* buf){
  buf[0] = n;
  buf[1] = n >>  8;
}

/* writes a 32 bit integer to Serial */
void serialwrite_32(uint32_t n){
  char _buf[4];
  escape32(n, _buf);
//  Serial.write(_buf, 4);
  uart_write_bytes(UART_NUM_0,_buf, 4);
}

/* writes a 16 bit integer to Serial */
void serialwrite_16(uint16_t n){
  char _buf[2];
  escape16(n, _buf);
  uart_write_bytes(UART_NUM_0, _buf, 2);
//  Serial.write(_buf, 2);
}


