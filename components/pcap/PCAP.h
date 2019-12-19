/*
  ===========================================
       Copyright (c) 2017 Stefan Kremser
              github.com/spacehuhn
  ===========================================
*/

#ifndef PCAP_h
#define PCAP_h

#include <string.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"

    void pcap_start_serial();
    void pcap_new_packet_serial(uint32_t ts_sec, uint32_t ts_usec, uint32_t len, void* buf);

    extern uint32_t magic_number ;//= 0xa1b2c3d4;
    extern uint16_t version_major ;//= 2;
    extern uint16_t version_minor ;//= 4;
    extern uint32_t thiszone ;//= 0;
    extern uint32_t sigfigs ;//= 0;
    extern uint32_t snaplen ;//= sizeof(int);
    extern uint32_t network ;//= 105;

    void escape32(uint32_t n, char* buf);
    void escape16(uint16_t n, char* buf);


    void serialwrite_16(uint16_t n);
    void serialwrite_32(uint32_t n);

#endif
