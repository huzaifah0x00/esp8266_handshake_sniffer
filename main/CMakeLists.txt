#idf_component_register(SRCS "esp8266_pcap_serial.c"
#                    INCLUDE_DIRS "")

set(COMPONENT_SRCS "sniffer_main.cpp")
set(COMPONENT_ADD_INCLUDEDIRS ".")

register_component()

