#include <stdint.h>

struct mgmt_header_t {
    uint16_t   fc;
    uint16_t   duration;
    uint8_t    da[6];
    uint8_t    sa[6];
    uint8_t    bssid[6];
    uint16_t   seq_ctrl;
};

struct radiotap_data_t {
    uint8_t   flags;
    uint8_t   rate;
    uint16_t  chan_freq;
    uint16_t  chan_flags;
    uint8_t   antsignal;
    uint8_t   antenna;
};
