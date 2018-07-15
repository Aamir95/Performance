nclude <core.p4>
#include <sume_switch.p4>

typedef bit<48> EthAddr_t;

const port_t CPU_PORT = 8w0b00000010;

typedef bit<8> digCode_t;
const digCode_t DIG_LOCAL_IP = 1;

@Xilinx_MaxLatency(1)
@Xilinx_ControlWidth(0)
extern void start_timestamp(in bit<1> valid, out bit<32> result);

@Xilinx_MaxLatency(1)
@Xilinx_ControlWidth(0)
extern void end_timestamp(in bit<1> valid, out bit<32> result);

header Ethernet_t {
    EthAddr_t dstAddr;
    EthAddr_t srcAddr;
    bit<16> etherType;
}

header Perf_t {
        bit<16>    seq;
        bit<32>    tss;
        bit<32>    tse;
}

