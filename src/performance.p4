#include <core.p4>
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
truct Parsed_packet {
    Ethernet_t  ethernet;
    Perf_t      Perf;
}

struct digest_data_t {
    bit<240>  unused;
    bit<8>   digest_code;
    bit<8>   src_port;
}

struct user_metadata_t {
    bit<8> unused;
}


@Xilinx_MaxPacketRegion(16384)
parser TopParser(packet_in b,
                 out Parsed_packet p,
                 out user_metadata_t user_metadata,
                 out digest_data_t digest_data,
                 inout sume_metadata_t sume_metadata) {

        state start {
                b.extract(p.ethernet);
                b.extract(p.Perf);
                user_metadata.unused = 0;
		digest_data.src_port = 0;
                digest_data.digest_code = 0;
                digest_data.unused = 0;
                transition accept;
        }
}

control TopPipe(inout Parsed_packet p,
        inout user_metadata_t user_metadata,
        inout digest_data_t digest_data,
        inout sume_metadata_t sume_metadata) {

        action send_to_cpu(digCode_t code) {
                sume_metadata.dst_port = CPU_PORT;
                digest_data.digest_code = code;
                digest_data.src_port = sume_metadata.src_port;
         }

        action set_dst_port(port_t port) {
                sume_metadata.dst_port = port;
        }

        table mac_to_port {
                key = {
                p.ethernet.srcAddr : exact;
                }
                actions = {
                set_dst_port;
                NoAction;
                }
                size = 64;
                default_action = NoAction;
    }
        apply{

                if (p.Perf.isValid()){
                        if (sume_metadata.src_port == CPU_PORT){
                                start_timestamp(1, p.Perf.tss);
                                mac_to_port.apply();
                        }
                        else {
                                end_timestamp(1,p.Perf.tse);
                                send_to_cpu(DIG_LOCAL_IP);
                        }
                }
        }
}
@Xlinx_MaxPacketRegion(16384)
control TopDeparser(packet_out b,
                    in Parsed_packet p,
                    in user_metadata_t user_metadata,
                    inout digest_data_t digest_data,
                    inout sume_metadata_t sume_metadata) {
    apply {
        b.emit(p.ethernet);
        b.emit(p.Perf);
    }
}

// Instantiate the switch
SimpleSumeSwitch(TopParser(), TopPipe(), TopDeparser()) main;

