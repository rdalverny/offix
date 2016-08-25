#include "radiotap.h"
#include "ieee80211.h"

#include <amqp.h>
#include <amqp_tcp_socket.h>
#include <pcap.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#define QUEUE_EXCHANGE_NAME ("offix")

void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void die(const char *context);
void die_on_amqp_error(amqp_rpc_reply_t reply, const char *context);
void die_if_null(const void *ptr, const char *context);

amqp_connection_state_t queue_connect(const char *hostname, const uint16_t port, const char *user, const char *pass);
void send_message(amqp_connection_state_t conn, const char *body);
void usage();

struct arguments {
    int use_queue;
    char *network_device;
    char *queue_hostname;
    uint16_t queue_port;
    char *queue_user;
    char *queue_pass;
};

void parse_arguments(int argc, char *argv[], struct arguments *args)
{
    int opt;

    while ((opt = getopt(argc, argv, "i:h:p:s")) != -1) {
        switch (opt) {
        case 'i': args->network_device = optarg; break;
        case 'h': args->queue_hostname = optarg; break;
        case 'p': args->queue_port = atoi(optarg); break;
        case 's': args->use_queue = 0;
        default:
            usage();
        }
    }
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char filter_exp[] = "type mgt subtype probe-req";
    struct bpf_program fp;
    amqp_connection_state_t conn = NULL;

    struct arguments args;
    args.use_queue = 1;
    args.network_device = "wlan0";
    args.queue_hostname = "localhost";
    args.queue_port = 5672;
    args.queue_user = "guest";
    args.queue_pass = "guest";

    parse_arguments(argc, argv, &args);

    if (args.use_queue)
    {
        conn = queue_connect(args.queue_hostname, args.queue_port, args.queue_user, args.queue_pass);
    }

    handle = pcap_open_live(args.network_device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        die("Couldn't open device");
    }
    if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
        // see http://www.tcpdump.org/linktypes.html
        die("Device doesn't provide Radiotap link-layer information");
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        die("Couldn't parse filter");
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        die("Couldn't install filter");
    }

    pcap_loop(handle, -1, parse_packet, (u_char *) conn);

    pcap_freecode(&fp);
    pcap_close(handle);

    if (args.use_queue)
    {
        amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
    }

    return 0;
}

void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    amqp_connection_state_t conn;
    struct ieee80211_radiotap_header *radiotap;
    struct mgmt_header_t *frame;
    char buf[6*2 + (6 - 1) + 1];

    conn = (amqp_connection_state_t) args;

    if (header->caplen < sizeof(struct ieee80211_radiotap_header))
    {
        return;
    }
    radiotap = (struct ieee80211_radiotap_header *) packet;

    if (header->caplen < radiotap->it_len + sizeof(struct mgmt_header_t))
    {
        return;
    }
    frame = (struct mgmt_header_t *) (packet + radiotap->it_len);
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
        frame->sa[0],
        frame->sa[1],
        frame->sa[2],
        frame->sa[3],
        frame->sa[4],
        frame->sa[5]);
    // publish
    if (conn != NULL)
    {
        send_message(conn, buf);
    }
    printf("%s\n", buf); // also print to help with debugging
}

void send_message(amqp_connection_state_t conn, const char *body)
{
    int status;

    amqp_basic_properties_t props;
    props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
    props.content_type = amqp_cstring_bytes("text/plain");
    props.delivery_mode = 1; // non-persistent delivery mode
    status = amqp_basic_publish(conn, 1, amqp_cstring_bytes(QUEUE_EXCHANGE_NAME),
        amqp_cstring_bytes(""), 0, 0, &props, amqp_cstring_bytes(body));
    if (status != AMQP_STATUS_OK)
    {
        die("Error publishing message");
    }
}

amqp_connection_state_t queue_connect(const char *hostname, const uint16_t port, const char *user, const char *pass)
{
    amqp_socket_t *socket;
    amqp_connection_state_t conn;
    int status;

    conn = amqp_new_connection();
    socket = amqp_tcp_socket_new(conn);
    die_if_null(socket, "Error creating TCP socket");
    status = amqp_socket_open(socket, hostname, port);
    if (status != AMQP_STATUS_OK)
    {
        die("Error opening TCP socket");
    }
    die_on_amqp_error(amqp_login(conn, "/", 0, 131072, 0,
        AMQP_SASL_METHOD_PLAIN, user, pass), "logging in");
    amqp_channel_open(conn, 1);
    die_on_amqp_error(amqp_get_rpc_reply(conn), "opening channel");

    return conn;
}

void die_on_amqp_error(amqp_rpc_reply_t reply, const char *context)
{
    if (reply.reply_type != AMQP_RESPONSE_NORMAL)
    {
        fprintf(stderr, "AMQP error: %s\n", context);
        exit(1);
    }
}

void die_if_null(const void *ptr, const char *context)
{
    if (ptr == NULL)
    {
        fprintf(stderr, "Unexpected null pointer: %s\n", context);
        exit(1);
    }
}

void die(const char *context)
{
    fprintf(stderr, "%s\n", context);
    exit(1);
}

void usage()
{
    fprintf(stderr, "Usage:  sniffer [-i interface]\n");
    fprintf(stderr, "                [-h hostname] [-p port] [-s]\n\n");
    fprintf(stderr, "        -i interface    which network interface to listen to\n");
    fprintf(stderr, "        -h hostname     queue server hostname\n");
    fprintf(stderr, "        -p port         queue server port\n");
    fprintf(stderr, "        -s              do not connect/use the queue server\n");

    exit(EXIT_FAILURE);
}
