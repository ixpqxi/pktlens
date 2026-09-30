#include "packet.h"

#include <string.h>

#define ETHERNET_HEADER_LENGTH 14U
#define MAX_VLAN_TAGS 2U

typedef enum {
    NETWORK_UNKNOWN,
    NETWORK_ARP,
    NETWORK_IPV4
} NetworkKind;

typedef enum {
    TRANSPORT_NONE,
    TRANSPORT_TCP,
    TRANSPORT_UDP,
    TRANSPORT_ICMP
} TransportKind;

struct PacketRecord {
    guint64 id;
    gint64 timestamp_seconds;
    gint64 timestamp_microseconds;
    guint32 original_length;
    guint32 captured_length;
    guint8 *data;

    gboolean ethernet_valid;
    guint8 destination_mac[6];
    guint8 source_mac[6];
    guint16 ether_type;
    guint vlan_count;
    guint16 vlan_tci[MAX_VLAN_TAGS];
    gsize layer3_offset;

    NetworkKind network_kind;
    TransportKind transport_kind;
    gboolean network_valid;
    gboolean transport_valid;

    guint8 ipv4_version;
    guint8 ipv4_header_length;
    guint8 ipv4_tos;
    guint16 ipv4_total_length;
    guint16 ipv4_id;
    guint16 ipv4_fragment;
    guint8 ipv4_ttl;
    guint8 ipv4_protocol;
    guint16 ipv4_checksum;
    guint8 ipv4_source[4];
    guint8 ipv4_destination[4];

    guint16 source_port;
    guint16 destination_port;
    guint32 tcp_sequence;
    guint32 tcp_acknowledgement;
    guint8 tcp_header_length;
    guint8 tcp_flags;
    guint16 tcp_window;
    guint16 transport_checksum;
    guint16 tcp_urgent_pointer;
    guint16 udp_length;
    guint8 icmp_type;
    guint8 icmp_code;
    guint16 icmp_id;
    guint16 icmp_sequence;

    guint16 arp_hardware_type;
    guint16 arp_protocol_type;
    guint8 arp_hardware_length;
    guint8 arp_protocol_length;
    guint16 arp_operation;
    guint8 arp_source_mac[6];
    guint8 arp_source_ip[4];
    guint8 arp_destination_mac[6];
    guint8 arp_destination_ip[4];

    gchar source[64];
    gchar destination[64];
    gchar protocol[96];
    gchar application[16];
    gchar warning[160];
};

static gboolean range_available(const PacketRecord *packet, gsize offset, gsize length)
{
    return offset <= packet->captured_length &&
           length <= packet->captured_length - offset;
}

static gboolean read_u8(const PacketRecord *packet, gsize offset, guint8 *value)
{
    if (!range_available(packet, offset, 1)) {
        return FALSE;
    }
    *value = packet->data[offset];
    return TRUE;
}

static gboolean read_u16(const PacketRecord *packet, gsize offset, guint16 *value)
{
    if (!range_available(packet, offset, 2)) {
        return FALSE;
    }
    *value = ((guint16)packet->data[offset] << 8) |
             packet->data[offset + 1];
    return TRUE;
}

static gboolean read_u32(const PacketRecord *packet, gsize offset, guint32 *value)
{
    if (!range_available(packet, offset, 4)) {
        return FALSE;
    }
    *value = ((guint32)packet->data[offset] << 24) |
             ((guint32)packet->data[offset + 1] << 16) |
             ((guint32)packet->data[offset + 2] << 8) |
             packet->data[offset + 3];
    return TRUE;
}

static void set_warning(PacketRecord *packet, const gchar *warning)
{
    if (packet->warning[0] == '\0') {
        g_strlcpy(packet->warning, warning, sizeof(packet->warning));
    }
}

static void format_mac(const guint8 mac[6], gchar *output, gsize output_size)
{
    g_snprintf(output,
               output_size,
               "%02X:%02X:%02X:%02X:%02X:%02X",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void format_ipv4(const guint8 address[4], gchar *output, gsize output_size)
{
    g_snprintf(output,
               output_size,
               "%u.%u.%u.%u",
               address[0], address[1], address[2], address[3]);
}

static const gchar *classify_application(TransportKind kind,
                                         guint16 source_port,
                                         guint16 destination_port)
{
    if (kind == TRANSPORT_TCP) {
        if (source_port == 80 || destination_port == 80) return "HTTP";
        if (source_port == 21 || destination_port == 21) return "FTP";
        if (source_port == 23 || destination_port == 23) return "TELNET";
        if (source_port == 25 || destination_port == 25) return "SMTP";
        if (source_port == 110 || destination_port == 110) return "POP3";
        if (source_port == 443 || destination_port == 443) return "HTTPS";
    }

    if (kind == TRANSPORT_UDP) {
        if (source_port == 53 || destination_port == 53) return "DNS";
        if (source_port == 67 || destination_port == 67 ||
            source_port == 68 || destination_port == 68) return "DHCP";
    }

    return "";
}

static void parse_tcp(PacketRecord *packet, gsize offset, gsize limit)
{
    guint8 data_offset = 0;

    packet->transport_kind = TRANSPORT_TCP;
    if (offset > limit || limit - offset < 20 ||
        !range_available(packet, offset, 20)) {
        set_warning(packet, "Truncated TCP header");
        return;
    }

    read_u16(packet, offset, &packet->source_port);
    read_u16(packet, offset + 2, &packet->destination_port);
    read_u32(packet, offset + 4, &packet->tcp_sequence);
    read_u32(packet, offset + 8, &packet->tcp_acknowledgement);
    read_u8(packet, offset + 12, &data_offset);
    packet->tcp_header_length = (data_offset >> 4) * 4;
    read_u8(packet, offset + 13, &packet->tcp_flags);
    read_u16(packet, offset + 14, &packet->tcp_window);
    read_u16(packet, offset + 16, &packet->transport_checksum);
    read_u16(packet, offset + 18, &packet->tcp_urgent_pointer);

    if (packet->tcp_header_length < 20 ||
        packet->tcp_header_length > limit - offset ||
        !range_available(packet, offset, packet->tcp_header_length)) {
        set_warning(packet, "Invalid or truncated TCP header length");
        return;
    }

    packet->transport_valid = TRUE;
}

static void parse_udp(PacketRecord *packet, gsize offset, gsize limit)
{
    packet->transport_kind = TRANSPORT_UDP;
    if (offset > limit || limit - offset < 8 ||
        !range_available(packet, offset, 8)) {
        set_warning(packet, "Truncated UDP header");
        return;
    }

    read_u16(packet, offset, &packet->source_port);
    read_u16(packet, offset + 2, &packet->destination_port);
    read_u16(packet, offset + 4, &packet->udp_length);
    read_u16(packet, offset + 6, &packet->transport_checksum);

    if (packet->udp_length < 8) {
        set_warning(packet, "Invalid UDP length");
        return;
    }
    if (packet->udp_length > limit - offset) {
        set_warning(packet, "Captured UDP datagram is truncated");
    }
    packet->transport_valid = TRUE;
}

static void parse_icmp(PacketRecord *packet, gsize offset, gsize limit)
{
    packet->transport_kind = TRANSPORT_ICMP;
    if (offset > limit || limit - offset < 4 ||
        !range_available(packet, offset, 4)) {
        set_warning(packet, "Truncated ICMP header");
        return;
    }

    read_u8(packet, offset, &packet->icmp_type);
    read_u8(packet, offset + 1, &packet->icmp_code);
    read_u16(packet, offset + 2, &packet->transport_checksum);
    if (limit - offset >= 8 && range_available(packet, offset, 8)) {
        read_u16(packet, offset + 4, &packet->icmp_id);
        read_u16(packet, offset + 6, &packet->icmp_sequence);
    }
    packet->transport_valid = TRUE;
}

static void parse_ipv4(PacketRecord *packet)
{
    gsize offset = packet->layer3_offset;
    gsize layer4_offset;
    gsize packet_limit;
    guint8 version_and_ihl = 0;
    guint16 fragment_offset;

    packet->network_kind = NETWORK_IPV4;
    if (!range_available(packet, offset, 20)) {
        set_warning(packet, "Truncated IPv4 header");
        return;
    }

    read_u8(packet, offset, &version_and_ihl);
    packet->ipv4_version = version_and_ihl >> 4;
    packet->ipv4_header_length = (version_and_ihl & 0x0f) * 4;
    read_u8(packet, offset + 1, &packet->ipv4_tos);
    read_u16(packet, offset + 2, &packet->ipv4_total_length);
    read_u16(packet, offset + 4, &packet->ipv4_id);
    read_u16(packet, offset + 6, &packet->ipv4_fragment);
    read_u8(packet, offset + 8, &packet->ipv4_ttl);
    read_u8(packet, offset + 9, &packet->ipv4_protocol);
    read_u16(packet, offset + 10, &packet->ipv4_checksum);
    memcpy(packet->ipv4_source, packet->data + offset + 12, 4);
    memcpy(packet->ipv4_destination, packet->data + offset + 16, 4);

    format_ipv4(packet->ipv4_source, packet->source, sizeof(packet->source));
    format_ipv4(packet->ipv4_destination,
                packet->destination,
                sizeof(packet->destination));

    if (packet->ipv4_version != 4 || packet->ipv4_header_length < 20) {
        set_warning(packet, "Invalid IPv4 version or header length");
        return;
    }
    if (!range_available(packet, offset, packet->ipv4_header_length)) {
        set_warning(packet, "Truncated IPv4 options");
        return;
    }
    if (packet->ipv4_total_length < packet->ipv4_header_length) {
        set_warning(packet, "Invalid IPv4 total length");
        return;
    }

    packet->network_valid = TRUE;
    packet_limit = offset + packet->ipv4_total_length;
    if (packet_limit > packet->captured_length) {
        packet_limit = packet->captured_length;
        set_warning(packet, "Captured IPv4 packet is truncated");
    }

    fragment_offset = packet->ipv4_fragment & 0x1fff;
    if (fragment_offset != 0) {
        return;
    }

    layer4_offset = offset + packet->ipv4_header_length;
    switch (packet->ipv4_protocol) {
    case 6:
        parse_tcp(packet, layer4_offset, packet_limit);
        break;
    case 17:
        parse_udp(packet, layer4_offset, packet_limit);
        break;
    case 1:
        parse_icmp(packet, layer4_offset, packet_limit);
        break;
    default:
        break;
    }
}

static void parse_arp(PacketRecord *packet)
{
    gsize offset = packet->layer3_offset;
    gsize required_length;

    packet->network_kind = NETWORK_ARP;
    if (!range_available(packet, offset, 8)) {
        set_warning(packet, "Truncated ARP header");
        return;
    }

    read_u16(packet, offset, &packet->arp_hardware_type);
    read_u16(packet, offset + 2, &packet->arp_protocol_type);
    read_u8(packet, offset + 4, &packet->arp_hardware_length);
    read_u8(packet, offset + 5, &packet->arp_protocol_length);
    read_u16(packet, offset + 6, &packet->arp_operation);

    required_length = 8U + 2U * packet->arp_hardware_length +
                      2U * packet->arp_protocol_length;
    if (!range_available(packet, offset, required_length)) {
        set_warning(packet, "Truncated ARP addresses");
        return;
    }
    if (packet->arp_hardware_length != 6 ||
        packet->arp_protocol_length != 4) {
        set_warning(packet, "Unsupported ARP address sizes");
        return;
    }

    memcpy(packet->arp_source_mac, packet->data + offset + 8, 6);
    memcpy(packet->arp_source_ip, packet->data + offset + 14, 4);
    memcpy(packet->arp_destination_mac, packet->data + offset + 18, 6);
    memcpy(packet->arp_destination_ip, packet->data + offset + 24, 4);
    format_ipv4(packet->arp_source_ip, packet->source, sizeof(packet->source));
    format_ipv4(packet->arp_destination_ip,
                packet->destination,
                sizeof(packet->destination));
    packet->network_valid = TRUE;
}

static void build_protocol_name(PacketRecord *packet)
{
    g_strlcpy(packet->protocol, "Ethernet", sizeof(packet->protocol));
    if (packet->vlan_count > 0) {
        g_strlcat(packet->protocol, " / VLAN", sizeof(packet->protocol));
    }

    switch (packet->network_kind) {
    case NETWORK_ARP:
        g_strlcat(packet->protocol, " / ARP", sizeof(packet->protocol));
        break;
    case NETWORK_IPV4:
        g_strlcat(packet->protocol, " / IPv4", sizeof(packet->protocol));
        break;
    default: {
        gchar type[24];
        g_snprintf(type, sizeof(type), " / 0x%04X", packet->ether_type);
        g_strlcat(packet->protocol, type, sizeof(packet->protocol));
        break;
    }
    }

    switch (packet->transport_kind) {
    case TRANSPORT_TCP:
        g_strlcat(packet->protocol, " / TCP", sizeof(packet->protocol));
        break;
    case TRANSPORT_UDP:
        g_strlcat(packet->protocol, " / UDP", sizeof(packet->protocol));
        break;
    case TRANSPORT_ICMP:
        g_strlcat(packet->protocol, " / ICMP", sizeof(packet->protocol));
        break;
    default:
        break;
    }

    g_strlcpy(packet->application,
              classify_application(packet->transport_kind,
                                   packet->source_port,
                                   packet->destination_port),
              sizeof(packet->application));
    if (packet->application[0] != '\0') {
        g_strlcat(packet->protocol, " / ", sizeof(packet->protocol));
        g_strlcat(packet->protocol,
                  packet->application,
                  sizeof(packet->protocol));
    }
}

static void parse_packet(PacketRecord *packet)
{
    guint16 ether_type;

    g_strlcpy(packet->source, "-", sizeof(packet->source));
    g_strlcpy(packet->destination, "-", sizeof(packet->destination));
    g_strlcpy(packet->protocol, "Truncated", sizeof(packet->protocol));

    if (!range_available(packet, 0, ETHERNET_HEADER_LENGTH)) {
        set_warning(packet, "Truncated Ethernet header");
        return;
    }

    memcpy(packet->destination_mac, packet->data, 6);
    memcpy(packet->source_mac, packet->data + 6, 6);
    read_u16(packet, 12, &ether_type);
    packet->ethernet_valid = TRUE;
    packet->layer3_offset = ETHERNET_HEADER_LENGTH;
    format_mac(packet->source_mac, packet->source, sizeof(packet->source));
    format_mac(packet->destination_mac,
               packet->destination,
               sizeof(packet->destination));

    while ((ether_type == 0x8100 || ether_type == 0x88a8) &&
           packet->vlan_count < MAX_VLAN_TAGS) {
        if (!range_available(packet, packet->layer3_offset, 4)) {
            packet->ether_type = ether_type;
            set_warning(packet, "Truncated VLAN header");
            build_protocol_name(packet);
            return;
        }
        read_u16(packet,
                 packet->layer3_offset,
                 &packet->vlan_tci[packet->vlan_count]);
        read_u16(packet, packet->layer3_offset + 2, &ether_type);
        packet->vlan_count++;
        packet->layer3_offset += 4;
    }

    packet->ether_type = ether_type;
    if (ether_type == 0x8100 || ether_type == 0x88a8) {
        set_warning(packet, "More than two stacked VLAN tags are unsupported");
    } else if (ether_type == 0x0800) {
        parse_ipv4(packet);
    } else if (ether_type == 0x0806) {
        parse_arp(packet);
    }
    build_protocol_name(packet);
}

PacketRecord *packet_record_new(guint64 id,
                                gint64 timestamp_seconds,
                                gint64 timestamp_microseconds,
                                guint32 original_length,
                                guint32 captured_length,
                                const guint8 *data)
{
    PacketRecord *packet;

    if (captured_length > 0 && data == NULL) {
        return NULL;
    }

    packet = g_new0(PacketRecord, 1);
    packet->id = id;
    packet->timestamp_seconds = timestamp_seconds;
    packet->timestamp_microseconds = timestamp_microseconds;
    packet->original_length = original_length;
    packet->captured_length = captured_length;
    if (captured_length > 0) {
        packet->data = g_malloc(captured_length);
        memcpy(packet->data, data, captured_length);
    }
    parse_packet(packet);
    return packet;
}

void packet_record_free(PacketRecord *packet)
{
    if (packet == NULL) {
        return;
    }
    g_free(packet->data);
    g_free(packet);
}

guint64 packet_record_get_id(const PacketRecord *packet)
{
    return packet->id;
}

const gchar *packet_record_get_source(const PacketRecord *packet)
{
    return packet->source;
}

const gchar *packet_record_get_destination(const PacketRecord *packet)
{
    return packet->destination;
}

const gchar *packet_record_get_protocol(const PacketRecord *packet)
{
    return packet->protocol;
}

const gchar *packet_record_get_warning(const PacketRecord *packet)
{
    return packet->warning;
}

static void append_tcp_flags(GString *details, guint8 flags)
{
    if (flags & 0x01) g_string_append(details, " FIN");
    if (flags & 0x02) g_string_append(details, " SYN");
    if (flags & 0x04) g_string_append(details, " RST");
    if (flags & 0x08) g_string_append(details, " PSH");
    if (flags & 0x10) g_string_append(details, " ACK");
    if (flags & 0x20) g_string_append(details, " URG");
    if (flags & 0x40) g_string_append(details, " ECE");
    if (flags & 0x80) g_string_append(details, " CWR");
}

gchar *packet_record_format_details(const PacketRecord *packet)
{
    GString *details;
    gchar source_mac[32];
    gchar destination_mac[32];

    g_return_val_if_fail(packet != NULL, NULL);

    details = g_string_new(NULL);
    g_string_append_printf(details,
                           "Packet #%" G_GUINT64_FORMAT "\n"
                           "Timestamp: %" G_GINT64_FORMAT ".%06" G_GINT64_FORMAT "\n"
                           "Captured length: %u bytes\n"
                           "Original length: %u bytes\n",
                           packet->id,
                           packet->timestamp_seconds,
                           packet->timestamp_microseconds,
                           packet->captured_length,
                           packet->original_length);

    if (packet->warning[0] != '\0') {
        g_string_append_printf(details, "Warning: %s\n", packet->warning);
    }

    if (!packet->ethernet_valid) {
        return g_string_free(details, FALSE);
    }

    format_mac(packet->source_mac, source_mac, sizeof(source_mac));
    format_mac(packet->destination_mac,
               destination_mac,
               sizeof(destination_mac));
    g_string_append_printf(details,
                           "\nEthernet\n"
                           "  Source: %s\n"
                           "  Destination: %s\n"
                           "  EtherType: 0x%04X\n",
                           source_mac,
                           destination_mac,
                           packet->ether_type);

    if (packet->vlan_count > 0) {
        guint i;
        for (i = 0; i < packet->vlan_count; i++) {
            g_string_append_printf(details,
                                   "  VLAN %u: id=%u, priority=%u, DEI=%u\n",
                                   i + 1,
                                   packet->vlan_tci[i] & 0x0fff,
                                   (packet->vlan_tci[i] >> 13) & 0x7,
                                   (packet->vlan_tci[i] >> 12) & 0x1);
        }
    }

    if (packet->network_kind == NETWORK_ARP) {
        g_string_append_printf(details,
                               "\nARP\n"
                               "  Hardware type: %u\n"
                               "  Protocol type: 0x%04X\n"
                               "  Hardware address length: %u\n"
                               "  Protocol address length: %u\n"
                               "  Operation: %u\n",
                               packet->arp_hardware_type,
                               packet->arp_protocol_type,
                               packet->arp_hardware_length,
                               packet->arp_protocol_length,
                               packet->arp_operation);
        if (packet->network_valid) {
            gchar arp_source_mac[32];
            gchar arp_destination_mac[32];
            gchar arp_source_ip[32];
            gchar arp_destination_ip[32];

            format_mac(packet->arp_source_mac,
                       arp_source_mac,
                       sizeof(arp_source_mac));
            format_mac(packet->arp_destination_mac,
                       arp_destination_mac,
                       sizeof(arp_destination_mac));
            format_ipv4(packet->arp_source_ip,
                        arp_source_ip,
                        sizeof(arp_source_ip));
            format_ipv4(packet->arp_destination_ip,
                        arp_destination_ip,
                        sizeof(arp_destination_ip));
            g_string_append_printf(details,
                                   "  Sender MAC: %s\n"
                                   "  Sender IP: %s\n"
                                   "  Target MAC: %s\n"
                                   "  Target IP: %s\n",
                                   arp_source_mac,
                                   arp_source_ip,
                                   arp_destination_mac,
                                   arp_destination_ip);
        }
    }

    if (packet->network_kind == NETWORK_IPV4) {
        g_string_append_printf(details,
                               "\nIPv4\n"
                               "  Version: %u\n"
                               "  Header length: %u bytes\n"
                               "  DSCP/ECN: 0x%02X\n"
                               "  Total length: %u bytes\n"
                               "  Identification: %u\n"
                               "  Fragment offset: %u bytes\n"
                               "  More fragments: %s\n"
                               "  TTL: %u\n"
                               "  Protocol: %u\n"
                               "  Header checksum: 0x%04X\n"
                               "  Source: %s\n"
                               "  Destination: %s\n",
                               packet->ipv4_version,
                               packet->ipv4_header_length,
                               packet->ipv4_tos,
                               packet->ipv4_total_length,
                               packet->ipv4_id,
                               (packet->ipv4_fragment & 0x1fff) * 8,
                               (packet->ipv4_fragment & 0x2000) ? "yes" : "no",
                               packet->ipv4_ttl,
                               packet->ipv4_protocol,
                               packet->ipv4_checksum,
                               packet->source,
                               packet->destination);
    }

    if (packet->transport_kind == TRANSPORT_TCP) {
        g_string_append_printf(details,
                               "\nTCP\n"
                               "  Source port: %u\n"
                               "  Destination port: %u\n"
                               "  Sequence: %u\n"
                               "  Acknowledgement: %u\n"
                               "  Header length: %u bytes\n"
                               "  Flags:",
                               packet->source_port,
                               packet->destination_port,
                               packet->tcp_sequence,
                               packet->tcp_acknowledgement,
                               packet->tcp_header_length);
        append_tcp_flags(details, packet->tcp_flags);
        g_string_append_printf(details,
                               "\n  Window: %u\n"
                               "  Checksum: 0x%04X\n"
                               "  Urgent pointer: %u\n",
                               packet->tcp_window,
                               packet->transport_checksum,
                               packet->tcp_urgent_pointer);
    } else if (packet->transport_kind == TRANSPORT_UDP) {
        g_string_append_printf(details,
                               "\nUDP\n"
                               "  Source port: %u\n"
                               "  Destination port: %u\n"
                               "  Length: %u bytes\n"
                               "  Checksum: 0x%04X\n",
                               packet->source_port,
                               packet->destination_port,
                               packet->udp_length,
                               packet->transport_checksum);
    } else if (packet->transport_kind == TRANSPORT_ICMP) {
        g_string_append_printf(details,
                               "\nICMP\n"
                               "  Type: %u\n"
                               "  Code: %u\n"
                               "  Checksum: 0x%04X\n",
                               packet->icmp_type,
                               packet->icmp_code,
                               packet->transport_checksum);
        if (packet->icmp_type == 0 || packet->icmp_type == 8) {
            g_string_append_printf(details,
                                   "  Identifier: %u\n"
                                   "  Sequence: %u\n",
                                   packet->icmp_id,
                                   packet->icmp_sequence);
        }
    }

    if (packet->application[0] != '\0') {
        g_string_append_printf(details,
                               "\nApplication guess: %s (port-based)\n",
                               packet->application);
    }

    return g_string_free(details, FALSE);
}
