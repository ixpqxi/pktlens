#include "packet.h"

#include <string.h>

static void put_u16(guint8 *data, guint offset, guint16 value)
{
    data[offset] = (guint8)(value >> 8);
    data[offset + 1] = (guint8)value;
}

static void put_u32(guint8 *data, guint offset, guint32 value)
{
    data[offset] = (guint8)(value >> 24);
    data[offset + 1] = (guint8)(value >> 16);
    data[offset + 2] = (guint8)(value >> 8);
    data[offset + 3] = (guint8)value;
}

static void set_ethernet(guint8 *data, guint16 ether_type)
{
    guint i;
    for (i = 0; i < 6; i++) {
        data[i] = (guint8)(0x10 + i);
        data[6 + i] = (guint8)(0x20 + i);
    }
    put_u16(data, 12, ether_type);
}

static void set_ipv4_header(guint8 *data,
                            guint offset,
                            guint8 ihl_words,
                            guint16 total_length,
                            guint8 protocol)
{
    data[offset] = (guint8)(0x40 | ihl_words);
    data[offset + 1] = 0;
    put_u16(data, offset + 2, total_length);
    put_u16(data, offset + 4, 0x1234);
    put_u16(data, offset + 6, 0);
    data[offset + 8] = 64;
    data[offset + 9] = protocol;
    put_u16(data, offset + 10, 0);
    data[offset + 12] = 10;
    data[offset + 13] = 0;
    data[offset + 14] = 0;
    data[offset + 15] = 1;
    data[offset + 16] = 10;
    data[offset + 17] = 0;
    data[offset + 18] = 0;
    data[offset + 19] = 2;
}

static void test_truncated_packet(void)
{
    const guint8 data[] = {0, 1, 2, 3, 4};
    PacketRecord *packet = packet_record_new(1, 10, 20, 60, sizeof(data), data);

    g_assert_nonnull(packet);
    g_assert_cmpstr(packet_record_get_protocol(packet), ==, "Truncated");
    g_assert_true(strstr(packet_record_get_warning(packet), "Ethernet") != NULL);
    packet_record_free(packet);
}

static void test_tcp_with_ip_options(void)
{
    guint8 data[14 + 24 + 20] = {0};
    PacketRecord *packet;
    gchar *details;

    set_ethernet(data, 0x0800);
    set_ipv4_header(data, 14, 6, 44, 6);
    data[14 + 20] = 1;
    data[14 + 21] = 1;
    data[14 + 22] = 1;
    data[14 + 23] = 1;
    put_u16(data, 14 + 24, 1234);
    put_u16(data, 14 + 26, 80);
    put_u32(data, 14 + 28, 1);
    put_u32(data, 14 + 32, 2);
    data[14 + 36] = 0x50;
    data[14 + 37] = 0x02;
    put_u16(data, 14 + 38, 4096);

    packet = packet_record_new(2, 1, 2, sizeof(data), sizeof(data), data);
    g_assert_cmpstr(packet_record_get_source(packet), ==, "10.0.0.1");
    g_assert_cmpstr(packet_record_get_destination(packet), ==, "10.0.0.2");
    g_assert_true(strstr(packet_record_get_protocol(packet), "TCP") != NULL);
    g_assert_true(strstr(packet_record_get_protocol(packet), "HTTP") != NULL);
    details = packet_record_format_details(packet);
    g_assert_true(strstr(details, "Header length: 24 bytes") != NULL);
    g_assert_true(strstr(details, "SYN") != NULL);
    g_free(details);
    packet_record_free(packet);
}

static void test_vlan_udp_and_network_order(void)
{
    guint8 data[14 + 4 + 20 + 8] = {0};
    PacketRecord *packet;
    gchar *details;

    set_ethernet(data, 0x8100);
    put_u16(data, 14, 100);
    put_u16(data, 16, 0x0800);
    set_ipv4_header(data, 18, 5, 28, 17);
    put_u16(data, 18 + 20, 53);
    put_u16(data, 18 + 22, 60000);
    put_u16(data, 18 + 24, 8);
    put_u16(data, 18 + 26, 0x1234);

    packet = packet_record_new(3, 1, 2, sizeof(data), sizeof(data), data);
    g_assert_true(strstr(packet_record_get_protocol(packet), "VLAN") != NULL);
    g_assert_true(strstr(packet_record_get_protocol(packet), "UDP") != NULL);
    g_assert_true(strstr(packet_record_get_protocol(packet), "DNS") != NULL);
    details = packet_record_format_details(packet);
    g_assert_true(strstr(details, "Length: 8 bytes") != NULL);
    g_free(details);
    packet_record_free(packet);
}

static void test_arp(void)
{
    guint8 data[14 + 28] = {0};
    PacketRecord *packet;

    set_ethernet(data, 0x0806);
    put_u16(data, 14, 1);
    put_u16(data, 16, 0x0800);
    data[18] = 6;
    data[19] = 4;
    put_u16(data, 20, 1);
    memcpy(data + 22, data + 6, 6);
    data[28] = 192;
    data[29] = 168;
    data[30] = 1;
    data[31] = 1;
    memcpy(data + 32, data, 6);
    data[38] = 192;
    data[39] = 168;
    data[40] = 1;
    data[41] = 2;

    packet = packet_record_new(4, 1, 2, sizeof(data), sizeof(data), data);
    g_assert_cmpstr(packet_record_get_source(packet), ==, "192.168.1.1");
    g_assert_cmpstr(packet_record_get_destination(packet), ==, "192.168.1.2");
    g_assert_true(strstr(packet_record_get_protocol(packet), "ARP") != NULL);
    packet_record_free(packet);
}

static void test_packet_owns_copy(void)
{
    guint8 data[14] = {0};
    PacketRecord *packet;

    set_ethernet(data, 0x0806);
    packet = packet_record_new(5, 0, 0, sizeof(data), sizeof(data), data);
    data[0] = 0xff;
    g_assert_cmpstr(packet_record_get_destination(packet),
                    ==, "10:11:12:13:14:15");
    packet_record_free(packet);
}

static void test_random_packet_lengths(void)
{
    guint i;

    g_random_set_seed(0x50434150U);
    for (i = 0; i < 10000; i++) {
        guint8 data[256];
        guint length = g_random_int_range(0, sizeof(data) + 1);
        guint j;
        PacketRecord *packet;
        gchar *details;

        for (j = 0; j < sizeof(data); j++) {
            data[j] = (guint8)g_random_int_range(0, 256);
        }
        packet = packet_record_new(i, 0, 0, length + 32, length, data);
        g_assert_nonnull(packet);
        details = packet_record_format_details(packet);
        g_assert_nonnull(details);
        g_free(details);
        packet_record_free(packet);
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/packet/truncated", test_truncated_packet);
    g_test_add_func("/packet/tcp-options", test_tcp_with_ip_options);
    g_test_add_func("/packet/vlan-udp", test_vlan_udp_and_network_order);
    g_test_add_func("/packet/arp", test_arp);
    g_test_add_func("/packet/owns-copy", test_packet_owns_copy);
    g_test_add_func("/packet/random-lengths", test_random_packet_lengths);
    return g_test_run();
}
