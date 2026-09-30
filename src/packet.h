#ifndef PACP_PACKET_H
#define PACP_PACKET_H

#include <glib.h>

G_BEGIN_DECLS

typedef struct PacketRecord PacketRecord;

PacketRecord *packet_record_new(guint64 id,
                                gint64 timestamp_seconds,
                                gint64 timestamp_microseconds,
                                guint32 original_length,
                                guint32 captured_length,
                                const guint8 *data);

void packet_record_free(PacketRecord *packet);

guint64 packet_record_get_id(const PacketRecord *packet);
const gchar *packet_record_get_source(const PacketRecord *packet);
const gchar *packet_record_get_destination(const PacketRecord *packet);
const gchar *packet_record_get_protocol(const PacketRecord *packet);
const gchar *packet_record_get_warning(const PacketRecord *packet);

/* The caller owns the returned UTF-8 string. */
gchar *packet_record_format_details(const PacketRecord *packet);

G_END_DECLS

#endif
