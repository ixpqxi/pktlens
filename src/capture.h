#ifndef PACP_CAPTURE_H
#define PACP_CAPTURE_H

#include <glib.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/types.h>
#endif

#include <pcap.h>

G_BEGIN_DECLS

typedef struct CaptureDevice CaptureDevice;
typedef struct CaptureSession CaptureSession;

struct CaptureDevice {
    gchar *name;
    gchar *description;
    gchar *address;
    gchar *netmask;
    bpf_u_int32 netmask_value;
};

typedef void (*CapturePacketCallback)(const struct pcap_pkthdr *header,
                                       const guint8 *data,
                                       gpointer user_data);

GPtrArray *capture_list_devices(GError **error);
void capture_devices_free(GPtrArray *devices);

CaptureSession *capture_session_new(CapturePacketCallback callback,
                                    gpointer user_data);
void capture_session_free(CaptureSession *session);

gboolean capture_session_start(CaptureSession *session,
                               const CaptureDevice *device,
                               const gchar *filter_expression,
                               GError **error);
void capture_session_stop(CaptureSession *session);
gboolean capture_session_is_running(const CaptureSession *session);
const gchar *capture_session_get_error(const CaptureSession *session);

G_END_DECLS

#endif
