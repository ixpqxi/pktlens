#include "capture.h"

#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#define CAPTURE_SNAPSHOT_LENGTH 65535
#define CAPTURE_READ_TIMEOUT_MS 250

struct CaptureSession {
    pcap_t *handle;
    GThread *thread;
    GMutex lock;
    gint running;
    gint stopping;
    gchar last_error[PCAP_ERRBUF_SIZE];
    CapturePacketCallback callback;
    gpointer user_data;
};

static GQuark capture_error_quark(void)
{
    return g_quark_from_static_string("pacp-capture-error");
}

static void set_error_message(GError **error, const gchar *message)
{
    if (error != NULL) {
        g_set_error(error, capture_error_quark(), 1, "%s", message);
    }
}

static gchar *copy_text(const gchar *text, const gchar *fallback)
{
    gchar *converted;

    if (text == NULL || *text == '\0') {
        return g_strdup(fallback);
    }
    if (g_utf8_validate(text, -1, NULL)) {
        return g_strdup(text);
    }
    converted = g_locale_to_utf8(text, -1, NULL, NULL, NULL);
    if (converted != NULL) {
        return converted;
    }
    return g_strdup(fallback);
}

static void copy_ipv4_address(const struct sockaddr *address,
                              gchar *output,
                              gsize output_size)
{
    const guint8 *bytes;
    const struct sockaddr_in *ipv4;

    if (address == NULL || address->sa_family != AF_INET) {
        return;
    }
    ipv4 = (const struct sockaddr_in *)address;
    bytes = (const guint8 *)&ipv4->sin_addr;
    g_snprintf(output,
               output_size,
               "%u.%u.%u.%u",
               bytes[0], bytes[1], bytes[2], bytes[3]);
}

static void capture_device_free(CaptureDevice *device)
{
    if (device == NULL) {
        return;
    }
    g_free(device->name);
    g_free(device->description);
    g_free(device->address);
    g_free(device->netmask);
    g_free(device);
}

GPtrArray *capture_list_devices(GError **error)
{
    pcap_if_t *all_devices = NULL;
    pcap_if_t *current;
    gchar error_buffer[PCAP_ERRBUF_SIZE] = {0};
    GPtrArray *devices;

    if (pcap_findalldevs(&all_devices, error_buffer) == -1) {
        set_error_message(error, error_buffer[0] != '\0' ?
                          error_buffer : "Unable to enumerate capture devices");
        return NULL;
    }

    devices = g_ptr_array_new_with_free_func((GDestroyNotify)capture_device_free);
    for (current = all_devices; current != NULL; current = current->next) {
        CaptureDevice *device = g_new0(CaptureDevice, 1);
        pcap_addr_t *address;
        bpf_u_int32 network_value;

        device->name = g_strdup(current->name);
        device->description = copy_text(current->description, current->name);
        device->address = g_strdup("-");
        device->netmask = g_strdup("-");
        device->netmask_value = PCAP_NETMASK_UNKNOWN;

        for (address = current->addresses; address != NULL;
             address = address->next) {
            if (address->addr != NULL &&
                address->addr->sa_family == AF_INET) {
                gchar ip[32] = {0};
                gchar mask[32] = {0};

                copy_ipv4_address(address->addr, ip, sizeof(ip));
                if (address->netmask != NULL) {
                    copy_ipv4_address(address->netmask, mask, sizeof(mask));
                }
                if (ip[0] != '\0') {
                    g_free(device->address);
                    device->address = g_strdup(ip);
                }
                if (mask[0] != '\0') {
                    g_free(device->netmask);
                    device->netmask = g_strdup(mask);
                }
                break;
            }
        }

        if (pcap_lookupnet(device->name,
                           &network_value,
                           &device->netmask_value,
                           error_buffer) == -1) {
            device->netmask_value = PCAP_NETMASK_UNKNOWN;
        }
        g_ptr_array_add(devices, device);
    }
    pcap_freealldevs(all_devices);

    if (devices->len == 0) {
        g_ptr_array_free(devices, TRUE);
        set_error_message(error, "No capture devices were found");
        return NULL;
    }
    return devices;
}

void capture_devices_free(GPtrArray *devices)
{
    if (devices != NULL) {
        g_ptr_array_free(devices, TRUE);
    }
}

static void pcap_packet_handler(u_char *user_data,
                                const struct pcap_pkthdr *header,
                                const u_char *data)
{
    CaptureSession *session = (CaptureSession *)user_data;

    if (session == NULL || header == NULL || data == NULL ||
        g_atomic_int_get(&session->stopping)) {
        return;
    }
    session->callback(header, data, session->user_data);
}

static gpointer capture_thread_main(gpointer user_data)
{
    CaptureSession *session = (CaptureSession *)user_data;
    int result;

    result = pcap_loop(session->handle, -1, pcap_packet_handler,
                       (u_char *)session);
    if (result == -1 && !g_atomic_int_get(&session->stopping)) {
        g_mutex_lock(&session->lock);
        g_strlcpy(session->last_error,
                  pcap_geterr(session->handle),
                  sizeof(session->last_error));
        g_mutex_unlock(&session->lock);
    }
    g_atomic_int_set(&session->running, 0);
    return NULL;
}

CaptureSession *capture_session_new(CapturePacketCallback callback,
                                    gpointer user_data)
{
    CaptureSession *session;

    g_return_val_if_fail(callback != NULL, NULL);
    session = g_new0(CaptureSession, 1);
    g_mutex_init(&session->lock);
    session->callback = callback;
    session->user_data = user_data;
    return session;
}

void capture_session_free(CaptureSession *session)
{
    if (session == NULL) {
        return;
    }
    capture_session_stop(session);
    g_mutex_clear(&session->lock);
    g_free(session);
}

gboolean capture_session_start(CaptureSession *session,
                               const CaptureDevice *device,
                               const gchar *filter_expression,
                               GError **error)
{
    gchar error_buffer[PCAP_ERRBUF_SIZE] = {0};
    struct bpf_program program;
    bpf_u_int32 netmask;

    g_return_val_if_fail(session != NULL, FALSE);
    g_return_val_if_fail(device != NULL && device->name != NULL, FALSE);

    if (g_atomic_int_get(&session->running)) {
        set_error_message(error, "A capture session is already running");
        return FALSE;
    }

    /* A previous session can have ended on its own; reap it before reuse. */
    capture_session_stop(session);

    session->handle = pcap_open_live(device->name,
                                     CAPTURE_SNAPSHOT_LENGTH,
                                     1,
                                     CAPTURE_READ_TIMEOUT_MS,
                                     error_buffer);
    if (session->handle == NULL) {
        set_error_message(error, error_buffer[0] != '\0' ?
                          error_buffer : "Unable to open capture device");
        return FALSE;
    }
    if (pcap_datalink(session->handle) != DLT_EN10MB) {
        pcap_close(session->handle);
        session->handle = NULL;
        set_error_message(error, "Only Ethernet link-layer devices are supported");
        return FALSE;
    }

    netmask = device->netmask_value;
    if (pcap_compile(session->handle,
                     &program,
                     filter_expression != NULL ? filter_expression : "",
                     1,
                     netmask) == -1) {
        set_error_message(error, pcap_geterr(session->handle));
        pcap_close(session->handle);
        session->handle = NULL;
        return FALSE;
    }
    if (pcap_setfilter(session->handle, &program) == -1) {
        set_error_message(error, pcap_geterr(session->handle));
        pcap_freecode(&program);
        pcap_close(session->handle);
        session->handle = NULL;
        return FALSE;
    }
    pcap_freecode(&program);

    g_mutex_lock(&session->lock);
    session->last_error[0] = '\0';
    g_mutex_unlock(&session->lock);
    g_atomic_int_set(&session->stopping, 0);
    g_atomic_int_set(&session->running, 1);
    session->thread = g_thread_new("pcap-capture", capture_thread_main, session);
    if (session->thread == NULL) {
        g_atomic_int_set(&session->running, 0);
        pcap_close(session->handle);
        session->handle = NULL;
        set_error_message(error, "Unable to create capture thread");
        return FALSE;
    }
    return TRUE;
}

void capture_session_stop(CaptureSession *session)
{
    GThread *thread;
    pcap_t *handle;

    if (session == NULL) {
        return;
    }

    g_atomic_int_set(&session->stopping, 1);
    g_mutex_lock(&session->lock);
    handle = session->handle;
    thread = session->thread;
    g_mutex_unlock(&session->lock);

    if (handle != NULL) {
        pcap_breakloop(handle);
    }
    if (thread != NULL) {
        g_thread_join(thread);
    }

    g_mutex_lock(&session->lock);
    if (session->handle != NULL) {
        pcap_close(session->handle);
        session->handle = NULL;
    }
    session->thread = NULL;
    g_mutex_unlock(&session->lock);
    g_atomic_int_set(&session->running, 0);
}

gboolean capture_session_is_running(const CaptureSession *session)
{
    return session != NULL && g_atomic_int_get(&session->running) != 0;
}

const gchar *capture_session_get_error(const CaptureSession *session)
{
    return session != NULL ? session->last_error : "";
}
