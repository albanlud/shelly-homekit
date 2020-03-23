/* clang-format off */
/*
 * Generated file - do not edit.
 * Command: /mongoose-os/tools/mgos_gen_config.py --c_name=mgos_config --c_global_name=mgos_sys_config --dest_dir=/data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/gen/ /mongoose-os/src/mgos_debug_udp_config.yaml /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/gen/mos_conf_schema.yml
 */

#pragma once

#include <stdbool.h>
#include "common/mg_str.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mgos_config_debug {
  const char * udp_log_addr;
  int udp_log_level;
  int mbedtls_level;
  int level;
  const char * file_level;
  int event_level;
  int stdout_uart;
  int stderr_uart;
  int factory_reset_gpio;
  const char * mg_mgr_hexdump_file;
};

struct mgos_config_device {
  const char * id;
  const char * license;
  const char * mac;
  const char * public_key;
  const char * sn;
};

struct mgos_config_sys {
  const char * tz_spec;
  int wdt_timeout;
  const char * pref_ota_lib;
};

struct mgos_config_dns_sd {
  int enable;
  const char * host_name;
  const char * txt;
  int ttl;
};

struct mgos_config_hap {
  const char * salt;
  const char * verifier;
};

struct mgos_config_http {
  int enable;
  const char * listen_addr;
  const char * document_root;
  const char * index_files;
  const char * ssl_cert;
  const char * ssl_key;
  const char * ssl_ca_cert;
  const char * upload_acl;
  const char * hidden_files;
  const char * auth_domain;
  const char * auth_file;
};

struct mgos_config_update {
  int timeout;
  int commit_timeout;
  const char * url;
  int interval;
  const char * extra_http_headers;
  const char * ssl_ca_file;
  const char * ssl_client_cert_file;
  const char * ssl_server_name;
  int enable_post;
};

struct mgos_config_rpc_uart {
  int uart_no;
  int baud_rate;
  int fc_type;
  const char * dst;
};

struct mgos_config_rpc_ws {
  int enable;
  const char * server_address;
  int reconnect_interval_min;
  int reconnect_interval_max;
  const char * ssl_server_name;
  const char * ssl_cert;
  const char * ssl_key;
  const char * ssl_ca_cert;
};

struct mgos_config_rpc {
  int enable;
  int max_frame_size;
  int max_queue_length;
  int default_out_channel_idle_close_timeout;
  const char * acl_file;
  const char * auth_domain;
  const char * auth_file;
  struct mgos_config_rpc_uart uart;
  struct mgos_config_rpc_ws ws;
};

struct mgos_config_wifi_ap {
  int enable;
  const char * ssid;
  const char * pass;
  int hidden;
  int channel;
  int max_connections;
  const char * ip;
  const char * netmask;
  const char * gw;
  const char * dhcp_start;
  const char * dhcp_end;
  int trigger_on_gpio;
  int disable_after;
  const char * hostname;
  int keep_enabled;
};

struct mgos_config_wifi_sta {
  int enable;
  const char * ssid;
  const char * pass;
  const char * user;
  const char * anon_identity;
  const char * cert;
  const char * key;
  const char * ca_cert;
  const char * ip;
  const char * netmask;
  const char * gw;
  const char * nameserver;
  const char * dhcp_hostname;
};

struct mgos_config_wifi {
  struct mgos_config_wifi_ap ap;
  struct mgos_config_wifi_sta sta;
  struct mgos_config_wifi_sta sta1;
  struct mgos_config_wifi_sta sta2;
  int sta_cfg_idx;
  int sta_connect_timeout;
};

struct mgos_config_sw {
  int id;
  const char * name;
  int enable;
  int out_gpio;
  int out_on_value;
  int in_gpio;
  int in_mode;
  int state;
  int persist_state;
};

struct mgos_config {
  struct mgos_config_debug debug;
  struct mgos_config_device device;
  struct mgos_config_sys sys;
  const char * conf_acl;
  struct mgos_config_dns_sd dns_sd;
  struct mgos_config_hap hap;
  struct mgos_config_http http;
  struct mgos_config_update update;
  struct mgos_config_rpc rpc;
  struct mgos_config_wifi wifi;
  struct mgos_config_sw sw;
  struct mgos_config_sw sw1;
};


const struct mgos_conf_entry *mgos_config_schema();

extern struct mgos_config mgos_sys_config;
extern const struct mgos_config mgos_config_defaults;

/* debug */
#define MGOS_CONFIG_HAVE_DEBUG
#define MGOS_SYS_CONFIG_HAVE_DEBUG
const struct mgos_config_debug * mgos_config_get_debug(struct mgos_config *cfg);
static inline const struct mgos_config_debug * mgos_sys_config_get_debug(void) { return mgos_config_get_debug(&mgos_sys_config); }
const struct mgos_conf_entry *mgos_config_schema_debug(void);
bool mgos_config_parse_debug(struct mg_str json, struct mgos_config_debug *cfg);
bool mgos_config_copy_debug(const struct mgos_config_debug *src, struct mgos_config_debug *dst);
void mgos_config_free_debug(struct mgos_config_debug *cfg);

/* debug.udp_log_addr */
#define MGOS_CONFIG_HAVE_DEBUG_UDP_LOG_ADDR
#define MGOS_SYS_CONFIG_HAVE_DEBUG_UDP_LOG_ADDR
const char * mgos_config_get_debug_udp_log_addr(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_debug_udp_log_addr(void) { return mgos_config_get_debug_udp_log_addr(&mgos_sys_config); }
void mgos_config_set_debug_udp_log_addr(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_debug_udp_log_addr(const char * v) { mgos_config_set_debug_udp_log_addr(&mgos_sys_config, v); }

/* debug.udp_log_level */
#define MGOS_CONFIG_HAVE_DEBUG_UDP_LOG_LEVEL
#define MGOS_SYS_CONFIG_HAVE_DEBUG_UDP_LOG_LEVEL
int mgos_config_get_debug_udp_log_level(struct mgos_config *cfg);
static inline int mgos_sys_config_get_debug_udp_log_level(void) { return mgos_config_get_debug_udp_log_level(&mgos_sys_config); }
void mgos_config_set_debug_udp_log_level(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_debug_udp_log_level(int v) { mgos_config_set_debug_udp_log_level(&mgos_sys_config, v); }

/* debug.mbedtls_level */
#define MGOS_CONFIG_HAVE_DEBUG_MBEDTLS_LEVEL
#define MGOS_SYS_CONFIG_HAVE_DEBUG_MBEDTLS_LEVEL
int mgos_config_get_debug_mbedtls_level(struct mgos_config *cfg);
static inline int mgos_sys_config_get_debug_mbedtls_level(void) { return mgos_config_get_debug_mbedtls_level(&mgos_sys_config); }
void mgos_config_set_debug_mbedtls_level(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_debug_mbedtls_level(int v) { mgos_config_set_debug_mbedtls_level(&mgos_sys_config, v); }

/* debug.level */
#define MGOS_CONFIG_HAVE_DEBUG_LEVEL
#define MGOS_SYS_CONFIG_HAVE_DEBUG_LEVEL
int mgos_config_get_debug_level(struct mgos_config *cfg);
static inline int mgos_sys_config_get_debug_level(void) { return mgos_config_get_debug_level(&mgos_sys_config); }
void mgos_config_set_debug_level(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_debug_level(int v) { mgos_config_set_debug_level(&mgos_sys_config, v); }

/* debug.file_level */
#define MGOS_CONFIG_HAVE_DEBUG_FILE_LEVEL
#define MGOS_SYS_CONFIG_HAVE_DEBUG_FILE_LEVEL
const char * mgos_config_get_debug_file_level(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_debug_file_level(void) { return mgos_config_get_debug_file_level(&mgos_sys_config); }
void mgos_config_set_debug_file_level(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_debug_file_level(const char * v) { mgos_config_set_debug_file_level(&mgos_sys_config, v); }

/* debug.event_level */
#define MGOS_CONFIG_HAVE_DEBUG_EVENT_LEVEL
#define MGOS_SYS_CONFIG_HAVE_DEBUG_EVENT_LEVEL
int mgos_config_get_debug_event_level(struct mgos_config *cfg);
static inline int mgos_sys_config_get_debug_event_level(void) { return mgos_config_get_debug_event_level(&mgos_sys_config); }
void mgos_config_set_debug_event_level(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_debug_event_level(int v) { mgos_config_set_debug_event_level(&mgos_sys_config, v); }

/* debug.stdout_uart */
#define MGOS_CONFIG_HAVE_DEBUG_STDOUT_UART
#define MGOS_SYS_CONFIG_HAVE_DEBUG_STDOUT_UART
int mgos_config_get_debug_stdout_uart(struct mgos_config *cfg);
static inline int mgos_sys_config_get_debug_stdout_uart(void) { return mgos_config_get_debug_stdout_uart(&mgos_sys_config); }
void mgos_config_set_debug_stdout_uart(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_debug_stdout_uart(int v) { mgos_config_set_debug_stdout_uart(&mgos_sys_config, v); }

/* debug.stderr_uart */
#define MGOS_CONFIG_HAVE_DEBUG_STDERR_UART
#define MGOS_SYS_CONFIG_HAVE_DEBUG_STDERR_UART
int mgos_config_get_debug_stderr_uart(struct mgos_config *cfg);
static inline int mgos_sys_config_get_debug_stderr_uart(void) { return mgos_config_get_debug_stderr_uart(&mgos_sys_config); }
void mgos_config_set_debug_stderr_uart(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_debug_stderr_uart(int v) { mgos_config_set_debug_stderr_uart(&mgos_sys_config, v); }

/* debug.factory_reset_gpio */
#define MGOS_CONFIG_HAVE_DEBUG_FACTORY_RESET_GPIO
#define MGOS_SYS_CONFIG_HAVE_DEBUG_FACTORY_RESET_GPIO
int mgos_config_get_debug_factory_reset_gpio(struct mgos_config *cfg);
static inline int mgos_sys_config_get_debug_factory_reset_gpio(void) { return mgos_config_get_debug_factory_reset_gpio(&mgos_sys_config); }
void mgos_config_set_debug_factory_reset_gpio(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_debug_factory_reset_gpio(int v) { mgos_config_set_debug_factory_reset_gpio(&mgos_sys_config, v); }

/* debug.mg_mgr_hexdump_file */
#define MGOS_CONFIG_HAVE_DEBUG_MG_MGR_HEXDUMP_FILE
#define MGOS_SYS_CONFIG_HAVE_DEBUG_MG_MGR_HEXDUMP_FILE
const char * mgos_config_get_debug_mg_mgr_hexdump_file(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_debug_mg_mgr_hexdump_file(void) { return mgos_config_get_debug_mg_mgr_hexdump_file(&mgos_sys_config); }
void mgos_config_set_debug_mg_mgr_hexdump_file(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_debug_mg_mgr_hexdump_file(const char * v) { mgos_config_set_debug_mg_mgr_hexdump_file(&mgos_sys_config, v); }

/* device */
#define MGOS_CONFIG_HAVE_DEVICE
#define MGOS_SYS_CONFIG_HAVE_DEVICE
const struct mgos_config_device * mgos_config_get_device(struct mgos_config *cfg);
static inline const struct mgos_config_device * mgos_sys_config_get_device(void) { return mgos_config_get_device(&mgos_sys_config); }
const struct mgos_conf_entry *mgos_config_schema_device(void);
bool mgos_config_parse_device(struct mg_str json, struct mgos_config_device *cfg);
bool mgos_config_copy_device(const struct mgos_config_device *src, struct mgos_config_device *dst);
void mgos_config_free_device(struct mgos_config_device *cfg);

/* device.id */
#define MGOS_CONFIG_HAVE_DEVICE_ID
#define MGOS_SYS_CONFIG_HAVE_DEVICE_ID
const char * mgos_config_get_device_id(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_device_id(void) { return mgos_config_get_device_id(&mgos_sys_config); }
void mgos_config_set_device_id(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_device_id(const char * v) { mgos_config_set_device_id(&mgos_sys_config, v); }

/* device.license */
#define MGOS_CONFIG_HAVE_DEVICE_LICENSE
#define MGOS_SYS_CONFIG_HAVE_DEVICE_LICENSE
const char * mgos_config_get_device_license(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_device_license(void) { return mgos_config_get_device_license(&mgos_sys_config); }
void mgos_config_set_device_license(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_device_license(const char * v) { mgos_config_set_device_license(&mgos_sys_config, v); }

/* device.mac */
#define MGOS_CONFIG_HAVE_DEVICE_MAC
#define MGOS_SYS_CONFIG_HAVE_DEVICE_MAC
const char * mgos_config_get_device_mac(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_device_mac(void) { return mgos_config_get_device_mac(&mgos_sys_config); }
void mgos_config_set_device_mac(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_device_mac(const char * v) { mgos_config_set_device_mac(&mgos_sys_config, v); }

/* device.public_key */
#define MGOS_CONFIG_HAVE_DEVICE_PUBLIC_KEY
#define MGOS_SYS_CONFIG_HAVE_DEVICE_PUBLIC_KEY
const char * mgos_config_get_device_public_key(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_device_public_key(void) { return mgos_config_get_device_public_key(&mgos_sys_config); }
void mgos_config_set_device_public_key(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_device_public_key(const char * v) { mgos_config_set_device_public_key(&mgos_sys_config, v); }

/* device.sn */
#define MGOS_CONFIG_HAVE_DEVICE_SN
#define MGOS_SYS_CONFIG_HAVE_DEVICE_SN
const char * mgos_config_get_device_sn(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_device_sn(void) { return mgos_config_get_device_sn(&mgos_sys_config); }
void mgos_config_set_device_sn(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_device_sn(const char * v) { mgos_config_set_device_sn(&mgos_sys_config, v); }

/* sys */
#define MGOS_CONFIG_HAVE_SYS
#define MGOS_SYS_CONFIG_HAVE_SYS
const struct mgos_config_sys * mgos_config_get_sys(struct mgos_config *cfg);
static inline const struct mgos_config_sys * mgos_sys_config_get_sys(void) { return mgos_config_get_sys(&mgos_sys_config); }
const struct mgos_conf_entry *mgos_config_schema_sys(void);
bool mgos_config_parse_sys(struct mg_str json, struct mgos_config_sys *cfg);
bool mgos_config_copy_sys(const struct mgos_config_sys *src, struct mgos_config_sys *dst);
void mgos_config_free_sys(struct mgos_config_sys *cfg);

/* sys.tz_spec */
#define MGOS_CONFIG_HAVE_SYS_TZ_SPEC
#define MGOS_SYS_CONFIG_HAVE_SYS_TZ_SPEC
const char * mgos_config_get_sys_tz_spec(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_sys_tz_spec(void) { return mgos_config_get_sys_tz_spec(&mgos_sys_config); }
void mgos_config_set_sys_tz_spec(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_sys_tz_spec(const char * v) { mgos_config_set_sys_tz_spec(&mgos_sys_config, v); }

/* sys.wdt_timeout */
#define MGOS_CONFIG_HAVE_SYS_WDT_TIMEOUT
#define MGOS_SYS_CONFIG_HAVE_SYS_WDT_TIMEOUT
int mgos_config_get_sys_wdt_timeout(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sys_wdt_timeout(void) { return mgos_config_get_sys_wdt_timeout(&mgos_sys_config); }
void mgos_config_set_sys_wdt_timeout(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sys_wdt_timeout(int v) { mgos_config_set_sys_wdt_timeout(&mgos_sys_config, v); }

/* sys.pref_ota_lib */
#define MGOS_CONFIG_HAVE_SYS_PREF_OTA_LIB
#define MGOS_SYS_CONFIG_HAVE_SYS_PREF_OTA_LIB
const char * mgos_config_get_sys_pref_ota_lib(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_sys_pref_ota_lib(void) { return mgos_config_get_sys_pref_ota_lib(&mgos_sys_config); }
void mgos_config_set_sys_pref_ota_lib(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_sys_pref_ota_lib(const char * v) { mgos_config_set_sys_pref_ota_lib(&mgos_sys_config, v); }

/* conf_acl */
#define MGOS_CONFIG_HAVE_CONF_ACL
#define MGOS_SYS_CONFIG_HAVE_CONF_ACL
const char * mgos_config_get_conf_acl(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_conf_acl(void) { return mgos_config_get_conf_acl(&mgos_sys_config); }
void mgos_config_set_conf_acl(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_conf_acl(const char * v) { mgos_config_set_conf_acl(&mgos_sys_config, v); }

/* dns_sd */
#define MGOS_CONFIG_HAVE_DNS_SD
#define MGOS_SYS_CONFIG_HAVE_DNS_SD
const struct mgos_config_dns_sd * mgos_config_get_dns_sd(struct mgos_config *cfg);
static inline const struct mgos_config_dns_sd * mgos_sys_config_get_dns_sd(void) { return mgos_config_get_dns_sd(&mgos_sys_config); }
const struct mgos_conf_entry *mgos_config_schema_dns_sd(void);
bool mgos_config_parse_dns_sd(struct mg_str json, struct mgos_config_dns_sd *cfg);
bool mgos_config_copy_dns_sd(const struct mgos_config_dns_sd *src, struct mgos_config_dns_sd *dst);
void mgos_config_free_dns_sd(struct mgos_config_dns_sd *cfg);

/* dns_sd.enable */
#define MGOS_CONFIG_HAVE_DNS_SD_ENABLE
#define MGOS_SYS_CONFIG_HAVE_DNS_SD_ENABLE
int mgos_config_get_dns_sd_enable(struct mgos_config *cfg);
static inline int mgos_sys_config_get_dns_sd_enable(void) { return mgos_config_get_dns_sd_enable(&mgos_sys_config); }
void mgos_config_set_dns_sd_enable(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_dns_sd_enable(int v) { mgos_config_set_dns_sd_enable(&mgos_sys_config, v); }

/* dns_sd.host_name */
#define MGOS_CONFIG_HAVE_DNS_SD_HOST_NAME
#define MGOS_SYS_CONFIG_HAVE_DNS_SD_HOST_NAME
const char * mgos_config_get_dns_sd_host_name(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_dns_sd_host_name(void) { return mgos_config_get_dns_sd_host_name(&mgos_sys_config); }
void mgos_config_set_dns_sd_host_name(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_dns_sd_host_name(const char * v) { mgos_config_set_dns_sd_host_name(&mgos_sys_config, v); }

/* dns_sd.txt */
#define MGOS_CONFIG_HAVE_DNS_SD_TXT
#define MGOS_SYS_CONFIG_HAVE_DNS_SD_TXT
const char * mgos_config_get_dns_sd_txt(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_dns_sd_txt(void) { return mgos_config_get_dns_sd_txt(&mgos_sys_config); }
void mgos_config_set_dns_sd_txt(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_dns_sd_txt(const char * v) { mgos_config_set_dns_sd_txt(&mgos_sys_config, v); }

/* dns_sd.ttl */
#define MGOS_CONFIG_HAVE_DNS_SD_TTL
#define MGOS_SYS_CONFIG_HAVE_DNS_SD_TTL
int mgos_config_get_dns_sd_ttl(struct mgos_config *cfg);
static inline int mgos_sys_config_get_dns_sd_ttl(void) { return mgos_config_get_dns_sd_ttl(&mgos_sys_config); }
void mgos_config_set_dns_sd_ttl(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_dns_sd_ttl(int v) { mgos_config_set_dns_sd_ttl(&mgos_sys_config, v); }

/* hap */
#define MGOS_CONFIG_HAVE_HAP
#define MGOS_SYS_CONFIG_HAVE_HAP
const struct mgos_config_hap * mgos_config_get_hap(struct mgos_config *cfg);
static inline const struct mgos_config_hap * mgos_sys_config_get_hap(void) { return mgos_config_get_hap(&mgos_sys_config); }
const struct mgos_conf_entry *mgos_config_schema_hap(void);
bool mgos_config_parse_hap(struct mg_str json, struct mgos_config_hap *cfg);
bool mgos_config_copy_hap(const struct mgos_config_hap *src, struct mgos_config_hap *dst);
void mgos_config_free_hap(struct mgos_config_hap *cfg);

/* hap.salt */
#define MGOS_CONFIG_HAVE_HAP_SALT
#define MGOS_SYS_CONFIG_HAVE_HAP_SALT
const char * mgos_config_get_hap_salt(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_hap_salt(void) { return mgos_config_get_hap_salt(&mgos_sys_config); }
void mgos_config_set_hap_salt(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_hap_salt(const char * v) { mgos_config_set_hap_salt(&mgos_sys_config, v); }

/* hap.verifier */
#define MGOS_CONFIG_HAVE_HAP_VERIFIER
#define MGOS_SYS_CONFIG_HAVE_HAP_VERIFIER
const char * mgos_config_get_hap_verifier(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_hap_verifier(void) { return mgos_config_get_hap_verifier(&mgos_sys_config); }
void mgos_config_set_hap_verifier(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_hap_verifier(const char * v) { mgos_config_set_hap_verifier(&mgos_sys_config, v); }

/* http */
#define MGOS_CONFIG_HAVE_HTTP
#define MGOS_SYS_CONFIG_HAVE_HTTP
const struct mgos_config_http * mgos_config_get_http(struct mgos_config *cfg);
static inline const struct mgos_config_http * mgos_sys_config_get_http(void) { return mgos_config_get_http(&mgos_sys_config); }
const struct mgos_conf_entry *mgos_config_schema_http(void);
bool mgos_config_parse_http(struct mg_str json, struct mgos_config_http *cfg);
bool mgos_config_copy_http(const struct mgos_config_http *src, struct mgos_config_http *dst);
void mgos_config_free_http(struct mgos_config_http *cfg);

/* http.enable */
#define MGOS_CONFIG_HAVE_HTTP_ENABLE
#define MGOS_SYS_CONFIG_HAVE_HTTP_ENABLE
int mgos_config_get_http_enable(struct mgos_config *cfg);
static inline int mgos_sys_config_get_http_enable(void) { return mgos_config_get_http_enable(&mgos_sys_config); }
void mgos_config_set_http_enable(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_http_enable(int v) { mgos_config_set_http_enable(&mgos_sys_config, v); }

/* http.listen_addr */
#define MGOS_CONFIG_HAVE_HTTP_LISTEN_ADDR
#define MGOS_SYS_CONFIG_HAVE_HTTP_LISTEN_ADDR
const char * mgos_config_get_http_listen_addr(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_http_listen_addr(void) { return mgos_config_get_http_listen_addr(&mgos_sys_config); }
void mgos_config_set_http_listen_addr(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_http_listen_addr(const char * v) { mgos_config_set_http_listen_addr(&mgos_sys_config, v); }

/* http.document_root */
#define MGOS_CONFIG_HAVE_HTTP_DOCUMENT_ROOT
#define MGOS_SYS_CONFIG_HAVE_HTTP_DOCUMENT_ROOT
const char * mgos_config_get_http_document_root(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_http_document_root(void) { return mgos_config_get_http_document_root(&mgos_sys_config); }
void mgos_config_set_http_document_root(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_http_document_root(const char * v) { mgos_config_set_http_document_root(&mgos_sys_config, v); }

/* http.index_files */
#define MGOS_CONFIG_HAVE_HTTP_INDEX_FILES
#define MGOS_SYS_CONFIG_HAVE_HTTP_INDEX_FILES
const char * mgos_config_get_http_index_files(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_http_index_files(void) { return mgos_config_get_http_index_files(&mgos_sys_config); }
void mgos_config_set_http_index_files(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_http_index_files(const char * v) { mgos_config_set_http_index_files(&mgos_sys_config, v); }

/* http.ssl_cert */
#define MGOS_CONFIG_HAVE_HTTP_SSL_CERT
#define MGOS_SYS_CONFIG_HAVE_HTTP_SSL_CERT
const char * mgos_config_get_http_ssl_cert(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_http_ssl_cert(void) { return mgos_config_get_http_ssl_cert(&mgos_sys_config); }
void mgos_config_set_http_ssl_cert(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_http_ssl_cert(const char * v) { mgos_config_set_http_ssl_cert(&mgos_sys_config, v); }

/* http.ssl_key */
#define MGOS_CONFIG_HAVE_HTTP_SSL_KEY
#define MGOS_SYS_CONFIG_HAVE_HTTP_SSL_KEY
const char * mgos_config_get_http_ssl_key(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_http_ssl_key(void) { return mgos_config_get_http_ssl_key(&mgos_sys_config); }
void mgos_config_set_http_ssl_key(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_http_ssl_key(const char * v) { mgos_config_set_http_ssl_key(&mgos_sys_config, v); }

/* http.ssl_ca_cert */
#define MGOS_CONFIG_HAVE_HTTP_SSL_CA_CERT
#define MGOS_SYS_CONFIG_HAVE_HTTP_SSL_CA_CERT
const char * mgos_config_get_http_ssl_ca_cert(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_http_ssl_ca_cert(void) { return mgos_config_get_http_ssl_ca_cert(&mgos_sys_config); }
void mgos_config_set_http_ssl_ca_cert(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_http_ssl_ca_cert(const char * v) { mgos_config_set_http_ssl_ca_cert(&mgos_sys_config, v); }

/* http.upload_acl */
#define MGOS_CONFIG_HAVE_HTTP_UPLOAD_ACL
#define MGOS_SYS_CONFIG_HAVE_HTTP_UPLOAD_ACL
const char * mgos_config_get_http_upload_acl(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_http_upload_acl(void) { return mgos_config_get_http_upload_acl(&mgos_sys_config); }
void mgos_config_set_http_upload_acl(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_http_upload_acl(const char * v) { mgos_config_set_http_upload_acl(&mgos_sys_config, v); }

/* http.hidden_files */
#define MGOS_CONFIG_HAVE_HTTP_HIDDEN_FILES
#define MGOS_SYS_CONFIG_HAVE_HTTP_HIDDEN_FILES
const char * mgos_config_get_http_hidden_files(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_http_hidden_files(void) { return mgos_config_get_http_hidden_files(&mgos_sys_config); }
void mgos_config_set_http_hidden_files(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_http_hidden_files(const char * v) { mgos_config_set_http_hidden_files(&mgos_sys_config, v); }

/* http.auth_domain */
#define MGOS_CONFIG_HAVE_HTTP_AUTH_DOMAIN
#define MGOS_SYS_CONFIG_HAVE_HTTP_AUTH_DOMAIN
const char * mgos_config_get_http_auth_domain(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_http_auth_domain(void) { return mgos_config_get_http_auth_domain(&mgos_sys_config); }
void mgos_config_set_http_auth_domain(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_http_auth_domain(const char * v) { mgos_config_set_http_auth_domain(&mgos_sys_config, v); }

/* http.auth_file */
#define MGOS_CONFIG_HAVE_HTTP_AUTH_FILE
#define MGOS_SYS_CONFIG_HAVE_HTTP_AUTH_FILE
const char * mgos_config_get_http_auth_file(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_http_auth_file(void) { return mgos_config_get_http_auth_file(&mgos_sys_config); }
void mgos_config_set_http_auth_file(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_http_auth_file(const char * v) { mgos_config_set_http_auth_file(&mgos_sys_config, v); }

/* update */
#define MGOS_CONFIG_HAVE_UPDATE
#define MGOS_SYS_CONFIG_HAVE_UPDATE
const struct mgos_config_update * mgos_config_get_update(struct mgos_config *cfg);
static inline const struct mgos_config_update * mgos_sys_config_get_update(void) { return mgos_config_get_update(&mgos_sys_config); }
const struct mgos_conf_entry *mgos_config_schema_update(void);
bool mgos_config_parse_update(struct mg_str json, struct mgos_config_update *cfg);
bool mgos_config_copy_update(const struct mgos_config_update *src, struct mgos_config_update *dst);
void mgos_config_free_update(struct mgos_config_update *cfg);

/* update.timeout */
#define MGOS_CONFIG_HAVE_UPDATE_TIMEOUT
#define MGOS_SYS_CONFIG_HAVE_UPDATE_TIMEOUT
int mgos_config_get_update_timeout(struct mgos_config *cfg);
static inline int mgos_sys_config_get_update_timeout(void) { return mgos_config_get_update_timeout(&mgos_sys_config); }
void mgos_config_set_update_timeout(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_update_timeout(int v) { mgos_config_set_update_timeout(&mgos_sys_config, v); }

/* update.commit_timeout */
#define MGOS_CONFIG_HAVE_UPDATE_COMMIT_TIMEOUT
#define MGOS_SYS_CONFIG_HAVE_UPDATE_COMMIT_TIMEOUT
int mgos_config_get_update_commit_timeout(struct mgos_config *cfg);
static inline int mgos_sys_config_get_update_commit_timeout(void) { return mgos_config_get_update_commit_timeout(&mgos_sys_config); }
void mgos_config_set_update_commit_timeout(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_update_commit_timeout(int v) { mgos_config_set_update_commit_timeout(&mgos_sys_config, v); }

/* update.url */
#define MGOS_CONFIG_HAVE_UPDATE_URL
#define MGOS_SYS_CONFIG_HAVE_UPDATE_URL
const char * mgos_config_get_update_url(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_update_url(void) { return mgos_config_get_update_url(&mgos_sys_config); }
void mgos_config_set_update_url(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_update_url(const char * v) { mgos_config_set_update_url(&mgos_sys_config, v); }

/* update.interval */
#define MGOS_CONFIG_HAVE_UPDATE_INTERVAL
#define MGOS_SYS_CONFIG_HAVE_UPDATE_INTERVAL
int mgos_config_get_update_interval(struct mgos_config *cfg);
static inline int mgos_sys_config_get_update_interval(void) { return mgos_config_get_update_interval(&mgos_sys_config); }
void mgos_config_set_update_interval(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_update_interval(int v) { mgos_config_set_update_interval(&mgos_sys_config, v); }

/* update.extra_http_headers */
#define MGOS_CONFIG_HAVE_UPDATE_EXTRA_HTTP_HEADERS
#define MGOS_SYS_CONFIG_HAVE_UPDATE_EXTRA_HTTP_HEADERS
const char * mgos_config_get_update_extra_http_headers(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_update_extra_http_headers(void) { return mgos_config_get_update_extra_http_headers(&mgos_sys_config); }
void mgos_config_set_update_extra_http_headers(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_update_extra_http_headers(const char * v) { mgos_config_set_update_extra_http_headers(&mgos_sys_config, v); }

/* update.ssl_ca_file */
#define MGOS_CONFIG_HAVE_UPDATE_SSL_CA_FILE
#define MGOS_SYS_CONFIG_HAVE_UPDATE_SSL_CA_FILE
const char * mgos_config_get_update_ssl_ca_file(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_update_ssl_ca_file(void) { return mgos_config_get_update_ssl_ca_file(&mgos_sys_config); }
void mgos_config_set_update_ssl_ca_file(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_update_ssl_ca_file(const char * v) { mgos_config_set_update_ssl_ca_file(&mgos_sys_config, v); }

/* update.ssl_client_cert_file */
#define MGOS_CONFIG_HAVE_UPDATE_SSL_CLIENT_CERT_FILE
#define MGOS_SYS_CONFIG_HAVE_UPDATE_SSL_CLIENT_CERT_FILE
const char * mgos_config_get_update_ssl_client_cert_file(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_update_ssl_client_cert_file(void) { return mgos_config_get_update_ssl_client_cert_file(&mgos_sys_config); }
void mgos_config_set_update_ssl_client_cert_file(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_update_ssl_client_cert_file(const char * v) { mgos_config_set_update_ssl_client_cert_file(&mgos_sys_config, v); }

/* update.ssl_server_name */
#define MGOS_CONFIG_HAVE_UPDATE_SSL_SERVER_NAME
#define MGOS_SYS_CONFIG_HAVE_UPDATE_SSL_SERVER_NAME
const char * mgos_config_get_update_ssl_server_name(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_update_ssl_server_name(void) { return mgos_config_get_update_ssl_server_name(&mgos_sys_config); }
void mgos_config_set_update_ssl_server_name(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_update_ssl_server_name(const char * v) { mgos_config_set_update_ssl_server_name(&mgos_sys_config, v); }

/* update.enable_post */
#define MGOS_CONFIG_HAVE_UPDATE_ENABLE_POST
#define MGOS_SYS_CONFIG_HAVE_UPDATE_ENABLE_POST
int mgos_config_get_update_enable_post(struct mgos_config *cfg);
static inline int mgos_sys_config_get_update_enable_post(void) { return mgos_config_get_update_enable_post(&mgos_sys_config); }
void mgos_config_set_update_enable_post(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_update_enable_post(int v) { mgos_config_set_update_enable_post(&mgos_sys_config, v); }

/* rpc */
#define MGOS_CONFIG_HAVE_RPC
#define MGOS_SYS_CONFIG_HAVE_RPC
const struct mgos_config_rpc * mgos_config_get_rpc(struct mgos_config *cfg);
static inline const struct mgos_config_rpc * mgos_sys_config_get_rpc(void) { return mgos_config_get_rpc(&mgos_sys_config); }
const struct mgos_conf_entry *mgos_config_schema_rpc(void);
bool mgos_config_parse_rpc(struct mg_str json, struct mgos_config_rpc *cfg);
bool mgos_config_copy_rpc(const struct mgos_config_rpc *src, struct mgos_config_rpc *dst);
void mgos_config_free_rpc(struct mgos_config_rpc *cfg);

/* rpc.enable */
#define MGOS_CONFIG_HAVE_RPC_ENABLE
#define MGOS_SYS_CONFIG_HAVE_RPC_ENABLE
int mgos_config_get_rpc_enable(struct mgos_config *cfg);
static inline int mgos_sys_config_get_rpc_enable(void) { return mgos_config_get_rpc_enable(&mgos_sys_config); }
void mgos_config_set_rpc_enable(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_rpc_enable(int v) { mgos_config_set_rpc_enable(&mgos_sys_config, v); }

/* rpc.max_frame_size */
#define MGOS_CONFIG_HAVE_RPC_MAX_FRAME_SIZE
#define MGOS_SYS_CONFIG_HAVE_RPC_MAX_FRAME_SIZE
int mgos_config_get_rpc_max_frame_size(struct mgos_config *cfg);
static inline int mgos_sys_config_get_rpc_max_frame_size(void) { return mgos_config_get_rpc_max_frame_size(&mgos_sys_config); }
void mgos_config_set_rpc_max_frame_size(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_rpc_max_frame_size(int v) { mgos_config_set_rpc_max_frame_size(&mgos_sys_config, v); }

/* rpc.max_queue_length */
#define MGOS_CONFIG_HAVE_RPC_MAX_QUEUE_LENGTH
#define MGOS_SYS_CONFIG_HAVE_RPC_MAX_QUEUE_LENGTH
int mgos_config_get_rpc_max_queue_length(struct mgos_config *cfg);
static inline int mgos_sys_config_get_rpc_max_queue_length(void) { return mgos_config_get_rpc_max_queue_length(&mgos_sys_config); }
void mgos_config_set_rpc_max_queue_length(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_rpc_max_queue_length(int v) { mgos_config_set_rpc_max_queue_length(&mgos_sys_config, v); }

/* rpc.default_out_channel_idle_close_timeout */
#define MGOS_CONFIG_HAVE_RPC_DEFAULT_OUT_CHANNEL_IDLE_CLOSE_TIMEOUT
#define MGOS_SYS_CONFIG_HAVE_RPC_DEFAULT_OUT_CHANNEL_IDLE_CLOSE_TIMEOUT
int mgos_config_get_rpc_default_out_channel_idle_close_timeout(struct mgos_config *cfg);
static inline int mgos_sys_config_get_rpc_default_out_channel_idle_close_timeout(void) { return mgos_config_get_rpc_default_out_channel_idle_close_timeout(&mgos_sys_config); }
void mgos_config_set_rpc_default_out_channel_idle_close_timeout(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_rpc_default_out_channel_idle_close_timeout(int v) { mgos_config_set_rpc_default_out_channel_idle_close_timeout(&mgos_sys_config, v); }

/* rpc.acl_file */
#define MGOS_CONFIG_HAVE_RPC_ACL_FILE
#define MGOS_SYS_CONFIG_HAVE_RPC_ACL_FILE
const char * mgos_config_get_rpc_acl_file(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_rpc_acl_file(void) { return mgos_config_get_rpc_acl_file(&mgos_sys_config); }
void mgos_config_set_rpc_acl_file(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_rpc_acl_file(const char * v) { mgos_config_set_rpc_acl_file(&mgos_sys_config, v); }

/* rpc.auth_domain */
#define MGOS_CONFIG_HAVE_RPC_AUTH_DOMAIN
#define MGOS_SYS_CONFIG_HAVE_RPC_AUTH_DOMAIN
const char * mgos_config_get_rpc_auth_domain(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_rpc_auth_domain(void) { return mgos_config_get_rpc_auth_domain(&mgos_sys_config); }
void mgos_config_set_rpc_auth_domain(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_rpc_auth_domain(const char * v) { mgos_config_set_rpc_auth_domain(&mgos_sys_config, v); }

/* rpc.auth_file */
#define MGOS_CONFIG_HAVE_RPC_AUTH_FILE
#define MGOS_SYS_CONFIG_HAVE_RPC_AUTH_FILE
const char * mgos_config_get_rpc_auth_file(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_rpc_auth_file(void) { return mgos_config_get_rpc_auth_file(&mgos_sys_config); }
void mgos_config_set_rpc_auth_file(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_rpc_auth_file(const char * v) { mgos_config_set_rpc_auth_file(&mgos_sys_config, v); }

/* rpc.uart */
#define MGOS_CONFIG_HAVE_RPC_UART
#define MGOS_SYS_CONFIG_HAVE_RPC_UART
const struct mgos_config_rpc_uart * mgos_config_get_rpc_uart(struct mgos_config *cfg);
static inline const struct mgos_config_rpc_uart * mgos_sys_config_get_rpc_uart(void) { return mgos_config_get_rpc_uart(&mgos_sys_config); }
const struct mgos_conf_entry *mgos_config_schema_rpc_uart(void);
bool mgos_config_parse_rpc_uart(struct mg_str json, struct mgos_config_rpc_uart *cfg);
bool mgos_config_copy_rpc_uart(const struct mgos_config_rpc_uart *src, struct mgos_config_rpc_uart *dst);
void mgos_config_free_rpc_uart(struct mgos_config_rpc_uart *cfg);

/* rpc.uart.uart_no */
#define MGOS_CONFIG_HAVE_RPC_UART_UART_NO
#define MGOS_SYS_CONFIG_HAVE_RPC_UART_UART_NO
int mgos_config_get_rpc_uart_uart_no(struct mgos_config *cfg);
static inline int mgos_sys_config_get_rpc_uart_uart_no(void) { return mgos_config_get_rpc_uart_uart_no(&mgos_sys_config); }
void mgos_config_set_rpc_uart_uart_no(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_rpc_uart_uart_no(int v) { mgos_config_set_rpc_uart_uart_no(&mgos_sys_config, v); }

/* rpc.uart.baud_rate */
#define MGOS_CONFIG_HAVE_RPC_UART_BAUD_RATE
#define MGOS_SYS_CONFIG_HAVE_RPC_UART_BAUD_RATE
int mgos_config_get_rpc_uart_baud_rate(struct mgos_config *cfg);
static inline int mgos_sys_config_get_rpc_uart_baud_rate(void) { return mgos_config_get_rpc_uart_baud_rate(&mgos_sys_config); }
void mgos_config_set_rpc_uart_baud_rate(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_rpc_uart_baud_rate(int v) { mgos_config_set_rpc_uart_baud_rate(&mgos_sys_config, v); }

/* rpc.uart.fc_type */
#define MGOS_CONFIG_HAVE_RPC_UART_FC_TYPE
#define MGOS_SYS_CONFIG_HAVE_RPC_UART_FC_TYPE
int mgos_config_get_rpc_uart_fc_type(struct mgos_config *cfg);
static inline int mgos_sys_config_get_rpc_uart_fc_type(void) { return mgos_config_get_rpc_uart_fc_type(&mgos_sys_config); }
void mgos_config_set_rpc_uart_fc_type(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_rpc_uart_fc_type(int v) { mgos_config_set_rpc_uart_fc_type(&mgos_sys_config, v); }

/* rpc.uart.dst */
#define MGOS_CONFIG_HAVE_RPC_UART_DST
#define MGOS_SYS_CONFIG_HAVE_RPC_UART_DST
const char * mgos_config_get_rpc_uart_dst(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_rpc_uart_dst(void) { return mgos_config_get_rpc_uart_dst(&mgos_sys_config); }
void mgos_config_set_rpc_uart_dst(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_rpc_uart_dst(const char * v) { mgos_config_set_rpc_uart_dst(&mgos_sys_config, v); }

/* rpc.ws */
#define MGOS_CONFIG_HAVE_RPC_WS
#define MGOS_SYS_CONFIG_HAVE_RPC_WS
const struct mgos_config_rpc_ws * mgos_config_get_rpc_ws(struct mgos_config *cfg);
static inline const struct mgos_config_rpc_ws * mgos_sys_config_get_rpc_ws(void) { return mgos_config_get_rpc_ws(&mgos_sys_config); }
const struct mgos_conf_entry *mgos_config_schema_rpc_ws(void);
bool mgos_config_parse_rpc_ws(struct mg_str json, struct mgos_config_rpc_ws *cfg);
bool mgos_config_copy_rpc_ws(const struct mgos_config_rpc_ws *src, struct mgos_config_rpc_ws *dst);
void mgos_config_free_rpc_ws(struct mgos_config_rpc_ws *cfg);

/* rpc.ws.enable */
#define MGOS_CONFIG_HAVE_RPC_WS_ENABLE
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_ENABLE
int mgos_config_get_rpc_ws_enable(struct mgos_config *cfg);
static inline int mgos_sys_config_get_rpc_ws_enable(void) { return mgos_config_get_rpc_ws_enable(&mgos_sys_config); }
void mgos_config_set_rpc_ws_enable(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_rpc_ws_enable(int v) { mgos_config_set_rpc_ws_enable(&mgos_sys_config, v); }

/* rpc.ws.server_address */
#define MGOS_CONFIG_HAVE_RPC_WS_SERVER_ADDRESS
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_SERVER_ADDRESS
const char * mgos_config_get_rpc_ws_server_address(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_rpc_ws_server_address(void) { return mgos_config_get_rpc_ws_server_address(&mgos_sys_config); }
void mgos_config_set_rpc_ws_server_address(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_rpc_ws_server_address(const char * v) { mgos_config_set_rpc_ws_server_address(&mgos_sys_config, v); }

/* rpc.ws.reconnect_interval_min */
#define MGOS_CONFIG_HAVE_RPC_WS_RECONNECT_INTERVAL_MIN
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_RECONNECT_INTERVAL_MIN
int mgos_config_get_rpc_ws_reconnect_interval_min(struct mgos_config *cfg);
static inline int mgos_sys_config_get_rpc_ws_reconnect_interval_min(void) { return mgos_config_get_rpc_ws_reconnect_interval_min(&mgos_sys_config); }
void mgos_config_set_rpc_ws_reconnect_interval_min(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_rpc_ws_reconnect_interval_min(int v) { mgos_config_set_rpc_ws_reconnect_interval_min(&mgos_sys_config, v); }

/* rpc.ws.reconnect_interval_max */
#define MGOS_CONFIG_HAVE_RPC_WS_RECONNECT_INTERVAL_MAX
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_RECONNECT_INTERVAL_MAX
int mgos_config_get_rpc_ws_reconnect_interval_max(struct mgos_config *cfg);
static inline int mgos_sys_config_get_rpc_ws_reconnect_interval_max(void) { return mgos_config_get_rpc_ws_reconnect_interval_max(&mgos_sys_config); }
void mgos_config_set_rpc_ws_reconnect_interval_max(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_rpc_ws_reconnect_interval_max(int v) { mgos_config_set_rpc_ws_reconnect_interval_max(&mgos_sys_config, v); }

/* rpc.ws.ssl_server_name */
#define MGOS_CONFIG_HAVE_RPC_WS_SSL_SERVER_NAME
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_SSL_SERVER_NAME
const char * mgos_config_get_rpc_ws_ssl_server_name(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_rpc_ws_ssl_server_name(void) { return mgos_config_get_rpc_ws_ssl_server_name(&mgos_sys_config); }
void mgos_config_set_rpc_ws_ssl_server_name(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_rpc_ws_ssl_server_name(const char * v) { mgos_config_set_rpc_ws_ssl_server_name(&mgos_sys_config, v); }

/* rpc.ws.ssl_cert */
#define MGOS_CONFIG_HAVE_RPC_WS_SSL_CERT
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_SSL_CERT
const char * mgos_config_get_rpc_ws_ssl_cert(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_rpc_ws_ssl_cert(void) { return mgos_config_get_rpc_ws_ssl_cert(&mgos_sys_config); }
void mgos_config_set_rpc_ws_ssl_cert(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_rpc_ws_ssl_cert(const char * v) { mgos_config_set_rpc_ws_ssl_cert(&mgos_sys_config, v); }

/* rpc.ws.ssl_key */
#define MGOS_CONFIG_HAVE_RPC_WS_SSL_KEY
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_SSL_KEY
const char * mgos_config_get_rpc_ws_ssl_key(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_rpc_ws_ssl_key(void) { return mgos_config_get_rpc_ws_ssl_key(&mgos_sys_config); }
void mgos_config_set_rpc_ws_ssl_key(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_rpc_ws_ssl_key(const char * v) { mgos_config_set_rpc_ws_ssl_key(&mgos_sys_config, v); }

/* rpc.ws.ssl_ca_cert */
#define MGOS_CONFIG_HAVE_RPC_WS_SSL_CA_CERT
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_SSL_CA_CERT
const char * mgos_config_get_rpc_ws_ssl_ca_cert(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_rpc_ws_ssl_ca_cert(void) { return mgos_config_get_rpc_ws_ssl_ca_cert(&mgos_sys_config); }
void mgos_config_set_rpc_ws_ssl_ca_cert(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_rpc_ws_ssl_ca_cert(const char * v) { mgos_config_set_rpc_ws_ssl_ca_cert(&mgos_sys_config, v); }

/* wifi */
#define MGOS_CONFIG_HAVE_WIFI
#define MGOS_SYS_CONFIG_HAVE_WIFI
const struct mgos_config_wifi * mgos_config_get_wifi(struct mgos_config *cfg);
static inline const struct mgos_config_wifi * mgos_sys_config_get_wifi(void) { return mgos_config_get_wifi(&mgos_sys_config); }
const struct mgos_conf_entry *mgos_config_schema_wifi(void);
bool mgos_config_parse_wifi(struct mg_str json, struct mgos_config_wifi *cfg);
bool mgos_config_copy_wifi(const struct mgos_config_wifi *src, struct mgos_config_wifi *dst);
void mgos_config_free_wifi(struct mgos_config_wifi *cfg);

/* wifi.ap */
#define MGOS_CONFIG_HAVE_WIFI_AP
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP
const struct mgos_config_wifi_ap * mgos_config_get_wifi_ap(struct mgos_config *cfg);
static inline const struct mgos_config_wifi_ap * mgos_sys_config_get_wifi_ap(void) { return mgos_config_get_wifi_ap(&mgos_sys_config); }
const struct mgos_conf_entry *mgos_config_schema_wifi_ap(void);
bool mgos_config_parse_wifi_ap(struct mg_str json, struct mgos_config_wifi_ap *cfg);
bool mgos_config_copy_wifi_ap(const struct mgos_config_wifi_ap *src, struct mgos_config_wifi_ap *dst);
void mgos_config_free_wifi_ap(struct mgos_config_wifi_ap *cfg);

/* wifi.ap.enable */
#define MGOS_CONFIG_HAVE_WIFI_AP_ENABLE
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_ENABLE
int mgos_config_get_wifi_ap_enable(struct mgos_config *cfg);
static inline int mgos_sys_config_get_wifi_ap_enable(void) { return mgos_config_get_wifi_ap_enable(&mgos_sys_config); }
void mgos_config_set_wifi_ap_enable(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_wifi_ap_enable(int v) { mgos_config_set_wifi_ap_enable(&mgos_sys_config, v); }

/* wifi.ap.ssid */
#define MGOS_CONFIG_HAVE_WIFI_AP_SSID
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_SSID
const char * mgos_config_get_wifi_ap_ssid(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_ap_ssid(void) { return mgos_config_get_wifi_ap_ssid(&mgos_sys_config); }
void mgos_config_set_wifi_ap_ssid(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_ap_ssid(const char * v) { mgos_config_set_wifi_ap_ssid(&mgos_sys_config, v); }

/* wifi.ap.pass */
#define MGOS_CONFIG_HAVE_WIFI_AP_PASS
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_PASS
const char * mgos_config_get_wifi_ap_pass(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_ap_pass(void) { return mgos_config_get_wifi_ap_pass(&mgos_sys_config); }
void mgos_config_set_wifi_ap_pass(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_ap_pass(const char * v) { mgos_config_set_wifi_ap_pass(&mgos_sys_config, v); }

/* wifi.ap.hidden */
#define MGOS_CONFIG_HAVE_WIFI_AP_HIDDEN
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_HIDDEN
int mgos_config_get_wifi_ap_hidden(struct mgos_config *cfg);
static inline int mgos_sys_config_get_wifi_ap_hidden(void) { return mgos_config_get_wifi_ap_hidden(&mgos_sys_config); }
void mgos_config_set_wifi_ap_hidden(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_wifi_ap_hidden(int v) { mgos_config_set_wifi_ap_hidden(&mgos_sys_config, v); }

/* wifi.ap.channel */
#define MGOS_CONFIG_HAVE_WIFI_AP_CHANNEL
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_CHANNEL
int mgos_config_get_wifi_ap_channel(struct mgos_config *cfg);
static inline int mgos_sys_config_get_wifi_ap_channel(void) { return mgos_config_get_wifi_ap_channel(&mgos_sys_config); }
void mgos_config_set_wifi_ap_channel(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_wifi_ap_channel(int v) { mgos_config_set_wifi_ap_channel(&mgos_sys_config, v); }

/* wifi.ap.max_connections */
#define MGOS_CONFIG_HAVE_WIFI_AP_MAX_CONNECTIONS
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_MAX_CONNECTIONS
int mgos_config_get_wifi_ap_max_connections(struct mgos_config *cfg);
static inline int mgos_sys_config_get_wifi_ap_max_connections(void) { return mgos_config_get_wifi_ap_max_connections(&mgos_sys_config); }
void mgos_config_set_wifi_ap_max_connections(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_wifi_ap_max_connections(int v) { mgos_config_set_wifi_ap_max_connections(&mgos_sys_config, v); }

/* wifi.ap.ip */
#define MGOS_CONFIG_HAVE_WIFI_AP_IP
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_IP
const char * mgos_config_get_wifi_ap_ip(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_ap_ip(void) { return mgos_config_get_wifi_ap_ip(&mgos_sys_config); }
void mgos_config_set_wifi_ap_ip(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_ap_ip(const char * v) { mgos_config_set_wifi_ap_ip(&mgos_sys_config, v); }

/* wifi.ap.netmask */
#define MGOS_CONFIG_HAVE_WIFI_AP_NETMASK
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_NETMASK
const char * mgos_config_get_wifi_ap_netmask(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_ap_netmask(void) { return mgos_config_get_wifi_ap_netmask(&mgos_sys_config); }
void mgos_config_set_wifi_ap_netmask(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_ap_netmask(const char * v) { mgos_config_set_wifi_ap_netmask(&mgos_sys_config, v); }

/* wifi.ap.gw */
#define MGOS_CONFIG_HAVE_WIFI_AP_GW
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_GW
const char * mgos_config_get_wifi_ap_gw(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_ap_gw(void) { return mgos_config_get_wifi_ap_gw(&mgos_sys_config); }
void mgos_config_set_wifi_ap_gw(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_ap_gw(const char * v) { mgos_config_set_wifi_ap_gw(&mgos_sys_config, v); }

/* wifi.ap.dhcp_start */
#define MGOS_CONFIG_HAVE_WIFI_AP_DHCP_START
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_DHCP_START
const char * mgos_config_get_wifi_ap_dhcp_start(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_ap_dhcp_start(void) { return mgos_config_get_wifi_ap_dhcp_start(&mgos_sys_config); }
void mgos_config_set_wifi_ap_dhcp_start(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_ap_dhcp_start(const char * v) { mgos_config_set_wifi_ap_dhcp_start(&mgos_sys_config, v); }

/* wifi.ap.dhcp_end */
#define MGOS_CONFIG_HAVE_WIFI_AP_DHCP_END
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_DHCP_END
const char * mgos_config_get_wifi_ap_dhcp_end(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_ap_dhcp_end(void) { return mgos_config_get_wifi_ap_dhcp_end(&mgos_sys_config); }
void mgos_config_set_wifi_ap_dhcp_end(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_ap_dhcp_end(const char * v) { mgos_config_set_wifi_ap_dhcp_end(&mgos_sys_config, v); }

/* wifi.ap.trigger_on_gpio */
#define MGOS_CONFIG_HAVE_WIFI_AP_TRIGGER_ON_GPIO
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_TRIGGER_ON_GPIO
int mgos_config_get_wifi_ap_trigger_on_gpio(struct mgos_config *cfg);
static inline int mgos_sys_config_get_wifi_ap_trigger_on_gpio(void) { return mgos_config_get_wifi_ap_trigger_on_gpio(&mgos_sys_config); }
void mgos_config_set_wifi_ap_trigger_on_gpio(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_wifi_ap_trigger_on_gpio(int v) { mgos_config_set_wifi_ap_trigger_on_gpio(&mgos_sys_config, v); }

/* wifi.ap.disable_after */
#define MGOS_CONFIG_HAVE_WIFI_AP_DISABLE_AFTER
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_DISABLE_AFTER
int mgos_config_get_wifi_ap_disable_after(struct mgos_config *cfg);
static inline int mgos_sys_config_get_wifi_ap_disable_after(void) { return mgos_config_get_wifi_ap_disable_after(&mgos_sys_config); }
void mgos_config_set_wifi_ap_disable_after(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_wifi_ap_disable_after(int v) { mgos_config_set_wifi_ap_disable_after(&mgos_sys_config, v); }

/* wifi.ap.hostname */
#define MGOS_CONFIG_HAVE_WIFI_AP_HOSTNAME
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_HOSTNAME
const char * mgos_config_get_wifi_ap_hostname(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_ap_hostname(void) { return mgos_config_get_wifi_ap_hostname(&mgos_sys_config); }
void mgos_config_set_wifi_ap_hostname(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_ap_hostname(const char * v) { mgos_config_set_wifi_ap_hostname(&mgos_sys_config, v); }

/* wifi.ap.keep_enabled */
#define MGOS_CONFIG_HAVE_WIFI_AP_KEEP_ENABLED
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_KEEP_ENABLED
int mgos_config_get_wifi_ap_keep_enabled(struct mgos_config *cfg);
static inline int mgos_sys_config_get_wifi_ap_keep_enabled(void) { return mgos_config_get_wifi_ap_keep_enabled(&mgos_sys_config); }
void mgos_config_set_wifi_ap_keep_enabled(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_wifi_ap_keep_enabled(int v) { mgos_config_set_wifi_ap_keep_enabled(&mgos_sys_config, v); }

/* wifi.sta */
#define MGOS_CONFIG_HAVE_WIFI_STA
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA
const struct mgos_config_wifi_sta * mgos_config_get_wifi_sta(struct mgos_config *cfg);
static inline const struct mgos_config_wifi_sta * mgos_sys_config_get_wifi_sta(void) { return mgos_config_get_wifi_sta(&mgos_sys_config); }
const struct mgos_conf_entry *mgos_config_schema_wifi_sta(void);
bool mgos_config_parse_wifi_sta(struct mg_str json, struct mgos_config_wifi_sta *cfg);
bool mgos_config_copy_wifi_sta(const struct mgos_config_wifi_sta *src, struct mgos_config_wifi_sta *dst);
void mgos_config_free_wifi_sta(struct mgos_config_wifi_sta *cfg);

/* wifi.sta.enable */
#define MGOS_CONFIG_HAVE_WIFI_STA_ENABLE
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_ENABLE
int mgos_config_get_wifi_sta_enable(struct mgos_config *cfg);
static inline int mgos_sys_config_get_wifi_sta_enable(void) { return mgos_config_get_wifi_sta_enable(&mgos_sys_config); }
void mgos_config_set_wifi_sta_enable(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_wifi_sta_enable(int v) { mgos_config_set_wifi_sta_enable(&mgos_sys_config, v); }

/* wifi.sta.ssid */
#define MGOS_CONFIG_HAVE_WIFI_STA_SSID
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_SSID
const char * mgos_config_get_wifi_sta_ssid(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta_ssid(void) { return mgos_config_get_wifi_sta_ssid(&mgos_sys_config); }
void mgos_config_set_wifi_sta_ssid(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta_ssid(const char * v) { mgos_config_set_wifi_sta_ssid(&mgos_sys_config, v); }

/* wifi.sta.pass */
#define MGOS_CONFIG_HAVE_WIFI_STA_PASS
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_PASS
const char * mgos_config_get_wifi_sta_pass(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta_pass(void) { return mgos_config_get_wifi_sta_pass(&mgos_sys_config); }
void mgos_config_set_wifi_sta_pass(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta_pass(const char * v) { mgos_config_set_wifi_sta_pass(&mgos_sys_config, v); }

/* wifi.sta.user */
#define MGOS_CONFIG_HAVE_WIFI_STA_USER
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_USER
const char * mgos_config_get_wifi_sta_user(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta_user(void) { return mgos_config_get_wifi_sta_user(&mgos_sys_config); }
void mgos_config_set_wifi_sta_user(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta_user(const char * v) { mgos_config_set_wifi_sta_user(&mgos_sys_config, v); }

/* wifi.sta.anon_identity */
#define MGOS_CONFIG_HAVE_WIFI_STA_ANON_IDENTITY
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_ANON_IDENTITY
const char * mgos_config_get_wifi_sta_anon_identity(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta_anon_identity(void) { return mgos_config_get_wifi_sta_anon_identity(&mgos_sys_config); }
void mgos_config_set_wifi_sta_anon_identity(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta_anon_identity(const char * v) { mgos_config_set_wifi_sta_anon_identity(&mgos_sys_config, v); }

/* wifi.sta.cert */
#define MGOS_CONFIG_HAVE_WIFI_STA_CERT
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_CERT
const char * mgos_config_get_wifi_sta_cert(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta_cert(void) { return mgos_config_get_wifi_sta_cert(&mgos_sys_config); }
void mgos_config_set_wifi_sta_cert(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta_cert(const char * v) { mgos_config_set_wifi_sta_cert(&mgos_sys_config, v); }

/* wifi.sta.key */
#define MGOS_CONFIG_HAVE_WIFI_STA_KEY
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_KEY
const char * mgos_config_get_wifi_sta_key(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta_key(void) { return mgos_config_get_wifi_sta_key(&mgos_sys_config); }
void mgos_config_set_wifi_sta_key(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta_key(const char * v) { mgos_config_set_wifi_sta_key(&mgos_sys_config, v); }

/* wifi.sta.ca_cert */
#define MGOS_CONFIG_HAVE_WIFI_STA_CA_CERT
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_CA_CERT
const char * mgos_config_get_wifi_sta_ca_cert(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta_ca_cert(void) { return mgos_config_get_wifi_sta_ca_cert(&mgos_sys_config); }
void mgos_config_set_wifi_sta_ca_cert(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta_ca_cert(const char * v) { mgos_config_set_wifi_sta_ca_cert(&mgos_sys_config, v); }

/* wifi.sta.ip */
#define MGOS_CONFIG_HAVE_WIFI_STA_IP
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_IP
const char * mgos_config_get_wifi_sta_ip(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta_ip(void) { return mgos_config_get_wifi_sta_ip(&mgos_sys_config); }
void mgos_config_set_wifi_sta_ip(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta_ip(const char * v) { mgos_config_set_wifi_sta_ip(&mgos_sys_config, v); }

/* wifi.sta.netmask */
#define MGOS_CONFIG_HAVE_WIFI_STA_NETMASK
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_NETMASK
const char * mgos_config_get_wifi_sta_netmask(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta_netmask(void) { return mgos_config_get_wifi_sta_netmask(&mgos_sys_config); }
void mgos_config_set_wifi_sta_netmask(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta_netmask(const char * v) { mgos_config_set_wifi_sta_netmask(&mgos_sys_config, v); }

/* wifi.sta.gw */
#define MGOS_CONFIG_HAVE_WIFI_STA_GW
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_GW
const char * mgos_config_get_wifi_sta_gw(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta_gw(void) { return mgos_config_get_wifi_sta_gw(&mgos_sys_config); }
void mgos_config_set_wifi_sta_gw(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta_gw(const char * v) { mgos_config_set_wifi_sta_gw(&mgos_sys_config, v); }

/* wifi.sta.nameserver */
#define MGOS_CONFIG_HAVE_WIFI_STA_NAMESERVER
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_NAMESERVER
const char * mgos_config_get_wifi_sta_nameserver(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta_nameserver(void) { return mgos_config_get_wifi_sta_nameserver(&mgos_sys_config); }
void mgos_config_set_wifi_sta_nameserver(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta_nameserver(const char * v) { mgos_config_set_wifi_sta_nameserver(&mgos_sys_config, v); }

/* wifi.sta.dhcp_hostname */
#define MGOS_CONFIG_HAVE_WIFI_STA_DHCP_HOSTNAME
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_DHCP_HOSTNAME
const char * mgos_config_get_wifi_sta_dhcp_hostname(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta_dhcp_hostname(void) { return mgos_config_get_wifi_sta_dhcp_hostname(&mgos_sys_config); }
void mgos_config_set_wifi_sta_dhcp_hostname(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta_dhcp_hostname(const char * v) { mgos_config_set_wifi_sta_dhcp_hostname(&mgos_sys_config, v); }

/* wifi.sta1 */
#define MGOS_CONFIG_HAVE_WIFI_STA1
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1
const struct mgos_config_wifi_sta * mgos_config_get_wifi_sta1(struct mgos_config *cfg);
static inline const struct mgos_config_wifi_sta * mgos_sys_config_get_wifi_sta1(void) { return mgos_config_get_wifi_sta1(&mgos_sys_config); }

/* wifi.sta1.enable */
#define MGOS_CONFIG_HAVE_WIFI_STA1_ENABLE
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_ENABLE
int mgos_config_get_wifi_sta1_enable(struct mgos_config *cfg);
static inline int mgos_sys_config_get_wifi_sta1_enable(void) { return mgos_config_get_wifi_sta1_enable(&mgos_sys_config); }
void mgos_config_set_wifi_sta1_enable(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_wifi_sta1_enable(int v) { mgos_config_set_wifi_sta1_enable(&mgos_sys_config, v); }

/* wifi.sta1.ssid */
#define MGOS_CONFIG_HAVE_WIFI_STA1_SSID
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_SSID
const char * mgos_config_get_wifi_sta1_ssid(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta1_ssid(void) { return mgos_config_get_wifi_sta1_ssid(&mgos_sys_config); }
void mgos_config_set_wifi_sta1_ssid(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta1_ssid(const char * v) { mgos_config_set_wifi_sta1_ssid(&mgos_sys_config, v); }

/* wifi.sta1.pass */
#define MGOS_CONFIG_HAVE_WIFI_STA1_PASS
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_PASS
const char * mgos_config_get_wifi_sta1_pass(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta1_pass(void) { return mgos_config_get_wifi_sta1_pass(&mgos_sys_config); }
void mgos_config_set_wifi_sta1_pass(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta1_pass(const char * v) { mgos_config_set_wifi_sta1_pass(&mgos_sys_config, v); }

/* wifi.sta1.user */
#define MGOS_CONFIG_HAVE_WIFI_STA1_USER
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_USER
const char * mgos_config_get_wifi_sta1_user(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta1_user(void) { return mgos_config_get_wifi_sta1_user(&mgos_sys_config); }
void mgos_config_set_wifi_sta1_user(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta1_user(const char * v) { mgos_config_set_wifi_sta1_user(&mgos_sys_config, v); }

/* wifi.sta1.anon_identity */
#define MGOS_CONFIG_HAVE_WIFI_STA1_ANON_IDENTITY
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_ANON_IDENTITY
const char * mgos_config_get_wifi_sta1_anon_identity(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta1_anon_identity(void) { return mgos_config_get_wifi_sta1_anon_identity(&mgos_sys_config); }
void mgos_config_set_wifi_sta1_anon_identity(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta1_anon_identity(const char * v) { mgos_config_set_wifi_sta1_anon_identity(&mgos_sys_config, v); }

/* wifi.sta1.cert */
#define MGOS_CONFIG_HAVE_WIFI_STA1_CERT
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_CERT
const char * mgos_config_get_wifi_sta1_cert(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta1_cert(void) { return mgos_config_get_wifi_sta1_cert(&mgos_sys_config); }
void mgos_config_set_wifi_sta1_cert(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta1_cert(const char * v) { mgos_config_set_wifi_sta1_cert(&mgos_sys_config, v); }

/* wifi.sta1.key */
#define MGOS_CONFIG_HAVE_WIFI_STA1_KEY
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_KEY
const char * mgos_config_get_wifi_sta1_key(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta1_key(void) { return mgos_config_get_wifi_sta1_key(&mgos_sys_config); }
void mgos_config_set_wifi_sta1_key(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta1_key(const char * v) { mgos_config_set_wifi_sta1_key(&mgos_sys_config, v); }

/* wifi.sta1.ca_cert */
#define MGOS_CONFIG_HAVE_WIFI_STA1_CA_CERT
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_CA_CERT
const char * mgos_config_get_wifi_sta1_ca_cert(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta1_ca_cert(void) { return mgos_config_get_wifi_sta1_ca_cert(&mgos_sys_config); }
void mgos_config_set_wifi_sta1_ca_cert(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta1_ca_cert(const char * v) { mgos_config_set_wifi_sta1_ca_cert(&mgos_sys_config, v); }

/* wifi.sta1.ip */
#define MGOS_CONFIG_HAVE_WIFI_STA1_IP
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_IP
const char * mgos_config_get_wifi_sta1_ip(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta1_ip(void) { return mgos_config_get_wifi_sta1_ip(&mgos_sys_config); }
void mgos_config_set_wifi_sta1_ip(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta1_ip(const char * v) { mgos_config_set_wifi_sta1_ip(&mgos_sys_config, v); }

/* wifi.sta1.netmask */
#define MGOS_CONFIG_HAVE_WIFI_STA1_NETMASK
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_NETMASK
const char * mgos_config_get_wifi_sta1_netmask(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta1_netmask(void) { return mgos_config_get_wifi_sta1_netmask(&mgos_sys_config); }
void mgos_config_set_wifi_sta1_netmask(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta1_netmask(const char * v) { mgos_config_set_wifi_sta1_netmask(&mgos_sys_config, v); }

/* wifi.sta1.gw */
#define MGOS_CONFIG_HAVE_WIFI_STA1_GW
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_GW
const char * mgos_config_get_wifi_sta1_gw(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta1_gw(void) { return mgos_config_get_wifi_sta1_gw(&mgos_sys_config); }
void mgos_config_set_wifi_sta1_gw(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta1_gw(const char * v) { mgos_config_set_wifi_sta1_gw(&mgos_sys_config, v); }

/* wifi.sta1.nameserver */
#define MGOS_CONFIG_HAVE_WIFI_STA1_NAMESERVER
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_NAMESERVER
const char * mgos_config_get_wifi_sta1_nameserver(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta1_nameserver(void) { return mgos_config_get_wifi_sta1_nameserver(&mgos_sys_config); }
void mgos_config_set_wifi_sta1_nameserver(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta1_nameserver(const char * v) { mgos_config_set_wifi_sta1_nameserver(&mgos_sys_config, v); }

/* wifi.sta1.dhcp_hostname */
#define MGOS_CONFIG_HAVE_WIFI_STA1_DHCP_HOSTNAME
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_DHCP_HOSTNAME
const char * mgos_config_get_wifi_sta1_dhcp_hostname(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta1_dhcp_hostname(void) { return mgos_config_get_wifi_sta1_dhcp_hostname(&mgos_sys_config); }
void mgos_config_set_wifi_sta1_dhcp_hostname(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta1_dhcp_hostname(const char * v) { mgos_config_set_wifi_sta1_dhcp_hostname(&mgos_sys_config, v); }

/* wifi.sta2 */
#define MGOS_CONFIG_HAVE_WIFI_STA2
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2
const struct mgos_config_wifi_sta * mgos_config_get_wifi_sta2(struct mgos_config *cfg);
static inline const struct mgos_config_wifi_sta * mgos_sys_config_get_wifi_sta2(void) { return mgos_config_get_wifi_sta2(&mgos_sys_config); }

/* wifi.sta2.enable */
#define MGOS_CONFIG_HAVE_WIFI_STA2_ENABLE
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_ENABLE
int mgos_config_get_wifi_sta2_enable(struct mgos_config *cfg);
static inline int mgos_sys_config_get_wifi_sta2_enable(void) { return mgos_config_get_wifi_sta2_enable(&mgos_sys_config); }
void mgos_config_set_wifi_sta2_enable(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_wifi_sta2_enable(int v) { mgos_config_set_wifi_sta2_enable(&mgos_sys_config, v); }

/* wifi.sta2.ssid */
#define MGOS_CONFIG_HAVE_WIFI_STA2_SSID
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_SSID
const char * mgos_config_get_wifi_sta2_ssid(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta2_ssid(void) { return mgos_config_get_wifi_sta2_ssid(&mgos_sys_config); }
void mgos_config_set_wifi_sta2_ssid(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta2_ssid(const char * v) { mgos_config_set_wifi_sta2_ssid(&mgos_sys_config, v); }

/* wifi.sta2.pass */
#define MGOS_CONFIG_HAVE_WIFI_STA2_PASS
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_PASS
const char * mgos_config_get_wifi_sta2_pass(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta2_pass(void) { return mgos_config_get_wifi_sta2_pass(&mgos_sys_config); }
void mgos_config_set_wifi_sta2_pass(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta2_pass(const char * v) { mgos_config_set_wifi_sta2_pass(&mgos_sys_config, v); }

/* wifi.sta2.user */
#define MGOS_CONFIG_HAVE_WIFI_STA2_USER
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_USER
const char * mgos_config_get_wifi_sta2_user(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta2_user(void) { return mgos_config_get_wifi_sta2_user(&mgos_sys_config); }
void mgos_config_set_wifi_sta2_user(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta2_user(const char * v) { mgos_config_set_wifi_sta2_user(&mgos_sys_config, v); }

/* wifi.sta2.anon_identity */
#define MGOS_CONFIG_HAVE_WIFI_STA2_ANON_IDENTITY
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_ANON_IDENTITY
const char * mgos_config_get_wifi_sta2_anon_identity(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta2_anon_identity(void) { return mgos_config_get_wifi_sta2_anon_identity(&mgos_sys_config); }
void mgos_config_set_wifi_sta2_anon_identity(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta2_anon_identity(const char * v) { mgos_config_set_wifi_sta2_anon_identity(&mgos_sys_config, v); }

/* wifi.sta2.cert */
#define MGOS_CONFIG_HAVE_WIFI_STA2_CERT
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_CERT
const char * mgos_config_get_wifi_sta2_cert(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta2_cert(void) { return mgos_config_get_wifi_sta2_cert(&mgos_sys_config); }
void mgos_config_set_wifi_sta2_cert(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta2_cert(const char * v) { mgos_config_set_wifi_sta2_cert(&mgos_sys_config, v); }

/* wifi.sta2.key */
#define MGOS_CONFIG_HAVE_WIFI_STA2_KEY
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_KEY
const char * mgos_config_get_wifi_sta2_key(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta2_key(void) { return mgos_config_get_wifi_sta2_key(&mgos_sys_config); }
void mgos_config_set_wifi_sta2_key(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta2_key(const char * v) { mgos_config_set_wifi_sta2_key(&mgos_sys_config, v); }

/* wifi.sta2.ca_cert */
#define MGOS_CONFIG_HAVE_WIFI_STA2_CA_CERT
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_CA_CERT
const char * mgos_config_get_wifi_sta2_ca_cert(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta2_ca_cert(void) { return mgos_config_get_wifi_sta2_ca_cert(&mgos_sys_config); }
void mgos_config_set_wifi_sta2_ca_cert(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta2_ca_cert(const char * v) { mgos_config_set_wifi_sta2_ca_cert(&mgos_sys_config, v); }

/* wifi.sta2.ip */
#define MGOS_CONFIG_HAVE_WIFI_STA2_IP
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_IP
const char * mgos_config_get_wifi_sta2_ip(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta2_ip(void) { return mgos_config_get_wifi_sta2_ip(&mgos_sys_config); }
void mgos_config_set_wifi_sta2_ip(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta2_ip(const char * v) { mgos_config_set_wifi_sta2_ip(&mgos_sys_config, v); }

/* wifi.sta2.netmask */
#define MGOS_CONFIG_HAVE_WIFI_STA2_NETMASK
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_NETMASK
const char * mgos_config_get_wifi_sta2_netmask(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta2_netmask(void) { return mgos_config_get_wifi_sta2_netmask(&mgos_sys_config); }
void mgos_config_set_wifi_sta2_netmask(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta2_netmask(const char * v) { mgos_config_set_wifi_sta2_netmask(&mgos_sys_config, v); }

/* wifi.sta2.gw */
#define MGOS_CONFIG_HAVE_WIFI_STA2_GW
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_GW
const char * mgos_config_get_wifi_sta2_gw(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta2_gw(void) { return mgos_config_get_wifi_sta2_gw(&mgos_sys_config); }
void mgos_config_set_wifi_sta2_gw(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta2_gw(const char * v) { mgos_config_set_wifi_sta2_gw(&mgos_sys_config, v); }

/* wifi.sta2.nameserver */
#define MGOS_CONFIG_HAVE_WIFI_STA2_NAMESERVER
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_NAMESERVER
const char * mgos_config_get_wifi_sta2_nameserver(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta2_nameserver(void) { return mgos_config_get_wifi_sta2_nameserver(&mgos_sys_config); }
void mgos_config_set_wifi_sta2_nameserver(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta2_nameserver(const char * v) { mgos_config_set_wifi_sta2_nameserver(&mgos_sys_config, v); }

/* wifi.sta2.dhcp_hostname */
#define MGOS_CONFIG_HAVE_WIFI_STA2_DHCP_HOSTNAME
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_DHCP_HOSTNAME
const char * mgos_config_get_wifi_sta2_dhcp_hostname(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_wifi_sta2_dhcp_hostname(void) { return mgos_config_get_wifi_sta2_dhcp_hostname(&mgos_sys_config); }
void mgos_config_set_wifi_sta2_dhcp_hostname(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_wifi_sta2_dhcp_hostname(const char * v) { mgos_config_set_wifi_sta2_dhcp_hostname(&mgos_sys_config, v); }

/* wifi.sta_cfg_idx */
#define MGOS_CONFIG_HAVE_WIFI_STA_CFG_IDX
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_CFG_IDX
int mgos_config_get_wifi_sta_cfg_idx(struct mgos_config *cfg);
static inline int mgos_sys_config_get_wifi_sta_cfg_idx(void) { return mgos_config_get_wifi_sta_cfg_idx(&mgos_sys_config); }
void mgos_config_set_wifi_sta_cfg_idx(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_wifi_sta_cfg_idx(int v) { mgos_config_set_wifi_sta_cfg_idx(&mgos_sys_config, v); }

/* wifi.sta_connect_timeout */
#define MGOS_CONFIG_HAVE_WIFI_STA_CONNECT_TIMEOUT
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_CONNECT_TIMEOUT
int mgos_config_get_wifi_sta_connect_timeout(struct mgos_config *cfg);
static inline int mgos_sys_config_get_wifi_sta_connect_timeout(void) { return mgos_config_get_wifi_sta_connect_timeout(&mgos_sys_config); }
void mgos_config_set_wifi_sta_connect_timeout(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_wifi_sta_connect_timeout(int v) { mgos_config_set_wifi_sta_connect_timeout(&mgos_sys_config, v); }

/* sw */
#define MGOS_CONFIG_HAVE_SW
#define MGOS_SYS_CONFIG_HAVE_SW
const struct mgos_config_sw * mgos_config_get_sw(struct mgos_config *cfg);
static inline const struct mgos_config_sw * mgos_sys_config_get_sw(void) { return mgos_config_get_sw(&mgos_sys_config); }
const struct mgos_conf_entry *mgos_config_schema_sw(void);
bool mgos_config_parse_sw(struct mg_str json, struct mgos_config_sw *cfg);
bool mgos_config_copy_sw(const struct mgos_config_sw *src, struct mgos_config_sw *dst);
void mgos_config_free_sw(struct mgos_config_sw *cfg);

/* sw.id */
#define MGOS_CONFIG_HAVE_SW_ID
#define MGOS_SYS_CONFIG_HAVE_SW_ID
int mgos_config_get_sw_id(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw_id(void) { return mgos_config_get_sw_id(&mgos_sys_config); }
void mgos_config_set_sw_id(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw_id(int v) { mgos_config_set_sw_id(&mgos_sys_config, v); }

/* sw.name */
#define MGOS_CONFIG_HAVE_SW_NAME
#define MGOS_SYS_CONFIG_HAVE_SW_NAME
const char * mgos_config_get_sw_name(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_sw_name(void) { return mgos_config_get_sw_name(&mgos_sys_config); }
void mgos_config_set_sw_name(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_sw_name(const char * v) { mgos_config_set_sw_name(&mgos_sys_config, v); }

/* sw.enable */
#define MGOS_CONFIG_HAVE_SW_ENABLE
#define MGOS_SYS_CONFIG_HAVE_SW_ENABLE
int mgos_config_get_sw_enable(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw_enable(void) { return mgos_config_get_sw_enable(&mgos_sys_config); }
void mgos_config_set_sw_enable(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw_enable(int v) { mgos_config_set_sw_enable(&mgos_sys_config, v); }

/* sw.out_gpio */
#define MGOS_CONFIG_HAVE_SW_OUT_GPIO
#define MGOS_SYS_CONFIG_HAVE_SW_OUT_GPIO
int mgos_config_get_sw_out_gpio(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw_out_gpio(void) { return mgos_config_get_sw_out_gpio(&mgos_sys_config); }
void mgos_config_set_sw_out_gpio(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw_out_gpio(int v) { mgos_config_set_sw_out_gpio(&mgos_sys_config, v); }

/* sw.out_on_value */
#define MGOS_CONFIG_HAVE_SW_OUT_ON_VALUE
#define MGOS_SYS_CONFIG_HAVE_SW_OUT_ON_VALUE
int mgos_config_get_sw_out_on_value(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw_out_on_value(void) { return mgos_config_get_sw_out_on_value(&mgos_sys_config); }
void mgos_config_set_sw_out_on_value(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw_out_on_value(int v) { mgos_config_set_sw_out_on_value(&mgos_sys_config, v); }

/* sw.in_gpio */
#define MGOS_CONFIG_HAVE_SW_IN_GPIO
#define MGOS_SYS_CONFIG_HAVE_SW_IN_GPIO
int mgos_config_get_sw_in_gpio(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw_in_gpio(void) { return mgos_config_get_sw_in_gpio(&mgos_sys_config); }
void mgos_config_set_sw_in_gpio(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw_in_gpio(int v) { mgos_config_set_sw_in_gpio(&mgos_sys_config, v); }

/* sw.in_mode */
#define MGOS_CONFIG_HAVE_SW_IN_MODE
#define MGOS_SYS_CONFIG_HAVE_SW_IN_MODE
int mgos_config_get_sw_in_mode(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw_in_mode(void) { return mgos_config_get_sw_in_mode(&mgos_sys_config); }
void mgos_config_set_sw_in_mode(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw_in_mode(int v) { mgos_config_set_sw_in_mode(&mgos_sys_config, v); }

/* sw.state */
#define MGOS_CONFIG_HAVE_SW_STATE
#define MGOS_SYS_CONFIG_HAVE_SW_STATE
int mgos_config_get_sw_state(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw_state(void) { return mgos_config_get_sw_state(&mgos_sys_config); }
void mgos_config_set_sw_state(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw_state(int v) { mgos_config_set_sw_state(&mgos_sys_config, v); }

/* sw.persist_state */
#define MGOS_CONFIG_HAVE_SW_PERSIST_STATE
#define MGOS_SYS_CONFIG_HAVE_SW_PERSIST_STATE
int mgos_config_get_sw_persist_state(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw_persist_state(void) { return mgos_config_get_sw_persist_state(&mgos_sys_config); }
void mgos_config_set_sw_persist_state(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw_persist_state(int v) { mgos_config_set_sw_persist_state(&mgos_sys_config, v); }

/* sw1 */
#define MGOS_CONFIG_HAVE_SW1
#define MGOS_SYS_CONFIG_HAVE_SW1
const struct mgos_config_sw * mgos_config_get_sw1(struct mgos_config *cfg);
static inline const struct mgos_config_sw * mgos_sys_config_get_sw1(void) { return mgos_config_get_sw1(&mgos_sys_config); }

/* sw1.id */
#define MGOS_CONFIG_HAVE_SW1_ID
#define MGOS_SYS_CONFIG_HAVE_SW1_ID
int mgos_config_get_sw1_id(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw1_id(void) { return mgos_config_get_sw1_id(&mgos_sys_config); }
void mgos_config_set_sw1_id(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw1_id(int v) { mgos_config_set_sw1_id(&mgos_sys_config, v); }

/* sw1.name */
#define MGOS_CONFIG_HAVE_SW1_NAME
#define MGOS_SYS_CONFIG_HAVE_SW1_NAME
const char * mgos_config_get_sw1_name(struct mgos_config *cfg);
static inline const char * mgos_sys_config_get_sw1_name(void) { return mgos_config_get_sw1_name(&mgos_sys_config); }
void mgos_config_set_sw1_name(struct mgos_config *cfg, const char * v);
static inline void mgos_sys_config_set_sw1_name(const char * v) { mgos_config_set_sw1_name(&mgos_sys_config, v); }

/* sw1.enable */
#define MGOS_CONFIG_HAVE_SW1_ENABLE
#define MGOS_SYS_CONFIG_HAVE_SW1_ENABLE
int mgos_config_get_sw1_enable(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw1_enable(void) { return mgos_config_get_sw1_enable(&mgos_sys_config); }
void mgos_config_set_sw1_enable(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw1_enable(int v) { mgos_config_set_sw1_enable(&mgos_sys_config, v); }

/* sw1.out_gpio */
#define MGOS_CONFIG_HAVE_SW1_OUT_GPIO
#define MGOS_SYS_CONFIG_HAVE_SW1_OUT_GPIO
int mgos_config_get_sw1_out_gpio(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw1_out_gpio(void) { return mgos_config_get_sw1_out_gpio(&mgos_sys_config); }
void mgos_config_set_sw1_out_gpio(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw1_out_gpio(int v) { mgos_config_set_sw1_out_gpio(&mgos_sys_config, v); }

/* sw1.out_on_value */
#define MGOS_CONFIG_HAVE_SW1_OUT_ON_VALUE
#define MGOS_SYS_CONFIG_HAVE_SW1_OUT_ON_VALUE
int mgos_config_get_sw1_out_on_value(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw1_out_on_value(void) { return mgos_config_get_sw1_out_on_value(&mgos_sys_config); }
void mgos_config_set_sw1_out_on_value(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw1_out_on_value(int v) { mgos_config_set_sw1_out_on_value(&mgos_sys_config, v); }

/* sw1.in_gpio */
#define MGOS_CONFIG_HAVE_SW1_IN_GPIO
#define MGOS_SYS_CONFIG_HAVE_SW1_IN_GPIO
int mgos_config_get_sw1_in_gpio(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw1_in_gpio(void) { return mgos_config_get_sw1_in_gpio(&mgos_sys_config); }
void mgos_config_set_sw1_in_gpio(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw1_in_gpio(int v) { mgos_config_set_sw1_in_gpio(&mgos_sys_config, v); }

/* sw1.in_mode */
#define MGOS_CONFIG_HAVE_SW1_IN_MODE
#define MGOS_SYS_CONFIG_HAVE_SW1_IN_MODE
int mgos_config_get_sw1_in_mode(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw1_in_mode(void) { return mgos_config_get_sw1_in_mode(&mgos_sys_config); }
void mgos_config_set_sw1_in_mode(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw1_in_mode(int v) { mgos_config_set_sw1_in_mode(&mgos_sys_config, v); }

/* sw1.state */
#define MGOS_CONFIG_HAVE_SW1_STATE
#define MGOS_SYS_CONFIG_HAVE_SW1_STATE
int mgos_config_get_sw1_state(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw1_state(void) { return mgos_config_get_sw1_state(&mgos_sys_config); }
void mgos_config_set_sw1_state(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw1_state(int v) { mgos_config_set_sw1_state(&mgos_sys_config, v); }

/* sw1.persist_state */
#define MGOS_CONFIG_HAVE_SW1_PERSIST_STATE
#define MGOS_SYS_CONFIG_HAVE_SW1_PERSIST_STATE
int mgos_config_get_sw1_persist_state(struct mgos_config *cfg);
static inline int mgos_sys_config_get_sw1_persist_state(void) { return mgos_config_get_sw1_persist_state(&mgos_sys_config); }
void mgos_config_set_sw1_persist_state(struct mgos_config *cfg, int v);
static inline void mgos_sys_config_set_sw1_persist_state(int v) { mgos_config_set_sw1_persist_state(&mgos_sys_config, v); }

bool mgos_sys_config_get(const struct mg_str key, struct mg_str *value);
bool mgos_sys_config_set(const struct mg_str key, const struct mg_str value, bool free_strings);

#ifdef __cplusplus
}
#endif
