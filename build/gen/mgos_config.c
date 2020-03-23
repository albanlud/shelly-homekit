/* clang-format off */
/*
 * Generated file - do not edit.
 * Command: /mongoose-os/tools/mgos_gen_config.py --c_name=mgos_config --c_global_name=mgos_sys_config --dest_dir=/data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/gen/ /mongoose-os/src/mgos_debug_udp_config.yaml /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/gen/mos_conf_schema.yml
 */

#include "mgos_config.h"

#include <stddef.h>

#include "mgos_config_util.h"

const struct mgos_conf_entry mgos_config_schema_[156] = {
  {.type = CONF_TYPE_OBJECT, .key = "", .offset = 0, .num_desc = 155},
  {.type = CONF_TYPE_OBJECT, .key = "debug", .offset = offsetof(struct mgos_config, debug), .num_desc = 10},
  {.type = CONF_TYPE_STRING, .key = "udp_log_addr", .offset = offsetof(struct mgos_config, debug.udp_log_addr)},
  {.type = CONF_TYPE_INT, .key = "udp_log_level", .offset = offsetof(struct mgos_config, debug.udp_log_level)},
  {.type = CONF_TYPE_INT, .key = "mbedtls_level", .offset = offsetof(struct mgos_config, debug.mbedtls_level)},
  {.type = CONF_TYPE_INT, .key = "level", .offset = offsetof(struct mgos_config, debug.level)},
  {.type = CONF_TYPE_STRING, .key = "file_level", .offset = offsetof(struct mgos_config, debug.file_level)},
  {.type = CONF_TYPE_INT, .key = "event_level", .offset = offsetof(struct mgos_config, debug.event_level)},
  {.type = CONF_TYPE_INT, .key = "stdout_uart", .offset = offsetof(struct mgos_config, debug.stdout_uart)},
  {.type = CONF_TYPE_INT, .key = "stderr_uart", .offset = offsetof(struct mgos_config, debug.stderr_uart)},
  {.type = CONF_TYPE_INT, .key = "factory_reset_gpio", .offset = offsetof(struct mgos_config, debug.factory_reset_gpio)},
  {.type = CONF_TYPE_STRING, .key = "mg_mgr_hexdump_file", .offset = offsetof(struct mgos_config, debug.mg_mgr_hexdump_file)},
  {.type = CONF_TYPE_OBJECT, .key = "device", .offset = offsetof(struct mgos_config, device), .num_desc = 5},
  {.type = CONF_TYPE_STRING, .key = "id", .offset = offsetof(struct mgos_config, device.id)},
  {.type = CONF_TYPE_STRING, .key = "license", .offset = offsetof(struct mgos_config, device.license)},
  {.type = CONF_TYPE_STRING, .key = "mac", .offset = offsetof(struct mgos_config, device.mac)},
  {.type = CONF_TYPE_STRING, .key = "public_key", .offset = offsetof(struct mgos_config, device.public_key)},
  {.type = CONF_TYPE_STRING, .key = "sn", .offset = offsetof(struct mgos_config, device.sn)},
  {.type = CONF_TYPE_OBJECT, .key = "sys", .offset = offsetof(struct mgos_config, sys), .num_desc = 3},
  {.type = CONF_TYPE_STRING, .key = "tz_spec", .offset = offsetof(struct mgos_config, sys.tz_spec)},
  {.type = CONF_TYPE_INT, .key = "wdt_timeout", .offset = offsetof(struct mgos_config, sys.wdt_timeout)},
  {.type = CONF_TYPE_STRING, .key = "pref_ota_lib", .offset = offsetof(struct mgos_config, sys.pref_ota_lib)},
  {.type = CONF_TYPE_STRING, .key = "conf_acl", .offset = offsetof(struct mgos_config, conf_acl)},
  {.type = CONF_TYPE_OBJECT, .key = "dns_sd", .offset = offsetof(struct mgos_config, dns_sd), .num_desc = 4},
  {.type = CONF_TYPE_BOOL, .key = "enable", .offset = offsetof(struct mgos_config, dns_sd.enable)},
  {.type = CONF_TYPE_STRING, .key = "host_name", .offset = offsetof(struct mgos_config, dns_sd.host_name)},
  {.type = CONF_TYPE_STRING, .key = "txt", .offset = offsetof(struct mgos_config, dns_sd.txt)},
  {.type = CONF_TYPE_INT, .key = "ttl", .offset = offsetof(struct mgos_config, dns_sd.ttl)},
  {.type = CONF_TYPE_OBJECT, .key = "hap", .offset = offsetof(struct mgos_config, hap), .num_desc = 2},
  {.type = CONF_TYPE_STRING, .key = "salt", .offset = offsetof(struct mgos_config, hap.salt)},
  {.type = CONF_TYPE_STRING, .key = "verifier", .offset = offsetof(struct mgos_config, hap.verifier)},
  {.type = CONF_TYPE_OBJECT, .key = "http", .offset = offsetof(struct mgos_config, http), .num_desc = 11},
  {.type = CONF_TYPE_BOOL, .key = "enable", .offset = offsetof(struct mgos_config, http.enable)},
  {.type = CONF_TYPE_STRING, .key = "listen_addr", .offset = offsetof(struct mgos_config, http.listen_addr)},
  {.type = CONF_TYPE_STRING, .key = "document_root", .offset = offsetof(struct mgos_config, http.document_root)},
  {.type = CONF_TYPE_STRING, .key = "index_files", .offset = offsetof(struct mgos_config, http.index_files)},
  {.type = CONF_TYPE_STRING, .key = "ssl_cert", .offset = offsetof(struct mgos_config, http.ssl_cert)},
  {.type = CONF_TYPE_STRING, .key = "ssl_key", .offset = offsetof(struct mgos_config, http.ssl_key)},
  {.type = CONF_TYPE_STRING, .key = "ssl_ca_cert", .offset = offsetof(struct mgos_config, http.ssl_ca_cert)},
  {.type = CONF_TYPE_STRING, .key = "upload_acl", .offset = offsetof(struct mgos_config, http.upload_acl)},
  {.type = CONF_TYPE_STRING, .key = "hidden_files", .offset = offsetof(struct mgos_config, http.hidden_files)},
  {.type = CONF_TYPE_STRING, .key = "auth_domain", .offset = offsetof(struct mgos_config, http.auth_domain)},
  {.type = CONF_TYPE_STRING, .key = "auth_file", .offset = offsetof(struct mgos_config, http.auth_file)},
  {.type = CONF_TYPE_OBJECT, .key = "update", .offset = offsetof(struct mgos_config, update), .num_desc = 9},
  {.type = CONF_TYPE_INT, .key = "timeout", .offset = offsetof(struct mgos_config, update.timeout)},
  {.type = CONF_TYPE_INT, .key = "commit_timeout", .offset = offsetof(struct mgos_config, update.commit_timeout)},
  {.type = CONF_TYPE_STRING, .key = "url", .offset = offsetof(struct mgos_config, update.url)},
  {.type = CONF_TYPE_INT, .key = "interval", .offset = offsetof(struct mgos_config, update.interval)},
  {.type = CONF_TYPE_STRING, .key = "extra_http_headers", .offset = offsetof(struct mgos_config, update.extra_http_headers)},
  {.type = CONF_TYPE_STRING, .key = "ssl_ca_file", .offset = offsetof(struct mgos_config, update.ssl_ca_file)},
  {.type = CONF_TYPE_STRING, .key = "ssl_client_cert_file", .offset = offsetof(struct mgos_config, update.ssl_client_cert_file)},
  {.type = CONF_TYPE_STRING, .key = "ssl_server_name", .offset = offsetof(struct mgos_config, update.ssl_server_name)},
  {.type = CONF_TYPE_BOOL, .key = "enable_post", .offset = offsetof(struct mgos_config, update.enable_post)},
  {.type = CONF_TYPE_OBJECT, .key = "rpc", .offset = offsetof(struct mgos_config, rpc), .num_desc = 21},
  {.type = CONF_TYPE_BOOL, .key = "enable", .offset = offsetof(struct mgos_config, rpc.enable)},
  {.type = CONF_TYPE_INT, .key = "max_frame_size", .offset = offsetof(struct mgos_config, rpc.max_frame_size)},
  {.type = CONF_TYPE_INT, .key = "max_queue_length", .offset = offsetof(struct mgos_config, rpc.max_queue_length)},
  {.type = CONF_TYPE_INT, .key = "default_out_channel_idle_close_timeout", .offset = offsetof(struct mgos_config, rpc.default_out_channel_idle_close_timeout)},
  {.type = CONF_TYPE_STRING, .key = "acl_file", .offset = offsetof(struct mgos_config, rpc.acl_file)},
  {.type = CONF_TYPE_STRING, .key = "auth_domain", .offset = offsetof(struct mgos_config, rpc.auth_domain)},
  {.type = CONF_TYPE_STRING, .key = "auth_file", .offset = offsetof(struct mgos_config, rpc.auth_file)},
  {.type = CONF_TYPE_OBJECT, .key = "uart", .offset = offsetof(struct mgos_config, rpc.uart), .num_desc = 4},
  {.type = CONF_TYPE_INT, .key = "uart_no", .offset = offsetof(struct mgos_config, rpc.uart.uart_no)},
  {.type = CONF_TYPE_INT, .key = "baud_rate", .offset = offsetof(struct mgos_config, rpc.uart.baud_rate)},
  {.type = CONF_TYPE_INT, .key = "fc_type", .offset = offsetof(struct mgos_config, rpc.uart.fc_type)},
  {.type = CONF_TYPE_STRING, .key = "dst", .offset = offsetof(struct mgos_config, rpc.uart.dst)},
  {.type = CONF_TYPE_OBJECT, .key = "ws", .offset = offsetof(struct mgos_config, rpc.ws), .num_desc = 8},
  {.type = CONF_TYPE_BOOL, .key = "enable", .offset = offsetof(struct mgos_config, rpc.ws.enable)},
  {.type = CONF_TYPE_STRING, .key = "server_address", .offset = offsetof(struct mgos_config, rpc.ws.server_address)},
  {.type = CONF_TYPE_INT, .key = "reconnect_interval_min", .offset = offsetof(struct mgos_config, rpc.ws.reconnect_interval_min)},
  {.type = CONF_TYPE_INT, .key = "reconnect_interval_max", .offset = offsetof(struct mgos_config, rpc.ws.reconnect_interval_max)},
  {.type = CONF_TYPE_STRING, .key = "ssl_server_name", .offset = offsetof(struct mgos_config, rpc.ws.ssl_server_name)},
  {.type = CONF_TYPE_STRING, .key = "ssl_cert", .offset = offsetof(struct mgos_config, rpc.ws.ssl_cert)},
  {.type = CONF_TYPE_STRING, .key = "ssl_key", .offset = offsetof(struct mgos_config, rpc.ws.ssl_key)},
  {.type = CONF_TYPE_STRING, .key = "ssl_ca_cert", .offset = offsetof(struct mgos_config, rpc.ws.ssl_ca_cert)},
  {.type = CONF_TYPE_OBJECT, .key = "wifi", .offset = offsetof(struct mgos_config, wifi), .num_desc = 60},
  {.type = CONF_TYPE_OBJECT, .key = "ap", .offset = offsetof(struct mgos_config, wifi.ap), .num_desc = 15},
  {.type = CONF_TYPE_BOOL, .key = "enable", .offset = offsetof(struct mgos_config, wifi.ap.enable)},
  {.type = CONF_TYPE_STRING, .key = "ssid", .offset = offsetof(struct mgos_config, wifi.ap.ssid)},
  {.type = CONF_TYPE_STRING, .key = "pass", .offset = offsetof(struct mgos_config, wifi.ap.pass)},
  {.type = CONF_TYPE_BOOL, .key = "hidden", .offset = offsetof(struct mgos_config, wifi.ap.hidden)},
  {.type = CONF_TYPE_INT, .key = "channel", .offset = offsetof(struct mgos_config, wifi.ap.channel)},
  {.type = CONF_TYPE_INT, .key = "max_connections", .offset = offsetof(struct mgos_config, wifi.ap.max_connections)},
  {.type = CONF_TYPE_STRING, .key = "ip", .offset = offsetof(struct mgos_config, wifi.ap.ip)},
  {.type = CONF_TYPE_STRING, .key = "netmask", .offset = offsetof(struct mgos_config, wifi.ap.netmask)},
  {.type = CONF_TYPE_STRING, .key = "gw", .offset = offsetof(struct mgos_config, wifi.ap.gw)},
  {.type = CONF_TYPE_STRING, .key = "dhcp_start", .offset = offsetof(struct mgos_config, wifi.ap.dhcp_start)},
  {.type = CONF_TYPE_STRING, .key = "dhcp_end", .offset = offsetof(struct mgos_config, wifi.ap.dhcp_end)},
  {.type = CONF_TYPE_INT, .key = "trigger_on_gpio", .offset = offsetof(struct mgos_config, wifi.ap.trigger_on_gpio)},
  {.type = CONF_TYPE_INT, .key = "disable_after", .offset = offsetof(struct mgos_config, wifi.ap.disable_after)},
  {.type = CONF_TYPE_STRING, .key = "hostname", .offset = offsetof(struct mgos_config, wifi.ap.hostname)},
  {.type = CONF_TYPE_BOOL, .key = "keep_enabled", .offset = offsetof(struct mgos_config, wifi.ap.keep_enabled)},
  {.type = CONF_TYPE_OBJECT, .key = "sta", .offset = offsetof(struct mgos_config, wifi.sta), .num_desc = 13},
  {.type = CONF_TYPE_BOOL, .key = "enable", .offset = offsetof(struct mgos_config, wifi.sta.enable)},
  {.type = CONF_TYPE_STRING, .key = "ssid", .offset = offsetof(struct mgos_config, wifi.sta.ssid)},
  {.type = CONF_TYPE_STRING, .key = "pass", .offset = offsetof(struct mgos_config, wifi.sta.pass)},
  {.type = CONF_TYPE_STRING, .key = "user", .offset = offsetof(struct mgos_config, wifi.sta.user)},
  {.type = CONF_TYPE_STRING, .key = "anon_identity", .offset = offsetof(struct mgos_config, wifi.sta.anon_identity)},
  {.type = CONF_TYPE_STRING, .key = "cert", .offset = offsetof(struct mgos_config, wifi.sta.cert)},
  {.type = CONF_TYPE_STRING, .key = "key", .offset = offsetof(struct mgos_config, wifi.sta.key)},
  {.type = CONF_TYPE_STRING, .key = "ca_cert", .offset = offsetof(struct mgos_config, wifi.sta.ca_cert)},
  {.type = CONF_TYPE_STRING, .key = "ip", .offset = offsetof(struct mgos_config, wifi.sta.ip)},
  {.type = CONF_TYPE_STRING, .key = "netmask", .offset = offsetof(struct mgos_config, wifi.sta.netmask)},
  {.type = CONF_TYPE_STRING, .key = "gw", .offset = offsetof(struct mgos_config, wifi.sta.gw)},
  {.type = CONF_TYPE_STRING, .key = "nameserver", .offset = offsetof(struct mgos_config, wifi.sta.nameserver)},
  {.type = CONF_TYPE_STRING, .key = "dhcp_hostname", .offset = offsetof(struct mgos_config, wifi.sta.dhcp_hostname)},
  {.type = CONF_TYPE_OBJECT, .key = "sta1", .offset = offsetof(struct mgos_config, wifi.sta1), .num_desc = 13},
  {.type = CONF_TYPE_BOOL, .key = "enable", .offset = offsetof(struct mgos_config, wifi.sta1.enable)},
  {.type = CONF_TYPE_STRING, .key = "ssid", .offset = offsetof(struct mgos_config, wifi.sta1.ssid)},
  {.type = CONF_TYPE_STRING, .key = "pass", .offset = offsetof(struct mgos_config, wifi.sta1.pass)},
  {.type = CONF_TYPE_STRING, .key = "user", .offset = offsetof(struct mgos_config, wifi.sta1.user)},
  {.type = CONF_TYPE_STRING, .key = "anon_identity", .offset = offsetof(struct mgos_config, wifi.sta1.anon_identity)},
  {.type = CONF_TYPE_STRING, .key = "cert", .offset = offsetof(struct mgos_config, wifi.sta1.cert)},
  {.type = CONF_TYPE_STRING, .key = "key", .offset = offsetof(struct mgos_config, wifi.sta1.key)},
  {.type = CONF_TYPE_STRING, .key = "ca_cert", .offset = offsetof(struct mgos_config, wifi.sta1.ca_cert)},
  {.type = CONF_TYPE_STRING, .key = "ip", .offset = offsetof(struct mgos_config, wifi.sta1.ip)},
  {.type = CONF_TYPE_STRING, .key = "netmask", .offset = offsetof(struct mgos_config, wifi.sta1.netmask)},
  {.type = CONF_TYPE_STRING, .key = "gw", .offset = offsetof(struct mgos_config, wifi.sta1.gw)},
  {.type = CONF_TYPE_STRING, .key = "nameserver", .offset = offsetof(struct mgos_config, wifi.sta1.nameserver)},
  {.type = CONF_TYPE_STRING, .key = "dhcp_hostname", .offset = offsetof(struct mgos_config, wifi.sta1.dhcp_hostname)},
  {.type = CONF_TYPE_OBJECT, .key = "sta2", .offset = offsetof(struct mgos_config, wifi.sta2), .num_desc = 13},
  {.type = CONF_TYPE_BOOL, .key = "enable", .offset = offsetof(struct mgos_config, wifi.sta2.enable)},
  {.type = CONF_TYPE_STRING, .key = "ssid", .offset = offsetof(struct mgos_config, wifi.sta2.ssid)},
  {.type = CONF_TYPE_STRING, .key = "pass", .offset = offsetof(struct mgos_config, wifi.sta2.pass)},
  {.type = CONF_TYPE_STRING, .key = "user", .offset = offsetof(struct mgos_config, wifi.sta2.user)},
  {.type = CONF_TYPE_STRING, .key = "anon_identity", .offset = offsetof(struct mgos_config, wifi.sta2.anon_identity)},
  {.type = CONF_TYPE_STRING, .key = "cert", .offset = offsetof(struct mgos_config, wifi.sta2.cert)},
  {.type = CONF_TYPE_STRING, .key = "key", .offset = offsetof(struct mgos_config, wifi.sta2.key)},
  {.type = CONF_TYPE_STRING, .key = "ca_cert", .offset = offsetof(struct mgos_config, wifi.sta2.ca_cert)},
  {.type = CONF_TYPE_STRING, .key = "ip", .offset = offsetof(struct mgos_config, wifi.sta2.ip)},
  {.type = CONF_TYPE_STRING, .key = "netmask", .offset = offsetof(struct mgos_config, wifi.sta2.netmask)},
  {.type = CONF_TYPE_STRING, .key = "gw", .offset = offsetof(struct mgos_config, wifi.sta2.gw)},
  {.type = CONF_TYPE_STRING, .key = "nameserver", .offset = offsetof(struct mgos_config, wifi.sta2.nameserver)},
  {.type = CONF_TYPE_STRING, .key = "dhcp_hostname", .offset = offsetof(struct mgos_config, wifi.sta2.dhcp_hostname)},
  {.type = CONF_TYPE_INT, .key = "sta_cfg_idx", .offset = offsetof(struct mgos_config, wifi.sta_cfg_idx)},
  {.type = CONF_TYPE_INT, .key = "sta_connect_timeout", .offset = offsetof(struct mgos_config, wifi.sta_connect_timeout)},
  {.type = CONF_TYPE_OBJECT, .key = "sw", .offset = offsetof(struct mgos_config, sw), .num_desc = 9},
  {.type = CONF_TYPE_INT, .key = "id", .offset = offsetof(struct mgos_config, sw.id)},
  {.type = CONF_TYPE_STRING, .key = "name", .offset = offsetof(struct mgos_config, sw.name)},
  {.type = CONF_TYPE_BOOL, .key = "enable", .offset = offsetof(struct mgos_config, sw.enable)},
  {.type = CONF_TYPE_INT, .key = "out_gpio", .offset = offsetof(struct mgos_config, sw.out_gpio)},
  {.type = CONF_TYPE_INT, .key = "out_on_value", .offset = offsetof(struct mgos_config, sw.out_on_value)},
  {.type = CONF_TYPE_INT, .key = "in_gpio", .offset = offsetof(struct mgos_config, sw.in_gpio)},
  {.type = CONF_TYPE_INT, .key = "in_mode", .offset = offsetof(struct mgos_config, sw.in_mode)},
  {.type = CONF_TYPE_BOOL, .key = "state", .offset = offsetof(struct mgos_config, sw.state)},
  {.type = CONF_TYPE_BOOL, .key = "persist_state", .offset = offsetof(struct mgos_config, sw.persist_state)},
  {.type = CONF_TYPE_OBJECT, .key = "sw1", .offset = offsetof(struct mgos_config, sw1), .num_desc = 9},
  {.type = CONF_TYPE_INT, .key = "id", .offset = offsetof(struct mgos_config, sw1.id)},
  {.type = CONF_TYPE_STRING, .key = "name", .offset = offsetof(struct mgos_config, sw1.name)},
  {.type = CONF_TYPE_BOOL, .key = "enable", .offset = offsetof(struct mgos_config, sw1.enable)},
  {.type = CONF_TYPE_INT, .key = "out_gpio", .offset = offsetof(struct mgos_config, sw1.out_gpio)},
  {.type = CONF_TYPE_INT, .key = "out_on_value", .offset = offsetof(struct mgos_config, sw1.out_on_value)},
  {.type = CONF_TYPE_INT, .key = "in_gpio", .offset = offsetof(struct mgos_config, sw1.in_gpio)},
  {.type = CONF_TYPE_INT, .key = "in_mode", .offset = offsetof(struct mgos_config, sw1.in_mode)},
  {.type = CONF_TYPE_BOOL, .key = "state", .offset = offsetof(struct mgos_config, sw1.state)},
  {.type = CONF_TYPE_BOOL, .key = "persist_state", .offset = offsetof(struct mgos_config, sw1.persist_state)},
};

const struct mgos_conf_entry *mgos_config_schema() {
  return mgos_config_schema_;
}

/* Global instance */
struct mgos_config mgos_sys_config;
const struct mgos_config mgos_config_defaults = {
  .debug.udp_log_addr = NULL,
  .debug.udp_log_level = 3,
  .debug.mbedtls_level = 1,
  .debug.level = 2,
  .debug.file_level = NULL,
  .debug.event_level = 2,
  .debug.stdout_uart = 0,
  .debug.stderr_uart = 0,
  .debug.factory_reset_gpio = -1,
  .debug.mg_mgr_hexdump_file = NULL,
  .device.id = "shelly1pm-??????",
  .device.license = NULL,
  .device.mac = NULL,
  .device.public_key = NULL,
  .device.sn = "000000",
  .sys.tz_spec = NULL,
  .sys.wdt_timeout = 30,
  .sys.pref_ota_lib = NULL,
  .conf_acl = "*",
  .dns_sd.enable = 1,
  .dns_sd.host_name = NULL,
  .dns_sd.txt = NULL,
  .dns_sd.ttl = 120,
  .hap.salt = NULL,
  .hap.verifier = NULL,
  .http.enable = 1,
  .http.listen_addr = "80",
  .http.document_root = "/",
  .http.index_files = "index.html,index.html.gz",
  .http.ssl_cert = NULL,
  .http.ssl_key = NULL,
  .http.ssl_ca_cert = NULL,
  .http.upload_acl = "*",
  .http.hidden_files = NULL,
  .http.auth_domain = NULL,
  .http.auth_file = NULL,
  .update.timeout = 600,
  .update.commit_timeout = 0,
  .update.url = NULL,
  .update.interval = 0,
  .update.extra_http_headers = NULL,
  .update.ssl_ca_file = "ca.pem",
  .update.ssl_client_cert_file = NULL,
  .update.ssl_server_name = NULL,
  .update.enable_post = 1,
  .rpc.enable = 1,
  .rpc.max_frame_size = 4096,
  .rpc.max_queue_length = 25,
  .rpc.default_out_channel_idle_close_timeout = 10,
  .rpc.acl_file = NULL,
  .rpc.auth_domain = NULL,
  .rpc.auth_file = NULL,
  .rpc.uart.uart_no = 0,
  .rpc.uart.baud_rate = 115200,
  .rpc.uart.fc_type = 2,
  .rpc.uart.dst = NULL,
  .rpc.ws.enable = 1,
  .rpc.ws.server_address = NULL,
  .rpc.ws.reconnect_interval_min = 1,
  .rpc.ws.reconnect_interval_max = 60,
  .rpc.ws.ssl_server_name = NULL,
  .rpc.ws.ssl_cert = NULL,
  .rpc.ws.ssl_key = NULL,
  .rpc.ws.ssl_ca_cert = NULL,
  .wifi.ap.enable = 1,
  .wifi.ap.ssid = "shelly1pm-??????",
  .wifi.ap.pass = NULL,
  .wifi.ap.hidden = 0,
  .wifi.ap.channel = 6,
  .wifi.ap.max_connections = 10,
  .wifi.ap.ip = "192.168.33.1",
  .wifi.ap.netmask = "255.255.255.0",
  .wifi.ap.gw = NULL,
  .wifi.ap.dhcp_start = "192.168.33.2",
  .wifi.ap.dhcp_end = "192.168.33.100",
  .wifi.ap.trigger_on_gpio = -1,
  .wifi.ap.disable_after = 0,
  .wifi.ap.hostname = NULL,
  .wifi.ap.keep_enabled = 0,
  .wifi.sta.enable = 0,
  .wifi.sta.ssid = NULL,
  .wifi.sta.pass = NULL,
  .wifi.sta.user = NULL,
  .wifi.sta.anon_identity = NULL,
  .wifi.sta.cert = NULL,
  .wifi.sta.key = NULL,
  .wifi.sta.ca_cert = NULL,
  .wifi.sta.ip = NULL,
  .wifi.sta.netmask = NULL,
  .wifi.sta.gw = NULL,
  .wifi.sta.nameserver = NULL,
  .wifi.sta.dhcp_hostname = NULL,
  .wifi.sta1.enable = 0,
  .wifi.sta1.ssid = NULL,
  .wifi.sta1.pass = NULL,
  .wifi.sta1.user = NULL,
  .wifi.sta1.anon_identity = NULL,
  .wifi.sta1.cert = NULL,
  .wifi.sta1.key = NULL,
  .wifi.sta1.ca_cert = NULL,
  .wifi.sta1.ip = NULL,
  .wifi.sta1.netmask = NULL,
  .wifi.sta1.gw = NULL,
  .wifi.sta1.nameserver = NULL,
  .wifi.sta1.dhcp_hostname = NULL,
  .wifi.sta2.enable = 0,
  .wifi.sta2.ssid = NULL,
  .wifi.sta2.pass = NULL,
  .wifi.sta2.user = NULL,
  .wifi.sta2.anon_identity = NULL,
  .wifi.sta2.cert = NULL,
  .wifi.sta2.key = NULL,
  .wifi.sta2.ca_cert = NULL,
  .wifi.sta2.ip = NULL,
  .wifi.sta2.netmask = NULL,
  .wifi.sta2.gw = NULL,
  .wifi.sta2.nameserver = NULL,
  .wifi.sta2.dhcp_hostname = NULL,
  .wifi.sta_cfg_idx = 0,
  .wifi.sta_connect_timeout = 30,
  .sw.id = 0,
  .sw.name = NULL,
  .sw.enable = 1,
  .sw.out_gpio = -1,
  .sw.out_on_value = 1,
  .sw.in_gpio = -1,
  .sw.in_mode = 1,
  .sw.state = 0,
  .sw.persist_state = 0,
  .sw1.id = 0,
  .sw1.name = "Shelly SW",
  .sw1.enable = 1,
  .sw1.out_gpio = 15,
  .sw1.out_on_value = 1,
  .sw1.in_gpio = 4,
  .sw1.in_mode = 1,
  .sw1.state = 0,
  .sw1.persist_state = 0,
};

/* debug */
#define MGOS_CONFIG_HAVE_DEBUG
#define MGOS_SYS_CONFIG_HAVE_DEBUG
const struct mgos_config_debug * mgos_config_get_debug(struct mgos_config *cfg) {
  return &cfg->debug;
}
const struct mgos_conf_entry *mgos_config_schema_debug(void) {
  return mgos_conf_find_schema_entry("debug", mgos_config_schema());
}
bool mgos_config_parse_debug(struct mg_str json, struct mgos_config_debug *cfg) {
  return mgos_conf_parse_sub(json, mgos_config_schema(), cfg);
}
bool mgos_config_copy_debug(const struct mgos_config_debug *src, struct mgos_config_debug *dst) {
  return mgos_conf_copy(mgos_config_schema_debug(), src, dst);
}
void mgos_config_free_debug(struct mgos_config_debug *cfg) {
  return mgos_conf_free(mgos_config_schema_debug(), cfg);
}

/* debug.udp_log_addr */
#define MGOS_CONFIG_HAVE_DEBUG_UDP_LOG_ADDR
#define MGOS_SYS_CONFIG_HAVE_DEBUG_UDP_LOG_ADDR
const char * mgos_config_get_debug_udp_log_addr(struct mgos_config *cfg) {
  return cfg->debug.udp_log_addr;
}
void mgos_config_set_debug_udp_log_addr(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->debug.udp_log_addr, v);
}

/* debug.udp_log_level */
#define MGOS_CONFIG_HAVE_DEBUG_UDP_LOG_LEVEL
#define MGOS_SYS_CONFIG_HAVE_DEBUG_UDP_LOG_LEVEL
int mgos_config_get_debug_udp_log_level(struct mgos_config *cfg) {
  return cfg->debug.udp_log_level;
}
void mgos_config_set_debug_udp_log_level(struct mgos_config *cfg, int v) {
  cfg->debug.udp_log_level = v;
}

/* debug.mbedtls_level */
#define MGOS_CONFIG_HAVE_DEBUG_MBEDTLS_LEVEL
#define MGOS_SYS_CONFIG_HAVE_DEBUG_MBEDTLS_LEVEL
int mgos_config_get_debug_mbedtls_level(struct mgos_config *cfg) {
  return cfg->debug.mbedtls_level;
}
void mgos_config_set_debug_mbedtls_level(struct mgos_config *cfg, int v) {
  cfg->debug.mbedtls_level = v;
}

/* debug.level */
#define MGOS_CONFIG_HAVE_DEBUG_LEVEL
#define MGOS_SYS_CONFIG_HAVE_DEBUG_LEVEL
int mgos_config_get_debug_level(struct mgos_config *cfg) {
  return cfg->debug.level;
}
void mgos_config_set_debug_level(struct mgos_config *cfg, int v) {
  cfg->debug.level = v;
}

/* debug.file_level */
#define MGOS_CONFIG_HAVE_DEBUG_FILE_LEVEL
#define MGOS_SYS_CONFIG_HAVE_DEBUG_FILE_LEVEL
const char * mgos_config_get_debug_file_level(struct mgos_config *cfg) {
  return cfg->debug.file_level;
}
void mgos_config_set_debug_file_level(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->debug.file_level, v);
}

/* debug.event_level */
#define MGOS_CONFIG_HAVE_DEBUG_EVENT_LEVEL
#define MGOS_SYS_CONFIG_HAVE_DEBUG_EVENT_LEVEL
int mgos_config_get_debug_event_level(struct mgos_config *cfg) {
  return cfg->debug.event_level;
}
void mgos_config_set_debug_event_level(struct mgos_config *cfg, int v) {
  cfg->debug.event_level = v;
}

/* debug.stdout_uart */
#define MGOS_CONFIG_HAVE_DEBUG_STDOUT_UART
#define MGOS_SYS_CONFIG_HAVE_DEBUG_STDOUT_UART
int mgos_config_get_debug_stdout_uart(struct mgos_config *cfg) {
  return cfg->debug.stdout_uart;
}
void mgos_config_set_debug_stdout_uart(struct mgos_config *cfg, int v) {
  cfg->debug.stdout_uart = v;
}

/* debug.stderr_uart */
#define MGOS_CONFIG_HAVE_DEBUG_STDERR_UART
#define MGOS_SYS_CONFIG_HAVE_DEBUG_STDERR_UART
int mgos_config_get_debug_stderr_uart(struct mgos_config *cfg) {
  return cfg->debug.stderr_uart;
}
void mgos_config_set_debug_stderr_uart(struct mgos_config *cfg, int v) {
  cfg->debug.stderr_uart = v;
}

/* debug.factory_reset_gpio */
#define MGOS_CONFIG_HAVE_DEBUG_FACTORY_RESET_GPIO
#define MGOS_SYS_CONFIG_HAVE_DEBUG_FACTORY_RESET_GPIO
int mgos_config_get_debug_factory_reset_gpio(struct mgos_config *cfg) {
  return cfg->debug.factory_reset_gpio;
}
void mgos_config_set_debug_factory_reset_gpio(struct mgos_config *cfg, int v) {
  cfg->debug.factory_reset_gpio = v;
}

/* debug.mg_mgr_hexdump_file */
#define MGOS_CONFIG_HAVE_DEBUG_MG_MGR_HEXDUMP_FILE
#define MGOS_SYS_CONFIG_HAVE_DEBUG_MG_MGR_HEXDUMP_FILE
const char * mgos_config_get_debug_mg_mgr_hexdump_file(struct mgos_config *cfg) {
  return cfg->debug.mg_mgr_hexdump_file;
}
void mgos_config_set_debug_mg_mgr_hexdump_file(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->debug.mg_mgr_hexdump_file, v);
}

/* device */
#define MGOS_CONFIG_HAVE_DEVICE
#define MGOS_SYS_CONFIG_HAVE_DEVICE
const struct mgos_config_device * mgos_config_get_device(struct mgos_config *cfg) {
  return &cfg->device;
}
const struct mgos_conf_entry *mgos_config_schema_device(void) {
  return mgos_conf_find_schema_entry("device", mgos_config_schema());
}
bool mgos_config_parse_device(struct mg_str json, struct mgos_config_device *cfg) {
  return mgos_conf_parse_sub(json, mgos_config_schema(), cfg);
}
bool mgos_config_copy_device(const struct mgos_config_device *src, struct mgos_config_device *dst) {
  return mgos_conf_copy(mgos_config_schema_device(), src, dst);
}
void mgos_config_free_device(struct mgos_config_device *cfg) {
  return mgos_conf_free(mgos_config_schema_device(), cfg);
}

/* device.id */
#define MGOS_CONFIG_HAVE_DEVICE_ID
#define MGOS_SYS_CONFIG_HAVE_DEVICE_ID
const char * mgos_config_get_device_id(struct mgos_config *cfg) {
  return cfg->device.id;
}
void mgos_config_set_device_id(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->device.id, v);
}

/* device.license */
#define MGOS_CONFIG_HAVE_DEVICE_LICENSE
#define MGOS_SYS_CONFIG_HAVE_DEVICE_LICENSE
const char * mgos_config_get_device_license(struct mgos_config *cfg) {
  return cfg->device.license;
}
void mgos_config_set_device_license(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->device.license, v);
}

/* device.mac */
#define MGOS_CONFIG_HAVE_DEVICE_MAC
#define MGOS_SYS_CONFIG_HAVE_DEVICE_MAC
const char * mgos_config_get_device_mac(struct mgos_config *cfg) {
  return cfg->device.mac;
}
void mgos_config_set_device_mac(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->device.mac, v);
}

/* device.public_key */
#define MGOS_CONFIG_HAVE_DEVICE_PUBLIC_KEY
#define MGOS_SYS_CONFIG_HAVE_DEVICE_PUBLIC_KEY
const char * mgos_config_get_device_public_key(struct mgos_config *cfg) {
  return cfg->device.public_key;
}
void mgos_config_set_device_public_key(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->device.public_key, v);
}

/* device.sn */
#define MGOS_CONFIG_HAVE_DEVICE_SN
#define MGOS_SYS_CONFIG_HAVE_DEVICE_SN
const char * mgos_config_get_device_sn(struct mgos_config *cfg) {
  return cfg->device.sn;
}
void mgos_config_set_device_sn(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->device.sn, v);
}

/* sys */
#define MGOS_CONFIG_HAVE_SYS
#define MGOS_SYS_CONFIG_HAVE_SYS
const struct mgos_config_sys * mgos_config_get_sys(struct mgos_config *cfg) {
  return &cfg->sys;
}
const struct mgos_conf_entry *mgos_config_schema_sys(void) {
  return mgos_conf_find_schema_entry("sys", mgos_config_schema());
}
bool mgos_config_parse_sys(struct mg_str json, struct mgos_config_sys *cfg) {
  return mgos_conf_parse_sub(json, mgos_config_schema(), cfg);
}
bool mgos_config_copy_sys(const struct mgos_config_sys *src, struct mgos_config_sys *dst) {
  return mgos_conf_copy(mgos_config_schema_sys(), src, dst);
}
void mgos_config_free_sys(struct mgos_config_sys *cfg) {
  return mgos_conf_free(mgos_config_schema_sys(), cfg);
}

/* sys.tz_spec */
#define MGOS_CONFIG_HAVE_SYS_TZ_SPEC
#define MGOS_SYS_CONFIG_HAVE_SYS_TZ_SPEC
const char * mgos_config_get_sys_tz_spec(struct mgos_config *cfg) {
  return cfg->sys.tz_spec;
}
void mgos_config_set_sys_tz_spec(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->sys.tz_spec, v);
}

/* sys.wdt_timeout */
#define MGOS_CONFIG_HAVE_SYS_WDT_TIMEOUT
#define MGOS_SYS_CONFIG_HAVE_SYS_WDT_TIMEOUT
int mgos_config_get_sys_wdt_timeout(struct mgos_config *cfg) {
  return cfg->sys.wdt_timeout;
}
void mgos_config_set_sys_wdt_timeout(struct mgos_config *cfg, int v) {
  cfg->sys.wdt_timeout = v;
}

/* sys.pref_ota_lib */
#define MGOS_CONFIG_HAVE_SYS_PREF_OTA_LIB
#define MGOS_SYS_CONFIG_HAVE_SYS_PREF_OTA_LIB
const char * mgos_config_get_sys_pref_ota_lib(struct mgos_config *cfg) {
  return cfg->sys.pref_ota_lib;
}
void mgos_config_set_sys_pref_ota_lib(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->sys.pref_ota_lib, v);
}

/* conf_acl */
#define MGOS_CONFIG_HAVE_CONF_ACL
#define MGOS_SYS_CONFIG_HAVE_CONF_ACL
const char * mgos_config_get_conf_acl(struct mgos_config *cfg) {
  return cfg->conf_acl;
}
void mgos_config_set_conf_acl(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->conf_acl, v);
}

/* dns_sd */
#define MGOS_CONFIG_HAVE_DNS_SD
#define MGOS_SYS_CONFIG_HAVE_DNS_SD
const struct mgos_config_dns_sd * mgos_config_get_dns_sd(struct mgos_config *cfg) {
  return &cfg->dns_sd;
}
const struct mgos_conf_entry *mgos_config_schema_dns_sd(void) {
  return mgos_conf_find_schema_entry("dns_sd", mgos_config_schema());
}
bool mgos_config_parse_dns_sd(struct mg_str json, struct mgos_config_dns_sd *cfg) {
  return mgos_conf_parse_sub(json, mgos_config_schema(), cfg);
}
bool mgos_config_copy_dns_sd(const struct mgos_config_dns_sd *src, struct mgos_config_dns_sd *dst) {
  return mgos_conf_copy(mgos_config_schema_dns_sd(), src, dst);
}
void mgos_config_free_dns_sd(struct mgos_config_dns_sd *cfg) {
  return mgos_conf_free(mgos_config_schema_dns_sd(), cfg);
}

/* dns_sd.enable */
#define MGOS_CONFIG_HAVE_DNS_SD_ENABLE
#define MGOS_SYS_CONFIG_HAVE_DNS_SD_ENABLE
int mgos_config_get_dns_sd_enable(struct mgos_config *cfg) {
  return cfg->dns_sd.enable;
}
void mgos_config_set_dns_sd_enable(struct mgos_config *cfg, int v) {
  cfg->dns_sd.enable = v;
}

/* dns_sd.host_name */
#define MGOS_CONFIG_HAVE_DNS_SD_HOST_NAME
#define MGOS_SYS_CONFIG_HAVE_DNS_SD_HOST_NAME
const char * mgos_config_get_dns_sd_host_name(struct mgos_config *cfg) {
  return cfg->dns_sd.host_name;
}
void mgos_config_set_dns_sd_host_name(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->dns_sd.host_name, v);
}

/* dns_sd.txt */
#define MGOS_CONFIG_HAVE_DNS_SD_TXT
#define MGOS_SYS_CONFIG_HAVE_DNS_SD_TXT
const char * mgos_config_get_dns_sd_txt(struct mgos_config *cfg) {
  return cfg->dns_sd.txt;
}
void mgos_config_set_dns_sd_txt(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->dns_sd.txt, v);
}

/* dns_sd.ttl */
#define MGOS_CONFIG_HAVE_DNS_SD_TTL
#define MGOS_SYS_CONFIG_HAVE_DNS_SD_TTL
int mgos_config_get_dns_sd_ttl(struct mgos_config *cfg) {
  return cfg->dns_sd.ttl;
}
void mgos_config_set_dns_sd_ttl(struct mgos_config *cfg, int v) {
  cfg->dns_sd.ttl = v;
}

/* hap */
#define MGOS_CONFIG_HAVE_HAP
#define MGOS_SYS_CONFIG_HAVE_HAP
const struct mgos_config_hap * mgos_config_get_hap(struct mgos_config *cfg) {
  return &cfg->hap;
}
const struct mgos_conf_entry *mgos_config_schema_hap(void) {
  return mgos_conf_find_schema_entry("hap", mgos_config_schema());
}
bool mgos_config_parse_hap(struct mg_str json, struct mgos_config_hap *cfg) {
  return mgos_conf_parse_sub(json, mgos_config_schema(), cfg);
}
bool mgos_config_copy_hap(const struct mgos_config_hap *src, struct mgos_config_hap *dst) {
  return mgos_conf_copy(mgos_config_schema_hap(), src, dst);
}
void mgos_config_free_hap(struct mgos_config_hap *cfg) {
  return mgos_conf_free(mgos_config_schema_hap(), cfg);
}

/* hap.salt */
#define MGOS_CONFIG_HAVE_HAP_SALT
#define MGOS_SYS_CONFIG_HAVE_HAP_SALT
const char * mgos_config_get_hap_salt(struct mgos_config *cfg) {
  return cfg->hap.salt;
}
void mgos_config_set_hap_salt(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->hap.salt, v);
}

/* hap.verifier */
#define MGOS_CONFIG_HAVE_HAP_VERIFIER
#define MGOS_SYS_CONFIG_HAVE_HAP_VERIFIER
const char * mgos_config_get_hap_verifier(struct mgos_config *cfg) {
  return cfg->hap.verifier;
}
void mgos_config_set_hap_verifier(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->hap.verifier, v);
}

/* http */
#define MGOS_CONFIG_HAVE_HTTP
#define MGOS_SYS_CONFIG_HAVE_HTTP
const struct mgos_config_http * mgos_config_get_http(struct mgos_config *cfg) {
  return &cfg->http;
}
const struct mgos_conf_entry *mgos_config_schema_http(void) {
  return mgos_conf_find_schema_entry("http", mgos_config_schema());
}
bool mgos_config_parse_http(struct mg_str json, struct mgos_config_http *cfg) {
  return mgos_conf_parse_sub(json, mgos_config_schema(), cfg);
}
bool mgos_config_copy_http(const struct mgos_config_http *src, struct mgos_config_http *dst) {
  return mgos_conf_copy(mgos_config_schema_http(), src, dst);
}
void mgos_config_free_http(struct mgos_config_http *cfg) {
  return mgos_conf_free(mgos_config_schema_http(), cfg);
}

/* http.enable */
#define MGOS_CONFIG_HAVE_HTTP_ENABLE
#define MGOS_SYS_CONFIG_HAVE_HTTP_ENABLE
int mgos_config_get_http_enable(struct mgos_config *cfg) {
  return cfg->http.enable;
}
void mgos_config_set_http_enable(struct mgos_config *cfg, int v) {
  cfg->http.enable = v;
}

/* http.listen_addr */
#define MGOS_CONFIG_HAVE_HTTP_LISTEN_ADDR
#define MGOS_SYS_CONFIG_HAVE_HTTP_LISTEN_ADDR
const char * mgos_config_get_http_listen_addr(struct mgos_config *cfg) {
  return cfg->http.listen_addr;
}
void mgos_config_set_http_listen_addr(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->http.listen_addr, v);
}

/* http.document_root */
#define MGOS_CONFIG_HAVE_HTTP_DOCUMENT_ROOT
#define MGOS_SYS_CONFIG_HAVE_HTTP_DOCUMENT_ROOT
const char * mgos_config_get_http_document_root(struct mgos_config *cfg) {
  return cfg->http.document_root;
}
void mgos_config_set_http_document_root(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->http.document_root, v);
}

/* http.index_files */
#define MGOS_CONFIG_HAVE_HTTP_INDEX_FILES
#define MGOS_SYS_CONFIG_HAVE_HTTP_INDEX_FILES
const char * mgos_config_get_http_index_files(struct mgos_config *cfg) {
  return cfg->http.index_files;
}
void mgos_config_set_http_index_files(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->http.index_files, v);
}

/* http.ssl_cert */
#define MGOS_CONFIG_HAVE_HTTP_SSL_CERT
#define MGOS_SYS_CONFIG_HAVE_HTTP_SSL_CERT
const char * mgos_config_get_http_ssl_cert(struct mgos_config *cfg) {
  return cfg->http.ssl_cert;
}
void mgos_config_set_http_ssl_cert(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->http.ssl_cert, v);
}

/* http.ssl_key */
#define MGOS_CONFIG_HAVE_HTTP_SSL_KEY
#define MGOS_SYS_CONFIG_HAVE_HTTP_SSL_KEY
const char * mgos_config_get_http_ssl_key(struct mgos_config *cfg) {
  return cfg->http.ssl_key;
}
void mgos_config_set_http_ssl_key(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->http.ssl_key, v);
}

/* http.ssl_ca_cert */
#define MGOS_CONFIG_HAVE_HTTP_SSL_CA_CERT
#define MGOS_SYS_CONFIG_HAVE_HTTP_SSL_CA_CERT
const char * mgos_config_get_http_ssl_ca_cert(struct mgos_config *cfg) {
  return cfg->http.ssl_ca_cert;
}
void mgos_config_set_http_ssl_ca_cert(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->http.ssl_ca_cert, v);
}

/* http.upload_acl */
#define MGOS_CONFIG_HAVE_HTTP_UPLOAD_ACL
#define MGOS_SYS_CONFIG_HAVE_HTTP_UPLOAD_ACL
const char * mgos_config_get_http_upload_acl(struct mgos_config *cfg) {
  return cfg->http.upload_acl;
}
void mgos_config_set_http_upload_acl(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->http.upload_acl, v);
}

/* http.hidden_files */
#define MGOS_CONFIG_HAVE_HTTP_HIDDEN_FILES
#define MGOS_SYS_CONFIG_HAVE_HTTP_HIDDEN_FILES
const char * mgos_config_get_http_hidden_files(struct mgos_config *cfg) {
  return cfg->http.hidden_files;
}
void mgos_config_set_http_hidden_files(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->http.hidden_files, v);
}

/* http.auth_domain */
#define MGOS_CONFIG_HAVE_HTTP_AUTH_DOMAIN
#define MGOS_SYS_CONFIG_HAVE_HTTP_AUTH_DOMAIN
const char * mgos_config_get_http_auth_domain(struct mgos_config *cfg) {
  return cfg->http.auth_domain;
}
void mgos_config_set_http_auth_domain(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->http.auth_domain, v);
}

/* http.auth_file */
#define MGOS_CONFIG_HAVE_HTTP_AUTH_FILE
#define MGOS_SYS_CONFIG_HAVE_HTTP_AUTH_FILE
const char * mgos_config_get_http_auth_file(struct mgos_config *cfg) {
  return cfg->http.auth_file;
}
void mgos_config_set_http_auth_file(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->http.auth_file, v);
}

/* update */
#define MGOS_CONFIG_HAVE_UPDATE
#define MGOS_SYS_CONFIG_HAVE_UPDATE
const struct mgos_config_update * mgos_config_get_update(struct mgos_config *cfg) {
  return &cfg->update;
}
const struct mgos_conf_entry *mgos_config_schema_update(void) {
  return mgos_conf_find_schema_entry("update", mgos_config_schema());
}
bool mgos_config_parse_update(struct mg_str json, struct mgos_config_update *cfg) {
  return mgos_conf_parse_sub(json, mgos_config_schema(), cfg);
}
bool mgos_config_copy_update(const struct mgos_config_update *src, struct mgos_config_update *dst) {
  return mgos_conf_copy(mgos_config_schema_update(), src, dst);
}
void mgos_config_free_update(struct mgos_config_update *cfg) {
  return mgos_conf_free(mgos_config_schema_update(), cfg);
}

/* update.timeout */
#define MGOS_CONFIG_HAVE_UPDATE_TIMEOUT
#define MGOS_SYS_CONFIG_HAVE_UPDATE_TIMEOUT
int mgos_config_get_update_timeout(struct mgos_config *cfg) {
  return cfg->update.timeout;
}
void mgos_config_set_update_timeout(struct mgos_config *cfg, int v) {
  cfg->update.timeout = v;
}

/* update.commit_timeout */
#define MGOS_CONFIG_HAVE_UPDATE_COMMIT_TIMEOUT
#define MGOS_SYS_CONFIG_HAVE_UPDATE_COMMIT_TIMEOUT
int mgos_config_get_update_commit_timeout(struct mgos_config *cfg) {
  return cfg->update.commit_timeout;
}
void mgos_config_set_update_commit_timeout(struct mgos_config *cfg, int v) {
  cfg->update.commit_timeout = v;
}

/* update.url */
#define MGOS_CONFIG_HAVE_UPDATE_URL
#define MGOS_SYS_CONFIG_HAVE_UPDATE_URL
const char * mgos_config_get_update_url(struct mgos_config *cfg) {
  return cfg->update.url;
}
void mgos_config_set_update_url(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->update.url, v);
}

/* update.interval */
#define MGOS_CONFIG_HAVE_UPDATE_INTERVAL
#define MGOS_SYS_CONFIG_HAVE_UPDATE_INTERVAL
int mgos_config_get_update_interval(struct mgos_config *cfg) {
  return cfg->update.interval;
}
void mgos_config_set_update_interval(struct mgos_config *cfg, int v) {
  cfg->update.interval = v;
}

/* update.extra_http_headers */
#define MGOS_CONFIG_HAVE_UPDATE_EXTRA_HTTP_HEADERS
#define MGOS_SYS_CONFIG_HAVE_UPDATE_EXTRA_HTTP_HEADERS
const char * mgos_config_get_update_extra_http_headers(struct mgos_config *cfg) {
  return cfg->update.extra_http_headers;
}
void mgos_config_set_update_extra_http_headers(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->update.extra_http_headers, v);
}

/* update.ssl_ca_file */
#define MGOS_CONFIG_HAVE_UPDATE_SSL_CA_FILE
#define MGOS_SYS_CONFIG_HAVE_UPDATE_SSL_CA_FILE
const char * mgos_config_get_update_ssl_ca_file(struct mgos_config *cfg) {
  return cfg->update.ssl_ca_file;
}
void mgos_config_set_update_ssl_ca_file(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->update.ssl_ca_file, v);
}

/* update.ssl_client_cert_file */
#define MGOS_CONFIG_HAVE_UPDATE_SSL_CLIENT_CERT_FILE
#define MGOS_SYS_CONFIG_HAVE_UPDATE_SSL_CLIENT_CERT_FILE
const char * mgos_config_get_update_ssl_client_cert_file(struct mgos_config *cfg) {
  return cfg->update.ssl_client_cert_file;
}
void mgos_config_set_update_ssl_client_cert_file(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->update.ssl_client_cert_file, v);
}

/* update.ssl_server_name */
#define MGOS_CONFIG_HAVE_UPDATE_SSL_SERVER_NAME
#define MGOS_SYS_CONFIG_HAVE_UPDATE_SSL_SERVER_NAME
const char * mgos_config_get_update_ssl_server_name(struct mgos_config *cfg) {
  return cfg->update.ssl_server_name;
}
void mgos_config_set_update_ssl_server_name(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->update.ssl_server_name, v);
}

/* update.enable_post */
#define MGOS_CONFIG_HAVE_UPDATE_ENABLE_POST
#define MGOS_SYS_CONFIG_HAVE_UPDATE_ENABLE_POST
int mgos_config_get_update_enable_post(struct mgos_config *cfg) {
  return cfg->update.enable_post;
}
void mgos_config_set_update_enable_post(struct mgos_config *cfg, int v) {
  cfg->update.enable_post = v;
}

/* rpc */
#define MGOS_CONFIG_HAVE_RPC
#define MGOS_SYS_CONFIG_HAVE_RPC
const struct mgos_config_rpc * mgos_config_get_rpc(struct mgos_config *cfg) {
  return &cfg->rpc;
}
const struct mgos_conf_entry *mgos_config_schema_rpc(void) {
  return mgos_conf_find_schema_entry("rpc", mgos_config_schema());
}
bool mgos_config_parse_rpc(struct mg_str json, struct mgos_config_rpc *cfg) {
  return mgos_conf_parse_sub(json, mgos_config_schema(), cfg);
}
bool mgos_config_copy_rpc(const struct mgos_config_rpc *src, struct mgos_config_rpc *dst) {
  return mgos_conf_copy(mgos_config_schema_rpc(), src, dst);
}
void mgos_config_free_rpc(struct mgos_config_rpc *cfg) {
  return mgos_conf_free(mgos_config_schema_rpc(), cfg);
}

/* rpc.enable */
#define MGOS_CONFIG_HAVE_RPC_ENABLE
#define MGOS_SYS_CONFIG_HAVE_RPC_ENABLE
int mgos_config_get_rpc_enable(struct mgos_config *cfg) {
  return cfg->rpc.enable;
}
void mgos_config_set_rpc_enable(struct mgos_config *cfg, int v) {
  cfg->rpc.enable = v;
}

/* rpc.max_frame_size */
#define MGOS_CONFIG_HAVE_RPC_MAX_FRAME_SIZE
#define MGOS_SYS_CONFIG_HAVE_RPC_MAX_FRAME_SIZE
int mgos_config_get_rpc_max_frame_size(struct mgos_config *cfg) {
  return cfg->rpc.max_frame_size;
}
void mgos_config_set_rpc_max_frame_size(struct mgos_config *cfg, int v) {
  cfg->rpc.max_frame_size = v;
}

/* rpc.max_queue_length */
#define MGOS_CONFIG_HAVE_RPC_MAX_QUEUE_LENGTH
#define MGOS_SYS_CONFIG_HAVE_RPC_MAX_QUEUE_LENGTH
int mgos_config_get_rpc_max_queue_length(struct mgos_config *cfg) {
  return cfg->rpc.max_queue_length;
}
void mgos_config_set_rpc_max_queue_length(struct mgos_config *cfg, int v) {
  cfg->rpc.max_queue_length = v;
}

/* rpc.default_out_channel_idle_close_timeout */
#define MGOS_CONFIG_HAVE_RPC_DEFAULT_OUT_CHANNEL_IDLE_CLOSE_TIMEOUT
#define MGOS_SYS_CONFIG_HAVE_RPC_DEFAULT_OUT_CHANNEL_IDLE_CLOSE_TIMEOUT
int mgos_config_get_rpc_default_out_channel_idle_close_timeout(struct mgos_config *cfg) {
  return cfg->rpc.default_out_channel_idle_close_timeout;
}
void mgos_config_set_rpc_default_out_channel_idle_close_timeout(struct mgos_config *cfg, int v) {
  cfg->rpc.default_out_channel_idle_close_timeout = v;
}

/* rpc.acl_file */
#define MGOS_CONFIG_HAVE_RPC_ACL_FILE
#define MGOS_SYS_CONFIG_HAVE_RPC_ACL_FILE
const char * mgos_config_get_rpc_acl_file(struct mgos_config *cfg) {
  return cfg->rpc.acl_file;
}
void mgos_config_set_rpc_acl_file(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->rpc.acl_file, v);
}

/* rpc.auth_domain */
#define MGOS_CONFIG_HAVE_RPC_AUTH_DOMAIN
#define MGOS_SYS_CONFIG_HAVE_RPC_AUTH_DOMAIN
const char * mgos_config_get_rpc_auth_domain(struct mgos_config *cfg) {
  return cfg->rpc.auth_domain;
}
void mgos_config_set_rpc_auth_domain(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->rpc.auth_domain, v);
}

/* rpc.auth_file */
#define MGOS_CONFIG_HAVE_RPC_AUTH_FILE
#define MGOS_SYS_CONFIG_HAVE_RPC_AUTH_FILE
const char * mgos_config_get_rpc_auth_file(struct mgos_config *cfg) {
  return cfg->rpc.auth_file;
}
void mgos_config_set_rpc_auth_file(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->rpc.auth_file, v);
}

/* rpc.uart */
#define MGOS_CONFIG_HAVE_RPC_UART
#define MGOS_SYS_CONFIG_HAVE_RPC_UART
const struct mgos_config_rpc_uart * mgos_config_get_rpc_uart(struct mgos_config *cfg) {
  return &cfg->rpc.uart;
}
const struct mgos_conf_entry *mgos_config_schema_rpc_uart(void) {
  return mgos_conf_find_schema_entry("rpc.uart", mgos_config_schema());
}
bool mgos_config_parse_rpc_uart(struct mg_str json, struct mgos_config_rpc_uart *cfg) {
  return mgos_conf_parse_sub(json, mgos_config_schema(), cfg);
}
bool mgos_config_copy_rpc_uart(const struct mgos_config_rpc_uart *src, struct mgos_config_rpc_uart *dst) {
  return mgos_conf_copy(mgos_config_schema_rpc_uart(), src, dst);
}
void mgos_config_free_rpc_uart(struct mgos_config_rpc_uart *cfg) {
  return mgos_conf_free(mgos_config_schema_rpc_uart(), cfg);
}

/* rpc.uart.uart_no */
#define MGOS_CONFIG_HAVE_RPC_UART_UART_NO
#define MGOS_SYS_CONFIG_HAVE_RPC_UART_UART_NO
int mgos_config_get_rpc_uart_uart_no(struct mgos_config *cfg) {
  return cfg->rpc.uart.uart_no;
}
void mgos_config_set_rpc_uart_uart_no(struct mgos_config *cfg, int v) {
  cfg->rpc.uart.uart_no = v;
}

/* rpc.uart.baud_rate */
#define MGOS_CONFIG_HAVE_RPC_UART_BAUD_RATE
#define MGOS_SYS_CONFIG_HAVE_RPC_UART_BAUD_RATE
int mgos_config_get_rpc_uart_baud_rate(struct mgos_config *cfg) {
  return cfg->rpc.uart.baud_rate;
}
void mgos_config_set_rpc_uart_baud_rate(struct mgos_config *cfg, int v) {
  cfg->rpc.uart.baud_rate = v;
}

/* rpc.uart.fc_type */
#define MGOS_CONFIG_HAVE_RPC_UART_FC_TYPE
#define MGOS_SYS_CONFIG_HAVE_RPC_UART_FC_TYPE
int mgos_config_get_rpc_uart_fc_type(struct mgos_config *cfg) {
  return cfg->rpc.uart.fc_type;
}
void mgos_config_set_rpc_uart_fc_type(struct mgos_config *cfg, int v) {
  cfg->rpc.uart.fc_type = v;
}

/* rpc.uart.dst */
#define MGOS_CONFIG_HAVE_RPC_UART_DST
#define MGOS_SYS_CONFIG_HAVE_RPC_UART_DST
const char * mgos_config_get_rpc_uart_dst(struct mgos_config *cfg) {
  return cfg->rpc.uart.dst;
}
void mgos_config_set_rpc_uart_dst(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->rpc.uart.dst, v);
}

/* rpc.ws */
#define MGOS_CONFIG_HAVE_RPC_WS
#define MGOS_SYS_CONFIG_HAVE_RPC_WS
const struct mgos_config_rpc_ws * mgos_config_get_rpc_ws(struct mgos_config *cfg) {
  return &cfg->rpc.ws;
}
const struct mgos_conf_entry *mgos_config_schema_rpc_ws(void) {
  return mgos_conf_find_schema_entry("rpc.ws", mgos_config_schema());
}
bool mgos_config_parse_rpc_ws(struct mg_str json, struct mgos_config_rpc_ws *cfg) {
  return mgos_conf_parse_sub(json, mgos_config_schema(), cfg);
}
bool mgos_config_copy_rpc_ws(const struct mgos_config_rpc_ws *src, struct mgos_config_rpc_ws *dst) {
  return mgos_conf_copy(mgos_config_schema_rpc_ws(), src, dst);
}
void mgos_config_free_rpc_ws(struct mgos_config_rpc_ws *cfg) {
  return mgos_conf_free(mgos_config_schema_rpc_ws(), cfg);
}

/* rpc.ws.enable */
#define MGOS_CONFIG_HAVE_RPC_WS_ENABLE
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_ENABLE
int mgos_config_get_rpc_ws_enable(struct mgos_config *cfg) {
  return cfg->rpc.ws.enable;
}
void mgos_config_set_rpc_ws_enable(struct mgos_config *cfg, int v) {
  cfg->rpc.ws.enable = v;
}

/* rpc.ws.server_address */
#define MGOS_CONFIG_HAVE_RPC_WS_SERVER_ADDRESS
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_SERVER_ADDRESS
const char * mgos_config_get_rpc_ws_server_address(struct mgos_config *cfg) {
  return cfg->rpc.ws.server_address;
}
void mgos_config_set_rpc_ws_server_address(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->rpc.ws.server_address, v);
}

/* rpc.ws.reconnect_interval_min */
#define MGOS_CONFIG_HAVE_RPC_WS_RECONNECT_INTERVAL_MIN
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_RECONNECT_INTERVAL_MIN
int mgos_config_get_rpc_ws_reconnect_interval_min(struct mgos_config *cfg) {
  return cfg->rpc.ws.reconnect_interval_min;
}
void mgos_config_set_rpc_ws_reconnect_interval_min(struct mgos_config *cfg, int v) {
  cfg->rpc.ws.reconnect_interval_min = v;
}

/* rpc.ws.reconnect_interval_max */
#define MGOS_CONFIG_HAVE_RPC_WS_RECONNECT_INTERVAL_MAX
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_RECONNECT_INTERVAL_MAX
int mgos_config_get_rpc_ws_reconnect_interval_max(struct mgos_config *cfg) {
  return cfg->rpc.ws.reconnect_interval_max;
}
void mgos_config_set_rpc_ws_reconnect_interval_max(struct mgos_config *cfg, int v) {
  cfg->rpc.ws.reconnect_interval_max = v;
}

/* rpc.ws.ssl_server_name */
#define MGOS_CONFIG_HAVE_RPC_WS_SSL_SERVER_NAME
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_SSL_SERVER_NAME
const char * mgos_config_get_rpc_ws_ssl_server_name(struct mgos_config *cfg) {
  return cfg->rpc.ws.ssl_server_name;
}
void mgos_config_set_rpc_ws_ssl_server_name(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->rpc.ws.ssl_server_name, v);
}

/* rpc.ws.ssl_cert */
#define MGOS_CONFIG_HAVE_RPC_WS_SSL_CERT
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_SSL_CERT
const char * mgos_config_get_rpc_ws_ssl_cert(struct mgos_config *cfg) {
  return cfg->rpc.ws.ssl_cert;
}
void mgos_config_set_rpc_ws_ssl_cert(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->rpc.ws.ssl_cert, v);
}

/* rpc.ws.ssl_key */
#define MGOS_CONFIG_HAVE_RPC_WS_SSL_KEY
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_SSL_KEY
const char * mgos_config_get_rpc_ws_ssl_key(struct mgos_config *cfg) {
  return cfg->rpc.ws.ssl_key;
}
void mgos_config_set_rpc_ws_ssl_key(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->rpc.ws.ssl_key, v);
}

/* rpc.ws.ssl_ca_cert */
#define MGOS_CONFIG_HAVE_RPC_WS_SSL_CA_CERT
#define MGOS_SYS_CONFIG_HAVE_RPC_WS_SSL_CA_CERT
const char * mgos_config_get_rpc_ws_ssl_ca_cert(struct mgos_config *cfg) {
  return cfg->rpc.ws.ssl_ca_cert;
}
void mgos_config_set_rpc_ws_ssl_ca_cert(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->rpc.ws.ssl_ca_cert, v);
}

/* wifi */
#define MGOS_CONFIG_HAVE_WIFI
#define MGOS_SYS_CONFIG_HAVE_WIFI
const struct mgos_config_wifi * mgos_config_get_wifi(struct mgos_config *cfg) {
  return &cfg->wifi;
}
const struct mgos_conf_entry *mgos_config_schema_wifi(void) {
  return mgos_conf_find_schema_entry("wifi", mgos_config_schema());
}
bool mgos_config_parse_wifi(struct mg_str json, struct mgos_config_wifi *cfg) {
  return mgos_conf_parse_sub(json, mgos_config_schema(), cfg);
}
bool mgos_config_copy_wifi(const struct mgos_config_wifi *src, struct mgos_config_wifi *dst) {
  return mgos_conf_copy(mgos_config_schema_wifi(), src, dst);
}
void mgos_config_free_wifi(struct mgos_config_wifi *cfg) {
  return mgos_conf_free(mgos_config_schema_wifi(), cfg);
}

/* wifi.ap */
#define MGOS_CONFIG_HAVE_WIFI_AP
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP
const struct mgos_config_wifi_ap * mgos_config_get_wifi_ap(struct mgos_config *cfg) {
  return &cfg->wifi.ap;
}
const struct mgos_conf_entry *mgos_config_schema_wifi_ap(void) {
  return mgos_conf_find_schema_entry("wifi.ap", mgos_config_schema());
}
bool mgos_config_parse_wifi_ap(struct mg_str json, struct mgos_config_wifi_ap *cfg) {
  return mgos_conf_parse_sub(json, mgos_config_schema(), cfg);
}
bool mgos_config_copy_wifi_ap(const struct mgos_config_wifi_ap *src, struct mgos_config_wifi_ap *dst) {
  return mgos_conf_copy(mgos_config_schema_wifi_ap(), src, dst);
}
void mgos_config_free_wifi_ap(struct mgos_config_wifi_ap *cfg) {
  return mgos_conf_free(mgos_config_schema_wifi_ap(), cfg);
}

/* wifi.ap.enable */
#define MGOS_CONFIG_HAVE_WIFI_AP_ENABLE
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_ENABLE
int mgos_config_get_wifi_ap_enable(struct mgos_config *cfg) {
  return cfg->wifi.ap.enable;
}
void mgos_config_set_wifi_ap_enable(struct mgos_config *cfg, int v) {
  cfg->wifi.ap.enable = v;
}

/* wifi.ap.ssid */
#define MGOS_CONFIG_HAVE_WIFI_AP_SSID
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_SSID
const char * mgos_config_get_wifi_ap_ssid(struct mgos_config *cfg) {
  return cfg->wifi.ap.ssid;
}
void mgos_config_set_wifi_ap_ssid(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.ap.ssid, v);
}

/* wifi.ap.pass */
#define MGOS_CONFIG_HAVE_WIFI_AP_PASS
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_PASS
const char * mgos_config_get_wifi_ap_pass(struct mgos_config *cfg) {
  return cfg->wifi.ap.pass;
}
void mgos_config_set_wifi_ap_pass(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.ap.pass, v);
}

/* wifi.ap.hidden */
#define MGOS_CONFIG_HAVE_WIFI_AP_HIDDEN
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_HIDDEN
int mgos_config_get_wifi_ap_hidden(struct mgos_config *cfg) {
  return cfg->wifi.ap.hidden;
}
void mgos_config_set_wifi_ap_hidden(struct mgos_config *cfg, int v) {
  cfg->wifi.ap.hidden = v;
}

/* wifi.ap.channel */
#define MGOS_CONFIG_HAVE_WIFI_AP_CHANNEL
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_CHANNEL
int mgos_config_get_wifi_ap_channel(struct mgos_config *cfg) {
  return cfg->wifi.ap.channel;
}
void mgos_config_set_wifi_ap_channel(struct mgos_config *cfg, int v) {
  cfg->wifi.ap.channel = v;
}

/* wifi.ap.max_connections */
#define MGOS_CONFIG_HAVE_WIFI_AP_MAX_CONNECTIONS
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_MAX_CONNECTIONS
int mgos_config_get_wifi_ap_max_connections(struct mgos_config *cfg) {
  return cfg->wifi.ap.max_connections;
}
void mgos_config_set_wifi_ap_max_connections(struct mgos_config *cfg, int v) {
  cfg->wifi.ap.max_connections = v;
}

/* wifi.ap.ip */
#define MGOS_CONFIG_HAVE_WIFI_AP_IP
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_IP
const char * mgos_config_get_wifi_ap_ip(struct mgos_config *cfg) {
  return cfg->wifi.ap.ip;
}
void mgos_config_set_wifi_ap_ip(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.ap.ip, v);
}

/* wifi.ap.netmask */
#define MGOS_CONFIG_HAVE_WIFI_AP_NETMASK
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_NETMASK
const char * mgos_config_get_wifi_ap_netmask(struct mgos_config *cfg) {
  return cfg->wifi.ap.netmask;
}
void mgos_config_set_wifi_ap_netmask(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.ap.netmask, v);
}

/* wifi.ap.gw */
#define MGOS_CONFIG_HAVE_WIFI_AP_GW
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_GW
const char * mgos_config_get_wifi_ap_gw(struct mgos_config *cfg) {
  return cfg->wifi.ap.gw;
}
void mgos_config_set_wifi_ap_gw(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.ap.gw, v);
}

/* wifi.ap.dhcp_start */
#define MGOS_CONFIG_HAVE_WIFI_AP_DHCP_START
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_DHCP_START
const char * mgos_config_get_wifi_ap_dhcp_start(struct mgos_config *cfg) {
  return cfg->wifi.ap.dhcp_start;
}
void mgos_config_set_wifi_ap_dhcp_start(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.ap.dhcp_start, v);
}

/* wifi.ap.dhcp_end */
#define MGOS_CONFIG_HAVE_WIFI_AP_DHCP_END
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_DHCP_END
const char * mgos_config_get_wifi_ap_dhcp_end(struct mgos_config *cfg) {
  return cfg->wifi.ap.dhcp_end;
}
void mgos_config_set_wifi_ap_dhcp_end(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.ap.dhcp_end, v);
}

/* wifi.ap.trigger_on_gpio */
#define MGOS_CONFIG_HAVE_WIFI_AP_TRIGGER_ON_GPIO
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_TRIGGER_ON_GPIO
int mgos_config_get_wifi_ap_trigger_on_gpio(struct mgos_config *cfg) {
  return cfg->wifi.ap.trigger_on_gpio;
}
void mgos_config_set_wifi_ap_trigger_on_gpio(struct mgos_config *cfg, int v) {
  cfg->wifi.ap.trigger_on_gpio = v;
}

/* wifi.ap.disable_after */
#define MGOS_CONFIG_HAVE_WIFI_AP_DISABLE_AFTER
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_DISABLE_AFTER
int mgos_config_get_wifi_ap_disable_after(struct mgos_config *cfg) {
  return cfg->wifi.ap.disable_after;
}
void mgos_config_set_wifi_ap_disable_after(struct mgos_config *cfg, int v) {
  cfg->wifi.ap.disable_after = v;
}

/* wifi.ap.hostname */
#define MGOS_CONFIG_HAVE_WIFI_AP_HOSTNAME
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_HOSTNAME
const char * mgos_config_get_wifi_ap_hostname(struct mgos_config *cfg) {
  return cfg->wifi.ap.hostname;
}
void mgos_config_set_wifi_ap_hostname(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.ap.hostname, v);
}

/* wifi.ap.keep_enabled */
#define MGOS_CONFIG_HAVE_WIFI_AP_KEEP_ENABLED
#define MGOS_SYS_CONFIG_HAVE_WIFI_AP_KEEP_ENABLED
int mgos_config_get_wifi_ap_keep_enabled(struct mgos_config *cfg) {
  return cfg->wifi.ap.keep_enabled;
}
void mgos_config_set_wifi_ap_keep_enabled(struct mgos_config *cfg, int v) {
  cfg->wifi.ap.keep_enabled = v;
}

/* wifi.sta */
#define MGOS_CONFIG_HAVE_WIFI_STA
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA
const struct mgos_config_wifi_sta * mgos_config_get_wifi_sta(struct mgos_config *cfg) {
  return &cfg->wifi.sta;
}
const struct mgos_conf_entry *mgos_config_schema_wifi_sta(void) {
  return mgos_conf_find_schema_entry("wifi.sta", mgos_config_schema());
}
bool mgos_config_parse_wifi_sta(struct mg_str json, struct mgos_config_wifi_sta *cfg) {
  return mgos_conf_parse_sub(json, mgos_config_schema(), cfg);
}
bool mgos_config_copy_wifi_sta(const struct mgos_config_wifi_sta *src, struct mgos_config_wifi_sta *dst) {
  return mgos_conf_copy(mgos_config_schema_wifi_sta(), src, dst);
}
void mgos_config_free_wifi_sta(struct mgos_config_wifi_sta *cfg) {
  return mgos_conf_free(mgos_config_schema_wifi_sta(), cfg);
}

/* wifi.sta.enable */
#define MGOS_CONFIG_HAVE_WIFI_STA_ENABLE
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_ENABLE
int mgos_config_get_wifi_sta_enable(struct mgos_config *cfg) {
  return cfg->wifi.sta.enable;
}
void mgos_config_set_wifi_sta_enable(struct mgos_config *cfg, int v) {
  cfg->wifi.sta.enable = v;
}

/* wifi.sta.ssid */
#define MGOS_CONFIG_HAVE_WIFI_STA_SSID
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_SSID
const char * mgos_config_get_wifi_sta_ssid(struct mgos_config *cfg) {
  return cfg->wifi.sta.ssid;
}
void mgos_config_set_wifi_sta_ssid(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta.ssid, v);
}

/* wifi.sta.pass */
#define MGOS_CONFIG_HAVE_WIFI_STA_PASS
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_PASS
const char * mgos_config_get_wifi_sta_pass(struct mgos_config *cfg) {
  return cfg->wifi.sta.pass;
}
void mgos_config_set_wifi_sta_pass(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta.pass, v);
}

/* wifi.sta.user */
#define MGOS_CONFIG_HAVE_WIFI_STA_USER
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_USER
const char * mgos_config_get_wifi_sta_user(struct mgos_config *cfg) {
  return cfg->wifi.sta.user;
}
void mgos_config_set_wifi_sta_user(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta.user, v);
}

/* wifi.sta.anon_identity */
#define MGOS_CONFIG_HAVE_WIFI_STA_ANON_IDENTITY
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_ANON_IDENTITY
const char * mgos_config_get_wifi_sta_anon_identity(struct mgos_config *cfg) {
  return cfg->wifi.sta.anon_identity;
}
void mgos_config_set_wifi_sta_anon_identity(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta.anon_identity, v);
}

/* wifi.sta.cert */
#define MGOS_CONFIG_HAVE_WIFI_STA_CERT
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_CERT
const char * mgos_config_get_wifi_sta_cert(struct mgos_config *cfg) {
  return cfg->wifi.sta.cert;
}
void mgos_config_set_wifi_sta_cert(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta.cert, v);
}

/* wifi.sta.key */
#define MGOS_CONFIG_HAVE_WIFI_STA_KEY
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_KEY
const char * mgos_config_get_wifi_sta_key(struct mgos_config *cfg) {
  return cfg->wifi.sta.key;
}
void mgos_config_set_wifi_sta_key(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta.key, v);
}

/* wifi.sta.ca_cert */
#define MGOS_CONFIG_HAVE_WIFI_STA_CA_CERT
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_CA_CERT
const char * mgos_config_get_wifi_sta_ca_cert(struct mgos_config *cfg) {
  return cfg->wifi.sta.ca_cert;
}
void mgos_config_set_wifi_sta_ca_cert(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta.ca_cert, v);
}

/* wifi.sta.ip */
#define MGOS_CONFIG_HAVE_WIFI_STA_IP
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_IP
const char * mgos_config_get_wifi_sta_ip(struct mgos_config *cfg) {
  return cfg->wifi.sta.ip;
}
void mgos_config_set_wifi_sta_ip(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta.ip, v);
}

/* wifi.sta.netmask */
#define MGOS_CONFIG_HAVE_WIFI_STA_NETMASK
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_NETMASK
const char * mgos_config_get_wifi_sta_netmask(struct mgos_config *cfg) {
  return cfg->wifi.sta.netmask;
}
void mgos_config_set_wifi_sta_netmask(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta.netmask, v);
}

/* wifi.sta.gw */
#define MGOS_CONFIG_HAVE_WIFI_STA_GW
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_GW
const char * mgos_config_get_wifi_sta_gw(struct mgos_config *cfg) {
  return cfg->wifi.sta.gw;
}
void mgos_config_set_wifi_sta_gw(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta.gw, v);
}

/* wifi.sta.nameserver */
#define MGOS_CONFIG_HAVE_WIFI_STA_NAMESERVER
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_NAMESERVER
const char * mgos_config_get_wifi_sta_nameserver(struct mgos_config *cfg) {
  return cfg->wifi.sta.nameserver;
}
void mgos_config_set_wifi_sta_nameserver(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta.nameserver, v);
}

/* wifi.sta.dhcp_hostname */
#define MGOS_CONFIG_HAVE_WIFI_STA_DHCP_HOSTNAME
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_DHCP_HOSTNAME
const char * mgos_config_get_wifi_sta_dhcp_hostname(struct mgos_config *cfg) {
  return cfg->wifi.sta.dhcp_hostname;
}
void mgos_config_set_wifi_sta_dhcp_hostname(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta.dhcp_hostname, v);
}

/* wifi.sta1 */
#define MGOS_CONFIG_HAVE_WIFI_STA1
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1
const struct mgos_config_wifi_sta * mgos_config_get_wifi_sta1(struct mgos_config *cfg) {
  return &cfg->wifi.sta1;
}

/* wifi.sta1.enable */
#define MGOS_CONFIG_HAVE_WIFI_STA1_ENABLE
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_ENABLE
int mgos_config_get_wifi_sta1_enable(struct mgos_config *cfg) {
  return cfg->wifi.sta1.enable;
}
void mgos_config_set_wifi_sta1_enable(struct mgos_config *cfg, int v) {
  cfg->wifi.sta1.enable = v;
}

/* wifi.sta1.ssid */
#define MGOS_CONFIG_HAVE_WIFI_STA1_SSID
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_SSID
const char * mgos_config_get_wifi_sta1_ssid(struct mgos_config *cfg) {
  return cfg->wifi.sta1.ssid;
}
void mgos_config_set_wifi_sta1_ssid(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta1.ssid, v);
}

/* wifi.sta1.pass */
#define MGOS_CONFIG_HAVE_WIFI_STA1_PASS
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_PASS
const char * mgos_config_get_wifi_sta1_pass(struct mgos_config *cfg) {
  return cfg->wifi.sta1.pass;
}
void mgos_config_set_wifi_sta1_pass(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta1.pass, v);
}

/* wifi.sta1.user */
#define MGOS_CONFIG_HAVE_WIFI_STA1_USER
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_USER
const char * mgos_config_get_wifi_sta1_user(struct mgos_config *cfg) {
  return cfg->wifi.sta1.user;
}
void mgos_config_set_wifi_sta1_user(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta1.user, v);
}

/* wifi.sta1.anon_identity */
#define MGOS_CONFIG_HAVE_WIFI_STA1_ANON_IDENTITY
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_ANON_IDENTITY
const char * mgos_config_get_wifi_sta1_anon_identity(struct mgos_config *cfg) {
  return cfg->wifi.sta1.anon_identity;
}
void mgos_config_set_wifi_sta1_anon_identity(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta1.anon_identity, v);
}

/* wifi.sta1.cert */
#define MGOS_CONFIG_HAVE_WIFI_STA1_CERT
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_CERT
const char * mgos_config_get_wifi_sta1_cert(struct mgos_config *cfg) {
  return cfg->wifi.sta1.cert;
}
void mgos_config_set_wifi_sta1_cert(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta1.cert, v);
}

/* wifi.sta1.key */
#define MGOS_CONFIG_HAVE_WIFI_STA1_KEY
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_KEY
const char * mgos_config_get_wifi_sta1_key(struct mgos_config *cfg) {
  return cfg->wifi.sta1.key;
}
void mgos_config_set_wifi_sta1_key(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta1.key, v);
}

/* wifi.sta1.ca_cert */
#define MGOS_CONFIG_HAVE_WIFI_STA1_CA_CERT
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_CA_CERT
const char * mgos_config_get_wifi_sta1_ca_cert(struct mgos_config *cfg) {
  return cfg->wifi.sta1.ca_cert;
}
void mgos_config_set_wifi_sta1_ca_cert(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta1.ca_cert, v);
}

/* wifi.sta1.ip */
#define MGOS_CONFIG_HAVE_WIFI_STA1_IP
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_IP
const char * mgos_config_get_wifi_sta1_ip(struct mgos_config *cfg) {
  return cfg->wifi.sta1.ip;
}
void mgos_config_set_wifi_sta1_ip(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta1.ip, v);
}

/* wifi.sta1.netmask */
#define MGOS_CONFIG_HAVE_WIFI_STA1_NETMASK
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_NETMASK
const char * mgos_config_get_wifi_sta1_netmask(struct mgos_config *cfg) {
  return cfg->wifi.sta1.netmask;
}
void mgos_config_set_wifi_sta1_netmask(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta1.netmask, v);
}

/* wifi.sta1.gw */
#define MGOS_CONFIG_HAVE_WIFI_STA1_GW
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_GW
const char * mgos_config_get_wifi_sta1_gw(struct mgos_config *cfg) {
  return cfg->wifi.sta1.gw;
}
void mgos_config_set_wifi_sta1_gw(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta1.gw, v);
}

/* wifi.sta1.nameserver */
#define MGOS_CONFIG_HAVE_WIFI_STA1_NAMESERVER
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_NAMESERVER
const char * mgos_config_get_wifi_sta1_nameserver(struct mgos_config *cfg) {
  return cfg->wifi.sta1.nameserver;
}
void mgos_config_set_wifi_sta1_nameserver(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta1.nameserver, v);
}

/* wifi.sta1.dhcp_hostname */
#define MGOS_CONFIG_HAVE_WIFI_STA1_DHCP_HOSTNAME
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA1_DHCP_HOSTNAME
const char * mgos_config_get_wifi_sta1_dhcp_hostname(struct mgos_config *cfg) {
  return cfg->wifi.sta1.dhcp_hostname;
}
void mgos_config_set_wifi_sta1_dhcp_hostname(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta1.dhcp_hostname, v);
}

/* wifi.sta2 */
#define MGOS_CONFIG_HAVE_WIFI_STA2
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2
const struct mgos_config_wifi_sta * mgos_config_get_wifi_sta2(struct mgos_config *cfg) {
  return &cfg->wifi.sta2;
}

/* wifi.sta2.enable */
#define MGOS_CONFIG_HAVE_WIFI_STA2_ENABLE
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_ENABLE
int mgos_config_get_wifi_sta2_enable(struct mgos_config *cfg) {
  return cfg->wifi.sta2.enable;
}
void mgos_config_set_wifi_sta2_enable(struct mgos_config *cfg, int v) {
  cfg->wifi.sta2.enable = v;
}

/* wifi.sta2.ssid */
#define MGOS_CONFIG_HAVE_WIFI_STA2_SSID
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_SSID
const char * mgos_config_get_wifi_sta2_ssid(struct mgos_config *cfg) {
  return cfg->wifi.sta2.ssid;
}
void mgos_config_set_wifi_sta2_ssid(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta2.ssid, v);
}

/* wifi.sta2.pass */
#define MGOS_CONFIG_HAVE_WIFI_STA2_PASS
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_PASS
const char * mgos_config_get_wifi_sta2_pass(struct mgos_config *cfg) {
  return cfg->wifi.sta2.pass;
}
void mgos_config_set_wifi_sta2_pass(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta2.pass, v);
}

/* wifi.sta2.user */
#define MGOS_CONFIG_HAVE_WIFI_STA2_USER
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_USER
const char * mgos_config_get_wifi_sta2_user(struct mgos_config *cfg) {
  return cfg->wifi.sta2.user;
}
void mgos_config_set_wifi_sta2_user(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta2.user, v);
}

/* wifi.sta2.anon_identity */
#define MGOS_CONFIG_HAVE_WIFI_STA2_ANON_IDENTITY
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_ANON_IDENTITY
const char * mgos_config_get_wifi_sta2_anon_identity(struct mgos_config *cfg) {
  return cfg->wifi.sta2.anon_identity;
}
void mgos_config_set_wifi_sta2_anon_identity(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta2.anon_identity, v);
}

/* wifi.sta2.cert */
#define MGOS_CONFIG_HAVE_WIFI_STA2_CERT
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_CERT
const char * mgos_config_get_wifi_sta2_cert(struct mgos_config *cfg) {
  return cfg->wifi.sta2.cert;
}
void mgos_config_set_wifi_sta2_cert(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta2.cert, v);
}

/* wifi.sta2.key */
#define MGOS_CONFIG_HAVE_WIFI_STA2_KEY
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_KEY
const char * mgos_config_get_wifi_sta2_key(struct mgos_config *cfg) {
  return cfg->wifi.sta2.key;
}
void mgos_config_set_wifi_sta2_key(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta2.key, v);
}

/* wifi.sta2.ca_cert */
#define MGOS_CONFIG_HAVE_WIFI_STA2_CA_CERT
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_CA_CERT
const char * mgos_config_get_wifi_sta2_ca_cert(struct mgos_config *cfg) {
  return cfg->wifi.sta2.ca_cert;
}
void mgos_config_set_wifi_sta2_ca_cert(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta2.ca_cert, v);
}

/* wifi.sta2.ip */
#define MGOS_CONFIG_HAVE_WIFI_STA2_IP
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_IP
const char * mgos_config_get_wifi_sta2_ip(struct mgos_config *cfg) {
  return cfg->wifi.sta2.ip;
}
void mgos_config_set_wifi_sta2_ip(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta2.ip, v);
}

/* wifi.sta2.netmask */
#define MGOS_CONFIG_HAVE_WIFI_STA2_NETMASK
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_NETMASK
const char * mgos_config_get_wifi_sta2_netmask(struct mgos_config *cfg) {
  return cfg->wifi.sta2.netmask;
}
void mgos_config_set_wifi_sta2_netmask(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta2.netmask, v);
}

/* wifi.sta2.gw */
#define MGOS_CONFIG_HAVE_WIFI_STA2_GW
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_GW
const char * mgos_config_get_wifi_sta2_gw(struct mgos_config *cfg) {
  return cfg->wifi.sta2.gw;
}
void mgos_config_set_wifi_sta2_gw(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta2.gw, v);
}

/* wifi.sta2.nameserver */
#define MGOS_CONFIG_HAVE_WIFI_STA2_NAMESERVER
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_NAMESERVER
const char * mgos_config_get_wifi_sta2_nameserver(struct mgos_config *cfg) {
  return cfg->wifi.sta2.nameserver;
}
void mgos_config_set_wifi_sta2_nameserver(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta2.nameserver, v);
}

/* wifi.sta2.dhcp_hostname */
#define MGOS_CONFIG_HAVE_WIFI_STA2_DHCP_HOSTNAME
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA2_DHCP_HOSTNAME
const char * mgos_config_get_wifi_sta2_dhcp_hostname(struct mgos_config *cfg) {
  return cfg->wifi.sta2.dhcp_hostname;
}
void mgos_config_set_wifi_sta2_dhcp_hostname(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->wifi.sta2.dhcp_hostname, v);
}

/* wifi.sta_cfg_idx */
#define MGOS_CONFIG_HAVE_WIFI_STA_CFG_IDX
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_CFG_IDX
int mgos_config_get_wifi_sta_cfg_idx(struct mgos_config *cfg) {
  return cfg->wifi.sta_cfg_idx;
}
void mgos_config_set_wifi_sta_cfg_idx(struct mgos_config *cfg, int v) {
  cfg->wifi.sta_cfg_idx = v;
}

/* wifi.sta_connect_timeout */
#define MGOS_CONFIG_HAVE_WIFI_STA_CONNECT_TIMEOUT
#define MGOS_SYS_CONFIG_HAVE_WIFI_STA_CONNECT_TIMEOUT
int mgos_config_get_wifi_sta_connect_timeout(struct mgos_config *cfg) {
  return cfg->wifi.sta_connect_timeout;
}
void mgos_config_set_wifi_sta_connect_timeout(struct mgos_config *cfg, int v) {
  cfg->wifi.sta_connect_timeout = v;
}

/* sw */
#define MGOS_CONFIG_HAVE_SW
#define MGOS_SYS_CONFIG_HAVE_SW
const struct mgos_config_sw * mgos_config_get_sw(struct mgos_config *cfg) {
  return &cfg->sw;
}
const struct mgos_conf_entry *mgos_config_schema_sw(void) {
  return mgos_conf_find_schema_entry("sw", mgos_config_schema());
}
bool mgos_config_parse_sw(struct mg_str json, struct mgos_config_sw *cfg) {
  return mgos_conf_parse_sub(json, mgos_config_schema(), cfg);
}
bool mgos_config_copy_sw(const struct mgos_config_sw *src, struct mgos_config_sw *dst) {
  return mgos_conf_copy(mgos_config_schema_sw(), src, dst);
}
void mgos_config_free_sw(struct mgos_config_sw *cfg) {
  return mgos_conf_free(mgos_config_schema_sw(), cfg);
}

/* sw.id */
#define MGOS_CONFIG_HAVE_SW_ID
#define MGOS_SYS_CONFIG_HAVE_SW_ID
int mgos_config_get_sw_id(struct mgos_config *cfg) {
  return cfg->sw.id;
}
void mgos_config_set_sw_id(struct mgos_config *cfg, int v) {
  cfg->sw.id = v;
}

/* sw.name */
#define MGOS_CONFIG_HAVE_SW_NAME
#define MGOS_SYS_CONFIG_HAVE_SW_NAME
const char * mgos_config_get_sw_name(struct mgos_config *cfg) {
  return cfg->sw.name;
}
void mgos_config_set_sw_name(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->sw.name, v);
}

/* sw.enable */
#define MGOS_CONFIG_HAVE_SW_ENABLE
#define MGOS_SYS_CONFIG_HAVE_SW_ENABLE
int mgos_config_get_sw_enable(struct mgos_config *cfg) {
  return cfg->sw.enable;
}
void mgos_config_set_sw_enable(struct mgos_config *cfg, int v) {
  cfg->sw.enable = v;
}

/* sw.out_gpio */
#define MGOS_CONFIG_HAVE_SW_OUT_GPIO
#define MGOS_SYS_CONFIG_HAVE_SW_OUT_GPIO
int mgos_config_get_sw_out_gpio(struct mgos_config *cfg) {
  return cfg->sw.out_gpio;
}
void mgos_config_set_sw_out_gpio(struct mgos_config *cfg, int v) {
  cfg->sw.out_gpio = v;
}

/* sw.out_on_value */
#define MGOS_CONFIG_HAVE_SW_OUT_ON_VALUE
#define MGOS_SYS_CONFIG_HAVE_SW_OUT_ON_VALUE
int mgos_config_get_sw_out_on_value(struct mgos_config *cfg) {
  return cfg->sw.out_on_value;
}
void mgos_config_set_sw_out_on_value(struct mgos_config *cfg, int v) {
  cfg->sw.out_on_value = v;
}

/* sw.in_gpio */
#define MGOS_CONFIG_HAVE_SW_IN_GPIO
#define MGOS_SYS_CONFIG_HAVE_SW_IN_GPIO
int mgos_config_get_sw_in_gpio(struct mgos_config *cfg) {
  return cfg->sw.in_gpio;
}
void mgos_config_set_sw_in_gpio(struct mgos_config *cfg, int v) {
  cfg->sw.in_gpio = v;
}

/* sw.in_mode */
#define MGOS_CONFIG_HAVE_SW_IN_MODE
#define MGOS_SYS_CONFIG_HAVE_SW_IN_MODE
int mgos_config_get_sw_in_mode(struct mgos_config *cfg) {
  return cfg->sw.in_mode;
}
void mgos_config_set_sw_in_mode(struct mgos_config *cfg, int v) {
  cfg->sw.in_mode = v;
}

/* sw.state */
#define MGOS_CONFIG_HAVE_SW_STATE
#define MGOS_SYS_CONFIG_HAVE_SW_STATE
int mgos_config_get_sw_state(struct mgos_config *cfg) {
  return cfg->sw.state;
}
void mgos_config_set_sw_state(struct mgos_config *cfg, int v) {
  cfg->sw.state = v;
}

/* sw.persist_state */
#define MGOS_CONFIG_HAVE_SW_PERSIST_STATE
#define MGOS_SYS_CONFIG_HAVE_SW_PERSIST_STATE
int mgos_config_get_sw_persist_state(struct mgos_config *cfg) {
  return cfg->sw.persist_state;
}
void mgos_config_set_sw_persist_state(struct mgos_config *cfg, int v) {
  cfg->sw.persist_state = v;
}

/* sw1 */
#define MGOS_CONFIG_HAVE_SW1
#define MGOS_SYS_CONFIG_HAVE_SW1
const struct mgos_config_sw * mgos_config_get_sw1(struct mgos_config *cfg) {
  return &cfg->sw1;
}

/* sw1.id */
#define MGOS_CONFIG_HAVE_SW1_ID
#define MGOS_SYS_CONFIG_HAVE_SW1_ID
int mgos_config_get_sw1_id(struct mgos_config *cfg) {
  return cfg->sw1.id;
}
void mgos_config_set_sw1_id(struct mgos_config *cfg, int v) {
  cfg->sw1.id = v;
}

/* sw1.name */
#define MGOS_CONFIG_HAVE_SW1_NAME
#define MGOS_SYS_CONFIG_HAVE_SW1_NAME
const char * mgos_config_get_sw1_name(struct mgos_config *cfg) {
  return cfg->sw1.name;
}
void mgos_config_set_sw1_name(struct mgos_config *cfg, const char * v) {
  mgos_conf_set_str(&cfg->sw1.name, v);
}

/* sw1.enable */
#define MGOS_CONFIG_HAVE_SW1_ENABLE
#define MGOS_SYS_CONFIG_HAVE_SW1_ENABLE
int mgos_config_get_sw1_enable(struct mgos_config *cfg) {
  return cfg->sw1.enable;
}
void mgos_config_set_sw1_enable(struct mgos_config *cfg, int v) {
  cfg->sw1.enable = v;
}

/* sw1.out_gpio */
#define MGOS_CONFIG_HAVE_SW1_OUT_GPIO
#define MGOS_SYS_CONFIG_HAVE_SW1_OUT_GPIO
int mgos_config_get_sw1_out_gpio(struct mgos_config *cfg) {
  return cfg->sw1.out_gpio;
}
void mgos_config_set_sw1_out_gpio(struct mgos_config *cfg, int v) {
  cfg->sw1.out_gpio = v;
}

/* sw1.out_on_value */
#define MGOS_CONFIG_HAVE_SW1_OUT_ON_VALUE
#define MGOS_SYS_CONFIG_HAVE_SW1_OUT_ON_VALUE
int mgos_config_get_sw1_out_on_value(struct mgos_config *cfg) {
  return cfg->sw1.out_on_value;
}
void mgos_config_set_sw1_out_on_value(struct mgos_config *cfg, int v) {
  cfg->sw1.out_on_value = v;
}

/* sw1.in_gpio */
#define MGOS_CONFIG_HAVE_SW1_IN_GPIO
#define MGOS_SYS_CONFIG_HAVE_SW1_IN_GPIO
int mgos_config_get_sw1_in_gpio(struct mgos_config *cfg) {
  return cfg->sw1.in_gpio;
}
void mgos_config_set_sw1_in_gpio(struct mgos_config *cfg, int v) {
  cfg->sw1.in_gpio = v;
}

/* sw1.in_mode */
#define MGOS_CONFIG_HAVE_SW1_IN_MODE
#define MGOS_SYS_CONFIG_HAVE_SW1_IN_MODE
int mgos_config_get_sw1_in_mode(struct mgos_config *cfg) {
  return cfg->sw1.in_mode;
}
void mgos_config_set_sw1_in_mode(struct mgos_config *cfg, int v) {
  cfg->sw1.in_mode = v;
}

/* sw1.state */
#define MGOS_CONFIG_HAVE_SW1_STATE
#define MGOS_SYS_CONFIG_HAVE_SW1_STATE
int mgos_config_get_sw1_state(struct mgos_config *cfg) {
  return cfg->sw1.state;
}
void mgos_config_set_sw1_state(struct mgos_config *cfg, int v) {
  cfg->sw1.state = v;
}

/* sw1.persist_state */
#define MGOS_CONFIG_HAVE_SW1_PERSIST_STATE
#define MGOS_SYS_CONFIG_HAVE_SW1_PERSIST_STATE
int mgos_config_get_sw1_persist_state(struct mgos_config *cfg) {
  return cfg->sw1.persist_state;
}
void mgos_config_set_sw1_persist_state(struct mgos_config *cfg, int v) {
  cfg->sw1.persist_state = v;
}
bool mgos_sys_config_get(const struct mg_str key, struct mg_str *value) {
  return mgos_config_get(key, value, &mgos_sys_config, mgos_config_schema());
}
bool mgos_sys_config_set(const struct mg_str key, const struct mg_str value, bool free_strings) {
  return mgos_config_set(key, value, &mgos_sys_config, mgos_config_schema(), free_strings);
}
