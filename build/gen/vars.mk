APP=switch1pm
APP_BIN_LIBS=/data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/objs/libmbedtls-esp8266-noatca-2.17.0.a /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/objs/libmongoose-esp8266-nossl-2.17.0.a /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/objs/libota-common-esp8266-2.17.0.a /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/objs/libota-http-client-esp8266-2.17.0.a /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/objs/libota-http-server-esp8266-2.17.0.a /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/objs/librpc-service-ota-esp8266-2.17.0.a
APP_CFLAGS=-Wno-format -DBTN_GPIO=-1 -DHAP_DISABLE_ASSERTS=1 -DHAP_DISABLE_PRECONDITIONS=1 -DHAP_IDENTIFICATION=\"https://github.com/mongoose-os-libs/homekit-adk\" -DLED_GPIO=-1 -DLFS_NO_DEBUG=1 -DMBEDTLS_FREE_CERT_CHAIN=1 -DMBEDTLS_USER_CONFIG_FILE=\"mbedtls_platform_config.h\" -DMBEDTLS_X509_CA_CHAIN_ON_DISK=1 -DMGOS=1 -DMGOS_DNS_SD_HIDE_ADDITIONAL_INFO=0 -DMGOS_ENABLE_FILE_UPLOAD=1 -DMGOS_ENABLE_RPC_CHANNEL_HTTP=1 -DMGOS_ENABLE_SYS_SERVICE=1 -DMGOS_ENABLE_WEB_CONFIG=0 -DMGOS_ESP8266_WIFI_ENABLE_WPAENT=0 -DMGOS_HAP_SIMPLE_CONFIG=1 -DMGOS_HAVE_CORE=1 -DMGOS_HAVE_DNS_SD=1 -DMGOS_HAVE_HOMEKIT_ADK=1 -DMGOS_HAVE_HTTP_SERVER=1 -DMGOS_HAVE_MBEDTLS=1 -DMGOS_HAVE_MONGOOSE=1 -DMGOS_HAVE_OTA_COMMON=1 -DMGOS_HAVE_OTA_HTTP_CLIENT=1 -DMGOS_HAVE_OTA_HTTP_SERVER=1 -DMGOS_HAVE_RPC_COMMON=1 -DMGOS_HAVE_RPC_SERVICE_CONFIG=1 -DMGOS_HAVE_RPC_SERVICE_FS=1 -DMGOS_HAVE_RPC_SERVICE_OTA=1 -DMGOS_HAVE_RPC_UART=1 -DMGOS_HAVE_RPC_WS=1 -DMGOS_HAVE_VFS_COMMON=1 -DMGOS_HAVE_VFS_DEV_PART=1 -DMGOS_HAVE_VFS_FS_LFS=1 -DMGOS_HAVE_VFS_FS_SPIFFS=1 -DMGOS_HAVE_WIFI=1 -DMGOS_LFS1_COMPAT=0 -DMGOS_ROOT_FS_OPTS_LFS={"bs":4096,"is":128} -DMGOS_ROOT_FS_OPTS_SPIFFS={"bs":4096,"ps":256,"es":4096} -DMGOS_WIFI_ENABLE_AP_STA=1 -DMG_ENABLE_DNS=1 -DMG_ENABLE_DNS_SERVER=1 -DMG_ENABLE_MQTT=1 -DMG_ENABLE_SNTP=1 -DMG_ENABLE_SSL=0 -DMG_SSL_IF=MG_SSL_IF_MBEDTLS -DMG_SSL_IF_MBEDTLS_FREE_CERTS=1 -DNUM_SWITCHES=1 -DPRODUCT_HW_REV="1.0" -DPRODUCT_MODEL="Shelly1PM" -DPRODUCT_VENDOR="Allterco" -DSERVICE_NAME="Switch"
APP_CONF_SCHEMA=/data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/gen/mos_conf_schema.yml
APP_CXXFLAGS=-DBTN_GPIO=-1 -DHAP_DISABLE_ASSERTS=1 -DHAP_DISABLE_PRECONDITIONS=1 -DHAP_IDENTIFICATION=\"https://github.com/mongoose-os-libs/homekit-adk\" -DLED_GPIO=-1 -DLFS_NO_DEBUG=1 -DMBEDTLS_FREE_CERT_CHAIN=1 -DMBEDTLS_USER_CONFIG_FILE=\"mbedtls_platform_config.h\" -DMBEDTLS_X509_CA_CHAIN_ON_DISK=1 -DMGOS=1 -DMGOS_DNS_SD_HIDE_ADDITIONAL_INFO=0 -DMGOS_ENABLE_FILE_UPLOAD=1 -DMGOS_ENABLE_RPC_CHANNEL_HTTP=1 -DMGOS_ENABLE_SYS_SERVICE=1 -DMGOS_ENABLE_WEB_CONFIG=0 -DMGOS_ESP8266_WIFI_ENABLE_WPAENT=0 -DMGOS_HAP_SIMPLE_CONFIG=1 -DMGOS_HAVE_CORE=1 -DMGOS_HAVE_DNS_SD=1 -DMGOS_HAVE_HOMEKIT_ADK=1 -DMGOS_HAVE_HTTP_SERVER=1 -DMGOS_HAVE_MBEDTLS=1 -DMGOS_HAVE_MONGOOSE=1 -DMGOS_HAVE_OTA_COMMON=1 -DMGOS_HAVE_OTA_HTTP_CLIENT=1 -DMGOS_HAVE_OTA_HTTP_SERVER=1 -DMGOS_HAVE_RPC_COMMON=1 -DMGOS_HAVE_RPC_SERVICE_CONFIG=1 -DMGOS_HAVE_RPC_SERVICE_FS=1 -DMGOS_HAVE_RPC_SERVICE_OTA=1 -DMGOS_HAVE_RPC_UART=1 -DMGOS_HAVE_RPC_WS=1 -DMGOS_HAVE_VFS_COMMON=1 -DMGOS_HAVE_VFS_DEV_PART=1 -DMGOS_HAVE_VFS_FS_LFS=1 -DMGOS_HAVE_VFS_FS_SPIFFS=1 -DMGOS_HAVE_WIFI=1 -DMGOS_LFS1_COMPAT=0 -DMGOS_ROOT_FS_OPTS_LFS={"bs":4096,"is":128} -DMGOS_ROOT_FS_OPTS_SPIFFS={"bs":4096,"ps":256,"es":4096} -DMGOS_WIFI_ENABLE_AP_STA=1 -DMG_ENABLE_DNS=1 -DMG_ENABLE_DNS_SERVER=1 -DMG_ENABLE_MQTT=1 -DMG_ENABLE_SNTP=1 -DMG_ENABLE_SSL=0 -DMG_SSL_IF=MG_SSL_IF_MBEDTLS -DMG_SSL_IF_MBEDTLS_FREE_CERTS=1 -DNUM_SWITCHES=1 -DPRODUCT_HW_REV="1.0" -DPRODUCT_MODEL="Shelly1PM" -DPRODUCT_VENDOR="Allterco" -DSERVICE_NAME="Switch"
APP_FS_FILES=/data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/fs/axios.min.js.gz /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/fs/index.html
APP_INCLUDES=/data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/mbedtls/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/mbedtls/include/esp8266 /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/mbedtls/mbedtls/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-common/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-common/include/esp8266 /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/mongoose/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-dev-part/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-lfs/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-lfs/littlefs /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-lfs/littlefs1 /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-spiffs/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-spiffs/include/spiffs /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-spiffs/include/esp8266 /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/core/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/core/include/esp8266 /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/dns-sd/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/http-server/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/ota-common/src /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/ota-common/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/ota-common/include/esp8266 /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/ota-http-client/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-common/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-service-config/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-service-fs/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-service-ota/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-uart/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-ws/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/wifi/include /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/wifi/include/esp8266
APP_SOURCES=/data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/src/shelly_main.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/src/shelly_sw_service.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/gen/mgos_deps_init.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-common/src/mgos_vfs.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-common/src/mgos_vfs_dev.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-common/src/mgos_vfs_internal.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-common/src/esp8266/esp_flash_writer.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-common/src/esp8266/esp_fs.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-common/src/esp8266/esp_vfs_dev_sysflash.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-dev-part/src/mgos_vfs_dev_part.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-lfs/src/mgos_vfs_lfs.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-lfs/littlefs/lfs.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-lfs/littlefs/lfs_util.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-lfs/littlefs1/lfs1.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-lfs/littlefs1/lfs1_util.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-spiffs/src/mgos_vfs_fs_spiffs.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-spiffs/src/spiffs/spiffs_cache.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-spiffs/src/spiffs/spiffs_check.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-spiffs/src/spiffs/spiffs_gc.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-spiffs/src/spiffs/spiffs_hydrogen.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/vfs-fs-spiffs/src/spiffs/spiffs_nucleus.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/core/src/mgos_core.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/core/src/esp8266/esp_rboot.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/dns-sd/src/lwip/lwip_mdns.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/dns-sd/src/mongoose/mgos_dns_sd.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/dns-sd/src/mongoose/mgos_mdns.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPAccessory+Info.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPAccessoryServer+Reset.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPAccessoryServer.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPAccessorySetup.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPAccessorySetupInfo.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPAccessoryValidation.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLEAccessoryServer+Advertising.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLEAccessoryServer+Broadcast.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLEAccessoryServer.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLECharacteristic+Broadcast.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLECharacteristic+Configuration.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLECharacteristic+Signature.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLECharacteristic.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLECharacteristicParseAndWriteValue.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLECharacteristicReadAndSerializeValue.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLEPDU+TLV.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLEPDU.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLEPeripheralManager.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLEProcedure.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLEProtocol+Configuration.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLEService+Signature.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLESession.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBLETransaction.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPBitSet.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPCharacteristic.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPCharacteristicTypes.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPDeviceID.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPIP+ByteBuffer.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPIPAccessory.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPIPAccessoryProtocol.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPIPAccessoryServer.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPIPCharacteristic.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPIPSecurityProtocol.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPIPServiceDiscovery.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPJSONUtils.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPLegacyImport.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPMACAddress.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPMFiHWAuth.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPMFiTokenAuth.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPPDU.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPPairing.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPPairingBLESessionCache.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPPairingPairSetup.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPPairingPairVerify.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPPairingPairings.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPRequestHandlers+AccessoryInformation.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPRequestHandlers+HAPProtocolInformation.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPRequestHandlers+Pairing.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPRequestHandlers.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPServiceTypes.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPSession.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPStringBuilder.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPTLV.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPTLVMemory.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPTLVReader.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPTLVWriter.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPUUID.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/HAP/HAPVersion.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/PAL/HAPAssert.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/PAL/HAPBase+Crypto.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/PAL/HAPBase+Double.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/PAL/HAPBase+Float.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/PAL/HAPBase+Int.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/PAL/HAPBase+MACAddress.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/PAL/HAPBase+RawBuffer.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/PAL/HAPBase+Sha1Checksum.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/PAL/HAPBase+String.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/PAL/HAPBase+UTF8.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/PAL/HAPLog.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/PAL/HAPPlatformSystemInit.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/PAL/Crypto/MbedTLS/HAPMbedTLS.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/External/Base64/util_base64.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/External/HTTP/util_http_reader.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/HomeKitADK/External/JSON/util_json_reader.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/mgos_homekit_adk.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/mgos_homekit_adk_db.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/mgos_homekit_adk_rpc_service.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/PAL/HAPPlatform.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/PAL/HAPPlatformAbort.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/PAL/HAPPlatformAccessorySetup.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/PAL/HAPPlatformBLEPeripheralManager.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/PAL/HAPPlatformClock.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/PAL/HAPPlatformLog.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/PAL/HAPPlatformMFiHWAuth.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/PAL/HAPPlatformMFiTokenAuth.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/PAL/HAPPlatformRandomNumber.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/PAL/HAPPlatformServiceDiscovery.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/PAL/HAPPlatformTCPStreamManager.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/PAL/HAPPlatformTimer.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/homekit-adk/src/PAL/HAPPlatformKeyValueStore.cpp /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/http-server/src/mgos_http_server.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-common/src/mg_rpc.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-common/src/mg_rpc_channel.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-common/src/mg_rpc_channel_http.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-common/src/mgos_rpc.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-service-config/src/mgos_service_config.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-service-fs/src/mgos_service_fs.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-uart/src/mgos_rpc_channel_uart.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-ws/src/mgos_rpc_channel_ws.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/rpc-ws/src/mgos_rpc_ws.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/wifi/src/mgos_wifi.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/wifi/src/mjs_wifi.c /data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/deps/wifi/src/esp8266/esp_wifi.c
APP_VERSION=1.4.0
BOARD=
BOOT_CONFIG_ADDR=0x1000
BUILD_DIR=/data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/objs
FFI_SYMBOLS=
FLASH_SIZE=2097152
FS_SIZE=262144
FS_STAGING_DIR=/data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/fs
FW_DIR=/data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/fw
GEN_DIR=/data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/gen
MANIFEST_FINAL=/data/fwbuild-volumes/2.17.0/apps/switch1pm/esp8266/build_contexts/build_ctx_780968662/build/gen/mos_final.yml
MGOS=1
MGOS_HAP_SIMPLE_CONFIG=1
MGOS_HAVE_CORE=1
MGOS_HAVE_DNS_SD=1
MGOS_HAVE_HOMEKIT_ADK=1
MGOS_HAVE_HTTP_SERVER=1
MGOS_HAVE_MBEDTLS=1
MGOS_HAVE_MONGOOSE=1
MGOS_HAVE_OTA_COMMON=1
MGOS_HAVE_OTA_HTTP_CLIENT=1
MGOS_HAVE_OTA_HTTP_SERVER=1
MGOS_HAVE_RPC_COMMON=1
MGOS_HAVE_RPC_SERVICE_CONFIG=1
MGOS_HAVE_RPC_SERVICE_FS=1
MGOS_HAVE_RPC_SERVICE_OTA=1
MGOS_HAVE_RPC_UART=1
MGOS_HAVE_RPC_WS=1
MGOS_HAVE_VFS_COMMON=1
MGOS_HAVE_VFS_DEV_PART=1
MGOS_HAVE_VFS_FS_LFS=1
MGOS_HAVE_VFS_FS_SPIFFS=1
MGOS_HAVE_WIFI=1
MGOS_MBEDTLS_ENABLE_ATCA=0
MGOS_PATH=/mongoose-os
MGOS_ROOT_FS_OPTS_LFS={"bs":4096,"is":128}
MGOS_ROOT_FS_OPTS_SPIFFS={"bs":4096,"ps":256,"es":4096}
MGOS_ROOT_FS_TYPE=SPIFFS
MGOS_WIFI_ENABLE_AP_STA=0
MODEL=Shelly1PM
PLATFORM=esp8266