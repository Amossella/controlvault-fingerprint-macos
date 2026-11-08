#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_util.hpp>

#define TAG "usbcfg"

static const char *bootargOff[]   { "-usbcfgoff" };
static const char *bootargDebug[] { "-usbcfgdbg" };
static const char *bootargBeta[]  { "-usbcfgbeta" };

static const char *pathUSBHost[] { "/System/Library/Extensions/IOUSBHostFamily.kext/Contents/MacOS/IOUSBHostFamily" };
static KernelPatcher::KextInfo kextUSBHost { "com.apple.iokit.IOUSBHostFamily", pathUSBHost, arrsize(pathUSBHost), {}, {}, KernelPatcher::KextInfo::Unloaded };

static mach_vm_address_t orgSetConfig {}, orgSetConfigGated {}, orgCacheDesc {}, orgCacheDescGated {};

// v6: il device ha una sola configurazione con bConfigurationValue = 0 (come vede anche Windows,
// che gli manda SET_CONFIGURATION(0)). Il descrittore resta patchato a 1 per IOKit, ma sul cavo
// la richiesta SET_CONFIGURATION(1) viene riscritta in SET_CONFIGURATION(0).
struct __attribute__((packed)) UsbSetup { uint8_t bmRequestType, bRequest; uint16_t wValue, wIndex, wLength; };
static_assert(sizeof(UsbSetup) == 8, "setup packet");

static mach_vm_address_t orgIDR {}, orgDR_buf_sync {}, orgDR_md_sync {}, orgDR_buf_async {}, orgDR_md_async {}, orgDR_full {};

static bool isTarget(IOService *s);

static void fixSetConfig(IOService *that, void *req, const char *who) {
    auto r = (UsbSetup *)req;
    if (!r || r->bmRequestType != 0x00 || r->bRequest != 9 || r->wValue != 1) return;
    if (!isTarget(that)) return;
    SYSLOG(TAG, "%s: SET_CONFIGURATION(1) -> SET_CONFIGURATION(0) sul cavo (this=%p)", who, that);
    r->wValue = 0;
}

static int wrapIDR(IOService *that, IOService *c, void *req, void *buf, void *md, void *len, void *cmp, uint32_t to) {
    fixSetConfig(that, req, "internalDeviceRequest");
    return FunctionCast(wrapIDR, orgIDR)(that, c, req, buf, md, len, cmp, to);
}
static int wrapDRbufSync(IOService *that, IOService *c, void *req, void *buf, void *len, uint32_t to) {
    fixSetConfig(that, req, "deviceRequest(buf,sync)");
    return FunctionCast(wrapDRbufSync, orgDR_buf_sync)(that, c, req, buf, len, to);
}
static int wrapDRmdSync(IOService *that, IOService *c, void *req, void *md, void *len, uint32_t to) {
    fixSetConfig(that, req, "deviceRequest(md,sync)");
    return FunctionCast(wrapDRmdSync, orgDR_md_sync)(that, c, req, md, len, to);
}
static int wrapDRbufAsync(IOService *that, IOService *c, void *req, void *buf, void *cmp, uint32_t to) {
    fixSetConfig(that, req, "deviceRequest(buf,async)");
    return FunctionCast(wrapDRbufAsync, orgDR_buf_async)(that, c, req, buf, cmp, to);
}
static int wrapDRmdAsync(IOService *that, IOService *c, void *req, void *md, void *cmp, uint32_t to) {
    fixSetConfig(that, req, "deviceRequest(md,async)");
    return FunctionCast(wrapDRmdAsync, orgDR_md_async)(that, c, req, md, cmp, to);
}
static int wrapDRfull(IOService *that, IOService *c, void *req, void *buf, void *md, void *len, void *cmp, uint32_t to) {
    fixSetConfig(that, req, "deviceRequest(full)");
    return FunctionCast(wrapDRfull, orgDR_full)(that, c, req, buf, md, len, cmp, to);
}

static bool isTarget(IOService *s) {
    if (!s) return false;
    auto v = OSDynamicCast(OSNumber, s->getProperty("idVendor"));
    auto p = OSDynamicCast(OSNumber, s->getProperty("idProduct"));
    return v && p && v->unsigned32BitValue() == 0x0a5c && p->unsigned32BitValue() == 0x5834;
}

static void patchIfConfigDesc(IOService *that, const void *desc, const char *who) {
    if (!isTarget(that) || !desc) return;
    uint8_t *d = (uint8_t *)desc;
    if (d[0] == 9 && d[1] == 2) {
        if (d[5] == 0) {
            SYSLOG(TAG, "%s: PATCH bConfigurationValue 0 -> 1 (this=%p)", who, that);
            d[5] = 1;
        } else {
            SYSLOG(TAG, "%s: bConfigurationValue già %u, nessuna patch necessaria", who, d[5]);
        }
    }
}

static int wrapSetConfig(IOService *that, uint8_t value, bool match) {
    bool t = isTarget(that);
    if (t) SYSLOG(TAG, "DEVICE setConfiguration(%u, match=%d) this=%p CHIAMATA", value, match, that);
    int r = FunctionCast(wrapSetConfig, orgSetConfig)(that, value, match);
    if (t) SYSLOG(TAG, "DEVICE setConfiguration(%u) -> 0x%x", value, r);
    return r;
}

static int wrapSetConfigGated(IOService *that, uint8_t value, bool match) {
    bool t = isTarget(that);
    if (t) SYSLOG(TAG, "DEVICE setConfigurationGated(%u, match=%d) this=%p CHIAMATA", value, match, that);
    int r = FunctionCast(wrapSetConfigGated, orgSetConfigGated)(that, value, match);
    if (t) SYSLOG(TAG, "DEVICE setConfigurationGated(%u) -> 0x%x", value, r);
    return r;
}

static void *wrapCacheDesc(IOService *that, const void *desc, uint16_t a, uint8_t b, uint16_t c) {
    patchIfConfigDesc(that, desc, "cacheDescriptor");
    return FunctionCast(wrapCacheDesc, orgCacheDesc)(that, desc, a, b, c);
}

static void *wrapCacheDescGated(IOService *that, const void *desc, uint16_t a, uint8_t b, uint16_t c) {
    patchIfConfigDesc(that, desc, "cacheDescriptorGated");
    return FunctionCast(wrapCacheDescGated, orgCacheDescGated)(that, desc, a, b, c);
}

static void processKext(void *user, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size) {
    if (kextUSBHost.loadIndex != index) return;
    SYSLOG(TAG, "processKext chiamata per IOUSBHostFamily, index=%zu address=0x%llx size=%zu", index, address, size);
    KernelPatcher::RouteRequest requests[] = {
        {"__ZN15IOUSBHostDevice16setConfigurationEhb", wrapSetConfig, orgSetConfig},
        {"__ZN15IOUSBHostDevice21setConfigurationGatedEhb", wrapSetConfigGated, orgSetConfigGated},
        {"__ZN15IOUSBHostDevice15cacheDescriptorEPKN11StandardUSB10DescriptorEtht", wrapCacheDesc, orgCacheDesc},
        {"__ZN15IOUSBHostDevice20cacheDescriptorGatedEPKN11StandardUSB10DescriptorEtht", wrapCacheDescGated, orgCacheDescGated},
    };
    patcher.routeMultiple(index, requests, arrsize(requests), address, size);
    if (patcher.getError() != KernelPatcher::Error::NoError) {
        SYSLOG(TAG, "routeMultiple fallita, errore %d", patcher.getError());
        patcher.clearError();
    } else {
        SYSLOG(TAG, "funzioni agganciate (v6)");
    }

    // v6: hook separati, così un simbolo mancante non blocca gli altri
    KernelPatcher::RouteRequest wire[] = {
        {"__ZN15IOUSBHostDevice21internalDeviceRequestEP9IOServiceRN11StandardUSB13DeviceRequestEPvP18IOMemoryDescriptorRjP19IOUSBHostCompletionj", wrapIDR, orgIDR},
        {"__ZN15IOUSBHostDevice13deviceRequestEP9IOServiceRN11StandardUSB13DeviceRequestEPvRjj", wrapDRbufSync, orgDR_buf_sync},
        {"__ZN15IOUSBHostDevice13deviceRequestEP9IOServiceRN11StandardUSB13DeviceRequestEP18IOMemoryDescriptorRjj", wrapDRmdSync, orgDR_md_sync},
        {"__ZN15IOUSBHostDevice13deviceRequestEP9IOServiceRN11StandardUSB13DeviceRequestEPvP19IOUSBHostCompletionj", wrapDRbufAsync, orgDR_buf_async},
        {"__ZN15IOUSBHostDevice13deviceRequestEP9IOServiceRN11StandardUSB13DeviceRequestEP18IOMemoryDescriptorP19IOUSBHostCompletionj", wrapDRmdAsync, orgDR_md_async},
        {"__ZN15IOUSBHostDevice13deviceRequestEP9IOServiceRN11StandardUSB13DeviceRequestEPvP18IOMemoryDescriptorRjP19IOUSBHostCompletionj", wrapDRfull, orgDR_full},
    };
    for (auto &r : wire) {
        if (!patcher.routeMultiple(index, &r, 1, address, size)) {
            SYSLOG(TAG, "v6: hook fallito per %s (errore %d)", r.symbol, patcher.getError());
            patcher.clearError();
        } else {
            SYSLOG(TAG, "v6: agganciato %s", r.symbol);
        }
    }
}

PluginConfiguration ADDPR(config) {
    xStringify(PRODUCT_NAME),
    parseModuleVersion(xStringify(MODULE_VERSION)),
    LiluAPI::AllowNormal,
    bootargOff, arrsize(bootargOff),
    bootargDebug, arrsize(bootargDebug),
    bootargBeta, arrsize(bootargBeta),
    KernelVersion::BigSur,
    KernelVersion::Sequoia,
    []() {
        SYSLOG(TAG, "plugin avviato v6 (config 0 sul cavo), imposto flag Loaded e registro onKextLoadForce");
        kextUSBHost.sys[KernelPatcher::KextInfo::Loaded] = true;
        lilu.onKextLoadForce(&kextUSBHost, 1, processKext);
    }
};