// fphelper — LaunchAgent NON sandboxato che espone il Mach service com.cvfp.fphelper.
// All'arrivo di una richiesta XPC dall'estensione CTK, esegue il verificatore
// impronta one-shot (tools/fpauth.py) e risponde ok in base al suo exit code.
//
// Gira nella sessione utente (Aqua) così può accedere al lettore USB ControlVault.
#import <Foundation/Foundation.h>
#import "../src/FPHelperProtocol.h"

static NSString * const kPython = @"/usr/local/bin/python3";
static NSString * const kScript = @"/Users/amoslobianco/usbcfg/tools/fpauth.py";

@interface FPHelper : NSObject <FPHelperProtocol, NSXPCListenerDelegate>
@end

@implementation FPHelper

// Avvisa l'utente (notifica + suono) che deve appoggiare il dito. Non blocca.
static void FPCue(void) {
    @try {
        NSTask *t = [[NSTask alloc] init];
        t.executableURL = [NSURL fileURLWithPath:@"/usr/bin/osascript"];
        t.arguments = @[ @"-e",
            @"display notification \"Appoggia il dito sul sensore\" with title \"ControlVault\" sound name \"Ping\"" ];
        [t launchAndReturnError:nil];
    } @catch (NSException *e) { /* best effort */ }
}

- (void)verifyFingerprintWithTimeout:(double)timeout
                               reply:(void (^)(BOOL, NSString *))reply {
    NSLog(@"[fphelper] richiesta verifica impronta (timeout=%.0f)", timeout);
    FPCue();
    @try {
        NSTask *t = [[NSTask alloc] init];
        t.executableURL = [NSURL fileURLWithPath:kPython];
        t.arguments = @[ kScript, @"--timeout", [NSString stringWithFormat:@"%.0f", timeout] ];
        NSError *err = nil;
        if (![t launchAndReturnError:&err]) {
            reply(NO, [NSString stringWithFormat:@"avvio verificatore fallito: %@", err.localizedDescription]);
            return;
        }
        [t waitUntilExit];
        int rc = t.terminationStatus;
        NSLog(@"[fphelper] fpauth.py exit=%d", rc);
        reply(rc == 0, rc == 0 ? @"ok" : @"impronta non riconosciuta o timeout");
    } @catch (NSException *ex) {
        reply(NO, [NSString stringWithFormat:@"eccezione helper: %@", ex.reason]);
    }
}

// --- NSXPCListenerDelegate ---
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)conn {
    conn.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(FPHelperProtocol)];
    conn.exportedObject = self;
    [conn resume];
    return YES;
}

@end

int main(void) {
    @autoreleasepool {
        FPHelper *h = [[FPHelper alloc] init];
        // LaunchAgent con MachServices: si usa initWithMachServiceName (launchd
        // ha già registrato il nome del servizio dal plist).
        NSXPCListener *mach = [[NSXPCListener alloc] initWithMachServiceName:FP_HELPER_SERVICE];
        mach.delegate = h;
        [mach resume];
        NSLog(@"[fphelper] in ascolto su %@", FP_HELPER_SERVICE);
        [[NSRunLoop currentRunLoop] run];
    }
    return 0;
}
