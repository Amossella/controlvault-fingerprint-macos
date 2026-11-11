// Protocollo XPC condiviso tra l'estensione CTK (client, sandboxata) e l'helper
// (server, NON sandboxato) che parla col lettore ControlVault via USB.
#ifndef FP_HELPER_PROTOCOL_H
#define FP_HELPER_PROTOCOL_H

#import <Foundation/Foundation.h>

#define FP_HELPER_SERVICE @"com.cvfp.fphelper"

@protocol FPHelperProtocol <NSObject>
// Attende l'impronta sul sensore e risponde ok=YES solo se combacia con un
// template registrato. 'reason' è mostrabile all'utente in caso di errore.
- (void)verifyFingerprintWithTimeout:(double)timeout
                               reply:(void (^)(BOOL ok, NSString *reason))reply;
@end

#endif
