// FPTokenApp — app host dell'estensione CTK.
// driverConfigurations è popolato SOLO nell'app che ospita l'estensione (per
// design), quindi la configurazione del token va fatta qui. Oltre a creare la
// token-config, vi inseriamo l'identità (certificato + metadati chiave) così che
// `sc_auth identities` la veda e si possa fare `sc_auth pair`.
#import <Foundation/Foundation.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#import <Security/Security.h>
#import "IdentityMaterial.h"

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSDictionary *dc = TKTokenDriverConfiguration.driverConfigurations;
        NSLog(@"[FPTokenApp] driver class-id visti dall'host: %@", dc.allKeys);

        TKTokenDriverConfiguration *cfg = dc[@"com.cvfp.fptoken"];
        if (cfg == nil) {
            NSLog(@"[FPTokenApp] ESITO: 'com.cvfp.fptoken' NON registrata (estensione non ingerita).");
            return 2;
        }
        NSLog(@"[FPTokenApp] driver TROVATO. token già configurati: %@", cfg.tokenConfigurations.allKeys);

        // --- costruisci cert + chiave dal materiale incorporato ---
        NSData *certDER = [[NSData alloc] initWithBase64EncodedString:FP_CERT_B64 options:0];
        SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certDER);
        if (cert == NULL) { NSLog(@"[FPTokenApp] certificato non valido"); return 4; }

        TKTokenObjectID objID = @"fp-identity";
        TKTokenKeychainCertificate *certItem =
            [[TKTokenKeychainCertificate alloc] initWithCertificate:cert objectID:objID];
        certItem.label = @"ControlVault Fingerprint";

        TKTokenKeychainKey *keyItem =
            [[TKTokenKeychainKey alloc] initWithCertificate:cert objectID:objID];
        keyItem.label = @"ControlVault Fingerprint";
        keyItem.canSign = YES;
        keyItem.canDecrypt = YES;          // serve per sbloccare il portachiavi di login
        keyItem.suitableForLogin = YES;
        // Constraint @YES = "sempre permesso SENZA auth di sistema": così macOS NON
        // mostra il campo PIN (il suo modello smartcard non si adatta all'impronta).
        // La sicurezza NON cala: l'impronta è imposta DENTRO signData/decryptData
        // (vedi -ensureAuthedFor:), che gira comunque per ogni operazione del token.
        keyItem.constraints = @{
            @(TKTokenOperationSignData):    @YES,
            @(TKTokenOperationDecryptData): @YES,
        };
        CFRelease(cert);

        // --- (ri)crea la token-config e popola l'identità ---
        TKTokenConfiguration *tc = [cfg addTokenConfigurationForTokenInstanceID:@"fp-1"];
        if (tc == nil) { NSLog(@"[FPTokenApp] addTokenConfiguration nil"); return 3; }
        tc.keychainItems = @[ certItem, keyItem ];
        NSLog(@"[FPTokenApp] token-config 'fp-1' creata con %lu item (cert+chiave).",
              (unsigned long)tc.keychainItems.count);
        NSLog(@"[FPTokenApp] ORA configurati: %@", cfg.tokenConfigurations.allKeys);
    }
    return 0;
}
