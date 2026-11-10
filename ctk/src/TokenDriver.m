// Estensione CryptoTokenKit "ControlVault Fingerprint Token".
//
//   FPTokenDriver  (TKTokenDriver)         -> crea un FPToken per ogni config persistente
//   FPToken        (TKToken)               -> espone cert+chiave nel keychain, crea sessioni
//   FPTokenSession (TKTokenSession)        -> esegue la firma RSA con la chiave incorporata
//
// La chiave privata è incorporata (base64, PKCS#1) in IdentityMaterial.h: così
// l'estensione sandboxata non deve leggere file né parlare col lettore USB in questa
// tappa. Il gate-impronta sull'operazione di firma si aggiunge alla tappa successiva.
#import <Foundation/Foundation.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#import <Security/Security.h>
#import "IdentityMaterial.h"
#import "FPHelperProtocol.h"

// Log su file nel container sandbox (unified logging è inaffidabile su questo
// Hackintosh). Il file finisce in ~/Library/Containers/<bundle>/Data/fptoken.log
static void FPLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"fptoken.log"];
    NSString *stamp = [NSString stringWithFormat:@"%@ %@\n", [NSDate date], line];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) { [stamp writeToFile:path atomically:NO encoding:NSUTF8StringEncoding error:nil]; }
    else { [fh seekToEndOfFile]; [fh writeData:[stamp dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
}

// --- carica la chiave privata RSA incorporata come SecKeyRef ---
static SecKeyRef FPCopyPrivateKey(void) {
    NSData *der = [[NSData alloc] initWithBase64EncodedString:FP_KEY_B64 options:0];
    if (der == nil) return NULL;
    NSDictionary *attrs = @{
        (id)kSecAttrKeyType:  (id)kSecAttrKeyTypeRSA,
        (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
        (id)kSecAttrKeySizeInBits: @2048,
    };
    CFErrorRef err = NULL;
    SecKeyRef k = SecKeyCreateWithData((__bridge CFDataRef)der,
                                       (__bridge CFDictionaryRef)attrs, &err);
    if (k == NULL) {
        NSLog(@"[FPToken] SecKeyCreateWithData fallita: %@", (__bridge NSError *)err);
        if (err) CFRelease(err);
    }
    return k;
}

#pragma mark - Session

@interface FPTokenSession : TKTokenSession <TKTokenSessionDelegate> {
    NSDate *_authedUntil;   // finestra in cui una firma è consentita dopo un match
}
@end

@implementation FPTokenSession

// Esegue la verifica impronta tramite l'helper XPC. Ritorna YES solo su match.
// Su successo apre una breve finestra (20s) in cui signData può firmare senza
// ri-chiedere il dito (così un singolo flusso — login o sc_auth pair, che fa più
// firme — richiede un solo tocco).
- (BOOL)verifyFingerprint {
    __block BOOL ok = NO;
    __block NSString *why = @"nessuna risposta";
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSXPCConnection *c = [[NSXPCConnection alloc]
        initWithMachServiceName:FP_HELPER_SERVICE options:0];
    c.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(FPHelperProtocol)];
    [c resume];
    id<FPHelperProtocol> proxy = [c remoteObjectProxyWithErrorHandler:^(NSError *e) {
        FPLog(@"XPC errore: %@", e);
        why = @"helper impronta non raggiungibile";
        dispatch_semaphore_signal(sem);
    }];
    [proxy verifyFingerprintWithTimeout:25.0 reply:^(BOOL r, NSString *reason) {
        ok = r; why = reason ?: @"";
        dispatch_semaphore_signal(sem);
    }];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(32 * NSEC_PER_SEC)));
    [c invalidate];
    FPLog(@"verifyFingerprint ok=%d (%@)", ok, why);
    if (ok) _authedUntil = [NSDate dateWithTimeIntervalSinceNow:20.0];
    return ok;
}

// Il sistema chiede se sappiamo eseguire l'operazione con quella chiave/algoritmo.
- (BOOL)tokenSession:(TKTokenSession *)session
   supportsOperation:(TKTokenOperation)operation
             usingKey:(TKTokenObjectID)keyObjectID
            algorithm:(TKTokenKeyAlgorithm *)algorithm {
    FPLog(@"supportsOperation op=%ld key=%@", (long)operation, keyObjectID);
    if (operation != TKTokenOperationSignData) return NO;
    (void)keyObjectID;
    // Firma RSA: accettiamo gli algoritmi PKCS#1 v1.5 (raw + digest) che
    // il login/sblocco di macOS negozia.
    return [algorithm supportsAlgorithm:kSecKeyAlgorithmRSASignatureRaw]
        || [algorithm supportsAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw]
        || [algorithm supportsAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1]
        || [algorithm supportsAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256]
        || [algorithm supportsAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384]
        || [algorithm supportsAlgorithm:kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512]
        || [algorithm supportsAlgorithm:kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256];
}

// Gate impronta (via di sistema): chiamato prima di signData quando la chiave ha
// un constraint custom (@"fp"). Blocca finché l'helper XPC non conferma l'impronta.
- (TKTokenAuthOperation *)tokenSession:(TKTokenSession *)session
                 beginAuthForOperation:(TKTokenOperation)operation
                            constraint:(TKTokenOperationConstraint)constraint
                                 error:(NSError **)error {
    FPLog(@"beginAuth op=%ld constraint=%@", (long)operation, constraint);
    if (![self verifyFingerprint]) {
        if (error) *error = [NSError errorWithDomain:TKErrorDomain
            code:TKErrorCodeAuthenticationFailed
            userInfo:@{ NSLocalizedDescriptionKey: @"impronta non riconosciuta" }];
        return nil;
    }
    return [[TKTokenAuthOperation alloc] init];
}

- (NSData *)tokenSession:(TKTokenSession *)session
                signData:(NSData *)dataToSign
                usingKey:(TKTokenObjectID)keyObjectID
               algorithm:(TKTokenKeyAlgorithm *)algorithm
                   error:(NSError **)error {
    // GARANZIA: nessuna firma senza impronta. Se il sistema ha già chiamato
    // beginAuth con successo (finestra ancora valida) non ri-chiediamo il dito;
    // altrimenti (es. chiamata diretta a SecKeyCreateSignature) verifichiamo qui.
    // Un match apre una finestra di 10s valida per TUTTE le firme del flusso
    // (es. sc_auth pair ne fa diverse): non la consumiamo alla prima firma.
    BOOL fresh = (_authedUntil != nil && [_authedUntil timeIntervalSinceNow] > 0);
    if (!fresh && ![self verifyFingerprint]) {
        FPLog(@"signData BLOCCATO: impronta non verificata");
        if (error) *error = [NSError errorWithDomain:TKErrorDomain
            code:TKErrorCodeAuthenticationFailed
            userInfo:@{ NSLocalizedDescriptionKey: @"impronta non riconosciuta" }];
        return nil;
    }
    SecKeyRef priv = FPCopyPrivateKey();
    if (priv == NULL) {
        if (error) *error = [NSError errorWithDomain:TKErrorDomain
                                                code:TKErrorCodeTokenNotFound userInfo:nil];
        return nil;
    }
    // Scegli il SecKeyAlgorithm corrispondente a quello negoziato.
    SecKeyAlgorithm secAlg = NULL;
    SecKeyAlgorithm candidates[] = {
        kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw,
        kSecKeyAlgorithmRSASignatureRaw,
        kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
        kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1,
        kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384,
        kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,
        kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
    };
    for (size_t i = 0; i < sizeof(candidates)/sizeof(candidates[0]); i++) {
        if ([algorithm supportsAlgorithm:candidates[i]]) { secAlg = candidates[i]; break; }
    }
    if (secAlg == NULL) {
        CFRelease(priv);
        if (error) *error = [NSError errorWithDomain:TKErrorDomain
                                                code:TKErrorCodeBadParameter userInfo:nil];
        return nil;
    }
    CFErrorRef cfErr = NULL;
    CFDataRef sig = SecKeyCreateSignature(priv, secAlg,
                                          (__bridge CFDataRef)dataToSign, &cfErr);
    CFRelease(priv);
    if (sig == NULL) {
        FPLog(@"signData firma fallita: %@", (__bridge NSError *)cfErr);
        if (error) *error = (__bridge_transfer NSError *)cfErr;
        else if (cfErr) CFRelease(cfErr);
        return nil;
    }
    FPLog(@"signData firma OK (%ld byte)", (long)CFDataGetLength(sig));
    return (__bridge_transfer NSData *)sig;
}

@end

#pragma mark - Token

@interface FPToken : TKToken <TKTokenDelegate>
@end

@implementation FPToken

- (TKTokenSession *)token:(TKToken *)token createSessionWithError:(NSError **)error {
    FPLog(@"FPToken createSession (keychainContents items=%lu)",
          (unsigned long)self.keychainContents.items.count);
    return [[FPTokenSession alloc] initWithToken:self];
}

@end

#pragma mark - Driver

@interface FPTokenDriver : TKTokenDriver <TKTokenDriverDelegate>
@end

@implementation FPTokenDriver

+ (void)load { FPLog(@"=== estensione FPToken caricata (processo avviato da ctkd) ==="); }

- (instancetype)init {
    self = [super init];
    if (self) self.delegate = self;
    FPLog(@"FPTokenDriver init");
    return self;
}

- (nullable TKToken *)tokenDriver:(TKTokenDriver *)driver
            tokenForConfiguration:(TKTokenConfiguration *)configuration
                            error:(NSError * _Nullable __autoreleasing *)error {
    FPLog(@"tokenForConfiguration instanceID=%@ items=%lu",
          configuration.instanceID, (unsigned long)configuration.keychainItems.count);
    FPToken *token = [[FPToken alloc] initWithTokenDriver:driver
                                              instanceID:configuration.instanceID];
    token.delegate = token;
    // Propaga cert+chiave (impostati dall'app host) nel keychain di sistema,
    // così `sc_auth identities` vede l'identità.
    [token.keychainContents fillWithItems:configuration.keychainItems];
    FPLog(@"  token creato, keychainContents items=%lu", (unsigned long)token.keychainContents.items.count);
    return token;
}

@end
